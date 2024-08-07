use std::{
    collections::{HashMap, HashSet},
    ops::Range,
    sync::Arc,
};

use futures::{StreamExt, TryFutureExt};
use parking_lot::RwLock;
use plain_bitnames::{
    bip300301::{bitcoin, MainClient},
    format_deposit_address,
    miner::{self, Miner},
    node::{self, Node, THIS_SIDECHAIN},
    types::{
        self, hashes::BitName, Body, FilledOutput, GetValue, InPoint, OutPoint,
        Transaction,
    },
    wallet::{self, Wallet},
};
use tokio::{spawn, sync::RwLock as TokioRwLock, task::JoinHandle};
use tokio_util::task::LocalPoolHandle;

use crate::cli::Config;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("drivechain error")]
    Drivechain(#[from] bip300301::Error),
    #[error("io error")]
    Io(#[from] std::io::Error),
    #[error("jsonrpsee error")]
    Jsonrpsee(#[from] jsonrpsee::core::Error),
    #[error("miner error: {0}")]
    Miner(#[from] miner::Error),
    #[error("node error")]
    Node(#[from] node::Error),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
    #[error("wallet error")]
    Wallet(#[from] wallet::Error),
}

fn update_wallet(node: &Node, wallet: &Wallet) -> Result<(), Error> {
    let addresses = wallet.get_addresses()?;
    let utxos = node.get_utxos_by_addresses(&addresses)?;
    let outpoints: Vec<_> = wallet.get_utxos()?.into_keys().collect();
    let spent: Vec<_> = node
        .get_spent_utxos(&outpoints)?
        .into_iter()
        .map(|(outpoint, spent_output)| (outpoint, spent_output.inpoint))
        .collect();
    wallet.put_utxos(&utxos)?;
    wallet.spend_utxos(&spent)?;
    Ok(())
}

/// Update utxos & wallet
fn update(
    node: &Node,
    utxos: &mut HashMap<OutPoint, FilledOutput>,
    wallet: &Wallet,
) -> Result<(), Error> {
    let () = update_wallet(node, wallet)?;
    *utxos = wallet.get_utxos()?;
    Ok(())
}

#[derive(Clone)]
pub struct App {
    pub node: Arc<Node>,
    pub wallet: Wallet,
    pub miner: Arc<TokioRwLock<Miner>>,
    pub utxos: Arc<RwLock<HashMap<OutPoint, FilledOutput>>>,
    pub runtime: Arc<tokio::runtime::Runtime>,
    task: Arc<JoinHandle<()>>,
    pub local_pool: LocalPoolHandle,
}

impl App {
    async fn task(
        node: Arc<Node>,
        utxos: Arc<RwLock<HashMap<OutPoint, FilledOutput>>>,
        wallet: Wallet,
    ) -> Result<(), Error> {
        let mut state_changes = node.watch_state();
        while let Some(()) = state_changes.next().await {
            let () = update(&node, &mut utxos.write(), &wallet)?;
        }
        Ok(())
    }

    fn spawn_task(
        node: Arc<Node>,
        utxos: Arc<RwLock<HashMap<OutPoint, FilledOutput>>>,
        wallet: Wallet,
    ) -> JoinHandle<()> {
        spawn(Self::task(node, utxos, wallet).unwrap_or_else(|err| {
            let err = anyhow::Error::from(err);
            tracing::error!("{err:#}")
        }))
    }

    pub fn new(config: &Config) -> Result<Self, Error> {
        // Node launches some tokio tasks for p2p networking, that is why we need a tokio runtime
        // here.
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        let wallet = Wallet::new(&config.datadir.join("wallet.mdb"))?;
        if let Some(seed_phrase_path) = &config.mnemonic_seed_phrase_path {
            let mnemonic = std::fs::read_to_string(seed_phrase_path)?;
            let () = wallet.set_seed_from_mnemonic(mnemonic.as_str())?;
        }
        let miner = Miner::new(
            THIS_SIDECHAIN,
            config.main_addr,
            &config.main_user,
            &config.main_password,
        )?;
        let rt_guard = runtime.enter();
        let local_pool = LocalPoolHandle::new(1);
        let node = Node::new(
            config.net_addr,
            &config.datadir,
            config.main_addr,
            config.network,
            &config.main_password,
            &config.main_user,
            local_pool.clone(),
            #[cfg(all(not(target_os = "windows"), feature = "zmq"))]
            config.zmq_addr,
        )?;
        let utxos = {
            let mut utxos = wallet.get_utxos()?;
            let transactions = node.get_all_transactions()?;
            for transaction in &transactions {
                for input in &transaction.transaction.inputs {
                    utxos.remove(input);
                }
            }
            Arc::new(RwLock::new(utxos))
        };
        let node = Arc::new(node);
        let task =
            Self::spawn_task(node.clone(), utxos.clone(), wallet.clone());
        drop(rt_guard);
        Ok(Self {
            node,
            wallet,
            miner: Arc::new(TokioRwLock::new(miner)),
            utxos,
            task: Arc::new(task),
            runtime: Arc::new(runtime),
            local_pool,
        })
    }

    /// Update utxos & wallet
    fn update(&self) -> Result<(), Error> {
        update(self.node.as_ref(), &mut self.utxos.write(), &self.wallet)
    }

    pub fn sign_and_send(&self, tx: Transaction) -> Result<(), Error> {
        let authorized_transaction = self.wallet.authorize(tx)?;
        self.node.submit_transaction(authorized_transaction)?;
        let () = self.update()?;
        Ok(())
    }

    pub fn get_new_main_address(
        &self,
    ) -> Result<bitcoin::Address<bitcoin::address::NetworkChecked>, Error> {
        let address = self.runtime.block_on({
            let miner = self.miner.clone();
            async move {
                let miner_read = miner.read().await;
                let drivechain_client = &miner_read.drivechain.client;
                let mainchain_info =
                    drivechain_client.get_blockchain_info().await?;
                let res = drivechain_client
                    .getnewaddress("", "legacy")
                    .await?
                    .require_network(mainchain_info.chain)
                    .unwrap();
                Result::<_, Error>::Ok(res)
            }
        })?;
        Ok(address)
    }

    /** Get all paymail.
     *  If `inbox_whitelist` is `Some`,
     * only the specified bitnames will be used as inboxes. */
    pub fn get_paymail(
        &self,
        inbox_whitelist: Option<&HashSet<BitName>>,
    ) -> Result<HashMap<OutPoint, FilledOutput>, Error> {
        let mut utxos = self.wallet.get_utxos()?;
        let mut bitname_utxos = self.wallet.get_bitnames()?;
        let mut bitname_stxos = self.wallet.get_spent_bitnames()?;
        if let Some(inbox_whitelist) = inbox_whitelist {
            bitname_utxos.retain(|_, output| {
                let Some(bitname) = output.bitname() else {
                    return false;
                };
                inbox_whitelist.contains(bitname)
            });
            bitname_stxos.retain(|_, output| {
                let Some(bitname) = output.output.bitname() else {
                    return false;
                };
                inbox_whitelist.contains(bitname)
            })
        };
        let tip = self.node.get_tip()?;
        let outpoints_to_block_heights: HashMap<_, _> = utxos
            .iter()
            .map(|(&outpoint, _)| outpoint)
            .chain(bitname_stxos.iter().map(|(&outpoint, _)| outpoint))
            .filter_map(|outpoint| match outpoint {
                OutPoint::Regular { txid, vout: _ } => Some((outpoint, txid)),
                _ => None,
            })
            .map(|(outpoint, txid)| {
                let inclusions = self.node.get_tx_inclusions(txid)?;
                let Some(block_hash) =
                    inclusions.into_keys().try_find(|block_hash| {
                        self.node.is_descendant(*block_hash, tip)
                    })?
                else {
                    return Ok((outpoint, None));
                };
                let height = self.node.get_height(block_hash)?;
                Ok((outpoint, Some(height)))
            })
            .collect::<Result<_, node::Error>>()?;
        let inpoints_to_block_heights: HashMap<_, _> =
            bitname_stxos.values()
                .map(|spent_output| {
                let txid = match spent_output.inpoint {
                    InPoint::Regular { txid, vin:_ } => txid,
                    _ => panic!(
                        "Impossible: bitname inpoint can only refer to regular tx"
                    )
                };
                let inclusions = self.node.get_tx_inclusions(txid)?;
                let Some(block_hash) = inclusions.into_keys().try_find(|block_hash| {
                    self.node.is_descendant(*block_hash, tip)
                })? else {
                    return Ok((spent_output.inpoint, None));
                };
                let height = self.node.get_height(block_hash)?;
                Ok((spent_output.inpoint, Some(height)))
            }).collect::<Result<_, node::Error>>()?;
        /* associate to each address, a set of pairs of bitname data and
        ownership period for the bitname. */
        let mut addrs_to_bitnames_ownership: HashMap<_, HashSet<_>> =
            HashMap::new();
        // populate with owned bitnames
        for (outpoint, output) in bitname_utxos {
            let Some(bitname) = output.bitname() else {
                continue;
            };
            let bitname_data = self.node.get_current_bitname_data(bitname)?;
            let Some(height) = outpoints_to_block_heights[&outpoint] else {
                continue;
            };
            let owned = Range {
                start: height,
                end: u32::MAX,
            };
            addrs_to_bitnames_ownership
                .entry(output.address)
                .or_default()
                .insert((bitname_data, owned));
        }
        // populate with spent bitnames
        for (outpoint, output) in bitname_stxos {
            let Some(bitname) = output.output.bitname() else {
                continue;
            };
            let Some(acquired_height) = outpoints_to_block_heights[&outpoint]
            else {
                continue;
            };
            let spent_height = inpoints_to_block_heights[&output.inpoint];
            let bitname_data = self
                .node
                .get_bitname_data_at_block_height(bitname, acquired_height)?;
            let owned = Range {
                start: acquired_height,
                end: spent_height.unwrap_or(u32::MAX),
            };
            addrs_to_bitnames_ownership
                .entry(output.output.address)
                .or_default()
                .insert((bitname_data, owned));
        }
        // retain if memo exists, and output value >= paymail fee
        utxos.retain(|outpoint, output| {
            if output.memo.is_empty() {
                return false;
            }
            let Some(bitname_data_ownership) =
                addrs_to_bitnames_ownership.get(&output.address)
            else {
                return false;
            };
            let Some(height) = outpoints_to_block_heights[outpoint] else {
                return false;
            };
            let min_fee = bitname_data_ownership
                .iter()
                .filter_map(|(bitname_data, ownership)| {
                    if !ownership.contains(&height) {
                        return None;
                    };
                    bitname_data.paymail_fee
                })
                .min();
            let Some(min_fee) = min_fee else {
                return false;
            };
            output.get_value() >= min_fee
        });
        Ok(utxos)
    }

    const EMPTY_BLOCK_BMM_BRIBE: bip300301::bitcoin::Amount =
        bip300301::bitcoin::Amount::from_sat(1000);

    pub async fn mine(
        &self,
        fee: Option<bip300301::bitcoin::Amount>,
    ) -> Result<(), Error> {
        const NUM_TRANSACTIONS: usize = 1000;
        let (txs, tx_fees) = self.node.get_transactions(NUM_TRANSACTIONS)?;
        let coinbase = match tx_fees {
            0 => vec![],
            _ => vec![types::Output::new(
                self.wallet.get_new_address()?,
                types::OutputContent::Value(tx_fees),
            )],
        };
        let merkle_root = {
            let txs = txs
                .iter()
                .map(|authorized_tx| authorized_tx.transaction.clone())
                .collect::<Vec<_>>();
            Body::compute_merkle_root(&coinbase, &txs).ok_or(Error::Other(
                anyhow::anyhow!("Failed to compute merkle root"),
            ))
        }?;
        let body = {
            let txs = txs.into_iter().map(|tx| tx.into()).collect();
            Body::new(txs, coinbase)
        };
        let prev_side_hash = self.node.get_tip()?;
        let prev_main_hash = self
            .miner
            .read()
            .await
            .drivechain
            .get_mainchain_tip()
            .await?;
        let header = types::Header {
            merkle_root,
            prev_side_hash,
            prev_main_hash,
        };
        let bribe = fee.unwrap_or_else(|| {
            if tx_fees > 0 {
                bip300301::bitcoin::Amount::from_sat(tx_fees)
            } else {
                Self::EMPTY_BLOCK_BMM_BRIBE
            }
        });
        let mut miner_write = self.miner.write().await;
        miner_write
            .attempt_bmm(bribe.to_sat(), 0, header, body)
            .await?;
        // miner_write.generate().await?;
        tracing::trace!("confirming bmm...");
        if let Some((main_hash, header, body)) =
            miner_write.confirm_bmm().await?
        {
            tracing::trace!(
                "confirmed bmm, submitting block {}",
                header.hash()
            );
            self.node.submit_block(main_hash, &header, &body).await?;
        }
        let () = self.update()?;
        Ok(())
    }

    pub fn deposit(
        &mut self,
        amount: bitcoin::Amount,
        fee: bitcoin::Amount,
    ) -> Result<(), Error> {
        self.runtime.block_on(async {
            let address = self.wallet.get_new_address()?;
            let address =
                format_deposit_address(THIS_SIDECHAIN, &format!("{address}"));
            self.miner
                .read()
                .await
                .drivechain
                .client
                .createsidechaindeposit(
                    THIS_SIDECHAIN,
                    &address,
                    amount.into(),
                    fee.into(),
                )
                .await?;
            Ok(())
        })
    }
}

impl Drop for App {
    fn drop(&mut self) {
        self.task.abort()
    }
}
