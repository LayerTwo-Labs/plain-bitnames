use std::{
    collections::{HashMap, HashSet},
    ops::Range,
    sync::Arc,
};

use futures::{StreamExt as _, TryFutureExt as _};
use parking_lot::RwLock;
use plain_bitnames::{
    miner::{self, Miner},
    node::{self, Node},
    types::{
        self,
        hashes::BitName,
        proto::mainchain::{
            self,
            generated::{validator_service_server, wallet_service_server},
        },
        Address, AmountOverflowError, Body, FilledOutput, GetValue, InPoint,
        OutPoint, Transaction,
    },
    wallet::{self, Wallet},
};
use tokio::{spawn, sync::RwLock as TokioRwLock, task::JoinHandle};
use tokio_util::task::LocalPoolHandle;
use tonic_health::{
    pb::{health_client::HealthClient, HealthCheckRequest},
    ServingStatus,
};

use crate::cli::Config;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    AmountOverflow(#[from] AmountOverflowError),
    #[error("CUSF mainchain proto error")]
    CusfMainchain(#[from] plain_bitnames::types::proto::Error),
    #[error("io error")]
    Io(#[from] std::io::Error),
    #[error("miner error: {0}")]
    Miner(#[from] miner::Error),
    #[error("node error")]
    Node(#[from] node::Error),
    #[error("No CUSF mainchain wallet client")]
    NoCusfMainchainWalletClient,
    #[error(transparent)]
    Other(#[from] anyhow::Error),
    #[error(
        "Unable to verify existence of CUSF mainchain service(s) at {address}"
    )]
    VerifyMainchainServices {
        address: std::net::SocketAddr,
        source: tonic::Status,
    },
    #[error("wallet error")]
    Wallet(#[from] wallet::Error),
}

fn update_wallet(node: &Node, wallet: &Wallet) -> Result<(), Error> {
    tracing::trace!("starting wallet update");
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
    tracing::debug!("finished wallet update");
    Ok(())
}

/// Update utxos & wallet
fn update(
    node: &Node,
    utxos: &mut HashMap<OutPoint, FilledOutput>,
    wallet: &Wallet,
) -> Result<(), Error> {
    tracing::trace!("Updating wallet");
    let () = update_wallet(node, wallet)?;
    *utxos = wallet.get_utxos()?;
    tracing::trace!("Updated wallet");
    Ok(())
}

#[derive(Clone)]
pub struct App {
    pub node: Arc<Node>,
    pub wallet: Wallet,
    pub miner: Option<Arc<TokioRwLock<Miner>>>,
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

    /// Check that a service has `Serving` status via gRPC health
    async fn check_status_serving(
        client: &mut HealthClient<tonic::transport::Channel>,
        service_name: &str,
    ) -> Result<bool, tonic::Status> {
        let health_check_request = HealthCheckRequest {
            service: service_name.to_string(),
        };
        match client.check(health_check_request).await {
            Ok(res) => {
                let expected_status = ServingStatus::Serving;
                let status = res.into_inner().status;
                let as_expected = status == expected_status as i32;
                if !as_expected {
                    tracing::warn!(
                        "Expected status {} for {}, got {}",
                        expected_status,
                        service_name,
                        status
                    );
                }
                Ok(as_expected)
            }
            Err(status) if status.code() == tonic::Code::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Returns `true` if validator service AND wallet service are available,
    /// `false` if only validator service is available, and error if validator
    /// service is unavailable.
    async fn check_proto_support(
        transport: tonic::transport::channel::Channel,
    ) -> Result<bool, tonic::Status> {
        let mut health_client = HealthClient::new(transport);
        let validator_service_name = validator_service_server::SERVICE_NAME;
        let wallet_service_name = wallet_service_server::SERVICE_NAME;
        // The validator service MUST exist. We therefore error out here directly.
        if !Self::check_status_serving(
            &mut health_client,
            validator_service_name,
        )
        .await?
        {
            return Err(tonic::Status::aborted(format!(
                "{} is not supported in mainchain client",
                validator_service_name
            )));
        }
        tracing::info!("Verified existence of {}", validator_service_name);
        // The wallet service is optional.
        let has_wallet_service =
            Self::check_status_serving(&mut health_client, wallet_service_name)
                .await?;
        tracing::info!(
            "Checked existence of {}: {}",
            wallet_service_name,
            has_wallet_service
        );
        Ok(has_wallet_service)
    }

    pub fn new(config: &Config) -> Result<Self, Error> {
        // Node launches some tokio tasks for p2p networking, that is why we need a tokio runtime
        // here.
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        tracing::info!(
            "Instantiating wallet with data directory: {}",
            config.datadir.display()
        );
        let wallet = Wallet::new(&config.datadir.join("wallet.mdb"))?;
        if let Some(seed_phrase_path) = &config.mnemonic_seed_phrase_path {
            let mnemonic = std::fs::read_to_string(seed_phrase_path)?;
            let () = wallet.set_seed_from_mnemonic(mnemonic.as_str())?;
        }
        tracing::info!("Connecting to mainchain at {}", config.main_addr);
        let rt_guard = runtime.enter();
        let transport = tonic::transport::channel::Channel::from_shared(
            format!("https://{}", config.main_addr),
        )
        .unwrap()
        .concurrency_limit(256)
        .connect_lazy();
        let (cusf_mainchain, cusf_mainchain_wallet) = if runtime
            .block_on(Self::check_proto_support(transport.clone()))
            .map_err(|err| Error::VerifyMainchainServices {
                address: config.main_addr,
                source: err,
            })? {
            (
                mainchain::ValidatorClient::new(transport.clone()),
                Some(mainchain::WalletClient::new(transport)),
            )
        } else {
            (mainchain::ValidatorClient::new(transport), None)
        };
        let miner = cusf_mainchain_wallet
            .clone()
            .map(|wallet| Miner::new(cusf_mainchain.clone(), wallet))
            .transpose()?;
        let local_pool = LocalPoolHandle::new(1);
        tracing::debug!("Initializing node...");
        let node = runtime.block_on(Node::new(
            config.net_addr,
            &config.datadir,
            config.network,
            cusf_mainchain,
            cusf_mainchain_wallet,
            local_pool.clone(),
            #[cfg(feature = "zmq")]
            config.zmq_addr,
        ))?;
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
        let miner = miner.map(|miner| Arc::new(TokioRwLock::new(miner)));
        let task =
            Self::spawn_task(node.clone(), utxos.clone(), wallet.clone());
        drop(rt_guard);
        Ok(Self {
            node,
            wallet,
            miner,
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
        let Some(miner) = self.miner.as_ref() else {
            return Err(Error::NoCusfMainchainWalletClient);
        };
        let address = self.runtime.block_on({
            let miner = miner.clone();
            async move {
                let mut miner_write = miner.write().await;
                let cusf_mainchain = &mut miner_write.cusf_mainchain;
                let mainchain_info = cusf_mainchain.get_chain_info().await?;
                let cusf_mainchain_wallet =
                    &mut miner_write.cusf_mainchain_wallet;
                let res = cusf_mainchain_wallet
                    .create_new_address()
                    .await?
                    .require_network(mainchain_info.network)
                    .unwrap();
                drop(miner_write);
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
        let Some(tip) = self.node.try_get_tip()? else {
            return Ok(HashMap::new());
        };
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
                    bitname_data.mutable_data.paymail_fee_sats
                })
                .min();
            let Some(min_fee) = min_fee else {
                return false;
            };
            output.get_value().to_sat() >= min_fee
        });
        Ok(utxos)
    }

    const EMPTY_BLOCK_BMM_BRIBE: bitcoin::Amount =
        bitcoin::Amount::from_sat(1000);

    pub async fn mine(
        &self,
        fee: Option<bitcoin::Amount>,
    ) -> Result<(), Error> {
        let Some(miner) = self.miner.as_ref() else {
            return Err(Error::NoCusfMainchainWalletClient);
        };
        const NUM_TRANSACTIONS: usize = 1000;
        let (txs, tx_fees) = self.node.get_transactions(NUM_TRANSACTIONS)?;
        let coinbase = match tx_fees {
            bitcoin::Amount::ZERO => vec![],
            _ => vec![types::Output::new(
                self.wallet.get_new_address()?,
                types::OutputContent::Bitcoin(tx_fees),
            )],
        };
        let merkle_root = {
            let txs = txs
                .iter()
                .map(|authorized_tx| authorized_tx.transaction.clone())
                .collect::<Vec<_>>();
            Body::compute_merkle_root(&coinbase, &txs)?.ok_or(Error::Other(
                anyhow::anyhow!("Failed to compute merkle root"),
            ))
        }?;
        let body = {
            let txs = txs.into_iter().map(|tx| tx.into()).collect();
            Body::new(txs, coinbase)
        };
        let prev_side_hash = self.node.try_get_tip()?;
        let prev_main_hash = {
            let mut miner_write = miner.write().await;
            let prev_main_hash =
                miner_write.cusf_mainchain.get_chain_tip().await?.block_hash;
            drop(miner_write);
            prev_main_hash
        };
        let header = types::Header {
            merkle_root,
            prev_side_hash,
            prev_main_hash,
        };
        let bribe = fee.unwrap_or_else(|| {
            if tx_fees > bitcoin::Amount::ZERO {
                tx_fees
            } else {
                Self::EMPTY_BLOCK_BMM_BRIBE
            }
        });
        let mut miner_write = miner.write().await;
        miner_write
            .attempt_bmm(bribe.to_sat(), 0, header, body)
            .await?;
        tracing::trace!("confirming bmm...");
        if let Some((main_hash, header, body)) =
            miner_write.confirm_bmm().await?
        {
            tracing::trace!(
                %main_hash,
                side_hash = %header.hash(),
                "mine: confirmed BMM, submitting block",
            );
            self.node.submit_block(main_hash, &header, &body).await?;
        }
        let () = self.update()?;
        Ok(())
    }

    pub fn deposit(
        &self,
        address: Address,
        amount: bitcoin::Amount,
        fee: bitcoin::Amount,
    ) -> Result<bitcoin::Txid, Error> {
        let Some(miner) = self.miner.as_ref() else {
            return Err(Error::NoCusfMainchainWalletClient);
        };
        self.runtime.block_on(async {
            let mut miner_write = miner.write().await;
            let txid = miner_write
                .cusf_mainchain_wallet
                .create_deposit_tx(address, amount.to_sat(), fee.to_sat())
                .await?;
            drop(miner_write);
            Ok(txid)
        })
    }
}

impl Drop for App {
    fn drop(&mut self) {
        self.task.abort()
    }
}
