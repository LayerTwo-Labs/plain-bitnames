use std::{
    collections::{BTreeMap, HashMap, HashSet},
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
};

use bitcoin::amount::CheckedSum;
use fallible_iterator::{FallibleIterator, IteratorExt as _};
use futures::Stream;
use heed::EnvFlags;
use sneed::{DbError, Env, EnvError, RwTxnError};
use tokio::sync::Mutex;
use tonic::transport::Channel;

use crate::{
    archive::{self, Archive},
    mempool::{self, MemPool},
    net::{DialKnownPeersHandle, Net},
    state::{self, State},
    types::{
        Address, AmountOverflowError, AmountUnderflowError, Authorized,
        AuthorizedTransaction, BitName, BitNameData, Block, BlockHash,
        BmmResult, Body, FilledOutput, FilledTransaction, GetValue, Header,
        M6id, Network, OutPoint, OutPointKey, SpentOutput, Tip, Transaction,
        TxIn, Txid, WithdrawalBundle, WithdrawalBundleStatus,
        authorization::{BatchVerificationContext, rand_core::CryptoRng},
        net::{Peer, PeerAddress, ResolvedPeerAddress},
        proto::{self, mainchain},
        state::WithdrawalBundleInfo,
    },
    util::{ErrorChain, Watchable},
};

pub(crate) mod error;
pub use error::Error;
mod mainchain_task;
use mainchain_task::MainchainTaskHandle;
mod net_task;
use net_task::NetTaskHandle;
#[cfg(feature = "zmq")]
use net_task::ZmqPubHandler;

pub type FilledTransactionWithPosition =
    (Authorized<FilledTransaction>, Option<TxIn>);

#[derive(Debug)]
pub struct Config {
    pub datadir: PathBuf,
    pub bind_addr: SocketAddr,
    pub magic_bytes_override: Option<crate::net::peer_message::MagicBytes>,
    pub network: Network,
    pub add_peers: HashSet<PeerAddress>,
    pub server_names: HashSet<String>,
    #[cfg(feature = "zmq")]
    pub zmq_addr: SocketAddr,
}

/// A long-running task that stopped with an error
#[derive(Debug, thiserror::Error)]
#[error("{task} task error: {err}")]
pub struct TaskError {
    pub task: &'static str,
    /// Rendered error chain
    pub err: String,
}

impl TaskError {
    pub fn new<E>(task: &'static str, err: &E) -> Self
    where
        E: std::error::Error,
    {
        Self {
            task,
            err: format!("{:#}", crate::util::ErrorChain::new(err)),
        }
    }
}

/// Receives the error of any task that stops. The node makes no progress once
/// its net or mainchain task has ended, while its RPC server keeps answering,
/// so the owner of the process should exit on the first one.
pub type FatalErrorTx = futures::channel::mpsc::UnboundedSender<TaskError>;

/// Wrap a task that must run for the life of the node, reporting on
/// `fatal_error_tx` however it ends: an error, a panic, or returning at all.
/// A panic unwinds only the task, and a return leaves nothing running in its
/// place, so both would otherwise leave the node up with a frozen tip.
/// Aborting the spawned task, as dropping the node does, reports nothing.
pub fn supervise<Fut, E>(
    task: &'static str,
    fut: Fut,
    fatal_error_tx: FatalErrorTx,
) -> impl Future<Output = ()> + Send + 'static
where
    Fut: Future<Output = Result<(), E>> + Send + 'static,
    E: std::error::Error,
{
    use futures::FutureExt as _;
    async move {
        let err = match std::panic::AssertUnwindSafe(fut).catch_unwind().await {
            Ok(Ok(())) => TaskError {
                task,
                err: "exited unexpectedly".to_owned(),
            },
            Ok(Err(err)) => TaskError::new(task, &err),
            Err(panic) => {
                let msg = panic
                    .downcast_ref::<&str>()
                    .map(|msg| (*msg).to_owned())
                    .or_else(|| panic.downcast_ref::<String>().cloned())
                    .unwrap_or_else(|| "non-string payload".to_owned());
                TaskError {
                    task,
                    err: format!("panicked: {msg}"),
                }
            }
        };
        tracing::error!("{err}");
        let _send_err: Result<(), _> = fatal_error_tx.unbounded_send(err);
    }
}

/// Handles for spawned tasks / task sets
#[derive(Clone)]
struct TaskHandles {
    _dial_known_peers: Arc<DialKnownPeersHandle>,
    mainchain: MainchainTaskHandle,
    net: NetTaskHandle,
}

#[derive(Clone)]
pub struct Node<MainchainTransport = Channel> {
    archive: Archive,
    batch_verification_ctxt: BatchVerificationContext,
    cusf_mainchain: mainchain::ValidatorClient<MainchainTransport>,
    cusf_mainchain_block_producer:
        Option<Arc<Mutex<mainchain::BlockProducerClient<MainchainTransport>>>>,
    env: sneed::Env<heed::WithoutTls>,
    mempool: MemPool,
    net: Net,
    state: State,
    task_handles: TaskHandles,
    #[cfg(feature = "zmq")]
    zmq_pub_handler: Arc<ZmqPubHandler>,
}

impl<MainchainTransport> Node<MainchainTransport>
where
    MainchainTransport: proto::Transport,
{
    pub async fn new<R>(
        config: Config,
        cusf_mainchain: mainchain::ValidatorClient<MainchainTransport>,
        cusf_mainchain_block_producer: Option<
            mainchain::BlockProducerClient<MainchainTransport>,
        >,
        rng: &mut R,
        runtime: &tokio::runtime::Runtime,
        fatal_error_tx: FatalErrorTx,
    ) -> Result<Self, Error>
    where
        mainchain::ValidatorClient<MainchainTransport>: Clone,
        MainchainTransport: Send + 'static,
        <MainchainTransport as tonic::client::GrpcService<
            tonic::body::Body,
        >>::Future: Send,
        R: CryptoRng,
{
        let Config {
            datadir,
            bind_addr,
            magic_bytes_override,
            network,
            add_peers,
            server_names,
            #[cfg(feature = "zmq")]
            zmq_addr,
        } = config;
        let env_path = datadir.join("data.mdb");
        // let _ = std::fs::remove_dir_all(&env_path);
        std::fs::create_dir_all(&env_path)?;
        let env = {
            let mut env_open_opts =
                heed::EnvOpenOptions::new().read_txn_without_tls();
            env_open_opts
                .map_size(128 * 1024 * 1024 * 1024) // 128 GB
                .max_dbs(
                    Archive::NUM_DBS
                        + MemPool::NUM_DBS
                        + Net::NUM_DBS
                        + State::NUM_DBS,
                );
            // Apply LMDB "fast" flags consistent with our benchmark setup:
            // - WRITE_MAP lets us write directly into the memory map instead of
            //   copying into LMDB's page buffer, reducing syscall overhead for
            //   write-heavy workloads.
            // - MAP_ASYNC hands dirty-page flushing to the kernel so commits do
            //   not block waiting for msync, keeping latencies tight.
            // - NO_SYNC and NO_META_SYNC skip fsync calls for data and
            //   metadata; this trades durability for throughput, which is
            //   acceptable here because the state can be reconstructed from the
            //   canonical chain if a crash occurs.
            // - NO_READ_AHEAD disables kernel readahead that would otherwise
            //   touch cold pages we immediately overwrite, improving random
            //   access behaviour on SSDs used in testing.
            // - NO_TLS stops LMDB from relying on thread-local storage for
            //   reader slots so transactions can be moved across Tokio tasks.
            let fast_flags = EnvFlags::WRITE_MAP
                | EnvFlags::MAP_ASYNC
                | EnvFlags::NO_SYNC
                | EnvFlags::NO_META_SYNC
                | EnvFlags::NO_READ_AHEAD;
            unsafe { env_open_opts.flags(fast_flags) };
            unsafe { Env::open(&env_open_opts, &env_path) }?
        };
        let state = State::new(&env)?;
        #[cfg(feature = "zmq")]
        let zmq_pub_handler = Arc::new(ZmqPubHandler::new(zmq_addr).await?);
        let archive = Archive::new(&env)?;
        let mempool = MemPool::new(&env)?;
        let (mainchain_task_handle, mainchain_task_event_rx) =
            MainchainTaskHandle::new(
                env.clone(),
                archive.clone(),
                cusf_mainchain.clone(),
                fatal_error_tx.clone(),
            );
        let batch_verification_ctxt = BatchVerificationContext::new(rng);
        let (net, peer_info_rx, dial_known_peers_handle) = Net::new(
            runtime.handle(),
            &env,
            archive.clone(),
            batch_verification_ctxt,
            magic_bytes_override,
            network,
            state.clone(),
            bind_addr,
            add_peers,
            server_names,
        )?;
        let net_task_handle = NetTaskHandle::new(
            runtime,
            env.clone(),
            archive.clone(),
            fatal_error_tx,
            mainchain_task_handle.clone(),
            mainchain_task_event_rx,
            mempool.clone(),
            net.clone(),
            peer_info_rx,
            rng,
            state.clone(),
            #[cfg(feature = "zmq")]
            zmq_pub_handler.clone(),
        );
        let task_handles = TaskHandles {
            _dial_known_peers: Arc::new(dial_known_peers_handle),
            mainchain: mainchain_task_handle,
            net: net_task_handle,
        };
        let cusf_mainchain_block_producer = cusf_mainchain_block_producer
            .map(|block_producer| Arc::new(Mutex::new(block_producer)));
        Ok(Self {
            archive,
            batch_verification_ctxt,
            cusf_mainchain,
            cusf_mainchain_block_producer,
            env,
            mempool,
            net,
            state,
            task_handles,
            #[cfg(feature = "zmq")]
            zmq_pub_handler: zmq_pub_handler.clone(),
        })
    }

    pub fn env(&self) -> &Env<heed::WithoutTls> {
        &self.env
    }

    pub fn archive(&self) -> &Archive {
        &self.archive
    }

    pub fn state(&self) -> &State {
        &self.state
    }

    /// Borrow the CUSF mainchain client
    #[inline(always)]
    pub fn with_cusf_mainchain<F, Output>(&self, f: F) -> Output
    where
        F: FnOnce(&mainchain::ValidatorClient<MainchainTransport>) -> Output,
    {
        f(&self.cusf_mainchain)
    }

    pub fn dns_resolver(&self) -> &Arc<hickory_resolver::TokioResolver> {
        &self.net.dns_resolver
    }

    /// Invalidate a block.
    /// This will delete the header and body, and mark invalid, the specified
    /// block and any descendants.
    /// The node will re-org to a previous valid block in the active chain.
    pub fn invalidate_block(&self, block_hash: BlockHash) -> Result<(), Error> {
        let mut rwtxn = self.env.write_txn().map_err(EnvError::from)?;
        let Some(header) = self.archive.try_get_header(&rwtxn, block_hash)?
        else {
            return Ok(());
        };
        // check if the specified block is in the active chain
        let tip = self.state.try_get_tip(&rwtxn)?;
        let in_active_chain = if let Some(tip) = tip {
            self.archive.is_descendant(&rwtxn, block_hash, tip)?
        } else {
            false
        };
        // re-org if necessary
        if in_active_chain {
            while self.state.try_get_tip(&rwtxn)? != header.prev_side_hash {
                net_task::disconnect_tip_(
                    &mut rwtxn,
                    &self.archive,
                    &self.mempool,
                    &self.state,
                )?;
            }
        }
        // invalidate within archive
        let () = self.archive.invalidate_block(&mut rwtxn, block_hash)?;
        rwtxn.commit().map_err(RwTxnError::from)?;
        Ok(())
    }

    pub fn try_get_tip_height(&self) -> Result<Option<u32>, Error> {
        let rotxn = self.env.read_txn()?;
        Ok(self.state.try_get_height(&rotxn)?)
    }

    pub fn try_get_tip(&self) -> Result<Option<BlockHash>, Error> {
        let rotxn = self.env.read_txn()?;
        Ok(self.state.try_get_tip(&rotxn)?)
    }

    pub fn try_get_height(
        &self,
        block_hash: BlockHash,
    ) -> Result<Option<u32>, Error> {
        let rotxn = self.env.read_txn()?;
        Ok(self.archive.try_get_height(&rotxn, block_hash)?)
    }

    pub fn get_height(&self, block_hash: BlockHash) -> Result<u32, Error> {
        let rotxn = self.env.read_txn()?;
        Ok(self.archive.get_height(&rotxn, block_hash)?)
    }

    /// Get blocks in which a tx was included, and tx index within those blocks
    pub fn get_tx_inclusions(
        &self,
        txid: Txid,
    ) -> Result<BTreeMap<BlockHash, u32>, Error> {
        let rotxn = self.env.read_txn()?;
        Ok(self.archive.get_tx_inclusions(&rotxn, txid)?)
    }

    /// Returns true if the second specified block is a descendant of the first
    /// specified block
    /// Returns an error if either of the specified block headers do not exist
    /// in the archive.
    pub fn is_descendant(
        &self,
        ancestor: BlockHash,
        descendant: BlockHash,
    ) -> Result<bool, Error> {
        let rotxn = self.env.read_txn()?;
        Ok(self.archive.is_descendant(&rotxn, ancestor, descendant)?)
    }

    /// List all BitNames and their current data
    pub fn bitnames(&self) -> Result<Vec<(BitName, BitNameData)>, Error> {
        let rotxn = self.env.read_txn()?;
        let res = self
            .state
            .bitnames()
            .bitnames()
            .iter(&rotxn)
            .map_err(state::Error::from)?
            .map_err(state::Error::from)
            .map(|(bitname, bitname_data)| {
                Ok((bitname, bitname_data.current()))
            })
            .collect()?;
        Ok(res)
    }

    /** Resolve bitname data at the specified block height.
     * Returns an error if it does not exist.rror if it does not exist. */
    pub fn get_bitname_data_at_block_height(
        &self,
        bitname: &BitName,
        height: u32,
    ) -> Result<BitNameData, Error> {
        let rotxn = self.env.read_txn()?;
        Ok(self
            .state
            .bitnames()
            .get_bitname_data_at_block_height(&rotxn, bitname, height)
            .map_err(state::Error::BitName)?)
    }

    /// resolve current bitname data, if it exists
    pub fn try_get_current_bitname_data(
        &self,
        bitname: &BitName,
    ) -> Result<Option<BitNameData>, Error> {
        let rotxn = self.env.read_txn()?;
        Ok(self
            .state
            .bitnames()
            .try_get_current_bitname_data(&rotxn, bitname)
            .map_err(state::Error::BitName)?)
    }

    /// Resolve current bitname data. Returns an error if it does not exist.
    pub fn get_current_bitname_data(
        &self,
        bitname: &BitName,
    ) -> Result<BitNameData, Error> {
        let rotxn = self.env.read_txn()?;
        Ok(self
            .state
            .bitnames()
            .get_current_bitname_data(&rotxn, bitname)
            .map_err(state::Error::BitName)?)
    }

    pub fn submit_transaction(
        &self,
        transaction: &AuthorizedTransaction,
    ) -> Result<(), Error> {
        {
            let mut rwtxn = self.env.write_txn()?;
            let main_tip = self
                .archive
                .side_tips()
                .get_mainchain_tip(&rwtxn)
                .map_err(archive::Error::from)?;
            let main_tip_height = self
                .archive
                .get_main_height(&rwtxn, main_tip.block_hash())?;
            self.state.validate_transaction(
                &rwtxn,
                &self.batch_verification_ctxt,
                main_tip_height,
                transaction,
            )?;
            self.mempool.put(&mut rwtxn, transaction)?;
            rwtxn.commit().map_err(RwTxnError::from)?;
        }
        self.net.push_tx(Default::default(), transaction);
        Ok(())
    }

    pub fn get_all_stxos(
        &self,
    ) -> Result<HashMap<OutPoint, SpentOutput>, Error> {
        let rotxn = self.env.read_txn()?;
        self.state.get_stxos(&rotxn).map_err(Error::from)
    }

    pub fn get_all_utxos(
        &self,
    ) -> Result<HashMap<OutPoint, FilledOutput>, Error> {
        let rotxn = self.env.read_txn()?;
        self.state.get_utxos(&rotxn).map_err(Error::from)
    }

    pub fn get_latest_failed_withdrawal_bundle_height(
        &self,
    ) -> Result<Option<u32>, Error> {
        let rotxn = self.env.read_txn()?;
        let res = self
            .state
            .get_latest_failed_withdrawal_bundle(&rotxn)?
            .map(|(height, _)| height);
        Ok(res)
    }

    pub fn get_spent_utxos(
        &self,
        outpoints: &[OutPoint],
    ) -> Result<Vec<(OutPoint, SpentOutput)>, Error> {
        let rotxn = self.env.read_txn()?;
        let mut spent = vec![];
        for outpoint in outpoints {
            if let Some(output) = self
                .state
                .stxos()
                .try_get(&rotxn, &OutPointKey::from(outpoint))
                .map_err(state::Error::from)?
            {
                spent.push((*outpoint, output));
            }
        }
        Ok(spent)
    }

    pub fn get_stxos_by_addresses(
        &self,
        addresses: &HashSet<Address>,
    ) -> Result<HashMap<OutPoint, SpentOutput>, Error> {
        let rotxn = self.env.read_txn()?;
        let stxos = self
            .state
            .get_stxos_by_addresses(&rotxn, addresses)
            .map_err(DbError::from)?;
        Ok(stxos)
    }

    pub fn get_utxos_by_addresses(
        &self,
        addresses: &HashSet<Address>,
    ) -> Result<HashMap<OutPoint, FilledOutput>, Error> {
        let rotxn = self.env.read_txn()?;
        let utxos = self.state.get_utxos_by_addresses(&rotxn, addresses)?;
        Ok(utxos)
    }

    pub fn try_get_mainchain_tip_height(&self) -> Result<Option<u32>, Error> {
        let rotxn = self.env.read_txn()?;
        let mainchain_tip = self
            .archive
            .side_tips()
            .get_mainchain_tip(&rotxn)
            .map_err(archive::Error::from)?;
        let height = mainchain_tip.tip_info.map(|info| info.height);
        Ok(height)
    }

    pub fn try_get_header(
        &self,
        block_hash: BlockHash,
    ) -> Result<Option<Header>, Error> {
        let rotxn = self.env.read_txn()?;
        Ok(self.archive.try_get_header(&rotxn, block_hash)?)
    }

    pub fn get_header(&self, block_hash: BlockHash) -> Result<Header, Error> {
        let rotxn = self.env.read_txn()?;
        Ok(self.archive.get_header(&rotxn, block_hash)?)
    }

    /// Get the block hash at the specified height in the active chain,
    /// if it exists
    pub fn try_get_block_hash(
        &self,
        height: u32,
    ) -> Result<Option<BlockHash>, Error> {
        let rotxn = self.env.read_txn()?;
        let Some(tip) = self.state.try_get_tip(&rotxn)? else {
            return Ok(None);
        };
        let Some(tip_height) = self.state.try_get_height(&rotxn)? else {
            return Ok(None);
        };
        if tip_height >= height {
            self.archive
                .ancestors(&rotxn, tip)
                .nth((tip_height - height) as usize)
                .map_err(Error::from)
        } else {
            Ok(None)
        }
    }

    pub fn try_get_body(
        &self,
        block_hash: BlockHash,
    ) -> Result<Option<Body>, Error> {
        let rotxn = self.env.read_txn()?;
        Ok(self.archive.try_get_body(&rotxn, block_hash)?)
    }

    pub fn get_body(&self, block_hash: BlockHash) -> Result<Body, Error> {
        let rotxn = self.env.read_txn()?;
        Ok(self.archive.get_body(&rotxn, block_hash)?)
    }

    pub fn get_best_main_verification(
        &self,
        hash: BlockHash,
    ) -> Result<bitcoin::BlockHash, Error> {
        let rotxn = self.env.read_txn()?;
        let hash = self.archive.get_best_main_verification(&rotxn, hash)?;
        Ok(hash)
    }

    pub fn get_bmm_inclusions(
        &self,
        block_hash: BlockHash,
    ) -> Result<Vec<bitcoin::BlockHash>, Error> {
        let rotxn = self.env.read_txn()?;
        let bmm_inclusions = self
            .archive
            .get_bmm_results(&rotxn, block_hash)?
            .into_iter()
            .filter_map(|(block_hash, bmm_res)| match bmm_res {
                BmmResult::Verified => Some(block_hash),
                BmmResult::Failed => None,
            })
            .collect();
        Ok(bmm_inclusions)
    }

    pub fn get_block(&self, block_hash: BlockHash) -> Result<Block, Error> {
        let rotxn = self.env.read_txn()?;
        Ok(self.archive.get_block(&rotxn, block_hash)?)
    }

    pub fn get_all_transactions(
        &self,
    ) -> Result<Vec<AuthorizedTransaction>, Error> {
        let rotxn = self.env.read_txn()?;
        let transactions = self.mempool.take_all(&rotxn)?;
        Ok(transactions)
    }

    /// Get total sidechain wealth in Bitcoin
    pub fn get_sidechain_wealth(&self) -> Result<bitcoin::Amount, Error> {
        let rotxn = self.env.read_txn()?;
        Ok(self.state.sidechain_wealth(&rotxn)?)
    }

    pub fn get_transactions(
        &self,
        number: usize,
    ) -> Result<(Vec<Authorized<FilledTransaction>>, bitcoin::Amount), Error>
    {
        let mut rwtxn = self.env.write_txn()?;
        let transactions = self.mempool.take(&rwtxn, number)?;
        let mut fee = bitcoin::Amount::ZERO;
        let mut returned_transactions = vec![];
        let mut spent_utxos = HashSet::new();
        let mut registration_names = HashSet::new();
        let main_tip_height = {
            let main_tip = self
                .archive
                .side_tips()
                .get_mainchain_tip(&rwtxn)
                .map_err(archive::Error::from)?;
            self.archive
                .get_main_height(&rwtxn, main_tip.block_hash())?
        };
        for transaction in transactions {
            let inputs: HashSet<_> =
                transaction.transaction.inputs.iter().copied().collect();
            if !spent_utxos.is_disjoint(&inputs) {
                // UTXO double spent
                self.mempool
                    .delete(&mut rwtxn, transaction.transaction.txid())?;
                continue;
            }
            if transaction
                .transaction
                .registration_name_hash()
                .is_some_and(|name| registration_names.contains(&name))
            {
                // Blocks containing multiple registrations for one name are
                // ambiguous. Leave the conflicting transaction for a later block.
                continue;
            }
            if self
                .state
                .validate_transaction(
                    &rwtxn,
                    &self.batch_verification_ctxt,
                    main_tip_height,
                    &transaction,
                )
                .is_err()
            {
                self.mempool
                    .delete(&mut rwtxn, transaction.transaction.txid())?;
                continue;
            }
            let filled_transaction = self
                .state
                .fill_authorized_transaction(&rwtxn, transaction)?;
            let value_in: bitcoin::Amount = filled_transaction
                .transaction
                .spent_utxos
                .iter()
                .map(GetValue::get_value)
                .checked_sum()
                .ok_or(AmountOverflowError)?;
            let value_out: bitcoin::Amount = filled_transaction
                .transaction
                .outputs()
                .iter()
                .map(GetValue::get_value)
                .checked_sum()
                .ok_or(AmountOverflowError)?;
            fee = fee
                .checked_add(
                    value_in
                        .checked_sub(value_out)
                        .ok_or(AmountOverflowError)?,
                )
                .ok_or(AmountUnderflowError)?;
            spent_utxos.extend(filled_transaction.transaction.inputs());
            if let Some(name) =
                filled_transaction.transaction.registration_name_hash()
            {
                registration_names.insert(name);
            }
            returned_transactions.push(filled_transaction);
        }
        rwtxn.commit().map_err(RwTxnError::from)?;
        Ok((returned_transactions, fee))
    }

    /// Get a transaction if it exists in the active chain or mempool.
    /// Returns the transaction and the block it was included in, if it exists
    /// in the active chain.
    pub fn try_get_transaction(
        &self,
        txid: Txid,
    ) -> Result<Option<(Transaction, Option<BlockHash>)>, Error> {
        let rotxn = self.env.read_txn()?;
        let tip = self.state.try_get_tip(&rotxn)?;
        if let Some(tip) = tip
            && let Some((block_hash, txin)) = self
                .archive
                .get_tx_inclusions(&rotxn, txid)?
                .into_iter()
                .map(Ok)
                .transpose_into_fallible()
                .find(|(block_hash, _idx)| {
                    self.archive.is_descendant(&rotxn, *block_hash, tip)
                })?
        {
            let body = self.archive.get_body(&rotxn, block_hash)?;
            let tx = body.transactions.into_iter().nth(txin as usize).unwrap();
            Ok(Some((tx, Some(block_hash))))
        } else if let Some(auth_tx) = self
            .mempool
            .transactions
            .try_get(&rotxn, &txid)
            .map_err(mempool::Error::from)?
        {
            Ok(Some((auth_tx.transaction, None)))
        } else {
            Ok(None)
        }
    }

    /// get a filled transaction from the archive/state or mempool,
    /// and the tx index, if the transaction exists
    /// and can be filled with the current state.
    /// a tx index of `None` indicates that the tx is in the mempool.
    pub fn try_get_filled_transaction(
        &self,
        txid: Txid,
    ) -> Result<Option<FilledTransactionWithPosition>, Error> {
        let rotxn = self.env.read_txn()?;
        let tip = self.state.try_get_tip(&rotxn)?;
        let inclusions = self.archive.get_tx_inclusions(&rotxn, txid)?;
        if let Some((block_hash, idx)) = inclusions
            .into_iter()
            .map(Ok)
            .transpose_into_fallible()
            .find(|(block_hash, _)| {
                if let Some(tip) = tip {
                    self.archive.is_descendant(&rotxn, *block_hash, tip)
                } else {
                    Ok(true)
                }
            })?
        {
            let body = self.archive.get_body(&rotxn, block_hash)?;
            let auth_txs = body.authorized_transactions();
            let auth_tx = auth_txs.into_iter().nth(idx as usize).unwrap();
            let filled_tx = self
                .state
                .fill_transaction_from_stxos(&rotxn, auth_tx.transaction)?;
            let auth_tx = Authorized {
                transaction: filled_tx,
                authorizations: auth_tx.authorizations,
            };
            let txin = TxIn { block_hash, idx };
            let res = (auth_tx, Some(txin));
            return Ok(Some(res));
        }
        if let Some(auth_tx) = self
            .mempool
            .transactions
            .try_get(&rotxn, &txid)
            .map_err(mempool::Error::from)?
        {
            match self.state.fill_authorized_transaction(&rotxn, auth_tx) {
                Ok(filled_tx) => {
                    let res = (filled_tx, None);
                    Ok(Some(res))
                }
                Err(state::Error::NoUtxo { .. }) => Ok(None),
                Err(err) => Err(err.into()),
            }
        } else {
            Ok(None)
        }
    }

    pub fn try_get_withdrawal_bundle(
        &self,
        m6id: &M6id,
    ) -> Result<Option<(WithdrawalBundleInfo, WithdrawalBundleStatus)>, Error>
    {
        let rotxn = self.env.read_txn()?;
        let res = self
            .state
            .try_get_withdrawal_bundle(&rotxn, m6id)
            .map_err(state::Error::from)?;
        Ok(res)
    }

    pub fn try_get_pending_withdrawal_bundle(
        &self,
    ) -> Result<Option<WithdrawalBundle>, Error> {
        let rotxn = self.env.read_txn()?;
        let bundle = self
            .state
            .try_get_pending_withdrawal_bundle(&rotxn)?
            .map(|(bundle, _)| bundle);
        Ok(bundle)
    }

    /// Compute the 2WPD events that a block with the given
    /// `prev_main_hash` built on the current tip would connect:
    /// mainchain events in blocks after the tip's `prev_main_hash`, up
    /// to and including `prev_main_hash`.
    pub fn get_pending_two_way_peg_data(
        &self,
        prev_main_hash: bitcoin::BlockHash,
    ) -> Result<mainchain::TwoWayPegData, Error> {
        let rotxn = self.env.read_txn().map_err(EnvError::from)?;
        let tip_prev_main_hash = self
            .state
            .try_get_tip(&rotxn)?
            .map(|tip| self.archive.get_header(&rotxn, tip))
            .transpose()?
            .map(|header| header.prev_main_hash);
        let block_infos: Vec<_> = self
            .archive
            .main_ancestors(&rotxn, prev_main_hash)
            .take_while(|ancestor| Ok(Some(*ancestor) != tip_prev_main_hash))
            .filter_map(|ancestor| {
                let block_info =
                    self.archive.get_main_block_info(&rotxn, &ancestor)?;
                if block_info.events.is_empty() {
                    Ok(None)
                } else {
                    let height =
                        self.archive.get_main_height(&rotxn, ancestor)?;
                    let block_info = mainchain::two_way_peg_data::BlockInfo {
                        height,
                        inner: block_info,
                    };
                    Ok(Some((ancestor, block_info)))
                }
            })
            .collect()?;
        Ok(mainchain::TwoWayPegData {
            block_info: block_infos.into_iter().rev().collect(),
        })
    }

    pub fn remove_from_mempool(&self, txid: Txid) -> Result<(), Error> {
        let mut rwtxn = self.env.write_txn()?;
        let () = self.mempool.delete(&mut rwtxn, txid)?;
        rwtxn.commit().map_err(RwTxnError::from)?;
        Ok(())
    }

    pub fn connect_peer(&self, addr: ResolvedPeerAddress) -> Result<(), Error> {
        let peer_addr = addr.as_peer_address().to_owned();
        let () =
            self.net
                .connect_peer(self.env.clone(), addr)
                .map_err(|err| crate::net::Error::ConnectPeer {
                    peer_addr,
                    source: err,
                })?;
        Ok(())
    }

    pub fn forget_peer(&self, addr: &PeerAddress) -> Result<bool, Error> {
        let mut rwtxn = self.env.write_txn().map_err(EnvError::from)?;
        let res = self.net.forget_peer(&mut rwtxn, addr)?;
        rwtxn.commit().map_err(RwTxnError::from)?;
        Ok(res)
    }

    pub fn get_active_peers(&self) -> Vec<Peer> {
        self.net.get_active_peers()
    }

    pub async fn request_mainchain_ancestor_infos(
        &self,
        block_hash: bitcoin::BlockHash,
    ) -> Result<bool, Error> {
        let mainchain_task::Response::AncestorInfos(_, res): mainchain_task::Response = self
            .task_handles
            .mainchain
            .request_oneshot(mainchain_task::Request::AncestorInfos(
                block_hash,
            ))
            .map_err(|_| Error::SendMainchainTaskRequest)?
            .await
            .map_err(|_| Error::ReceiveMainchainTaskResponse)?;
        res.map_err(Error::MainchainAncestors)
    }

    /// Attempt to submit a block.
    /// Returns `Ok(true)` if the block was accepted successfully as the new tip.
    /// Returns `Ok(false)` if the block could not be submitted for some reason,
    /// or was rejected as the new tip.
    pub async fn submit_block(
        &self,
        main_block_hash: bitcoin::BlockHash,
        header: &Header,
        body: &Body,
    ) -> Result<bool, Error> {
        let block_hash = header.hash();
        // Store the header, if ancestors exist
        if let Some(parent) = header.prev_side_hash
            && self.try_get_header(parent)?.is_none()
        {
            tracing::error!(%block_hash,
                "Rejecting block {block_hash} due to missing ancestor headers",
            );
            return Ok(false);
        }
        // Request mainchain header/infos if they do not exist
        let mainchain_task::Response::AncestorInfos(_, res): mainchain_task::Response = self
            .task_handles
            .mainchain
            .request_oneshot(mainchain_task::Request::AncestorInfos(
                main_block_hash,
            ))
            .map_err(|_| Error::SendMainchainTaskRequest)?
            .await
            .map_err(|_| Error::ReceiveMainchainTaskResponse)?;
        if !res.map_err(Error::MainchainAncestors)? {
            return Ok(false);
        };
        // Write header
        tracing::trace!("Storing header: {block_hash}");
        {
            let mut rwtxn = self.env.write_txn()?;
            let () = self.archive.put_header(&mut rwtxn, header)?;
            rwtxn.commit().map_err(RwTxnError::from)?;
        }
        tracing::trace!("Stored header: {block_hash}");
        // Check BMM
        {
            let rotxn = self.env.read_txn()?;
            match self.archive.get_bmm_result(
                &rotxn,
                block_hash,
                main_block_hash,
            )? {
                BmmResult::Verified => (),
                BmmResult::Failed => {
                    tracing::error!(%block_hash,
                        "Rejecting block {block_hash} due to failing BMM verification",
                    );
                    return Ok(false);
                }
            }
        }
        // Check that ancestor bodies exist, and store body
        {
            let rotxn = self.env.read_txn()?;
            let tip = self.state.try_get_tip(&rotxn)?;
            let common_ancestor = if let Some(tip) = tip {
                self.archive.last_common_ancestor(&rotxn, tip, block_hash)?
            } else {
                None
            };
            let missing_bodies = self.archive.get_missing_bodies(
                &rotxn,
                block_hash,
                common_ancestor,
            )?;
            if !(missing_bodies.is_empty()
                || missing_bodies == vec![block_hash])
            {
                tracing::error!(%block_hash,
                    "Rejecting block {block_hash} due to missing ancestor bodies",
                );
                return Ok(false);
            }
            drop(rotxn);
            if missing_bodies == vec![block_hash] {
                let mut rwtxn = self.env.write_txn()?;
                let () = self.archive.put_body(&mut rwtxn, block_hash, body)?;
                rwtxn.commit().map_err(RwTxnError::from)?;
            }
        }
        // Submit new tip
        let new_tip = Tip {
            block_hash,
            main_block_hash,
        };
        if !self.task_handles.net.new_tip_ready_confirm(new_tip).await? {
            tracing::warn!(%block_hash, "Not ready to reorg");
            return Ok(false);
        };
        let rotxn = self.env.read_txn()?;
        let bundle = self.state.try_get_pending_withdrawal_bundle(&rotxn)?;
        #[cfg(feature = "zmq")]
        {
            let height = self
                .state
                .try_get_height(&rotxn)?
                .expect("Height should exist for tip");
            let block_hash = header.hash();
            let mut zmq_msg = zeromq::ZmqMessage::from("hashblock");
            zmq_msg.push_back(bytes::Bytes::copy_from_slice(&block_hash.0));
            zmq_msg.push_back(bytes::Bytes::copy_from_slice(
                &height.to_le_bytes(),
            ));
            self.zmq_pub_handler.tx.unbounded_send(zmq_msg).unwrap();
        }
        if let Some((bundle, _)) = bundle {
            let m6id = bundle.compute_m6id();
            if let Some(cusf_mainchain_block_producer) =
                self.cusf_mainchain_block_producer.as_ref()
            {
                let broadcast_res = {
                    let mut cusf_mainchain_block_producer_lock =
                        cusf_mainchain_block_producer.lock().await;
                    cusf_mainchain_block_producer_lock
                        .propose_withdrawal_bundle(bundle.tx())
                        .await
                };
                // The new tip is already committed at this point, so a broadcast
                // failure MUST NOT be reported as a rejected block.
                // The bundle remains pending until the corresponding mainchain
                // event is connected, so it is re-broadcast on the next block.
                match broadcast_res {
                    Ok(()) => {
                        tracing::trace!(%m6id, "Proposed withdrawal bundle")
                    }
                    Err(err) => {
                        tracing::error!(
                            %m6id,
                            "Failed to broadcast withdrawal bundle; \
                            will retry on next block: {:#}",
                            ErrorChain::new(&err),
                        )
                    }
                }
            } else {
                // Without the mainchain's block producer service there is
                // nowhere to send the bundle, and it stays pending for every
                // block that follows. Say so, or the withdrawal simply never
                // completes and nothing explains why.
                tracing::warn!(
                    %m6id,
                    "Withdrawal bundle is pending, but the mainchain node \
                     does not serve BlockProducerService, so the bundle \
                     cannot be proposed and the withdrawal cannot complete",
                );
            }
        }
        Ok(true)
    }

    /// Get a notification whenever the tip changes
    pub fn watch_state(&self) -> impl Stream<Item = ()> {
        self.state.watch()
    }
}
