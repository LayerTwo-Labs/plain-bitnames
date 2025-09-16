use std::{
    borrow::Borrow,
    cmp::Ordering,
    collections::{BTreeMap, HashMap},
    sync::LazyLock,
};

use bitcoin::amount::CheckedSum as _;
use borsh::BorshSerialize;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use thiserror::Error;
use utoipa::ToSchema;

pub use crate::authorization::Authorization;

mod address;
pub mod bitname_data;
pub mod bitname_seq_id;
pub mod constants;
pub mod hashes;
pub mod keys;
pub mod proto;
pub mod schema;
mod transaction;

pub use address::Address;
pub use bitname_data::{
    BitNameData, BitNameDataUpdates, MutableBitNameData, Update,
};
pub use bitname_seq_id::BitNameSeqId;
pub use hashes::{BitName, BlockHash, Hash, M6id, MerkleRoot, Txid};
pub use keys::{EncryptionPubKey, VerifyingKey};
pub use transaction::{
    Authorized, AuthorizedTransaction, BatchIcannRegistrationData,
    BitcoinOutputContent, Content as OutputContent,
    FilledContent as FilledOutputContent, FilledOutput, FilledTransaction,
    InPoint, OutPoint, OutPointKey, Output, Pointed as PointedOutput,
    SpentOutput, Transaction, TransactionData, TxData, WithdrawalOutputContent,
};

pub const THIS_SIDECHAIN: u8 = 2;

#[derive(Debug, Error)]
#[error("Bitcoin amount overflow")]
pub struct AmountOverflowError;

#[derive(Debug, Error)]
#[error("Bitcoin amount underflow")]
pub struct AmountUnderflowError;

#[derive(Debug, Error)]
pub enum ComputeMerkleRootError {
    #[error("Fee computation failed for transaction {txid}: {source}")]
    FeeComputation {
        txid: Txid,
        #[source]
        source: GetFeeError,
    },
}

#[derive(Debug, Error)]
pub enum GetFeeError {
    #[error("Amount overflow")]
    AmountOverflow,
    #[error("Amount underflow")]
    AmountUnderflow,
}

// Helper module for serializing bitcoin::Amount with Borsh
mod borsh_bitcoin_amount {
    use bitcoin::Amount;
    use borsh::{BorshDeserialize, BorshSerialize};

    pub fn serialize<W: borsh::io::Write>(
        amount: &Amount,
        writer: &mut W,
    ) -> borsh::io::Result<()> {
        amount.to_sat().serialize(writer)
    }

    #[allow(dead_code)]
    pub fn deserialize(buf: &mut &[u8]) -> borsh::io::Result<Amount> {
        let sats = u64::deserialize(buf)?;
        Ok(Amount::from_sat(sats))
    }
}

/// (de)serialize as Display/FromStr for human-readable forms like json,
/// and default serialization for non human-readable forms like bincode
mod serde_display_fromstr_human_readable {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use serde_with::{DeserializeAs, DisplayFromStr, SerializeAs};
    use std::{fmt::Display, str::FromStr};

    pub fn serialize<S, T>(data: T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        T: Serialize + Display,
    {
        if serializer.is_human_readable() {
            DisplayFromStr::serialize_as(&data, serializer)
        } else {
            data.serialize(serializer)
        }
    }

    pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
    where
        D: Deserializer<'de>,
        T: Deserialize<'de> + FromStr,
        <T as FromStr>::Err: Display,
    {
        if deserializer.is_human_readable() {
            DisplayFromStr::deserialize_as(deserializer)
        } else {
            T::deserialize(deserializer)
        }
    }
}

/// (de)serialize as hex strings for human-readable forms like json,
/// and default serialization for non human-readable formats like bincode
mod serde_hexstr_human_readable {
    use hex::{FromHex, ToHex};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S, T>(data: T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        T: Serialize + ToHex,
    {
        if serializer.is_human_readable() {
            hex::serde::serialize(data, serializer)
        } else {
            data.serialize(serializer)
        }
    }

    pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
    where
        D: Deserializer<'de>,
        T: Deserialize<'de> + FromHex,
        <T as FromHex>::Error: std::fmt::Display,
    {
        if deserializer.is_human_readable() {
            hex::serde::deserialize(deserializer)
        } else {
            T::deserialize(deserializer)
        }
    }
}

pub trait GetAddress {
    fn get_address(&self) -> Address;
}

pub trait GetValue {
    fn get_value(&self) -> bitcoin::Amount;
}

fn borsh_serialize_bitcoin_block_hash<W>(
    block_hash: &bitcoin::BlockHash,
    writer: &mut W,
) -> borsh::io::Result<()>
where
    W: borsh::io::Write,
{
    let bytes: &[u8; 32] = block_hash.as_ref();
    borsh::BorshSerialize::serialize(bytes, writer)
}

#[derive(
    BorshSerialize,
    Clone,
    Debug,
    Deserialize,
    Eq,
    Hash,
    PartialEq,
    Serialize,
    ToSchema,
)]
pub struct Header {
    pub merkle_root: MerkleRoot,
    pub prev_side_hash: Option<BlockHash>,
    #[borsh(serialize_with = "borsh_serialize_bitcoin_block_hash")]
    #[schema(value_type = crate::types::schema::BitcoinBlockHash)]
    pub prev_main_hash: bitcoin::BlockHash,
}

impl Header {
    pub fn hash(&self) -> BlockHash {
        hashes::hash(self).into()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum WithdrawalBundleStatus {
    Confirmed,
    Failed,
    Submitted,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WithdrawalBundleEvent {
    pub m6id: M6id,
    pub status: WithdrawalBundleStatus,
}

pub static OP_DRIVECHAIN_SCRIPT: LazyLock<bitcoin::ScriptBuf> =
    LazyLock::new(|| {
        let mut script = bitcoin::ScriptBuf::new();
        script.push_opcode(bitcoin::opcodes::all::OP_RETURN);
        script.push_instruction(bitcoin::script::Instruction::PushBytes(
            &bitcoin::script::PushBytesBuf::from([THIS_SIDECHAIN]),
        ));
        script.push_opcode(bitcoin::opcodes::OP_TRUE);
        script
    });

#[derive(Debug, Error)]
enum WithdrawalBundleErrorInner {
    #[error("bundle too heavy: weight `{weight}` > max weight `{max_weight}`")]
    BundleTooHeavy { weight: u64, max_weight: u64 },
}

#[derive(Debug, Error)]
#[error("Withdrawal bundle error")]
pub struct WithdrawalBundleError(#[from] WithdrawalBundleErrorInner);

#[serde_as]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct WithdrawalBundle {
    #[schema(value_type = Vec<(
        transaction::OutPoint,
        transaction::FilledOutput)>
    )]
    #[serde_as(as = "serde_with::IfIsHumanReadable<serde_with::Seq<(_, _)>>")]
    spend_utxos: BTreeMap<OutPoint, FilledOutput>,
    #[schema(value_type = schema::BitcoinTransaction)]
    tx: bitcoin::Transaction,
}

impl WithdrawalBundle {
    pub fn new(
        block_height: u32,
        fee: bitcoin::Amount,
        spend_utxos: BTreeMap<transaction::OutPoint, transaction::FilledOutput>,
        bundle_outputs: Vec<bitcoin::TxOut>,
    ) -> Result<Self, WithdrawalBundleError> {
        let inputs_commitment_txout = {
            // Create inputs commitment.
            let inputs: Vec<OutPoint> = [
                // Commit to inputs.
                spend_utxos.keys().copied().collect(),
                // Commit to block height.
                vec![OutPoint::Regular {
                    txid: [0; 32].into(),
                    vout: block_height,
                }],
            ]
            .concat();
            let commitment = hashes::hash(&inputs);
            let script_pubkey = bitcoin::script::Builder::new()
                .push_opcode(bitcoin::opcodes::all::OP_RETURN)
                .push_slice(commitment)
                .into_script();
            bitcoin::TxOut {
                value: bitcoin::Amount::ZERO,
                script_pubkey,
            }
        };
        let mainchain_fee_txout = {
            let script_pubkey = bitcoin::script::Builder::new()
                .push_opcode(bitcoin::opcodes::all::OP_RETURN)
                .push_slice(fee.to_sat().to_be_bytes())
                .into_script();
            bitcoin::TxOut {
                value: bitcoin::Amount::ZERO,
                script_pubkey,
            }
        };
        let outputs = Vec::from_iter(
            [mainchain_fee_txout, inputs_commitment_txout]
                .into_iter()
                .chain(bundle_outputs),
        );
        let tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::blockdata::locktime::absolute::LockTime::ZERO,
            input: Vec::new(),
            output: outputs,
        };
        if tx.weight().to_wu() > bitcoin::policy::MAX_STANDARD_TX_WEIGHT as u64
        {
            Err(WithdrawalBundleErrorInner::BundleTooHeavy {
                weight: tx.weight().to_wu(),
                max_weight: bitcoin::policy::MAX_STANDARD_TX_WEIGHT as u64,
            })?;
        }
        Ok(Self { spend_utxos, tx })
    }

    pub fn compute_m6id(&self) -> M6id {
        M6id(self.tx.compute_txid())
    }

    pub fn spend_utxos(
        &self,
    ) -> &BTreeMap<transaction::OutPoint, transaction::FilledOutput> {
        &self.spend_utxos
    }

    pub fn tx(&self) -> &bitcoin::Transaction {
        &self.tx
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct TwoWayPegData {
    pub deposits: HashMap<OutPoint, Output>,
    pub deposit_block_hash: Option<bitcoin::BlockHash>,
    pub bundle_statuses: HashMap<M6id, WithdrawalBundleEvent>,
}

// Internal node of a CBMT
#[derive(Clone, Debug, Default, Eq, PartialEq, BorshSerialize)]
struct CbmtNode {
    // Commitment to child nodes or leaf value
    commitment: Hash,
    // Sum of fees for child nodes or leaf value
    #[borsh(serialize_with = "borsh_bitcoin_amount::serialize")]
    fees: bitcoin::Amount,
    // Sum of canonical tx sizes for child nodes or leaf value
    canonical_size: u64,
    // CBT index, see https://github.com/nervosnetwork/merkle-tree/blob/5d1898263e7167560fdaa62f09e8d52991a1c712/README.md#tree-struct
    // This is required so that `CbmtNode` can be `Ord` correctly
    index: usize,
}

impl PartialOrd for CbmtNode {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for CbmtNode {
    fn cmp(&self, other: &Self) -> Ordering {
        self.index.cmp(&other.index)
    }
}

// Marker type for merging branch commitments with
// * branch fee totals
// * branch canonical size totals
/// Hash to get a [`CbmtNode`] inner commitment for a leaf value
#[derive(Debug, BorshSerialize)]
struct CbmtLeafPreCommitment<'a> {
    #[borsh(serialize_with = "borsh_bitcoin_amount::serialize")]
    fee: bitcoin::Amount,
    canonical_size: u64,
    tx: &'a Transaction,
}

/// Hash to get a [`CbmtNode`] inner commitment for an internal node
#[derive(Debug, BorshSerialize)]
struct CbmtNodePreCommitment {
    left_commitment: Hash,
    #[borsh(serialize_with = "borsh_bitcoin_amount::serialize")]
    fees: bitcoin::Amount,
    canonical_size: u64,
    right_commitment: Hash,
}

struct MergeFeeSizeTotal;

impl merkle_cbt::merkle_tree::Merge for MergeFeeSizeTotal {
    type Item = CbmtNode;

    fn merge(lnode: &Self::Item, rnode: &Self::Item) -> Self::Item {
        let fees = lnode.fees + rnode.fees;
        let canonical_size = lnode.canonical_size + rnode.canonical_size;
        // see https://github.com/nervosnetwork/merkle-tree/blob/5d1898263e7167560fdaa62f09e8d52991a1c712/README.md#tree-struct
        assert_eq!(lnode.index + 1, rnode.index);
        let index = (lnode.index - 1) / 2;
        let commitment =
            hashes::hash_with_scratch_buffer(&CbmtNodePreCommitment {
                left_commitment: lnode.commitment,
                fees,
                canonical_size,
                right_commitment: rnode.commitment,
            });
        Self::Item {
            commitment,
            fees,
            canonical_size,
            index,
        }
    }
}

// Complete binary merkle tree with annotated fee and canonical size totals
type CbmtWithFeeTotal = merkle_cbt::CBMT<CbmtNode, MergeFeeSizeTotal>;

#[derive(BorshSerialize, Clone, Debug, Deserialize, Serialize, ToSchema)]
pub struct Body {
    pub coinbase: Vec<Output>,
    pub transactions: Vec<Transaction>,
    pub authorizations: Vec<Authorization>,
}

impl Body {
    pub fn new(
        authorized_transactions: Vec<AuthorizedTransaction>,
        coinbase: Vec<Output>,
    ) -> Self {
        let mut authorizations = Vec::with_capacity(
            authorized_transactions
                .iter()
                .map(|t| t.transaction.inputs.len())
                .sum(),
        );
        let mut transactions =
            Vec::with_capacity(authorized_transactions.len());
        for at in authorized_transactions.into_iter() {
            authorizations.extend(at.authorizations);
            transactions.push(at.transaction);
        }
        Self {
            coinbase,
            transactions,
            authorizations,
        }
    }

    pub fn authorized_transactions(&self) -> Vec<AuthorizedTransaction> {
        let mut authorizations_iter = self.authorizations.iter();
        self.transactions
            .iter()
            .map(|tx| {
                let mut authorizations = Vec::with_capacity(tx.inputs.len());
                for _ in 0..tx.inputs.len() {
                    let auth = authorizations_iter.next().unwrap();
                    authorizations.push(auth.clone());
                }
                AuthorizedTransaction {
                    transaction: tx.clone(),
                    authorizations,
                }
            })
            .collect()
    }

    pub fn compute_merkle_root<FilledTx>(
        coinbase: &[Output],
        txs: &[FilledTx],
    ) -> Result<MerkleRoot, ComputeMerkleRootError>
    where
        FilledTx: Borrow<FilledTransaction> + Sync,
    {
        let CbmtNode {
            commitment: txs_root,
            ..
        } = {
            let n_txs = txs.len();

            // Pre-allocate Vec for direct indexing by parallel threads
            let mut leaves = vec![CbmtNode::default(); n_txs];

            // Use Rayon to compute leaves in parallel across all CPU cores
            use rayon::iter::{
                IndexedParallelIterator, IntoParallelRefIterator,
                ParallelIterator,
            };
            let results: Result<Vec<_>, ComputeMerkleRootError> = txs
                .par_iter()
                .enumerate()
                .map(|(idx, tx)| {
                    let tx = tx.borrow();
                    let fees = tx.get_fee().map_err(|err| {
                        ComputeMerkleRootError::FeeComputation {
                            txid: tx.transaction.txid(),
                            source: err,
                        }
                    })?;
                    let canonical_size = tx.transaction.canonical_size();
                    let leaf_pre_commitment = CbmtLeafPreCommitment {
                        fee: fees,
                        canonical_size,
                        tx: &tx.transaction,
                    };
                    let node = CbmtNode {
                        commitment: hashes::hash_with_scratch_buffer(
                            &leaf_pre_commitment,
                        ),
                        fees,
                        canonical_size,
                        // see https://github.com/nervosnetwork/merkle-tree/blob/5d1898263e7167560fdaa62f09e8d52991a1c712/README.md#tree-struct
                        index: (idx + n_txs) - 1,
                    };
                    Ok((idx, node))
                })
                .collect();

            // Fill the pre-allocated vector with computed nodes
            for (idx, node) in results? {
                leaves[idx] = node;
            }

            // Replace tree-based CBMT with parallel levelized approach for better performance
            if n_txs >= 1000 {
                // Use optimized parallel level merging for large transaction sets
                Self::compute_merkle_root_levelized_parallel(leaves)
            } else {
                // Use original CBMT for smaller sets
                CbmtWithFeeTotal::build_merkle_root(leaves.as_slice())
            }
        };
        // FIXME: Compute actual merkle root instead of just a hash.
        let coinbase_root = hashes::hash_with_scratch_buffer(&coinbase);
        // TODO: Should this include `total_fees`?
        let root =
            hashes::hash_with_scratch_buffer(&(coinbase_root, txs_root)).into();
        Ok(root)
    }

    /// Optimized level-by-level parallel merkle tree construction
    /// Processes each level of the tree in parallel for maximum performance
    fn compute_merkle_root_levelized_parallel(
        mut current_level: Vec<CbmtNode>,
    ) -> CbmtNode {
        use rayon::prelude::*;

        while current_level.len() > 1 {
            // Handle odd number of nodes by duplicating the last node (standard merkle tree approach)
            if current_level.len() % 2 == 1 {
                let last_node = current_level.last().unwrap().clone();
                current_level.push(last_node);
            }

            // Process pairs of nodes in parallel across all CPU cores
            current_level = current_level
                .par_chunks_exact(2)
                .enumerate()
                .map(|(parent_idx, pair)| {
                    let lnode = &pair[0];
                    let rnode = &pair[1];

                    // Compute parent node using the same merge logic as MergeFeeSizeTotal
                    let fees = lnode.fees + rnode.fees;
                    let canonical_size =
                        lnode.canonical_size + rnode.canonical_size;

                    let commitment = hashes::hash_with_scratch_buffer(
                        &CbmtNodePreCommitment {
                            left_commitment: lnode.commitment,
                            fees,
                            canonical_size,
                            right_commitment: rnode.commitment,
                        },
                    );

                    CbmtNode {
                        commitment,
                        fees,
                        canonical_size,
                        index: parent_idx,
                    }
                })
                .collect();
        }

        // Return the root node
        current_level
            .into_iter()
            .next()
            .expect("Tree should have exactly one root")
    }

    pub fn get_inputs(&self) -> Vec<OutPoint> {
        self.transactions
            .iter()
            .flat_map(|tx| tx.inputs.iter())
            .copied()
            .collect()
    }

    pub fn get_outputs(
        coinbase: &[Output],
        txs: &[FilledTransaction],
    ) -> Result<Option<HashMap<OutPoint, Output>>, AmountOverflowError> {
        let mut outputs = HashMap::new();
        let merkle_root = Self::compute_merkle_root(coinbase, txs)
            .map_err(|_| AmountOverflowError)?;
        for (vout, output) in coinbase.iter().enumerate() {
            let vout = vout as u32;
            let outpoint = OutPoint::Coinbase { merkle_root, vout };
            outputs.insert(outpoint, output.clone());
        }
        for transaction in txs {
            let txid = transaction.txid();
            for (vout, output) in transaction.outputs().iter().enumerate() {
                let vout = vout as u32;
                let outpoint = OutPoint::Regular { txid, vout };
                outputs.insert(outpoint, output.clone());
            }
        }
        Ok(Some(outputs))
    }

    pub fn get_coinbase_value(
        &self,
    ) -> Result<bitcoin::Amount, AmountOverflowError> {
        self.coinbase
            .iter()
            .map(|output| output.get_value())
            .checked_sum()
            .ok_or(AmountOverflowError)
    }
}

pub trait Verify {
    type Error;
    fn verify_transaction(
        transaction: &AuthorizedTransaction,
    ) -> Result<(), Self::Error>;
    fn verify_body(body: &Body) -> Result<(), Self::Error>;
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
pub struct Block {
    #[serde(flatten)]
    pub header: Header,
    #[serde(flatten)]
    pub body: Body,
    pub height: u32,
}

/*
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisconnectData {
    pub spent_utxos: HashMap<types::OutPoint, Output>,
    pub deposits: Vec<types::OutPoint>,
    pub pending_bundles: Vec<bitcoin::Txid>,
    pub spent_bundles: HashMap<bitcoin::Txid, Vec<types::OutPoint>>,
    pub spent_withdrawals: HashMap<types::OutPoint, Output>,
    pub failed_withdrawals: Vec<bitcoin::Txid>,
}
*/

#[derive(Eq, PartialEq, Clone, Debug)]
pub struct AggregatedWithdrawal {
    pub spend_utxos: HashMap<OutPoint, FilledOutput>,
    pub main_address: bitcoin::Address<bitcoin::address::NetworkUnchecked>,
    pub value: bitcoin::Amount,
    pub main_fee: bitcoin::Amount,
}

impl Ord for AggregatedWithdrawal {
    fn cmp(&self, other: &Self) -> Ordering {
        if self == other {
            Ordering::Equal
        } else if self.main_fee > other.main_fee
            || self.value > other.value
            || self.main_address > other.main_address
        {
            Ordering::Greater
        } else {
            Ordering::Less
        }
    }
}

impl PartialOrd for AggregatedWithdrawal {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Transaction index
#[derive(Clone, Copy, Debug, Deserialize, Serialize, ToSchema)]
pub struct TxIn {
    pub block_hash: BlockHash,
    pub idx: u32,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum BmmResult {
    Verified,
    Failed,
}

/// A tip refers to both a sidechain block AND the mainchain block that commits
/// to it.
#[derive(
    BorshSerialize,
    Clone,
    Copy,
    Debug,
    Deserialize,
    Eq,
    Hash,
    PartialEq,
    Serialize,
)]
pub struct Tip {
    pub block_hash: BlockHash,
    #[borsh(serialize_with = "borsh_serialize_bitcoin_block_hash")]
    pub main_block_hash: bitcoin::BlockHash,
}

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum, strum::Display))]
pub enum Network {
    #[default]
    Signet,
    Regtest,
}

/// Semver-compatible version
#[derive(
    BorshSerialize,
    Clone,
    Copy,
    Debug,
    Deserialize,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
)]
pub struct Version {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

impl From<semver::Version> for Version {
    fn from(version: semver::Version) -> Self {
        let semver::Version {
            major,
            minor,
            patch,
            pre: _,
            build: _,
        } = version;
        Self {
            major,
            minor,
            patch,
        }
    }
}
// Do not make this public outside of this crate, as it could break semver
pub(crate) static VERSION: LazyLock<Version> = LazyLock::new(|| {
    const VERSION_STR: &str = env!("CARGO_PKG_VERSION");
    semver::Version::parse(VERSION_STR).unwrap().into()
});
