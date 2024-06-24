use std::{
    cmp::Ordering,
    collections::{BTreeMap, HashMap},
};

use bech32::{FromBase32, ToBase32};
use borsh::BorshSerialize;
use serde::{Deserialize, Serialize};

use bip300301::bitcoin;
use thiserror::Error;
use utoipa::ToSchema;

pub use crate::authorization::Authorization;

mod address;
pub mod constants;
pub mod hashes;
mod transaction;

pub use address::*;
pub use hashes::{BitName, BlockHash, Hash, MerkleRoot, Txid};
pub use transaction::{
    open_api_schemas, Authorized, AuthorizedTransaction,
    BatchIcannRegistrationData, BitNameData, BitNameDataUpdates,
    Content as OutputContent, FilledContent as FilledOutputContent,
    FilledOutput, FilledTransaction, InPoint, OutPoint, Output,
    Pointed as PointedOutput, SpentOutput, Transaction, TransactionData,
    TxData, Update,
};

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
    fn get_value(&self) -> u64;
}

impl GetValue for () {
    fn get_value(&self) -> u64 {
        0
    }
}

pub trait Verify {
    type Error;
    fn verify_transaction(
        transaction: &AuthorizedTransaction,
    ) -> Result<(), Self::Error>;
    fn verify_body(body: &Body) -> Result<(), Self::Error>;
}

fn borsh_serialize_x25519_pubkey<W>(
    pk: &x25519_dalek::PublicKey,
    writer: &mut W,
) -> borsh::io::Result<()>
where
    W: borsh::io::Write,
{
    borsh::BorshSerialize::serialize(pk.as_bytes(), writer)
}

/// Wrapper around x25519 pubkeys
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
#[repr(transparent)]
#[serde(transparent)]
pub struct EncryptionPubKey(
    #[borsh(serialize_with = "borsh_serialize_x25519_pubkey")]
    pub  x25519_dalek::PublicKey,
);

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
    pub prev_side_hash: BlockHash,
    #[borsh(serialize_with = "borsh_serialize_bitcoin_block_hash")]
    pub prev_main_hash: bitcoin::BlockHash,
}

impl Header {
    pub fn hash(&self) -> BlockHash {
        hashes::hash(self).into()
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum WithdrawalBundleStatus {
    Failed,
    Confirmed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalBundle {
    pub spend_utxos: BTreeMap<OutPoint, FilledOutput>,
    pub transaction: bitcoin::Transaction,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct TwoWayPegData {
    pub deposits: HashMap<OutPoint, Output>,
    pub deposit_block_hash: Option<bitcoin::BlockHash>,
    pub bundle_statuses: HashMap<bitcoin::Txid, WithdrawalBundleStatus>,
}

// Internal node of a CBMT
#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct CbmtNode {
    // Commitment to child nodes or leaf value
    commitment: Hash,
    // Sum of fees for child nodes or leaf value
    fees: u64,
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
struct MergeFeeSizeTotal;

impl merkle_cbt::merkle_tree::Merge for MergeFeeSizeTotal {
    type Item = CbmtNode;

    fn merge(lnode: &Self::Item, rnode: &Self::Item) -> Self::Item {
        let fees = lnode.fees + rnode.fees;
        let canonical_size = lnode.canonical_size + rnode.canonical_size;
        // see https://github.com/nervosnetwork/merkle-tree/blob/5d1898263e7167560fdaa62f09e8d52991a1c712/README.md#tree-struct
        assert_eq!(lnode.index + 1, rnode.index);
        let index = (lnode.index - 1) / 2;
        let commitment = hashes::hash(&(
            lnode.commitment,
            rnode.commitment,
            fees,
            canonical_size,
        ));
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

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
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

    pub fn compute_merkle_root(
        coinbase: &[Output],
        txs: &[FilledTransaction],
    ) -> Option<MerkleRoot> {
        let CbmtNode {
            commitment: txs_root,
            ..
        } = {
            let n_txs = txs.len();
            let leaves = txs
                .iter()
                .enumerate()
                .map(|(idx, tx)| {
                    Some(CbmtNode {
                        commitment: hashes::hash(&tx.transaction),
                        fees: tx.fee()?,
                        canonical_size: tx.transaction.canonical_size(),
                        // see https://github.com/nervosnetwork/merkle-tree/blob/5d1898263e7167560fdaa62f09e8d52991a1c712/README.md#tree-struct
                        index: (idx + n_txs) - 1,
                    })
                })
                .collect::<Option<Vec<_>>>()?;
            CbmtWithFeeTotal::build_merkle_root(leaves.as_slice())
        };
        // FIXME: Compute actual merkle root instead of just a hash.
        // TODO: Should this include `total_fees`?
        let root = hashes::hash(&(coinbase, txs_root)).into();
        Some(root)
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
    ) -> Option<HashMap<OutPoint, Output>> {
        let mut outputs = HashMap::new();
        let merkle_root = Self::compute_merkle_root(coinbase, txs)?;
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
        Some(outputs)
    }

    pub fn get_coinbase_value(&self) -> u64 {
        self.coinbase.iter().map(|output| output.get_value()).sum()
    }
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
    pub value: u64,
    pub main_fee: u64,
}

#[derive(Debug, Error)]
pub enum Bech32mDecodeError {
    #[error(transparent)]
    Bech32m(#[from] bech32::Error),
    #[error("Wrong Bech32 HRP. Perhaps this key is being used somewhere it shouldn't be.")]
    WrongHrp,
    #[error("Wrong decoded byte length. Must decode to 32 bytes of data.")]
    WrongSize,
    #[error("Wrong Bech32 variant. Only Bech32m is accepted.")]
    WrongVariant,
}

impl EncryptionPubKey {
    /// HRP for Bech32m encoding
    const BECH32M_HRP: &'static str = "bn-enc";

    /// Encode to Bech32m format
    pub fn bech32m_encode(&self) -> String {
        bech32::encode(
            Self::BECH32M_HRP,
            self.0.as_bytes().to_base32(),
            bech32::Variant::Bech32m,
        )
        .expect("Bech32m Encoding should not fail")
    }

    /// Decode from Bech32m format
    pub fn bech32m_decode(s: &str) -> Result<Self, Bech32mDecodeError> {
        let (hrp, data5, variant) = bech32::decode(s)?;
        if variant != bech32::Variant::Bech32m {
            return Err(Bech32mDecodeError::WrongVariant);
        }
        if hrp != Self::BECH32M_HRP {
            return Err(Bech32mDecodeError::WrongHrp);
        }
        let data8 = Vec::<u8>::from_base32(&data5)?;
        let Ok(bytes) = <[u8; 32]>::try_from(data8) else {
            return Err(Bech32mDecodeError::WrongSize);
        };
        Ok(Self::from(bytes))
    }
}

impl std::fmt::Display for EncryptionPubKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.bech32m_encode().fmt(f)
    }
}

impl<T> From<T> for EncryptionPubKey
where
    x25519_dalek::PublicKey: From<T>,
{
    fn from(value: T) -> Self {
        Self(value.into())
    }
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
