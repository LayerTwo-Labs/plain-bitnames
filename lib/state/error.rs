//! State errors

use sneed::{db::error as db, env::error as env, rwtxn::error as rwtxn};
use thiserror::Error;
use transitive::Transitive;

use crate::types::{
    AmountOverflowError, AmountUnderflowError, BitName as BitNameId, BlockHash,
    M6id, MerkleRoot, OutPoint, Txid, WithdrawalBundleError,
};

/// Errors related to BitNames
#[derive(Debug, Error, Transitive)]
#[transitive(from(db::Delete))]
#[transitive(from(db::Last))]
#[transitive(from(db::Put))]
#[transitive(from(db::TryGet))]
pub enum BitName {
    #[error("Bitname {bitname} already registered as an ICANN name")]
    AlreadyIcann { bitname: BitNameId },
    #[error(transparent)]
    Db(#[from] db::Error),
    #[error("Missing BitName {bitname}")]
    Missing { bitname: BitNameId },
    #[error("Missing BitName input {bitname}")]
    MissingBitNameInput { bitname: BitNameId },
    #[error(
        "Missing BitName data for {bitname} at block height {block_height}"
    )]
    MissingData {
        bitname: BitNameId,
        block_height: u32,
    },
    #[error("missing BitName reservation {txid}")]
    MissingReservation { txid: Txid },
    #[error("no BitNames to update")]
    NoBitNamesToUpdate,
}

#[derive(Debug, thiserror::Error)]
pub enum InvalidHeader {
    #[error("expected block hash {expected}, but computed {computed}")]
    BlockHash {
        expected: BlockHash,
        computed: BlockHash,
    },
    #[error("expected previous sidechain block hash {expected:?}, but received {received:?}")]
    PrevSideHash {
        expected: Option<BlockHash>,
        received: Option<BlockHash>,
    },
}

#[derive(Debug, Error, Transitive)]
#[transitive(from(db::Clear))]
#[transitive(from(db::Delete))]
#[transitive(from(db::IterInit))]
#[transitive(from(db::IterItem))]
#[transitive(from(db::Last))]
#[transitive(from(db::Put))]
#[transitive(from(db::TryGet))]
#[transitive(from(env::CreateDb))]
#[transitive(from(env::WriteTxn))]
#[transitive(from(rwtxn::Commit))]
pub enum Error {
    #[error(transparent)]
    AmountOverflow(#[from] AmountOverflowError),
    #[error(transparent)]
    AmountUnderflow(#[from] AmountUnderflowError),
    #[error("failed to verify authorization")]
    AuthorizationError,
    #[error("bad coinbase output content")]
    BadCoinbaseOutputContent,
    #[error(transparent)]
    BitName(#[from] BitName),
    #[error("bitname {name_hash} already registered")]
    BitNameAlreadyRegistered { name_hash: BitNameId },
    #[error("bundle too heavy {weight} > {max_weight}")]
    BundleTooHeavy { weight: u64, max_weight: u64 },
    #[error(transparent)]
    BorshSerialize(borsh::io::Error),
    #[error("failed to fill tx output contents: invalid transaction")]
    FillTxOutputContentsFailed,
    #[error("heed error")]
    Heed(#[from] heed::Error),
    #[error("invalid ICANN name: {plain_name}")]
    IcannNameInvalid { plain_name: String },
    #[error("invalid body: expected merkle root {expected}, but computed {computed}")]
    InvalidBody {
        expected: MerkleRoot,
        computed: MerkleRoot,
    },
    #[error("invalid header")]
    InvalidHeader(#[from] InvalidHeader),
    #[error("failed to compute merkle root")]
    MerkleRoot,
    #[error("deposit block doesn't exist")]
    NoDepositBlock,
    #[error("total fees less than coinbase value")]
    NotEnoughFees,
    #[error("value in is less than value out")]
    NotEnoughValueIn,
    #[error("stxo {outpoint} doesn't exist")]
    NoStxo { outpoint: OutPoint },
    #[error("no tip")]
    NoTip,
    #[error("utxo {outpoint} doesn't exist")]
    NoUtxo { outpoint: OutPoint },
    #[error("Withdrawal bundle event block doesn't exist")]
    NoWithdrawalBundleEventBlock,
    #[error(transparent)]
    SignatureError(#[from] ed25519_dalek::SignatureError),
    #[error("Too few BitName outputs")]
    TooFewBitNameOutputs,
    #[error("unbalanced BitNames: {n_bitname_inputs} BitName inputs, {n_bitname_outputs} BitName outputs")]
    UnbalancedBitNames {
        n_bitname_inputs: usize,
        n_bitname_outputs: usize,
    },
    #[error("unbalanced reservations: {n_reservation_inputs} reservation inputs, {n_reservation_outputs} reservation outputs")]
    UnbalancedReservations {
        n_reservation_inputs: usize,
        n_reservation_outputs: usize,
    },
    #[error("Unknown withdrawal bundle: {m6id}")]
    UnknownWithdrawalBundle { m6id: M6id },
    #[error(
        "Unknown withdrawal bundle confirmed in {event_block_hash}: {m6id}"
    )]
    UnknownWithdrawalBundleConfirmed {
        event_block_hash: bitcoin::BlockHash,
        m6id: M6id,
    },
    #[error("utxo double spent")]
    UtxoDoubleSpent,
    #[error(transparent)]
    WithdrawalBundle(#[from] WithdrawalBundleError),
    #[error("wrong public key for address")]
    WrongPubKeyForAddress,
}
