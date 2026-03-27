//! State errors

use sneed::{db::error as db, env::error as env, rwtxn::error as rwtxn};
use thiserror::Error;
use transitive::Transitive;

use crate::types::{
    AmountOverflowError, AmountUnderflowError, BitName as BitNameId, BlockHash,
    M6id, MerkleRoot, OutPoint, Txid, WithdrawalBundleError,
};

/// Errors related to BitNames
#[allow(clippy::duplicated_attributes)]
#[derive(Debug, Error, Transitive)]
#[allow(clippy::duplicated_attributes)]
#[transitive(from(db::Delete, db::Error))]
#[transitive(from(db::Last, db::Error))]
#[transitive(from(db::Put, db::Error))]
#[transitive(from(db::TryGet, db::Error))]
pub enum BitName {
    #[error("Bitname {bitname} already registered as an ICANN name")]
    AlreadyIcann { bitname: BitNameId },
    #[error(transparent)]
    Db(Box<db::Error>),
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

impl From<db::Error> for BitName {
    fn from(err: db::Error) -> Self {
        Self::Db(Box::new(err))
    }
}

#[derive(Debug, Error)]
#[error("utxo {outpoint} doesn't exist")]
pub struct NoUtxo {
    pub outpoint: OutPoint,
}

#[derive(Debug, Error)]
#[error("pending withdrawal bundle {0} unknown in withdrawal_bundles")]
#[repr(transparent)]
pub struct PendingWithdrawalBundleUnknown(pub M6id);

#[allow(clippy::duplicated_attributes)]
#[derive(Debug, Error, Transitive)]
#[transitive(
    from(db::Delete, db::Error),
    from(db::Put, db::Error),
    from(db::TryGet, db::Error)
)]
pub enum ConnectWithdrawalBundleSubmitted {
    #[error(
        "confirmed withdrawal bundle {} resubmitted in {}",
        .m6id,
        .event_block_hash,
    )]
    ConfirmedResubmitted {
        event_block_hash: bitcoin::BlockHash,
        m6id: M6id,
    },
    #[error(transparent)]
    Db(Box<db::Error>),
    #[error(
        "dropped withdrawal bundle {0} marked as pending in withdrawal_bundles"
    )]
    DroppedPending(M6id),
    #[error(transparent)]
    NoUtxo(#[from] NoUtxo),
    #[error(transparent)]
    PendingWithdrawalBundleUnknown(#[from] PendingWithdrawalBundleUnknown),
    #[error(
        "withdrawal bundle {} submitted in {} resubmitted in {}",
        m6id,
        submitted_block_height,
        event_block_hash
    )]
    Resubmitted {
        event_block_hash: bitcoin::BlockHash,
        m6id: M6id,
        submitted_block_height: u32,
    },
    #[error(
        "unknown confirmed withdrawal bundle {} marked as failed in {}",
        .m6id,
        .failed_block_height,
    )]
    UnknownConfirmedFailed {
        m6id: M6id,
        failed_block_height: u32,
    },
    #[error(
        "unknown withdrawal bundle {} marked as dropped in {}",
        .m6id,
        .dropped_block_height,
    )]
    UnknownDropped {
        m6id: M6id,
        dropped_block_height: u32,
    },
    #[error(
        "unknown withdrawal bundle {} marked as pending in {}",
        .m6id,
        .pending_block_height,
    )]
    UnknownPending {
        m6id: M6id,
        pending_block_height: u32,
    },
}

impl From<db::Error> for ConnectWithdrawalBundleSubmitted {
    fn from(err: db::Error) -> Self {
        Self::Db(Box::new(err))
    }
}

#[derive(Debug, Error)]
pub enum InvalidHeader {
    #[error("expected block hash {expected}, but computed {computed}")]
    BlockHash {
        expected: BlockHash,
        computed: BlockHash,
    },
    #[error(
        "expected previous sidechain block hash {expected:?}, but received {received:?}"
    )]
    PrevSideHash {
        expected: Option<BlockHash>,
        received: Option<BlockHash>,
    },
}

#[allow(clippy::duplicated_attributes)]
#[derive(Debug, Error, Transitive)]
#[allow(clippy::duplicated_attributes)]
#[transitive(from(db::Clear, db::Error))]
#[transitive(from(db::Delete, db::Error))]
#[transitive(from(db::Error, sneed::Error))]
#[transitive(from(db::Get, db::Error))]
#[transitive(from(db::IterInit, db::Error))]
#[transitive(from(db::IterItem, db::Error))]
#[transitive(from(db::Last, db::Error))]
#[transitive(from(db::Put, db::Error))]
#[transitive(from(db::TryGet, db::Error))]
#[transitive(from(env::CreateDb, env::Error))]
#[transitive(from(env::Error, sneed::Error))]
#[transitive(from(env::WriteTxn, env::Error))]
#[transitive(from(rwtxn::Commit, rwtxn::Error))]
#[transitive(from(rwtxn::Error, sneed::Error))]
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
    #[error(transparent)]
    ComputeMerkleRoot(#[from] crate::types::ComputeMerkleRootError),
    #[error(transparent)]
    ConnectWithdrawalBundleSubmitted(#[from] ConnectWithdrawalBundleSubmitted),
    #[error(transparent)]
    Db(Box<sneed::Error>),
    #[error("failed to fill tx output contents: invalid transaction")]
    FillTxOutputContentsFailed,
    #[error("invalid ICANN name: {plain_name}")]
    IcannNameInvalid { plain_name: String },
    #[error("Invalid Batch ICANN registration signature")]
    InvalidBatchIcannRegistrationSignature,
    #[error(
        "invalid body: expected merkle root {expected}, but computed {computed}"
    )]
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
    #[error(transparent)]
    NoUtxo(#[from] NoUtxo),
    #[error("Withdrawal bundle event block doesn't exist")]
    NoWithdrawalBundleEventBlock,
    #[error(transparent)]
    PendingWithdrawalBundleUnknown(#[from] PendingWithdrawalBundleUnknown),
    #[error("Too few BitName outputs")]
    TooFewBitNameOutputs,
    #[error(
        "unbalanced BitNames: {n_bitname_inputs} BitName inputs, {n_bitname_outputs} BitName outputs"
    )]
    UnbalancedBitNames {
        n_bitname_inputs: usize,
        n_bitname_outputs: usize,
    },
    #[error(
        "unbalanced reservations: {n_reservation_inputs} reservation inputs, {n_reservation_outputs} reservation outputs"
    )]
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

impl From<sneed::Error> for Error {
    fn from(err: sneed::Error) -> Self {
        Self::Db(Box::new(err))
    }
}
