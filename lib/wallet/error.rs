//! Wallet errors

use libes::EciesError;
use sneed::{db::error as db, env::error as env, rwtxn::error as rwtxn};
use thiserror::Error;
use transitive::Transitive;

use crate::types::{
    Address, AmountOverflowError, AmountUnderflowError, EncryptionPubKey,
    VerifyingKey,
};

#[derive(Debug, Error)]
#[error("wallet does not have a seed (set with RPC `set-seed-from-mnemonic`)")]
pub struct NoSeed;

#[derive(Debug, Error)]
pub(in crate::wallet) enum GetMasterXprvInner {
    #[error(transparent)]
    DbTryGet(#[from] db::TryGet),
    #[error(transparent)]
    NoSeed(#[from] NoSeed),
}

#[derive(Debug, Error)]
#[error("failed to get master xprv")]
#[repr(transparent)]
pub struct GetMasterXprv(#[source] GetMasterXprvInner);

impl<Err> From<Err> for GetMasterXprv
where
    GetMasterXprvInner: From<Err>,
{
    fn from(err: Err) -> Self {
        Self(err.into())
    }
}

#[derive(Debug, Error)]
#[error("Encryption pubkey {epk} does not exist")]
#[repr(transparent)]
pub struct EpkDoesNotExist {
    pub epk: EncryptionPubKey,
}

#[derive(Debug, Error)]
pub(in crate::wallet) enum GetEpkIndex {
    #[error(transparent)]
    DbTryGet(#[from] db::TryGet),
    #[error(transparent)]
    EpkDoesNotExist(#[from] EpkDoesNotExist),
}

#[derive(Debug, Error)]
pub(in crate::wallet) enum GetEncryptionXEskForEpkInner {
    #[error(transparent)]
    GetEpkIndex(#[from] GetEpkIndex),
    #[error(transparent)]
    GetMasterXprv(#[from] GetMasterXprv),
}

#[derive(Debug, Error)]
#[error("failed to get encryption xesk for encryption pubkey")]
#[repr(transparent)]
pub struct GetEncryptionXEskForEpk(#[source] GetEncryptionXEskForEpkInner);

impl<Err> From<Err> for GetEncryptionXEskForEpk
where
    GetEncryptionXEskForEpkInner: From<Err>,
{
    fn from(err: Err) -> Self {
        Self(err.into())
    }
}

#[derive(Debug, Error)]
#[error("message signature verification key {vk} does not exist")]
pub struct VkDoesNotExist {
    pub vk: VerifyingKey,
}

#[allow(clippy::duplicated_attributes)]
#[derive(Debug, Error, Transitive)]
#[transitive(
    from(db::Clear, db::Error),
    from(db::Delete, db::Error),
    from(db::IterInit, db::Error),
    from(db::IterItem, db::Error),
    from(db::Last, db::Error),
    from(db::Len, db::Error),
    from(db::Put, db::Error),
    from(db::TryGet, db::Error),
    from(env::CreateDb, env::Error),
    from(env::OpenEnv, env::Error),
    from(env::ReadTxn, env::Error),
    from(env::WriteTxn, env::Error),
    from(rwtxn::Commit, rwtxn::Error)
)]
pub enum Error {
    #[error("address {address} does not exist")]
    AddressDoesNotExist { address: crate::types::Address },
    #[error(transparent)]
    AmountOverflow(#[from] AmountOverflowError),
    #[error(transparent)]
    AmountUnderflow(#[from] AmountUnderflowError),
    #[error("authorization error")]
    Authorization(#[from] crate::authorization::Error),
    #[error("bip32 error")]
    Bip32(#[from] bitcoin::bip32::Error),
    #[error(transparent)]
    Db(#[from] db::Error),
    #[error("Database env error")]
    DbEnv(#[from] env::Error),
    #[error("Database write error")]
    DbWrite(#[from] rwtxn::Error),
    #[error("ECIES error: {:?}", .0)]
    Ecies(EciesError),
    #[error(transparent)]
    EpkDoesNotExist(#[from] EpkDoesNotExist),
    #[error("io error")]
    Io(#[from] std::io::Error),
    #[error("no index for address {address}")]
    NoIndex { address: Address },
    #[error(transparent)]
    NoSeed(#[from] NoSeed),
    #[error("could not find bitname reservation for `{plain_name}`")]
    NoBitnameReservation { plain_name: String },
    #[error("not enough funds")]
    NotEnoughFunds,
    #[error("utxo does not exist")]
    NoUtxo,
    #[error("failed to parse mnemonic seed phrase")]
    ParseMnemonic(#[from] bip39::ErrorKind),
    #[error("seed has already been set")]
    SeedAlreadyExists,
    #[error(transparent)]
    VkDoesNotExist(Box<VkDoesNotExist>),
}

impl From<VkDoesNotExist> for Error {
    fn from(err: VkDoesNotExist) -> Self {
        Self::VkDoesNotExist(Box::new(err))
    }
}

impl From<GetMasterXprvInner> for Error {
    fn from(err: GetMasterXprvInner) -> Self {
        match err {
            GetMasterXprvInner::DbTryGet(err) => err.into(),
            GetMasterXprvInner::NoSeed(err) => err.into(),
        }
    }
}

impl From<GetMasterXprv> for Error {
    fn from(err: GetMasterXprv) -> Self {
        err.0.into()
    }
}

impl From<GetEpkIndex> for Error {
    fn from(err: GetEpkIndex) -> Self {
        match err {
            GetEpkIndex::DbTryGet(err) => err.into(),
            GetEpkIndex::EpkDoesNotExist(err) => err.into(),
        }
    }
}

impl From<GetEncryptionXEskForEpkInner> for Error {
    fn from(err: GetEncryptionXEskForEpkInner) -> Self {
        match err {
            GetEncryptionXEskForEpkInner::GetEpkIndex(err) => err.into(),
            GetEncryptionXEskForEpkInner::GetMasterXprv(err) => err.into(),
        }
    }
}

impl From<GetEncryptionXEskForEpk> for Error {
    fn from(err: GetEncryptionXEskForEpk) -> Self {
        err.0.into()
    }
}
