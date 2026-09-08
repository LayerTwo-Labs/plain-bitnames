//! Wallet errors

use std::path::PathBuf;

use sneed::{db::error as db, env::error as env, rwtxn::error as rwtxn};
use thiserror::Error;
use transitive::Transitive;

use crate::{
    types::{
        Address, AmountOverflowError, AmountUnderflowError, Version,
        ecies::error as ecies, keys::CompressedPublicKey,
    },
    wallet::bip32,
};

#[derive(Debug, Error)]
#[error("wallet does not have a seed (set with RPC `set-seed-from-mnemonic`)")]
pub struct NoSeed;

#[allow(clippy::duplicated_attributes)]
#[derive(Debug, Error, Transitive)]
#[transitive(
    from(bip32::HardenedDeriveError, bip32::Error),
    from(bip32::NonHardenedDeriveError, bip32::Error)
)]
pub(in crate::wallet) enum GetSecret {
    #[error("bip32 error")]
    Bip32(#[from] bip32::Error),
    #[error(transparent)]
    DbTryGet(#[from] db::TryGet),
    #[error(transparent)]
    NoSeed(#[from] NoSeed),
}

#[derive(Debug, Error)]
#[error("failed to get tx signing key")]
#[repr(transparent)]
pub struct GetTxSigningKey(#[source] GetSecret);

impl<Err> From<Err> for GetTxSigningKey
where
    GetSecret: From<Err>,
{
    fn from(err: Err) -> Self {
        Self(err.into())
    }
}

#[derive(Debug, Error)]
#[error("failed to get secret key")]
#[repr(transparent)]
pub struct GetSecretKey(#[source] GetSecret);

impl<Err> From<Err> for GetSecretKey
where
    GetSecret: From<Err>,
{
    fn from(err: Err) -> Self {
        Self(err.into())
    }
}

#[derive(Debug, Error)]
#[error("Public key {cpk} does not exist")]
#[repr(transparent)]
pub struct PubkeyDoesNotExist {
    pub cpk: CompressedPublicKey,
}

#[allow(clippy::duplicated_attributes)]
#[derive(Debug, Error, Transitive)]
#[transitive(
    from(bip32::HardenedDeriveError, bip32::Error),
    from(bip32::NonHardenedDeriveError, bip32::Error),
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
    Authorization(#[from] crate::types::AuthorizationError),
    #[error("bip32 error")]
    Bip32(#[from] bip32::Error),
    #[error(transparent)]
    Db(#[from] db::Error),
    #[error("Database env error")]
    DbEnv(#[from] env::Error),
    #[error("Database write error")]
    DbWrite(#[from] rwtxn::Error),
    #[error("ECIES decryption error")]
    EciesDecrypt(#[from] ecies::Decrypt),
    #[error(
        "Incompatible DB version ({}). Please clear the DB (`{}`) and re-sync",
        .version,
        .db_path.display()
    )]
    IncompatibleVersion { version: Version, db_path: PathBuf },
    #[error("io error")]
    Io(#[from] std::io::Error),
    #[error("no index for address {address}")]
    NoIndex { address: Address },
    #[error("no transfer destination")]
    NoTransferDestination,
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
    #[error(transparent)]
    PubkeyDoesNotExist(#[from] PubkeyDoesNotExist),
    #[error("seed has already been set")]
    SeedAlreadyExists,
}

impl From<GetSecret> for Error {
    fn from(err: GetSecret) -> Self {
        match err {
            GetSecret::Bip32(err) => err.into(),
            GetSecret::DbTryGet(err) => err.into(),
            GetSecret::NoSeed(err) => err.into(),
        }
    }
}

impl From<GetSecretKey> for Error {
    fn from(err: GetSecretKey) -> Self {
        err.0.into()
    }
}

impl From<GetTxSigningKey> for Error {
    fn from(err: GetTxSigningKey) -> Self {
        err.0.into()
    }
}
