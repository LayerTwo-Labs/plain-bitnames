use std::collections::VecDeque;

use fallible_iterator::FallibleIterator as _;
use heed::types::SerdeBincode;
use sneed::{
    DatabaseUnique, DbError, EnvError, RoTxn, RwTxn, RwTxnError, UnitKey, db,
    env, rwtxn,
};

use crate::types::{AuthorizedTransaction, OutPoint, Txid, VERSION, Version};

#[allow(clippy::duplicated_attributes)]
#[derive(thiserror::Error, transitive::Transitive, Debug)]
#[transitive(from(db::error::Delete, DbError))]
#[transitive(from(db::error::Put, DbError))]
#[transitive(from(db::error::TryGet, DbError))]
#[transitive(from(env::error::CreateDb, EnvError))]
#[transitive(from(env::error::WriteTxn, EnvError))]
#[transitive(from(rwtxn::error::Commit, RwTxnError))]
pub enum Error {
    #[error(transparent)]
    Db(Box<DbError>),
    #[error("Database env error")]
    DbEnv(#[source] Box<EnvError>),
    #[error("Database write error")]
    DbWrite(#[from] RwTxnError),
    #[error("Missing transaction {0}")]
    MissingTransaction(Txid),
    #[error("can't add transaction, utxo double spent")]
    UtxoDoubleSpent,
}

impl From<DbError> for Error {
    fn from(err: DbError) -> Self {
        Self::Db(Box::new(err))
    }
}

impl From<EnvError> for Error {
    fn from(err: EnvError) -> Self {
        Self::DbEnv(Box::new(err))
    }
}

#[derive(Clone)]
pub struct MemPool {
    pub transactions:
        DatabaseUnique<SerdeBincode<Txid>, SerdeBincode<AuthorizedTransaction>>,
    pub spent_utxos: DatabaseUnique<SerdeBincode<OutPoint>, SerdeBincode<Txid>>,
    _version: DatabaseUnique<UnitKey, SerdeBincode<Version>>,
}

impl MemPool {
    pub const NUM_DBS: u32 = 3;

    pub fn new(env: &sneed::Env) -> Result<Self, Error> {
        let mut rwtxn = env.write_txn()?;
        let transactions =
            DatabaseUnique::create(env, &mut rwtxn, "transactions")?;
        let spent_utxos =
            DatabaseUnique::create(env, &mut rwtxn, "spent_utxos")?;
        let version =
            DatabaseUnique::create(env, &mut rwtxn, "mempool_version")?;
        if version.try_get(&rwtxn, &())?.is_none() {
            version.put(&mut rwtxn, &(), &*VERSION)?;
        }
        rwtxn.commit()?;
        Ok(Self {
            transactions,
            spent_utxos,
            _version: version,
        })
    }

    /// Delete STXOs
    fn delete_stxos<'a, Iter>(
        &self,
        rwtxn: &mut RwTxn,
        stxos: Iter,
    ) -> Result<(), Error>
    where
        Iter: IntoIterator<Item = &'a OutPoint>,
    {
        stxos.into_iter().try_for_each(|stxo| {
            let _ = self.spent_utxos.delete(rwtxn, stxo)?;
            Ok(())
        })
    }

    pub fn put(
        &self,
        txn: &mut RwTxn,
        transaction: &AuthorizedTransaction,
    ) -> Result<(), Error> {
        let txid = transaction.transaction.txid();
        tracing::debug!("adding transaction {txid} to mempool");
        for input in &transaction.transaction.inputs {
            if self.spent_utxos.try_get(txn, input)?.is_some() {
                return Err(Error::UtxoDoubleSpent);
            }
            self.spent_utxos.put(txn, input, &txid)?;
        }
        self.transactions.put(txn, &txid, transaction)?;
        Ok(())
    }

    pub fn delete(&self, rwtxn: &mut RwTxn, txid: Txid) -> Result<(), Error> {
        let mut pending_deletes = VecDeque::from([txid]);
        while let Some(txid) = pending_deletes.pop_front() {
            if let Some(tx) = self.transactions.try_get(rwtxn, &txid)? {
                let () = self.delete_stxos(rwtxn, &tx.transaction.inputs)?;
                self.transactions.delete(rwtxn, &txid)?;
                for vout in 0..tx.transaction.outputs.len() {
                    let outpoint = OutPoint::Regular {
                        txid,
                        vout: vout as u32,
                    };
                    if let Some(child_txid) =
                        self.spent_utxos.try_get(rwtxn, &outpoint)?
                    {
                        pending_deletes.push_back(child_txid);
                    }
                }
            }
        }
        Ok(())
    }

    pub fn take(
        &self,
        rotxn: &RoTxn,
        number: usize,
    ) -> Result<Vec<AuthorizedTransaction>, Error> {
        self.transactions
            .iter(rotxn)
            .map_err(DbError::from)?
            .take(number)
            .map(|(_, transaction)| Ok(transaction))
            .collect()
            .map_err(|err| DbError::from(err).into())
    }

    pub fn take_all(
        &self,
        rotxn: &RoTxn,
    ) -> Result<Vec<AuthorizedTransaction>, Error> {
        self.transactions
            .iter(rotxn)
            .map_err(DbError::from)?
            .map(|(_, transaction)| Ok(transaction))
            .collect()
            .map_err(|err| DbError::from(err).into())
    }
}
