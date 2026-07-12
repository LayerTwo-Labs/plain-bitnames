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

    pub fn new<Tls>(env: &sneed::Env<Tls>) -> Result<Self, Error>
    where
        Tls: heed::TlsUsage,
    {
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

#[cfg(test)]
mod p2p_validation_bypass_tests {
    use bitcoin::Amount;
    use heed::EnvOpenOptions;

    use super::MemPool;
    use crate::authorization::{Authorization, get_address, Signature};
    use crate::state::State;
    use crate::types::{
        Address, AuthorizedTransaction, FilledOutput, FilledOutputContent, OutPoint,
        OutPointKey, Output, OutputContent, Transaction, Txid, VerifyingKey,
    };

    fn signing_key(seed: u8) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
    }

    fn temp_env() -> sneed::Env {
        let dir = std::env::temp_dir()
            .join(format!("bitnames-p2p-test-{}", std::process::id()));
        drop(std::fs::remove_dir_all(&dir));
        std::fs::create_dir_all(&dir).expect("create temp env dir");
        let mut opts = EnvOpenOptions::new();
        opts.map_size(16 * 1024 * 1024)
            .max_dbs(State::NUM_DBS + MemPool::NUM_DBS + 4);
        unsafe { sneed::Env::open(&opts, &dir) }.expect("open env")
    }

    #[test]
    fn p2p_path_accepts_transaction_that_validation_rejects() {
        let env = temp_env();
        let state = State::new(&env).expect("State::new");
        let mempool = MemPool::new(&env).expect("MemPool::new");

        let victim = signing_key(1);
        let victim_vk = VerifyingKey(victim.verifying_key());
        let victim_addr: Address = get_address(&victim_vk);
        let funding_outpoint = OutPoint::Regular {
            txid: Txid([7u8; 32]),
            vout: 0,
        };
        let funded_output = FilledOutput::new(
            victim_addr,
            FilledOutputContent::Bitcoin(crate::types::BitcoinOutputContent(
                Amount::from_sat(100_000),
            )),
        );
        {
            let mut rwtxn = env.write_txn().expect("write txn");
            state
                .utxos
                .put(&mut rwtxn, &OutPointKey::from(&funding_outpoint), &funded_output)
                .expect("put utxo");
            rwtxn.commit().expect("commit funding");
        }

        let tx = Transaction {
            inputs: vec![funding_outpoint],
            outputs: vec![Output::new(
                get_address(&VerifyingKey(signing_key(2).verifying_key())),
                OutputContent::Bitcoin(crate::types::BitcoinOutputContent(
                    Amount::from_sat(90_000),
                )),
            )],
            memo: vec![],
            data: None,
        };

        let forged = Authorization {
            verifying_key: victim_vk,
            signature: Signature(ed25519_dalek::Signature::from_bytes(&[0u8; 64])),
        };
        let authd_tx = AuthorizedTransaction {
            transaction: tx,
            authorizations: vec![forged],
        };

        {
            let rotxn = env.read_txn().expect("read txn");
            let result = state.validate_transaction(&rotxn, &authd_tx);
            eprintln!("validate_transaction(forged tx) => {result:?}");
            assert!(result.is_err(), "validator must reject the forged-sig tx: {result:?}");
            assert!(
                format!("{result:?}").to_lowercase().contains("authoriz"),
                "rejection must be an authorization error, got {result:?}"
            );
        }

        {
            let mut rwtxn = env.write_txn().expect("write txn");
            mempool
                .put(&mut rwtxn, &authd_tx)
                .expect("mempool.put accepted the invalid tx (the bug)");
            rwtxn.commit().expect("commit mempool");
        }

        {
            let rotxn = env.read_txn().expect("read txn");
            let in_mempool = mempool.take_all(&rotxn).expect("take_all");
            assert_eq!(
                in_mempool.len(),
                1,
                "the forged-signature tx must be sitting in the mempool"
            );
            assert_eq!(
                in_mempool[0].transaction.txid(),
                authd_tx.transaction.txid(),
            );
        }
    }
}
