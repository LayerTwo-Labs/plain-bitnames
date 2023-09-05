use std::{
    collections::{HashMap, HashSet},
    path::Path
};

use bip300301::bitcoin;
use byteorder::{BigEndian, ByteOrder};
use ed25519_dalek_bip32::*;
use heed::{types::*, Database, RoTxn};

use crate::{
    authorization::{get_address, Authorization},
    types::{
        Address, AuthorizedTransaction, FilledOutput, GetValue, OutPoint, Output,
        OutputContent, Transaction, TxData, Hash,
    }
};


#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("address {address} does not exist")]
    AddressDoesNotExist { address: crate::types::Address },
    #[error("authorization error")]
    Authorization(#[from] crate::authorization::Error),
    #[error("bip32 error")]
    Bip32(#[from] ed25519_dalek_bip32::Error),
    #[error("heed error")]
    Heed(#[from] heed::Error),
    #[error("io error")]
    Io(#[from] std::io::Error),
    #[error("no index for address {address}")]
    NoIndex { address: Address },
    #[error("wallet doesn't have a seed")]
    NoSeed,
    #[error("not enough funds")]
    NotEnoughFunds,
    #[error("utxo doesn't exist")]
    NoUtxo,
}

#[derive(Clone)]
pub struct Wallet {
    env: heed::Env,
    // FIXME: Don't store the seed in plaintext.
    seed: Database<OwnedType<u8>, OwnedType<[u8; 64]>>,
    pub address_to_index: Database<SerdeBincode<Address>, OwnedType<[u8; 4]>>,
    pub index_to_address: Database<OwnedType<[u8; 4]>, SerdeBincode<Address>>,
    pub utxos: Database<SerdeBincode<OutPoint>, SerdeBincode<FilledOutput>>,
}

impl Wallet {
    pub const NUM_DBS: u32 = 4;

    pub fn new(path: &Path) -> Result<Self, Error> {
        std::fs::create_dir_all(path)?;
        let env = heed::EnvOpenOptions::new()
            .map_size(10 * 1024 * 1024) // 10MB
            .max_dbs(Self::NUM_DBS)
            .open(path)?;
        let seed_db = env.create_database(Some("seed"))?;
        let address_to_index = env.create_database(Some("address_to_index"))?;
        let index_to_address = env.create_database(Some("index_to_address"))?;
        let utxos = env.create_database(Some("utxos"))?;
        Ok(Self {
            env,
            seed: seed_db,
            address_to_index,
            index_to_address,
            utxos,
        })
    }

    fn get_keypair(
        &self,
        txn: &RoTxn,
        index: u32,
    ) -> Result<ed25519_dalek::Keypair, Error> {
        let seed = self.seed.get(txn, &0)?.ok_or(Error::NoSeed)?;
        let xpriv = ExtendedSecretKey::from_seed(&seed)?;
        let derivation_path = DerivationPath::new([
            ChildIndex::Hardened(1),
            ChildIndex::Hardened(0),
            ChildIndex::Hardened(0),
            ChildIndex::Hardened(index),
        ]);
        let child = xpriv.derive(&derivation_path)?;
        let public = child.public_key();
        let secret = child.secret_key;
        Ok(ed25519_dalek::Keypair { secret, public })
    }

    pub fn get_new_address(&self) -> Result<Address, Error> {
        let mut txn = self.env.write_txn()?;
        let (last_index, _) = self
            .index_to_address
            .last(&txn)?
            .unwrap_or(([0; 4], [0; 20].into()));
        let last_index = BigEndian::read_u32(&last_index);
        let index = last_index + 1;
        let keypair = self.get_keypair(&txn, index)?;
        let address = get_address(&keypair.public);
        let index = index.to_be_bytes();
        self.index_to_address.put(&mut txn, &index, &address)?;
        self.address_to_index.put(&mut txn, &address, &index)?;
        txn.commit()?;
        Ok(address)
    }

    pub fn set_seed(&self, seed: &[u8; 64]) -> Result<(), Error> {
        let mut txn = self.env.write_txn()?;
        self.seed.put(&mut txn, &0, seed)?;
        self.address_to_index.clear(&mut txn)?;
        self.index_to_address.clear(&mut txn)?;
        self.utxos.clear(&mut txn)?;
        txn.commit()?;
        Ok(())
    }

    pub fn has_seed(&self) -> Result<bool, Error> {
        let txn = self.env.read_txn()?;
        Ok(self.seed.get(&txn, &0)?.is_some())
    }

    pub fn create_withdrawal(
        &self,
        main_address: bitcoin::Address<bitcoin::address::NetworkUnchecked>,
        value: u64,
        main_fee: u64,
        fee: u64,
    ) -> Result<Transaction, Error> {
        let (total, coins) = self.select_coins(value + fee + main_fee)?;
        let change = total - value - fee;
        let inputs = coins.into_keys().collect();
        let outputs = vec![
            Output::new(
                self.get_new_address()?,
                OutputContent::Withdrawal {
                    value,
                    main_fee,
                    main_address,
                },
            ),
            Output::new(self.get_new_address()?, OutputContent::Value(change)),
        ];
        Ok(Transaction::new(inputs, outputs))
    }

    pub fn create_regular_transaction(
        &self,
        address: Address,
        value: u64,
        fee: u64,
    ) -> Result<Transaction, Error> {
        let (total, coins) = self.select_coins(value + fee)?;
        let change = total - value - fee;
        let inputs = coins.into_keys().collect();
        let outputs = vec![
            Output::new(address, OutputContent::Value(value)),
            Output::new(self.get_new_address()?, OutputContent::Value(change)),
        ];
        Ok(Transaction::new(inputs, outputs))
    }

    /// converts a regular or bitname reservation tx to a regular tx.
    /// panics if the tx is not regular or a bitname reservation tx.
    pub fn regularize(&self, tx: &mut Transaction) {
        match tx.data {
            None => (),
            Some(TxData::BitNameReservation { .. }) => {
                // reverse index of last reservation output
                let last_reservation_rev_idx =
                    tx.outputs.iter().rev().position(Output::is_reservation)
                    .expect("A bitname reservation tx must have at least one reservation output")
                ;
                //  index of last reservation output
                let last_reservation_idx = (tx.outputs.len() - 1) - last_reservation_rev_idx;
                tx.outputs.remove(last_reservation_idx);
                tx.data = None;
            },
            Some(_) => panic!("this function only accepts a regular or bitname reservation tx")
        }
    }

    /// given a regular transaction, add a bitname reservation.
    /// given a bitname reservation tx, change the reserved name.
    /// panics if the tx is not regular or a bitname reservation tx.
    pub fn reserve_bitname(&self, tx: &mut Transaction, plain_name: &str) -> Result<(), Error> {
        assert!(tx.is_regular() || tx.is_reservation(), "this function only accepts a regular or bitname reservation tx");
        // address for the reservation output
        let reservation_addr =
            // if the tx is already bitname reservation,
            // re-use the reservation address
            if tx.is_reservation() {
                tx.reservation_outputs().rev().next()
                    .expect("A bitname reservation tx must have at least one reservation output")
                    .address
            }
            // if the last output is owned by this wallet, then use
            // the address associated with the last output
            else if let Some(last_output) = tx.outputs.last() {
                let last_output_addr = last_output.address;
                let rotxn = self.env.read_txn()?;
                if self.address_to_index.get(&rotxn, &last_output_addr)?.is_some() {
                    last_output_addr
                } else {
                    self.get_new_address()?
                }
            } else {
                self.get_new_address()?
            };
        let rotxn = self.env.read_txn()?;
        let reservation_addr_idx =
            self.address_to_index.get(&rotxn, &reservation_addr)?
                .ok_or(Error::AddressDoesNotExist { address: reservation_addr })?;
        let reservation_keypair =
            self.get_keypair(&rotxn, u32::from_be_bytes(reservation_addr_idx))?;
        // sanity check that reservation_keypair corresponds to reservation_addr
        assert_eq!(reservation_addr, get_address(&reservation_keypair.public));
        let name_hash: Hash = blake3::hash(plain_name.as_bytes()).into();
        // hmac(secret, name_hash)
        let nonce = blake3::keyed_hash(
            reservation_keypair.secret.as_bytes(),
            &name_hash).into();
        // hmac(nonce, name_hash)
        let commitment = blake3::keyed_hash(&nonce, &name_hash).into();
        // if the tx is regular, add a reservation output
        if tx.is_regular() {
            let reservation_output =
                Output::new(reservation_addr, OutputContent::BitNameReservation);
            tx.outputs.push(reservation_output);
        };
        tx.data = Some(TxData::BitNameReservation { commitment });
        Ok(())
    }

    pub fn select_coins(
        &self,
        value: u64,
    ) -> Result<(u64, HashMap<OutPoint, FilledOutput>), Error> {
        let txn = self.env.read_txn()?;
        let mut utxos = vec![];
        for item in self.utxos.iter(&txn)? {
            utxos.push(item?);
        }
        utxos.sort_unstable_by_key(|(_, output)| output.get_value());

        let mut selected = HashMap::new();
        let mut total: u64 = 0;
        for (outpoint, output) in &utxos {
            if output.content.is_withdrawal() {
                continue;
            }
            if total > value {
                break;
            }
            total += output.get_value();
            selected.insert(*outpoint, output.clone());
        }
        if total < value {
            return Err(Error::NotEnoughFunds);
        }
        Ok((total, selected))
    }

    pub fn delete_utxos(&self, outpoints: &[OutPoint]) -> Result<(), Error> {
        let mut txn = self.env.write_txn()?;
        for outpoint in outpoints {
            self.utxos.delete(&mut txn, outpoint)?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn put_utxos(
        &self,
        utxos: &HashMap<OutPoint, FilledOutput>,
    ) -> Result<(), Error> {
        let mut txn = self.env.write_txn()?;
        for (outpoint, output) in utxos {
            self.utxos.put(&mut txn, outpoint, output)?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn get_balance(&self) -> Result<u64, Error> {
        let mut balance: u64 = 0;
        let txn = self.env.read_txn()?;
        for item in self.utxos.iter(&txn)? {
            let (_, utxo) = item?;
            balance += utxo.get_value();
        }
        Ok(balance)
    }

    pub fn get_utxos(&self) -> Result<HashMap<OutPoint, FilledOutput>, Error> {
        let txn = self.env.read_txn()?;
        let mut utxos = HashMap::new();
        for item in self.utxos.iter(&txn)? {
            let (outpoint, output) = item?;
            utxos.insert(outpoint, output);
        }
        Ok(utxos)
    }

    pub fn get_addresses(&self) -> Result<HashSet<Address>, Error> {
        let txn = self.env.read_txn()?;
        let mut addresses = HashSet::new();
        for item in self.index_to_address.iter(&txn)? {
            let (_, address) = item?;
            addresses.insert(address);
        }
        Ok(addresses)
    }

    pub fn authorize(
        &self,
        transaction: Transaction,
    ) -> Result<AuthorizedTransaction, Error> {
        let txn = self.env.read_txn()?;
        let mut authorizations = vec![];
        for input in &transaction.inputs {
            let spent_utxo =
                self.utxos.get(&txn, input)?.ok_or(Error::NoUtxo)?;
            let index = self
                .address_to_index
                .get(&txn, &spent_utxo.address)?
                .ok_or(Error::NoIndex {
                address: spent_utxo.address,
            })?;
            let index = BigEndian::read_u32(&index);
            let keypair = self.get_keypair(&txn, index)?;
            let signature = crate::authorization::sign(&keypair, &transaction)?;
            authorizations.push(Authorization {
                public_key: keypair.public,
                signature,
            });
        }
        Ok(AuthorizedTransaction {
            authorizations,
            transaction,
        })
    }

    pub fn get_num_addresses(&self) -> Result<u32, Error> {
        let txn = self.env.read_txn()?;
        let (last_index, _) = self
            .index_to_address
            .last(&txn)?
            .unwrap_or(([0; 4], [0; 20].into()));
        let last_index = BigEndian::read_u32(&last_index);
        Ok(last_index)
    }
}