use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    path::Path,
};

use bip300301::bitcoin;
use byteorder::{BigEndian, ByteOrder};
use ed25519_dalek_bip32::{ChildIndex, DerivationPath, ExtendedSigningKey};
use heed::{
    types::{OwnedType, SerdeBincode, Str},
    Database, RoTxn,
};

use crate::{
    authorization::{get_address, Authorization},
    types::{
        hashes::BitName, Address, AuthorizedTransaction, BitNameData,
        FilledOutput, GetValue, Hash, InPoint, OutPoint, Output, OutputContent,
        SpentOutput, Transaction, TxData,
    },
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
    #[error("could not find bitname reservation for `{plain_name}`")]
    NoBitnameReservation { plain_name: String },
    #[error("not enough funds")]
    NotEnoughFunds,
    #[error("utxo doesn't exist")]
    NoUtxo,
    #[error("failed to parse mnemonic seed phrase")]
    ParseMnemonic(#[source] anyhow::Error),
    #[error("seed has already been set")]
    SeedAlreadyExists,
}

#[derive(Clone)]
pub struct Wallet {
    env: heed::Env,
    // FIXME: Don't store the seed in plaintext.
    seed: Database<OwnedType<u8>, OwnedType<[u8; 64]>>,
    pub address_to_index: Database<SerdeBincode<Address>, OwnedType<[u8; 4]>>,
    pub index_to_address: Database<OwnedType<[u8; 4]>, SerdeBincode<Address>>,
    pub utxos: Database<SerdeBincode<OutPoint>, SerdeBincode<FilledOutput>>,
    pub stxos: Database<SerdeBincode<OutPoint>, SerdeBincode<SpentOutput>>,
    /// associates reservation commitments with plaintext bitnames
    pub bitname_reservations: Database<OwnedType<[u8; 32]>, Str>,
    /// associates bitnames with plaintext names
    pub known_bitnames: Database<SerdeBincode<BitName>, Str>,
}

impl Wallet {
    pub const NUM_DBS: u32 = 7;

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
        let stxos = env.create_database(Some("stxos"))?;
        let bitname_reservations =
            env.create_database(Some("bitname_reservations"))?;
        let known_bitnames = env.create_database(Some("known_bitnames"))?;
        Ok(Self {
            env,
            seed: seed_db,
            address_to_index,
            index_to_address,
            utxos,
            stxos,
            bitname_reservations,
            known_bitnames,
        })
    }

    fn get_signing_key(
        &self,
        txn: &RoTxn,
        index: u32,
    ) -> Result<ed25519_dalek::SigningKey, Error> {
        let seed = self.seed.get(txn, &0)?.ok_or(Error::NoSeed)?;
        let xpriv = ExtendedSigningKey::from_seed(&seed)?;
        let derivation_path = DerivationPath::new([
            ChildIndex::Hardened(1),
            ChildIndex::Hardened(0),
            ChildIndex::Hardened(0),
            ChildIndex::Hardened(index),
        ]);
        let xsigning_key = xpriv.derive(&derivation_path)?;
        Ok(xsigning_key.signing_key)
    }

    // get the signing key that corresponds to the provided address
    fn get_signing_key_for_addr(
        &self,
        rotxn: &RoTxn,
        address: &Address,
    ) -> Result<ed25519_dalek::SigningKey, Error> {
        let addr_idx = self
            .address_to_index
            .get(rotxn, address)?
            .ok_or(Error::AddressDoesNotExist { address: *address })?;
        let signing_key =
            self.get_signing_key(rotxn, u32::from_be_bytes(addr_idx))?;
        // sanity check that signing key corresponds to address
        assert_eq!(*address, get_address(&signing_key.verifying_key()));
        Ok(signing_key)
    }

    pub fn get_new_address(&self) -> Result<Address, Error> {
        let mut txn = self.env.write_txn()?;
        let (last_index, _) = self
            .index_to_address
            .last(&txn)?
            .unwrap_or(([0; 4], [0; 20].into()));
        let last_index = BigEndian::read_u32(&last_index);
        let index = last_index + 1;
        let signing_key = self.get_signing_key(&txn, index)?;
        let address = get_address(&signing_key.verifying_key());
        let index = index.to_be_bytes();
        self.index_to_address.put(&mut txn, &index, &address)?;
        self.address_to_index.put(&mut txn, &address, &index)?;
        txn.commit()?;
        Ok(address)
    }

    /// Overwrite the seed, or set it if it does not already exist.
    pub fn overwrite_seed(&self, seed: &[u8; 64]) -> Result<(), Error> {
        let mut txn = self.env.write_txn()?;
        self.seed.put(&mut txn, &0, seed)?;
        self.address_to_index.clear(&mut txn)?;
        self.index_to_address.clear(&mut txn)?;
        self.utxos.clear(&mut txn)?;
        self.stxos.clear(&mut txn)?;
        self.bitname_reservations.clear(&mut txn)?;
        txn.commit()?;
        Ok(())
    }

    /// Set the seed, if it does not already exist
    pub fn set_seed(&self, seed: &[u8; 64]) -> Result<(), Error> {
        if self.has_seed()? {
            Err(Error::SeedAlreadyExists)
        } else {
            self.overwrite_seed(seed)
        }
    }

    /// Set the seed from a mnemonic seed phrase,
    /// if the seed does not already exist
    pub fn set_seed_from_mnemonic(&self, mnemonic: &str) -> Result<(), Error> {
        let mnemonic =
            bip39::Mnemonic::from_phrase(mnemonic, bip39::Language::English)
                .map_err(Error::ParseMnemonic)?;
        let seed = bip39::Seed::new(&mnemonic, "");
        let seed_bytes: [u8; 64] = seed.as_bytes().try_into().unwrap();
        self.set_seed(&seed_bytes)
    }

    pub fn has_seed(&self) -> Result<bool, Error> {
        let txn = self.env.read_txn()?;
        Ok(self.seed.get(&txn, &0)?.is_some())
    }

    /// Create a transaction with a fee only.
    pub fn create_regular_transaction(
        &self,
        fee: u64,
    ) -> Result<Transaction, Error> {
        let (total, coins) = self.select_coins(fee)?;
        let change = total - fee;
        let inputs = coins.into_keys().collect();
        let outputs = vec![Output::new(
            self.get_new_address()?,
            OutputContent::Value(change),
        )];
        Ok(Transaction::new(inputs, outputs))
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

    pub fn create_transfer(
        &self,
        address: Address,
        value: u64,
        fee: u64,
        memo: Option<Vec<u8>>,
    ) -> Result<Transaction, Error> {
        let (total, coins) = self.select_coins(value + fee)?;
        let change = total - value - fee;
        let inputs = coins.into_keys().collect();
        let outputs = vec![
            Output {
                address,
                content: OutputContent::Value(value),
                memo: memo.unwrap_or_default(),
            },
            Output::new(self.get_new_address()?, OutputContent::Value(change)),
        ];
        Ok(Transaction::new(inputs, outputs))
    }

    /// given a regular transaction, add a bitname reservation.
    /// given a bitname reservation tx, change the reserved name.
    /// panics if the tx is not regular or a bitname reservation tx.
    pub fn reserve_bitname(
        &self,
        tx: &mut Transaction,
        plain_name: &str,
    ) -> Result<(), Error> {
        assert!(
            tx.is_regular() || tx.is_reservation(),
            "this function only accepts a regular or bitname reservation tx"
        );
        // address for the reservation output
        let reservation_addr =
            // if the tx is already bitname reservation,
            // re-use the reservation address
            if tx.is_reservation() {
                tx.reservation_outputs().next_back()
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
        let reservation_signing_key =
            self.get_signing_key_for_addr(&rotxn, &reservation_addr)?;
        let name_hash: Hash = blake3::hash(plain_name.as_bytes()).into();
        let bitname = BitName(name_hash);
        // hmac(secret, name_hash)
        let nonce =
            blake3::keyed_hash(reservation_signing_key.as_bytes(), &name_hash)
                .into();
        // hmac(nonce, name_hash)
        let commitment = blake3::keyed_hash(&nonce, &name_hash).into();
        // store reservation data
        let mut rwtxn = self.env.write_txn()?;
        self.bitname_reservations
            .put(&mut rwtxn, &commitment, plain_name)?;
        self.known_bitnames.put(&mut rwtxn, &bitname, plain_name)?;
        rwtxn.commit()?;
        // if the tx is regular, add a reservation output
        if tx.is_regular() {
            let reservation_output = Output::new(
                reservation_addr,
                OutputContent::BitNameReservation,
            );
            tx.outputs.push(reservation_output);
        };
        tx.data = Some(TxData::BitNameReservation { commitment });
        Ok(())
    }

    /// given a regular transaction, add a bitname registration.
    /// panics if the tx is not regular.
    /// returns an error if there is no corresponding reservation utxo
    /// does not modify the tx if there is no corresponding reservation utxo.
    pub fn register_bitname(
        &self,
        tx: &mut Transaction,
        plain_name: &str,
        bitname_data: Cow<BitNameData>,
    ) -> Result<(), Error> {
        assert!(tx.is_regular(), "this function only accepts a regular tx");
        // address for the registration output
        let registration_addr =
            // if the last output is owned by this wallet, then use
            // the address associated with the last output
            if let Some(last_output) = tx.outputs.last() {
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
        let name_hash: Hash = blake3::hash(plain_name.as_bytes()).into();
        let bitname = BitName(name_hash);
        /* Search for reservation utxo by the following procedure:
        For each reservation:
        * Get the corresponding signing key
        * Compute a reservation commitment for the bitname to be registered
        * If the computed commitment is the same as the reservation commitment,
          then use this utxo. Otherwise, continue */
        // outpoint and nonce, if found
        let mut reservation_outpoint_nonce: Option<(OutPoint, Hash)> = None;
        for (outpoint, filled_output) in self.get_utxos()?.into_iter() {
            if let Some(reservation_commitment) =
                filled_output.reservation_commitment()
            {
                // for each reservation, get the signing key, and
                let reservation_addr = filled_output.address;
                let rotxn = self.env.read_txn()?;
                let reservation_signing_key =
                    self.get_signing_key_for_addr(&rotxn, &reservation_addr)?;
                // hmac(secret, name_hash)
                let nonce = blake3::keyed_hash(
                    reservation_signing_key.as_bytes(),
                    &name_hash,
                )
                .into();
                // hmac(nonce, name_hash)
                let commitment = blake3::keyed_hash(&nonce, &name_hash);
                // WARNING: This comparison MUST be done in constant time.
                // `blake3::Hash` handles this; DO NOT compare as byte arrays
                if commitment == *reservation_commitment {
                    reservation_outpoint_nonce = Some((outpoint, nonce));
                    break;
                }
            }
        }
        // store bitname data
        let mut rwtxn = self.env.write_txn()?;
        self.known_bitnames.put(&mut rwtxn, &bitname, plain_name)?;
        rwtxn.commit()?;
        let (reservation_outpoint, nonce) = reservation_outpoint_nonce
            .ok_or_else(|| Error::NoBitnameReservation {
                plain_name: plain_name.to_owned(),
            })?;
        let registration_output =
            Output::new(registration_addr, OutputContent::BitName);
        tx.inputs.push(reservation_outpoint);
        tx.outputs.push(registration_output);
        tx.data = Some(TxData::BitNameRegistration {
            name_hash: bitname,
            revealed_nonce: nonce,
            bitname_data: Box::new(bitname_data.into_owned()),
        });
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
            if output.content.is_withdrawal()
                || output.is_bitname()
                || output.is_reservation()
                || output.get_value() == 0
            {
                continue;
            }
            if total >= value {
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

    pub fn spend_utxos(
        &self,
        spent: &[(OutPoint, InPoint)],
    ) -> Result<(), Error> {
        let mut txn = self.env.write_txn()?;
        for (outpoint, inpoint) in spent {
            let output = self.utxos.get(&txn, outpoint)?;
            if let Some(output) = output {
                self.utxos.delete(&mut txn, outpoint)?;
                let spent_output = SpentOutput {
                    output,
                    inpoint: *inpoint,
                };
                self.stxos.put(&mut txn, outpoint, &spent_output)?;
            }
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

    /// gets the plaintext name associated with a bitname reservation
    /// commitment, if it is known by the wallet.
    pub fn get_bitname_reservation_plaintext(
        &self,
        commitment: &Hash,
    ) -> Result<Option<String>, Error> {
        let txn = self.env.read_txn()?;
        let res = self.bitname_reservations.get(&txn, commitment)?;
        Ok(res.map(String::from))
    }

    /// gets the plaintext name associated with a bitname,
    /// if it is known by the wallet.
    pub fn get_bitname_plaintext(
        &self,
        bitname: &BitName,
    ) -> Result<Option<String>, Error> {
        let txn = self.env.read_txn()?;
        let res = self.known_bitnames.get(&txn, bitname)?;
        Ok(res.map(String::from))
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

    pub fn get_stxos(&self) -> Result<HashMap<OutPoint, SpentOutput>, Error> {
        let txn = self.env.read_txn()?;
        let mut stxos = HashMap::new();
        for item in self.stxos.iter(&txn)? {
            let (outpoint, spent_output) = item?;
            stxos.insert(outpoint, spent_output);
        }
        Ok(stxos)
    }

    /// get all owned bitname utxos
    pub fn get_bitnames(
        &self,
    ) -> Result<HashMap<OutPoint, FilledOutput>, Error> {
        let mut utxos = self.get_utxos()?;
        utxos.retain(|_, output| output.is_bitname());
        Ok(utxos)
    }

    /// get all spent bitname utxos
    pub fn get_spent_bitnames(
        &self,
    ) -> Result<HashMap<OutPoint, SpentOutput>, Error> {
        let mut stxos = self.get_stxos()?;
        stxos.retain(|_, output| output.output.is_bitname());
        Ok(stxos)
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
            let signing_key = self.get_signing_key(&txn, index)?;
            let signature =
                crate::authorization::sign(&signing_key, &transaction)?;
            authorizations.push(Authorization {
                verifying_key: signing_key.verifying_key(),
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
