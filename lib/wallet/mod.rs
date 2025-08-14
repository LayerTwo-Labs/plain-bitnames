use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    path::Path,
};

use bitcoin::Amount;
use borsh::{BorshDeserialize, BorshSerialize};
use ed25519_bip32::XPrv;
use fallible_iterator::FallibleIterator as _;
use futures::{Stream, StreamExt};
use heed::{
    byteorder::BigEndian,
    types::{Bytes, SerdeBincode, Str, U8, U32},
};
use serde::{Deserialize, Serialize};
use sneed::{DbError, Env, UnitKey};
use tokio_stream::{StreamMap, wrappers::WatchStream};

use crate::{
    authorization::{self, Authorization, Signature, get_address},
    types::{
        Address, AmountOverflowError, AuthorizedTransaction,
        BitcoinOutputContent, EncryptionPubKey, FilledOutput, GetValue, Hash,
        InPoint, MutableBitNameData, OutPoint, Output, OutputContent,
        SpentOutput, Transaction, TxData, VERSION, VerifyingKey, Version,
        WithdrawalOutputContent,
        hashes::BitName,
        keys::{Bip32ChainCode, Ecies},
    },
    util::Watchable,
    wallet::util::KnownBip32Path,
};

pub mod error;
pub mod sign_in_with_bitnames;
mod util;

pub use error::Error;

#[derive(Clone, Debug, Default, Deserialize, Serialize, utoipa::ToSchema)]
pub struct Balance {
    #[serde(rename = "total_sats", with = "bitcoin::amount::serde::as_sat")]
    #[schema(value_type = u64)]
    pub total: Amount,
    #[serde(
        rename = "available_sats",
        with = "bitcoin::amount::serde::as_sat"
    )]
    #[schema(value_type = u64)]
    pub available: Amount,
}

/// Marker type for Wallet Env
struct WalletEnv;

type DatabaseUnique<KC, DC> = sneed::DatabaseUnique<KC, DC, WalletEnv>;
type RoTxn<'a> = sneed::RoTxn<'a, WalletEnv>;

#[derive(Clone)]
pub struct Wallet {
    env: sneed::Env<WalletEnv>,
    // Seed is always [u8; 64], but due to serde not implementing serialize
    // for [T; 64], use heed's `Bytes`
    // TODO: Don't store the seed in plaintext.
    seed: DatabaseUnique<U8, Bytes>,
    /// Map each address to it's index
    address_to_index: DatabaseUnique<SerdeBincode<Address>, U32<BigEndian>>,
    /// Map each encryption pubkey to it's index
    epk_to_index:
        DatabaseUnique<SerdeBincode<EncryptionPubKey>, U32<BigEndian>>,
    /// Map each address index to an address
    index_to_address: DatabaseUnique<U32<BigEndian>, SerdeBincode<Address>>,
    /// Map each encryption key index to an encryption pubkey
    index_to_epk:
        DatabaseUnique<U32<BigEndian>, SerdeBincode<EncryptionPubKey>>,
    /// Map each signing key index to a verifying key
    index_to_vk: DatabaseUnique<U32<BigEndian>, SerdeBincode<VerifyingKey>>,
    utxos: DatabaseUnique<SerdeBincode<OutPoint>, SerdeBincode<FilledOutput>>,
    stxos: DatabaseUnique<SerdeBincode<OutPoint>, SerdeBincode<SpentOutput>>,
    /// Associates reservation commitments with plaintext BitNames
    bitname_reservations: DatabaseUnique<SerdeBincode<[u8; 32]>, Str>,
    /// Associates BitNames with plaintext names
    known_bitnames: DatabaseUnique<SerdeBincode<BitName>, Str>,
    /// Map each verifying key to it's index
    vk_to_index: DatabaseUnique<SerdeBincode<VerifyingKey>, U32<BigEndian>>,
    _version: DatabaseUnique<UnitKey, SerdeBincode<Version>>,
}

impl Wallet {
    pub const NUM_DBS: u32 = 12;

    pub fn new(path: &Path) -> Result<Self, Error> {
        std::fs::create_dir_all(path)?;
        let env = {
            let mut env_open_options = heed::EnvOpenOptions::new();
            env_open_options
                .map_size(10 * 1024 * 1024) // 10MB
                .max_dbs(Self::NUM_DBS);
            unsafe { Env::open(&env_open_options, path) }?
        };
        let mut rwtxn = env.write_txn()?;
        let seed_db = DatabaseUnique::create(&env, &mut rwtxn, "seed")?;
        let address_to_index =
            DatabaseUnique::create(&env, &mut rwtxn, "address_to_index")?;
        let epk_to_index =
            DatabaseUnique::create(&env, &mut rwtxn, "epk_to_index")?;
        let index_to_address =
            DatabaseUnique::create(&env, &mut rwtxn, "index_to_address")?;
        let index_to_epk =
            DatabaseUnique::create(&env, &mut rwtxn, "index_to_epk")?;
        let index_to_vk =
            DatabaseUnique::create(&env, &mut rwtxn, "index_to_vk")?;
        let utxos = DatabaseUnique::create(&env, &mut rwtxn, "utxos")?;
        let stxos = DatabaseUnique::create(&env, &mut rwtxn, "stxos")?;
        let bitname_reservations =
            DatabaseUnique::create(&env, &mut rwtxn, "bitname_reservations")?;
        let known_bitnames =
            DatabaseUnique::create(&env, &mut rwtxn, "known_bitnames")?;
        let vk_to_index =
            DatabaseUnique::create(&env, &mut rwtxn, "vk_to_index")?;
        let version = DatabaseUnique::create(&env, &mut rwtxn, "version")?;
        if version.try_get(&rwtxn, &())?.is_none() {
            version.put(&mut rwtxn, &(), &*VERSION)?;
        }
        rwtxn.commit()?;
        Ok(Self {
            env,
            seed: seed_db,
            address_to_index,
            epk_to_index,
            index_to_address,
            index_to_epk,
            index_to_vk,
            utxos,
            stxos,
            bitname_reservations,
            known_bitnames,
            vk_to_index,
            _version: version,
        })
    }

    // Adapted from https://input-output-hk.github.io/adrestia/static/Ed25519_BIP.pdf
    fn get_master_xprv(
        &self,
        rotxn: &RoTxn,
    ) -> Result<XPrv, error::GetMasterXprv> {
        use bitcoin::hashes::{Hash as _, HashEngine as _, sha256};
        let seed_bytes = self.seed.try_get(rotxn, &0)?.ok_or(error::NoSeed)?;
        // Master secret must be 256 bits, see
        // https://input-output-hk.github.io/adrestia/static/Ed25519_BIP.pdf
        let mut master_secret: [u8; 32] =
            sha256::Hash::hash(seed_bytes).to_byte_array();
        // If master secret generates a valid extended secret, return it
        // Otherwise, hash and try again.
        // Each iteration of the loop has a 50% chance of success
        loop {
            // Derived as described in
            // https://input-output-hk.github.io/adrestia/static/Ed25519_BIP.pdf
            let root_chain_code: [u8; 32] = {
                let mut hasher = sha256::HashEngine::default();
                hasher.input(&[0x01]);
                hasher.input(&master_secret);
                assert_eq!(hasher.n_bytes_hashed(), 33);
                sha256::Hash::from_engine(hasher).to_byte_array()
            };
            if let Ok(res) =
                XPrv::from_nonextended_noforce(&master_secret, &root_chain_code)
            {
                return Ok(res);
            } else {
                master_secret =
                    sha256::Hash::hash(&master_secret).to_byte_array();
            }
        }
    }

    fn get_epk_index(
        &self,
        rotxn: &RoTxn,
        epk: &EncryptionPubKey,
    ) -> Result<u32, error::GetEpkIndex> {
        let epk_idx = self
            .epk_to_index
            .try_get(rotxn, epk)?
            .ok_or(error::EpkDoesNotExist { epk: *epk })?;
        Ok(epk_idx)
    }

    fn get_encryption_xprv(
        &self,
        rotxn: &RoTxn,
        index: u32,
    ) -> Result<ed25519_bip32::XPrv, error::GetMasterXprv> {
        let master_xprv = self.get_master_xprv(rotxn)?;
        let derivation_path = KnownBip32Path::Encryption { index }.into();
        let xprv = util::derive_xprv(master_xprv, &derivation_path);
        Ok(xprv)
    }

    fn get_encryption_secret(
        &self,
        rotxn: &RoTxn,
        index: u32,
    ) -> Result<x25519_dalek::StaticSecret, error::GetMasterXprv> {
        let xprv = self.get_encryption_xprv(rotxn, index)?;
        // This is safe since the signing scalar is already clamped
        let (secret_bytes, _): (&[u8; 32], _) = xprv
            .extended_secret_key_bytes()
            .split_first_chunk()
            .unwrap();
        Ok((*secret_bytes).into())
    }

    /// Get the xprv that corresponds to the provided encryption pubkey
    fn get_encryption_xprv_for_epk(
        &self,
        rotxn: &RoTxn,
        epk: &EncryptionPubKey,
    ) -> Result<ed25519_bip32::XPrv, error::GetEncryptionXprvForEpk> {
        let epk_idx = self.get_epk_index(rotxn, epk)?;
        let xprv = self.get_encryption_xprv(rotxn, epk_idx)?;
        // sanity check that encryption secret corresponds to epk
        {
            let (secret_bytes, _): (&[u8; 32], _) = xprv
                .extended_secret_key_bytes()
                .split_first_chunk()
                .unwrap();
            let encryption_secret =
                x25519_dalek::StaticSecret::from(*secret_bytes);
            assert_eq!(*epk, (&encryption_secret).into());
        }
        Ok(xprv)
    }

    /// Get the tx signing key that corresponds to the provided encryption
    /// pubkey
    fn get_encryption_secret_for_epk(
        &self,
        rotxn: &RoTxn,
        epk: &EncryptionPubKey,
    ) -> Result<x25519_dalek::StaticSecret, error::GetEncryptionXprvForEpk>
    {
        let epk_idx = self.get_epk_index(rotxn, epk)?;
        let encryption_secret = self.get_encryption_secret(rotxn, epk_idx)?;
        // sanity check that encryption secret corresponds to epk
        assert_eq!(*epk, (&encryption_secret).into());
        Ok(encryption_secret)
    }

    fn get_tx_signing_key(
        &self,
        rotxn: &RoTxn,
        index: u32,
    ) -> Result<ed25519_dalek::hazmat::ExpandedSecretKey, error::GetMasterXprv>
    {
        let master_xprv = self.get_master_xprv(rotxn)?;
        let derivation_path = KnownBip32Path::TxSigning { index }.into();
        let xpriv = util::derive_xprv(master_xprv, &derivation_path);
        let esk_bytes = xpriv.extended_secret_key_bytes();
        Ok(ed25519_dalek::hazmat::ExpandedSecretKey::from_bytes(
            esk_bytes,
        ))
    }

    /// Get the tx signing key that corresponds to the provided address
    fn get_tx_signing_key_for_addr(
        &self,
        rotxn: &RoTxn,
        address: &Address,
    ) -> Result<ed25519_dalek::hazmat::ExpandedSecretKey, Error> {
        let addr_idx = self
            .address_to_index
            .try_get(rotxn, address)?
            .ok_or(Error::AddressDoesNotExist { address: *address })?;
        let signing_key = self.get_tx_signing_key(rotxn, addr_idx)?;
        // sanity check that signing key corresponds to address
        {
            let vk = ed25519_dalek::VerifyingKey::from(&signing_key);
            assert_eq!(*address, get_address(&vk.into()));
        }
        Ok(signing_key)
    }

    fn get_message_signing_key(
        &self,
        rotxn: &RoTxn,
        index: u32,
    ) -> Result<ed25519_dalek::hazmat::ExpandedSecretKey, error::GetMasterXprv>
    {
        let master_xprv = self.get_master_xprv(rotxn)?;
        let derivation_path = KnownBip32Path::MessageSigning { index }.into();
        let xpriv = util::derive_xprv(master_xprv, &derivation_path);
        let esk_bytes = xpriv.extended_secret_key_bytes();
        Ok(ed25519_dalek::hazmat::ExpandedSecretKey::from_bytes(
            esk_bytes,
        ))
    }

    /// Get the tx signing key that corresponds to the provided verifying key,
    /// if it exists
    fn try_get_message_signing_key_for_vk(
        &self,
        rotxn: &RoTxn,
        vk: &VerifyingKey,
    ) -> Result<Option<ed25519_dalek::hazmat::ExpandedSecretKey>, Error> {
        let Some(vk_idx) = self.vk_to_index.try_get(rotxn, vk)? else {
            return Ok(None);
        };
        let signing_key = self.get_message_signing_key(rotxn, vk_idx)?;
        // sanity check that signing key corresponds to vk
        {
            assert_eq!(
                *vk,
                ed25519_dalek::VerifyingKey::from(&signing_key).into()
            );
        }
        Ok(Some(signing_key))
    }

    /// Get the tx signing key that corresponds to the provided verifying key
    fn get_message_signing_key_for_vk(
        &self,
        rotxn: &RoTxn,
        vk: &VerifyingKey,
    ) -> Result<ed25519_dalek::hazmat::ExpandedSecretKey, Error> {
        self.try_get_message_signing_key_for_vk(rotxn, vk)?
            .ok_or_else(|| error::VkDoesNotExist { vk: *vk }.into())
    }

    /// Get the SIWB auth xprv for a given BitName, service BitName, and nonce
    fn get_siwb_auth_xprv(
        &self,
        rotxn: &RoTxn,
        bitname: BitName,
        service_bitname: BitName,
        nonce: u64,
    ) -> Result<XPrv, error::GetMasterXprv> {
        let master_xprv = self.get_master_xprv(rotxn)?;
        let derivation_path = KnownBip32Path::SiwbAuthentication {
            bitname,
            service_bitname,
            nonce,
        }
        .into();
        let xprv = util::derive_xprv(master_xprv, &derivation_path);
        Ok(xprv)
    }

    pub fn get_new_address(&self) -> Result<Address, Error> {
        let mut txn = self.env.write_txn()?;
        let next_index = self
            .index_to_address
            .last(&txn)?
            .map(|(idx, _)| idx + 1)
            .unwrap_or(0);
        let tx_signing_key = self.get_tx_signing_key(&txn, next_index)?;
        let vk = ed25519_dalek::VerifyingKey::from(&tx_signing_key);
        let address = get_address(&vk.into());
        self.index_to_address.put(&mut txn, &next_index, &address)?;
        self.address_to_index.put(&mut txn, &address, &next_index)?;
        txn.commit()?;
        Ok(address)
    }

    pub fn get_new_encryption_key(&self) -> Result<EncryptionPubKey, Error> {
        let mut txn = self.env.write_txn()?;
        let next_index = self
            .index_to_epk
            .last(&txn)?
            .map(|(idx, _)| idx + 1)
            .unwrap_or(0);
        let encryption_secret = self.get_encryption_secret(&txn, next_index)?;
        let epk = (&encryption_secret).into();
        self.index_to_epk.put(&mut txn, &next_index, &epk)?;
        self.epk_to_index.put(&mut txn, &epk, &next_index)?;
        txn.commit()?;
        Ok(epk)
    }

    /// Get a new message verifying key
    pub fn get_new_verifying_key(&self) -> Result<VerifyingKey, Error> {
        let mut txn = self.env.write_txn()?;
        let next_index = self
            .index_to_vk
            .last(&txn)?
            .map(|(idx, _)| idx + 1)
            .unwrap_or(0);
        let signing_key = self.get_message_signing_key(&txn, next_index)?;
        let vk = ed25519_dalek::VerifyingKey::from(&signing_key).into();
        self.index_to_vk.put(&mut txn, &next_index, &vk)?;
        self.vk_to_index.put(&mut txn, &vk, &next_index)?;
        txn.commit()?;
        Ok(vk)
    }

    /// Overwrite the seed, or set it if it does not already exist.
    pub fn overwrite_seed(&self, seed: &[u8; 64]) -> Result<(), Error> {
        let mut rwtxn = self.env.write_txn()?;
        self.seed.put(&mut rwtxn, &0, seed)?;
        self.address_to_index.clear(&mut rwtxn)?;
        self.index_to_address.clear(&mut rwtxn)?;
        self.utxos.clear(&mut rwtxn)?;
        self.stxos.clear(&mut rwtxn)?;
        self.bitname_reservations.clear(&mut rwtxn)?;
        rwtxn.commit()?;
        Ok(())
    }

    pub fn has_seed(&self) -> Result<bool, Error> {
        let rotxn = self.env.read_txn()?;
        Ok(self
            .seed
            .try_get(&rotxn, &0)
            .map_err(DbError::from)?
            .is_some())
    }

    /// Set the seed, if it does not already exist
    pub fn set_seed(&self, seed: &[u8; 64]) -> Result<(), Error> {
        let rotxn = self.env.read_txn()?;
        match self.seed.try_get(&rotxn, &0).map_err(DbError::from)? {
            Some(current_seed) => {
                if current_seed == seed {
                    Ok(())
                } else {
                    Err(Error::SeedAlreadyExists)
                }
            }
            None => {
                drop(rotxn);
                self.overwrite_seed(seed)
            }
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

    pub fn decrypt_msg(
        &self,
        encryption_pubkey: &EncryptionPubKey,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let rotxn = self.env.read_txn()?;
        let encryption_secret =
            self.get_encryption_secret_for_epk(&rotxn, encryption_pubkey)?;
        let res = Ecies::decrypt(&encryption_secret, ciphertext)
            .map_err(Error::Ecies)?;
        Ok(res)
    }

    /// Create a transaction with a fee only.
    pub fn create_regular_transaction(
        &self,
        fee: bitcoin::Amount,
    ) -> Result<Transaction, Error> {
        let (total, coins) = self.select_coins(fee)?;
        let change = total - fee;
        let inputs = coins.into_keys().collect();
        let outputs = vec![Output::new(
            self.get_new_address()?,
            OutputContent::Bitcoin(BitcoinOutputContent(change)),
        )];
        Ok(Transaction::new(inputs, outputs))
    }

    pub fn create_withdrawal(
        &self,
        main_address: bitcoin::Address<bitcoin::address::NetworkUnchecked>,
        value: bitcoin::Amount,
        main_fee: bitcoin::Amount,
        fee: bitcoin::Amount,
    ) -> Result<Transaction, Error> {
        tracing::trace!(
            fee = %fee.display_dynamic(),
            ?main_address,
            main_fee = %main_fee.display_dynamic(),
            value = %value.display_dynamic(),
            "Creating withdrawal"
        );
        let (total, coins) = self.select_coins(
            value
                .checked_add(fee)
                .ok_or(AmountOverflowError)?
                .checked_add(main_fee)
                .ok_or(AmountOverflowError)?,
        )?;
        let change = total - value - fee;
        let inputs = coins.into_keys().collect();
        let outputs = vec![
            Output::new(
                self.get_new_address()?,
                OutputContent::Withdrawal(WithdrawalOutputContent {
                    value,
                    main_fee,
                    main_address,
                }),
            ),
            Output::new(
                self.get_new_address()?,
                OutputContent::Bitcoin(BitcoinOutputContent(change)),
            ),
        ];
        Ok(Transaction::new(inputs, outputs))
    }

    pub fn create_transfer(
        &self,
        address: Address,
        value: bitcoin::Amount,
        fee: bitcoin::Amount,
        memo: Option<Vec<u8>>,
    ) -> Result<Transaction, Error> {
        let (total, coins) = self
            .select_coins(value.checked_add(fee).ok_or(AmountOverflowError)?)?;
        let change = total - value - fee;
        let inputs = coins.into_keys().collect();
        let mut outputs = vec![Output {
            address,
            content: OutputContent::Bitcoin(BitcoinOutputContent(value)),
            memo: memo.unwrap_or_default(),
        }];
        if change != Amount::ZERO {
            outputs.push(Output::new(
                self.get_new_address()?,
                OutputContent::Bitcoin(BitcoinOutputContent(change)),
            ))
        }
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
                if self.address_to_index.try_get(&rotxn, &last_output_addr)?.is_some() {
                    last_output_addr
                } else {
                    self.get_new_address()?
                }
            } else {
                self.get_new_address()?
            };
        let rotxn = self.env.read_txn()?;
        let reservation_signing_key =
            self.get_tx_signing_key_for_addr(&rotxn, &reservation_addr)?;
        let name_hash: Hash = blake3::hash(plain_name.as_bytes()).into();
        let bitname = BitName(name_hash);
        let reservation_hmac_key =
            blake3::hash(reservation_signing_key.scalar.as_bytes()).into();
        let nonce =
            blake3::keyed_hash(&reservation_hmac_key, &name_hash).into();
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
        bitname_data: Cow<MutableBitNameData>,
    ) -> Result<(), Error> {
        assert!(tx.is_regular(), "this function only accepts a regular tx");
        // address for the registration output
        let registration_addr =
            // if the last output is owned by this wallet, then use
            // the address associated with the last output
            if let Some(last_output) = tx.outputs.last() {
                let last_output_addr = last_output.address;
                let rotxn = self.env.read_txn()?;
                if self.address_to_index.try_get(&rotxn, &last_output_addr)?.is_some() {
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
                let reservation_signing_key = self
                    .get_tx_signing_key_for_addr(&rotxn, &reservation_addr)?;
                let reservation_hmac_key =
                    blake3::hash(reservation_signing_key.scalar.as_bytes())
                        .into();
                let nonce =
                    blake3::keyed_hash(&reservation_hmac_key, &name_hash)
                        .into();
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
        value: bitcoin::Amount,
    ) -> Result<(bitcoin::Amount, HashMap<OutPoint, FilledOutput>), Error> {
        let rotxn = self.env.read_txn()?;
        let mut utxos: Vec<_> = self.utxos.iter(&rotxn)?.collect()?;
        utxos.sort_unstable_by_key(|(_, output)| output.get_value());

        let mut selected = HashMap::new();
        let mut total = bitcoin::Amount::ZERO;
        for (outpoint, output) in &utxos {
            if output.content.is_withdrawal()
                || output.is_bitname()
                || output.is_reservation()
                || output.get_value() == bitcoin::Amount::ZERO
            {
                continue;
            }
            if total >= value {
                break;
            }
            total = total
                .checked_add(output.get_value())
                .ok_or(AmountOverflowError)?;
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
        let mut rwtxn = self.env.write_txn()?;
        for (outpoint, inpoint) in spent {
            if let Some(output) = self
                .utxos
                .try_get(&rwtxn, outpoint)
                .map_err(DbError::from)?
            {
                self.utxos.delete(&mut rwtxn, outpoint)?;
                let spent_output = SpentOutput {
                    output,
                    inpoint: *inpoint,
                };
                self.stxos.put(&mut rwtxn, outpoint, &spent_output)?;
            }
        }
        rwtxn.commit()?;
        Ok(())
    }

    pub fn put_utxos(
        &self,
        utxos: &HashMap<OutPoint, FilledOutput>,
    ) -> Result<(), Error> {
        let mut rwtxn = self.env.write_txn()?;
        for (outpoint, output) in utxos {
            self.utxos
                .put(&mut rwtxn, outpoint, output)
                .map_err(DbError::from)?;
        }
        rwtxn.commit()?;
        Ok(())
    }

    pub fn get_balance(&self) -> Result<Balance, Error> {
        let mut balance = Balance::default();
        let rotxn = self.env.read_txn()?;
        let () = self
            .utxos
            .iter(&rotxn)
            .map_err(DbError::from)?
            .map_err(|err| DbError::from(err).into())
            .for_each(|(_, utxo)| {
                let value = utxo.get_value();
                balance.total = balance
                    .total
                    .checked_add(value)
                    .ok_or(AmountOverflowError)?;
                if !utxo.content.is_withdrawal() {
                    balance.available = balance
                        .available
                        .checked_add(value)
                        .ok_or(AmountOverflowError)?;
                }
                Ok::<_, Error>(())
            })?;
        Ok(balance)
    }

    /// gets the plaintext name associated with a bitname reservation
    /// commitment, if it is known by the wallet.
    pub fn get_bitname_reservation_plaintext(
        &self,
        commitment: &Hash,
    ) -> Result<Option<String>, Error> {
        let rotxn = self.env.read_txn()?;
        let res = self.bitname_reservations.try_get(&rotxn, commitment)?;
        Ok(res.map(String::from))
    }

    /// gets the plaintext name associated with a bitname,
    /// if it is known by the wallet.
    pub fn get_bitname_plaintext(
        &self,
        bitname: &BitName,
    ) -> Result<Option<String>, Error> {
        let rotxn = self.env.read_txn()?;
        let res = self.known_bitnames.try_get(&rotxn, bitname)?;
        Ok(res.map(String::from))
    }

    pub fn get_utxos(&self) -> Result<HashMap<OutPoint, FilledOutput>, Error> {
        let rotxn = self.env.read_txn()?;
        let utxos: HashMap<_, _> = self
            .utxos
            .iter(&rotxn)
            .map_err(DbError::from)?
            .collect()
            .map_err(DbError::from)?;
        Ok(utxos)
    }

    pub fn get_stxos(&self) -> Result<HashMap<OutPoint, SpentOutput>, Error> {
        let rotxn = self.env.read_txn()?;
        let stxos = self.stxos.iter(&rotxn)?.collect()?;
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
        let rotxn = self.env.read_txn()?;
        let addresses: HashSet<_> = self
            .index_to_address
            .iter(&rotxn)
            .map_err(DbError::from)?
            .map(|(_, address)| Ok(address))
            .collect()
            .map_err(DbError::from)?;
        Ok(addresses)
    }

    pub fn authorize(
        &self,
        transaction: Transaction,
    ) -> Result<AuthorizedTransaction, Error> {
        let rotxn = self.env.read_txn()?;
        let mut authorizations = vec![];
        for input in &transaction.inputs {
            let spent_utxo =
                self.utxos.try_get(&rotxn, input)?.ok_or(Error::NoUtxo)?;
            let index = self
                .address_to_index
                .try_get(&rotxn, &spent_utxo.address)
                .map_err(DbError::from)?
                .ok_or(Error::NoIndex {
                    address: spent_utxo.address,
                })?;
            let tx_signing_key = self.get_tx_signing_key(&rotxn, index)?;
            let signature = crate::authorization::sign_tx_esk(
                &tx_signing_key,
                &transaction,
            )?;
            let vk = ed25519_dalek::VerifyingKey::from(&tx_signing_key);
            authorizations.push(Authorization {
                verifying_key: vk.into(),
                signature,
            });
        }
        Ok(AuthorizedTransaction {
            authorizations,
            transaction,
        })
    }

    pub fn get_num_addresses(&self) -> Result<u32, Error> {
        let rotxn = self.env.read_txn()?;
        let res = self.index_to_address.len(&rotxn)? as u32;
        Ok(res)
    }

    pub fn sign_arbitrary_msg(
        &self,
        verifying_key: &VerifyingKey,
        msg: &str,
    ) -> Result<Signature, Error> {
        use authorization::{Dst, sign_esk};
        let rotxn = self.env.read_txn()?;
        let signing_key =
            self.get_message_signing_key_for_vk(&rotxn, verifying_key)?;
        let res = sign_esk(&signing_key, Dst::Arbitrary, msg.as_bytes());
        Ok(res)
    }

    pub fn sign_arbitrary_msg_as_addr(
        &self,
        address: &Address,
        msg: &str,
    ) -> Result<Authorization, Error> {
        use authorization::{Dst, sign_esk};
        let rotxn = self.env.read_txn()?;
        let signing_key = self.get_tx_signing_key_for_addr(&rotxn, address)?;
        let signature = sign_esk(&signing_key, Dst::Arbitrary, msg.as_bytes());
        let verifying_key =
            ed25519_dalek::VerifyingKey::from(&signing_key).into();
        Ok(Authorization {
            verifying_key,
            signature,
        })
    }

    pub fn siwb_authenticate_as<C, F, E, T>(
        &self,
        auth_as_epk: &EncryptionPubKey,
        service_bitname: BitName,
        nonce: u64,
        service_epk: EncryptionPubKey,
        challenge: &sign_in_with_bitnames::AuthenticationChallenge<C>,
        validate_challenge: F,
    ) -> Result<
        (sign_in_with_bitnames::AuthenticationResponse, T),
        error::SiwbAuthentication<E>,
    >
    where
        C: BorshDeserialize + BorshSerialize,
        E: std::error::Error,
        F: FnOnce(&C) -> Result<Option<T>, E>,
    {
        let rotxn = self.env.read_txn()?;
        let auth_as_encryption_xprv =
            self.get_encryption_xprv_for_epk(&rotxn, auth_as_epk)?;
        let siwb_authentication_xprv = self.get_siwb_auth_xprv(
            &rotxn,
            challenge.bitname,
            service_bitname,
            nonce,
        )?;
        let auth_response = sign_in_with_bitnames::authenticate(
            auth_as_encryption_xprv,
            siwb_authentication_xprv,
            service_bitname,
            service_epk,
            challenge,
            validate_challenge,
        )?;
        Ok(auth_response)
    }

    pub fn siwb_register_as(
        &self,
        register_as_bitname: BitName,
        register_as_epk: &EncryptionPubKey,
        service_bitname: BitName,
        nonce: u64,
        service_epk: &EncryptionPubKey,
    ) -> Result<sign_in_with_bitnames::Registration, error::SiwbRegistration>
    {
        let rotxn = self.env.read_txn()?;
        let register_as_encryption_xprv =
            self.get_encryption_xprv_for_epk(&rotxn, register_as_epk)?;
        let siwb_auth_xprv = self.get_siwb_auth_xprv(
            &rotxn,
            register_as_bitname,
            service_bitname,
            nonce,
        )?;
        let registration = sign_in_with_bitnames::register_as(
            register_as_bitname,
            register_as_encryption_xprv,
            siwb_auth_xprv,
            service_bitname,
            service_epk,
        )?;
        Ok(registration)
    }

    /// Verify a registration, obtaining an authentication pubkey if successful
    pub fn siwb_verify_registration(
        &self,
        service_bitname: BitName,
        service_epk: &EncryptionPubKey,
        register_as_epk: &EncryptionPubKey,
        register_as_epk_chain_code: &Bip32ChainCode,
        registration: sign_in_with_bitnames::Registration,
    ) -> Result<curve25519_dalek::RistrettoPoint, error::SiwbVerifyRegistration>
    {
        let rotxn = self.env.read_txn()?;
        let service_encryption_secret =
            self.get_encryption_secret_for_epk(&rotxn, service_epk)?;
        // Check that the EPK encodes a valid ed25519 point
        let register_as_epk_ed25519 =
            curve25519_dalek::MontgomeryPoint(register_as_epk.0.to_bytes())
                .to_edwards(0)
                .ok_or(error::SiwbVerifyRegistration::ConvertEpk)?
                .compress();
        let register_as_encryption_xpub =
            ed25519_bip32::XPub::from_pk_and_chaincode(
                register_as_epk_ed25519.as_bytes(),
                &register_as_epk_chain_code.0,
            );
        let auth_pubkey = registration.verify(
            register_as_encryption_xpub,
            service_bitname,
            service_encryption_secret,
        )?;
        Ok(auth_pubkey)
    }

    /// Verify an authentication, returning the new authentication pubkey
    #[allow(clippy::too_many_arguments)]
    pub fn siwb_verify_authentication<C>(
        &self,
        service_bitname: BitName,
        service_epk: &EncryptionPubKey,
        challenge: &sign_in_with_bitnames::AuthenticationChallenge<C>,
        registered_auth_pk: curve25519_dalek::RistrettoPoint,
        register_as_epk: &EncryptionPubKey,
        register_as_epk_chain_code: &Bip32ChainCode,
        registered_epk_old: &EncryptionPubKey,
        registered_epk_old_chain_code: &Bip32ChainCode,
        auth_response: sign_in_with_bitnames::AuthenticationResponse,
    ) -> Result<curve25519_dalek::RistrettoPoint, error::SiwbVerifyAuthentication>
    where
        C: BorshSerialize,
    {
        let rotxn = self.env.read_txn()?;
        let service_encryption_secret =
            self.get_encryption_secret_for_epk(&rotxn, service_epk)?;
        // Check that the EPK encodes a valid ed25519 point
        let register_as_epk_ed25519 =
            curve25519_dalek::MontgomeryPoint(register_as_epk.0.to_bytes())
                .to_edwards(0)
                .ok_or(error::SiwbVerifyAuthentication::ConvertEpk)?
                .compress();
        let register_as_encryption_xpub =
            ed25519_bip32::XPub::from_pk_and_chaincode(
                register_as_epk_ed25519.as_bytes(),
                &register_as_epk_chain_code.0,
            );
        // Check that the EPK encodes a valid ed25519 point
        let register_as_epk_old_ed25519 =
            curve25519_dalek::MontgomeryPoint(registered_epk_old.0.to_bytes())
                .to_edwards(0)
                .ok_or(error::SiwbVerifyAuthentication::ConvertEpk)?
                .compress();
        let register_as_encryption_xpub_old =
            ed25519_bip32::XPub::from_pk_and_chaincode(
                register_as_epk_old_ed25519.as_bytes(),
                &registered_epk_old_chain_code.0,
            );
        let new_auth_pk = auth_response.verify(
            register_as_encryption_xpub,
            register_as_encryption_xpub_old,
            registered_auth_pk,
            challenge,
            service_bitname,
            service_encryption_secret,
        )?;
        Ok(new_auth_pk)
    }
}

impl Watchable<()> for Wallet {
    type WatchStream = impl Stream<Item = ()>;

    /// Get a signal that notifies whenever the wallet changes
    fn watch(&self) -> Self::WatchStream {
        let Self {
            env: _,
            seed,
            address_to_index,
            epk_to_index,
            index_to_address,
            index_to_epk,
            index_to_vk,
            utxos,
            stxos,
            bitname_reservations,
            known_bitnames,
            vk_to_index,
            _version: _,
        } = self;
        let watchables = [
            seed.watch().clone(),
            address_to_index.watch().clone(),
            epk_to_index.watch().clone(),
            index_to_address.watch().clone(),
            index_to_epk.watch().clone(),
            index_to_vk.watch().clone(),
            utxos.watch().clone(),
            stxos.watch().clone(),
            bitname_reservations.watch().clone(),
            known_bitnames.watch().clone(),
            vk_to_index.watch().clone(),
        ];
        let streams = StreamMap::from_iter(
            watchables.into_iter().map(WatchStream::new).enumerate(),
        );
        let streams_len = streams.len();
        streams.ready_chunks(streams_len).map(|signals| {
            assert_ne!(signals.len(), 0);
            #[allow(clippy::unused_unit)]
            ()
        })
    }
}
