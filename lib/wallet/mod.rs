use std::{
    borrow::Cow,
    collections::{BTreeMap, HashMap, HashSet},
    path::Path,
};

use bip32ish::U31;
use bitcoin::Amount;
use fallible_iterator::FallibleIterator as _;
use futures::{Stream, StreamExt};
use heed::{
    EnvFlags,
    byteorder::BigEndian,
    types::{Bytes, SerdeBincode, Str, U8, U32},
};
use rayon::prelude::ParallelSliceMut;
use sneed::{DbError, Env, UnitKey};
use tokio_stream::{StreamMap, wrappers::WatchStream};

use crate::{
    types::{
        Address, AmountOverflowError, AuthorizedTransaction,
        BitcoinOutputContent, CoinbaseTxid, FilledOutput, GetValue, Hash,
        InPoint, MutableBitNameData, OutPoint, OutPointKey, Output,
        OutputContent, SpentOutput, THIS_SIDECHAIN, Transaction, TxData,
        VERSION, Version, WithdrawalOutputContent,
        authorization::{
            self, Authorization, Signature, SigningKey, VerifyingKey,
            get_address, rand_core::CryptoRng,
        },
        bitname_data::XPublicKey,
        ecies,
        hashes::BitName,
        keys::{PublicKey, SecretKey},
        transaction::outpoint::{COINBASE_MATURITY, DEPOSIT_MATURITY},
        wallet::Balance,
    },
    util::Watchable,
};

pub mod bip32;
pub mod error;
pub use error::Error;

/// Marker type for Wallet Env
pub struct WalletEnv;

type DatabaseUnique<KC, DC> = sneed::DatabaseUnique<KC, DC, WalletEnv>;
type RoTxn<'a> = sneed::RoTxn<'a, heed::AnyTls, WalletEnv>;

#[derive(Clone)]
pub struct Wallet {
    pub env: sneed::Env<heed::WithoutTls, WalletEnv>,
    /// Map each address to it's index
    address_to_index: DatabaseUnique<SerdeBincode<Address>, U32<BigEndian>>,
    /// Associates reservation commitments with plaintext BitNames
    bitname_reservations: DatabaseUnique<SerdeBincode<[u8; 32]>, Str>,
    /// Sidechain heights for each coinbase txid
    coinbase_height:
        DatabaseUnique<SerdeBincode<CoinbaseTxid>, SerdeBincode<u32>>,
    /// Mainchain heights for each deposit txid
    deposit_mainchain_height:
        DatabaseUnique<SerdeBincode<bitcoin::Txid>, SerdeBincode<u32>>,
    /// Map each address index to an address
    index_to_address: DatabaseUnique<U32<BigEndian>, SerdeBincode<Address>>,
    /// Map each public key index to a public key
    index_to_pubkey: DatabaseUnique<U32<BigEndian>, SerdeBincode<PublicKey>>,
    /// Associates BitNames with plaintext names
    known_bitnames: DatabaseUnique<SerdeBincode<BitName>, Str>,
    /// Map each public key to it's index
    pubkey_to_index: DatabaseUnique<SerdeBincode<PublicKey>, U32<BigEndian>>,
    // Seed is always [u8; 64], but due to serde not implementing serialize
    // for [T; 64], use heed's `Bytes`
    // TODO: Don't store the seed in plaintext.
    seed: DatabaseUnique<U8, Bytes>,
    stxos: DatabaseUnique<OutPointKey, SerdeBincode<SpentOutput>>,
    utxos: DatabaseUnique<OutPointKey, SerdeBincode<FilledOutput>>,
    _version: DatabaseUnique<UnitKey, SerdeBincode<Version>>,
}

impl Wallet {
    pub const NUM_DBS: u32 = 12;

    pub fn new(path: &Path) -> Result<Self, Error> {
        std::fs::create_dir_all(path)?;
        // Wallet data includes the BIP39 seed in plaintext today. Restrict the
        // directory so only the node user can read it (best-effort on Unix).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o700);
            std::fs::set_permissions(path, perms)?;
        }
        let env = {
            let mut env_open_options =
                heed::EnvOpenOptions::new().read_txn_without_tls();
            env_open_options
                .map_size(10 * 1024 * 1024) // 10MB
                .max_dbs(Self::NUM_DBS);
            // Wallet durability flags:
            // - WRITE_MAP reduces copy overhead for writes.
            // - NO_READ_AHEAD improves random access on SSDs.
            //
            // Unlike the node state DB, we deliberately do NOT set NO_SYNC /
            // NO_META_SYNC / MAP_ASYNC here. The wallet stores the BIP39 seed
            // and spendable UTXO metadata that cannot be reconstructed from
            // the public chain alone after a crash; fsync on commit is the
            // correct durability trade-off.
            //
            // TODO: Don't store the seed in plaintext (encrypt at rest).
            let durable_flags = EnvFlags::WRITE_MAP | EnvFlags::NO_READ_AHEAD;
            unsafe { env_open_options.flags(durable_flags) };
            unsafe { Env::open(&env_open_options, path) }?
        };
        let mut rwtxn = env.write_txn()?;
        let address_to_index =
            DatabaseUnique::create(&env, &mut rwtxn, "address_to_index")?;
        let bitname_reservations =
            DatabaseUnique::create(&env, &mut rwtxn, "bitname_reservations")?;
        let coinbase_height =
            DatabaseUnique::create(&env, &mut rwtxn, "coinbase_height")?;
        let deposit_mainchain_height = DatabaseUnique::create(
            &env,
            &mut rwtxn,
            "deposit_mainchain_height",
        )?;
        let index_to_address =
            DatabaseUnique::create(&env, &mut rwtxn, "index_to_address")?;
        let index_to_pubkey =
            DatabaseUnique::create(&env, &mut rwtxn, "index_to_pubkey")?;
        let known_bitnames =
            DatabaseUnique::create(&env, &mut rwtxn, "known_bitnames")?;
        let pubkey_to_index =
            DatabaseUnique::create(&env, &mut rwtxn, "pubkey_to_index")?;
        let seed_db = DatabaseUnique::create(&env, &mut rwtxn, "seed")?;
        let stxos = DatabaseUnique::create(&env, &mut rwtxn, "stxos")?;
        let utxos = DatabaseUnique::create(&env, &mut rwtxn, "utxos")?;
        let version = DatabaseUnique::create(&env, &mut rwtxn, "version")?;
        match version.try_get(&rwtxn, &())? {
            Some(db_version)
                if db_version
                    < Version {
                        major: 0,
                        minor: 18,
                        patch: 0,
                    } =>
            {
                return Err(Error::IncompatibleVersion {
                    version: db_version,
                    db_path: env.path().to_path_buf(),
                });
            }
            Some(_) => (),
            None => version.put(&mut rwtxn, &(), &*VERSION)?,
        }
        rwtxn.commit()?;
        Ok(Self {
            env,
            address_to_index,
            bitname_reservations,
            coinbase_height,
            deposit_mainchain_height,
            index_to_address,
            index_to_pubkey,
            known_bitnames,
            pubkey_to_index,
            seed: seed_db,
            stxos,
            utxos,
            _version: version,
        })
    }

    fn get_tx_signing_key(
        &self,
        rotxn: &RoTxn,
        index: u32,
    ) -> Result<SigningKey, error::GetTxSigningKey> {
        let seed = self.seed.try_get(rotxn, &0)?.ok_or(error::NoSeed)?;
        let mut xpriv = bip32::new_master_xpriv(seed);
        // derive via path m/43'/1899'/0'/<SIDECHAIN_NUMBER>'/0'/0'/index
        // (m / bip43 purpose / eCash Token / purpose (0) / sidechain number /
        // account /  purpose (0) / index)
        {
            xpriv = xpriv.derive_hardened(U31::new(43).unwrap())?;
            xpriv = xpriv.derive_hardened(U31::new(1899).unwrap())?;
            xpriv = xpriv.derive_hardened(U31::new(0).unwrap())?;
            xpriv = xpriv
                .derive_hardened(U31::new(THIS_SIDECHAIN as u32).unwrap())?;
            xpriv = xpriv.derive_hardened(U31::new(0).unwrap())?;
            xpriv = xpriv.derive_hardened(U31::new(0).unwrap())?;
            match bip32ish::ChildIndex::from(index) {
                bip32ish::ChildIndex::Hardened { index } => {
                    xpriv = xpriv.derive_hardened(index)?;
                }
                bip32ish::ChildIndex::NonHardened { index } => {
                    xpriv = xpriv.derive_non_hardened(index)?;
                }
            }
        }
        let sk = SigningKey::from_scalar(xpriv.secret_scalar)
            .expect("expected secret scalar to be non-zero");
        Ok(sk)
    }

    /// Get the tx signing key that corresponds to the provided address
    fn get_tx_signing_key_for_addr(
        &self,
        rotxn: &RoTxn,
        address: &Address,
    ) -> Result<SigningKey, Error> {
        let addr_idx = self
            .address_to_index
            .try_get(rotxn, address)?
            .ok_or(Error::AddressDoesNotExist { address: *address })?;
        let signing_key = self.get_tx_signing_key(rotxn, addr_idx)?;
        // sanity check that signing key corresponds to address
        {
            let vk = VerifyingKey::from(&signing_key);
            assert_eq!(*address, get_address(vk));
        }
        Ok(signing_key)
    }

    // Get master secret key
    fn get_master_xsk(
        &self,
        rotxn: &RoTxn,
    ) -> Result<bip32::Xpriv, error::GetSecretKey> {
        let seed = self.seed.try_get(rotxn, &0)?.ok_or(error::NoSeed)?;
        let mut xpriv = bip32::new_master_xpriv(seed);
        // derive via path m/43'/1899'/0'/<SIDECHAIN_NUMBER>'/0'/1'
        // (m / bip43 purpose / eCash Token / purpose (0) / sidechain number /
        // account /  purpose (1))
        {
            xpriv = xpriv.derive_hardened(U31::new(43).unwrap())?;
            xpriv = xpriv.derive_hardened(U31::new(1899).unwrap())?;
            xpriv = xpriv.derive_hardened(U31::new(0).unwrap())?;
            xpriv = xpriv
                .derive_hardened(U31::new(THIS_SIDECHAIN as u32).unwrap())?;
            xpriv = xpriv.derive_hardened(U31::new(0).unwrap())?;
            xpriv = xpriv.derive_hardened(U31::new(1).unwrap())?;
        }
        Ok(xpriv)
    }

    // Get master public key
    pub fn get_master_xpk(
        &self,
        rotxn: &RoTxn,
    ) -> Result<XPublicKey, error::GetSecretKey> {
        let master_xsk = self.get_master_xsk(rotxn)?;
        let master_xpk = master_xsk.xpub();
        let master_xpk = XPublicKey {
            pubkey: PublicKey(master_xpk.pubkey),
            chaincode: master_xpk.chaincode.0,
        };
        Ok(master_xpk)
    }

    fn get_xsecret_key(
        &self,
        rotxn: &RoTxn,
        index: u32,
    ) -> Result<bip32::Xpriv, error::GetSecretKey> {
        let mut xsk = self.get_master_xsk(rotxn)?;
        match bip32ish::ChildIndex::from(index) {
            bip32ish::ChildIndex::Hardened { index } => {
                xsk = xsk.derive_hardened(index)?;
            }
            bip32ish::ChildIndex::NonHardened { index } => {
                xsk = xsk.derive_non_hardened(index)?;
            }
        }
        Ok(xsk)
    }

    /// Get the secret key that corresponds to the provided public key
    fn get_secret_key_for_pubkey(
        &self,
        rotxn: &RoTxn,
        pubkey: &PublicKey,
    ) -> Result<SecretKey, Error> {
        let pubkey_idx = self.pubkey_to_index.try_get(rotxn, pubkey)?.ok_or(
            error::PubkeyDoesNotExist {
                cpk: pubkey.compress(),
            },
        )?;
        let xsecret_key = self.get_xsecret_key(rotxn, pubkey_idx)?;
        let secret_key = xsecret_key.secret_scalar;
        // sanity check that secret key corresponds to pubkey
        {
            assert_eq!(*pubkey, PublicKey::from_secret_key(&secret_key));
        }
        Ok(secret_key)
    }

    pub fn get_new_address(&self) -> Result<Address, Error> {
        let mut rwtxn = self.env.write_txn()?;
        let next_index = self
            .index_to_address
            .last(&rwtxn)?
            .map(|(idx, _)| idx + 1)
            .unwrap_or(0);
        let tx_signing_key = self.get_tx_signing_key(&rwtxn, next_index)?;
        let address = get_address(tx_signing_key.into());
        self.index_to_address
            .put(&mut rwtxn, &next_index, &address)?;
        self.address_to_index
            .put(&mut rwtxn, &address, &next_index)?;
        rwtxn.commit()?;
        Ok(address)
    }

    pub fn get_new_xpubkey(&self) -> Result<XPublicKey, Error> {
        let mut rwtxn = self.env.write_txn()?;
        let next_index = self
            .index_to_pubkey
            .last(&rwtxn)?
            .map(|(idx, _)| idx + 1)
            .unwrap_or(0);
        let xsecret_key = self.get_xsecret_key(&rwtxn, next_index)?;
        let xpubkey = {
            let xpk = xsecret_key.xpub();
            XPublicKey {
                pubkey: PublicKey(xpk.pubkey),
                chaincode: xpk.chaincode.0,
            }
        };
        self.index_to_pubkey
            .put(&mut rwtxn, &next_index, &xpubkey.pubkey)?;
        self.pubkey_to_index
            .put(&mut rwtxn, &xpubkey.pubkey, &next_index)?;
        rwtxn.commit()?;
        Ok(xpubkey)
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
        pubkey: &PublicKey,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let rotxn = self.env.read_txn()?;
        let secret_key = self.get_secret_key_for_pubkey(&rotxn, pubkey)?;
        let res = ecies::decrypt(&secret_key, ciphertext)?;
        Ok(res)
    }

    /// Create a transaction with a fee only.
    pub fn create_regular_transaction(
        &self,
        spend_height: u32,
        main_height: u32,
        fee: bitcoin::Amount,
    ) -> Result<Transaction, Error> {
        let (total, coins) =
            self.select_coins(spend_height, main_height, fee)?;
        let change = total - fee;
        let inputs = coins.into_keys().collect::<Vec<_>>();
        let outputs = vec![Output::new(
            self.get_new_address()?,
            OutputContent::Bitcoin(BitcoinOutputContent(change)),
        )];
        Ok(Transaction::new(inputs.into(), outputs.into()))
    }

    pub fn create_withdrawal(
        &self,
        spend_height: u32,
        main_height: u32,
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
            spend_height,
            main_height,
            value
                .checked_add(fee)
                .ok_or(AmountOverflowError)?
                .checked_add(main_fee)
                .ok_or(AmountOverflowError)?,
        )?;
        let change = total - value - fee - main_fee;
        let inputs = coins.into_keys().collect::<Vec<_>>();
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
        Ok(Transaction::new(inputs.into(), outputs.into()))
    }

    pub fn create_transfer(
        &self,
        spend_height: u32,
        main_height: u32,
        address: Address,
        value: bitcoin::Amount,
        fee: bitcoin::Amount,
        memo: Option<Vec<u8>>,
    ) -> Result<Transaction, Error> {
        self.create_transaction_many(
            spend_height,
            main_height,
            &BTreeMap::from([(address, value)]),
            fee,
            memo,
        )
    }

    /// Pay each address in `dests`, and pay the change to a new address
    pub fn create_transaction_many(
        &self,
        spend_height: u32,
        main_height: u32,
        dests: &BTreeMap<Address, bitcoin::Amount>,
        fee: bitcoin::Amount,
        memo: Option<Vec<u8>>,
    ) -> Result<Transaction, Error> {
        if dests.is_empty() {
            return Err(Error::NoTransferDestination);
        }
        let value = dests
            .values()
            .try_fold(bitcoin::Amount::ZERO, |total, value| {
                total.checked_add(*value)
            })
            .ok_or(AmountOverflowError)?;
        let (total, coins) = self.select_coins(
            spend_height,
            main_height,
            value.checked_add(fee).ok_or(AmountOverflowError)?,
        )?;
        let change = total - value - fee;
        let inputs = coins.into_keys().collect::<Vec<_>>();
        let mut outputs: Vec<Output> = dests
            .iter()
            .map(|(address, value)| Output {
                address: *address,
                content: OutputContent::Bitcoin(BitcoinOutputContent(*value)),
                memo: Vec::new(),
            })
            .collect();
        if change != Amount::ZERO {
            outputs.push(Output::new(
                self.get_new_address()?,
                OutputContent::Bitcoin(BitcoinOutputContent(change)),
            ))
        }
        Ok(Transaction {
            inputs: inputs.into(),
            outputs: outputs.into(),
            data: None,
            memo: memo.unwrap_or_default(),
        })
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
            else if let Some(last_output) = tx.outputs.as_slice().last() {
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
            blake3::hash(reservation_signing_key.to_scalar().as_bytes()).into();
        let nonce =
            blake3::keyed_hash(&reservation_hmac_key, &name_hash).into();
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
        bitname_data: Cow<MutableBitNameData>,
    ) -> Result<(), Error> {
        assert!(tx.is_regular(), "this function only accepts a regular tx");
        // address for the registration output
        let registration_addr =
            // if the last output is owned by this wallet, then use
            // the address associated with the last output
            if let Some(last_output) = tx.outputs.as_slice().last() {
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
                let reservation_hmac_key = blake3::hash(
                    reservation_signing_key.to_scalar().as_bytes(),
                )
                .into();
                let nonce =
                    blake3::keyed_hash(&reservation_hmac_key, &name_hash)
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

    /// Select coins worth at least `value`, which will be spendable after the
    /// sidechain height and prev_main_height are greater than or equal to
    /// the specified heights.
    pub fn select_coins(
        &self,
        spend_height: u32,
        main_height: u32,
        value: bitcoin::Amount,
    ) -> Result<(bitcoin::Amount, HashMap<OutPoint, FilledOutput>), Error> {
        let rotxn = self.env.read_txn()?;
        let mut utxos: Vec<_> = self.utxos.iter(&rotxn)?.collect()?;
        // Parallel sort by value to accelerate coin selection on large wallets
        utxos.par_sort_unstable_by_key(|(_, output)| output.get_value());

        let mut selected = HashMap::new();
        let mut total = bitcoin::Amount::ZERO;
        for (outpoint_key, output) in &utxos {
            let outpoint: OutPoint = outpoint_key.into();
            match outpoint {
                OutPoint::Coinbase { txid, vout: _ } => {
                    let coinbase_height =
                        self.coinbase_height.get(&rotxn, &txid)?;
                    if spend_height.checked_sub(coinbase_height).is_none_or(
                        |height_diff| height_diff < COINBASE_MATURITY,
                    ) {
                        continue;
                    }
                }
                OutPoint::Deposit(bitcoin::OutPoint { txid, vout: _ }) => {
                    let deposit_height =
                        self.deposit_mainchain_height.get(&rotxn, &txid)?;
                    if main_height.checked_sub(deposit_height).is_none_or(
                        |height_diff| height_diff < DEPOSIT_MATURITY,
                    ) {
                        continue;
                    }
                }
                OutPoint::Regular { .. } => (),
            }
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
            selected.insert(outpoint, output.clone());
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
            let key = OutPointKey::from(outpoint);
            if let Some(output) = self.utxos.try_get(&rwtxn, &key)? {
                self.utxos.delete(&mut rwtxn, &key)?;
                let spent_output = SpentOutput {
                    output,
                    inpoint: *inpoint,
                };
                self.stxos.put(&mut rwtxn, &key, &spent_output)?;
            }
        }
        rwtxn.commit()?;
        Ok(())
    }

    pub fn put_utxos(
        &self,
        coinbase_heights: &HashMap<CoinbaseTxid, u32>,
        deposit_main_heights: &HashMap<bitcoin::Txid, u32>,
        utxos: &HashMap<OutPoint, FilledOutput>,
    ) -> Result<(), Error> {
        let mut rwtxn = self.env.write_txn()?;
        for (coinbase_txid, height) in coinbase_heights {
            self.coinbase_height
                .put(&mut rwtxn, coinbase_txid, height)?;
        }
        for (deposit_txid, height) in deposit_main_heights {
            self.deposit_mainchain_height.put(
                &mut rwtxn,
                deposit_txid,
                height,
            )?;
        }
        for (outpoint, output) in utxos {
            let key = OutPointKey::from(outpoint);
            self.utxos
                .put(&mut rwtxn, &key, output)
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
        let utxos: HashMap<OutPoint, FilledOutput> = self
            .utxos
            .iter(&rotxn)
            .map_err(DbError::from)?
            .map(|(key, output)| Ok((key.to_outpoint(), output)))
            .collect()
            .map_err(DbError::from)?;
        Ok(utxos)
    }

    pub fn get_stxos(&self) -> Result<HashMap<OutPoint, SpentOutput>, Error> {
        let rotxn = self.env.read_txn()?;
        let stxos: HashMap<OutPoint, SpentOutput> = self
            .stxos
            .iter(&rotxn)?
            .map(|(key, spent_output)| Ok((key.to_outpoint(), spent_output)))
            .collect()?;
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

    pub fn authorize<R>(
        &self,
        mut rng: R,
        transaction: Transaction,
    ) -> Result<AuthorizedTransaction, Error>
    where
        R: CryptoRng,
    {
        let rotxn = self.env.read_txn()?;
        let mut authorizations = vec![];
        for input in &transaction.inputs {
            let key = OutPointKey::from(input);
            let spent_utxo =
                self.utxos.try_get(&rotxn, &key)?.ok_or(Error::NoUtxo)?;
            let index = self
                .address_to_index
                .try_get(&rotxn, &spent_utxo.address)
                .map_err(DbError::from)?
                .ok_or(Error::NoIndex {
                    address: spent_utxo.address,
                })?;
            let tx_signing_key = self.get_tx_signing_key(&rotxn, index)?;
            let signature = authorization::sign_tx(
                &mut rng,
                &tx_signing_key,
                &transaction,
            )?;
            authorizations.push(Authorization {
                verifying_key: VerifyingKey::from(&tx_signing_key),
                signature,
            });
        }
        Ok(AuthorizedTransaction {
            authorizations,
            transaction,
        })
    }

    /// Gets the latest generated address
    pub fn try_get_last_address(&self) -> Result<Option<Address>, Error> {
        let rotxn = self.env.read_txn()?;
        let last = self.index_to_address.last(&rotxn)?;
        Ok(last.map(|(_, address)| address))
    }

    /// Gets the latest generated address, or generates a new one if no
    /// addresses have already been generated
    pub fn get_or_generate_last_address(&self) -> Result<Address, Error> {
        if let Some(address) = self.try_get_last_address()? {
            Ok(address)
        } else {
            self.get_new_address()
        }
    }

    pub fn get_num_addresses(&self) -> Result<u32, Error> {
        let rotxn = self.env.read_txn()?;
        let res = self.index_to_address.len(&rotxn)? as u32;
        Ok(res)
    }

    pub fn sign_arbitrary_msg<R>(
        &self,
        rng: R,
        public_key: &PublicKey,
        msg: &str,
    ) -> Result<Signature, Error>
    where
        R: CryptoRng,
    {
        use authorization::Dst;
        let rotxn = self.env.read_txn()?;
        let secret_key = self.get_secret_key_for_pubkey(&rotxn, public_key)?;
        let signing_key = SigningKey::from_scalar(secret_key)
            .expect("expected secret scalar to be non-zero");
        let res = authorization::sign(
            rng,
            &signing_key,
            Dst::Arbitrary,
            msg.as_bytes(),
        );
        Ok(res)
    }

    pub fn sign_arbitrary_msg_as_addr<R>(
        &self,
        rng: R,
        address: &Address,
        msg: &str,
    ) -> Result<Authorization, Error>
    where
        R: CryptoRng,
    {
        use authorization::Dst;
        let rotxn = self.env.read_txn()?;
        let signing_key = self.get_tx_signing_key_for_addr(&rotxn, address)?;
        let signature = authorization::sign(
            rng,
            &signing_key,
            Dst::Arbitrary,
            msg.as_bytes(),
        );
        let verifying_key = VerifyingKey::from(&signing_key);
        Ok(Authorization {
            verifying_key,
            signature,
        })
    }
}

impl Watchable<()> for Wallet {
    type WatchStream = std::pin::Pin<Box<dyn Stream<Item = ()> + Send>>;

    /// Get a signal that notifies whenever the wallet changes
    fn watch(&self) -> Self::WatchStream {
        let Self {
            env: _,
            seed,
            address_to_index,
            coinbase_height: _,
            deposit_mainchain_height: _,
            index_to_address,
            index_to_pubkey,
            pubkey_to_index,
            utxos,
            stxos,
            bitname_reservations,
            known_bitnames,
            _version: _,
        } = self;
        let watchables = [
            seed.watch().clone(),
            address_to_index.watch().clone(),
            index_to_address.watch().clone(),
            index_to_pubkey.watch().clone(),
            pubkey_to_index.watch().clone(),
            utxos.watch().clone(),
            stxos.watch().clone(),
            bitname_reservations.watch().clone(),
            known_bitnames.watch().clone(),
        ];
        let streams = StreamMap::from_iter(
            watchables.into_iter().map(WatchStream::new).enumerate(),
        );
        let streams_len = streams.len();
        Box::pin(streams.ready_chunks(streams_len).map(|signals| {
            assert_ne!(signals.len(), 0);
            #[allow(clippy::unused_unit)]
            ()
        }))
    }
}

#[cfg(test)]
mod test {
    use crate::wallet::Wallet;

    #[test]
    fn test_get_or_generate_last_address() -> anyhow::Result<()> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let test_dir =
            std::env::temp_dir().join(format!("bitnames_test_wallet_{nanos}"));

        // Ensure clean state
        if test_dir.exists() {
            let _unused = std::fs::remove_dir_all(&test_dir);
        }

        let wallet = Wallet::new(&test_dir)?;

        // Seed must be set before we can generate addresses
        assert!(!wallet.has_seed()?);
        let seed = [1u8; 64];
        wallet.set_seed(&seed)?;
        assert!(wallet.has_seed()?);

        // Get last address when none have been generated
        let last = wallet.try_get_last_address()?;
        assert!(last.is_none());

        // The first call should generate the first address.
        let addr1 = wallet.get_or_generate_last_address()?;

        let last = wallet.try_get_last_address()?;
        assert_eq!(last, Some(addr1));

        let addr2 = wallet.get_or_generate_last_address()?;
        assert_eq!(addr1, addr2);

        let addr3 = wallet.get_new_address()?;
        assert_ne!(addr1, addr3);

        let last = wallet.try_get_last_address()?;
        assert_eq!(last, Some(addr3));

        let addr4 = wallet.get_or_generate_last_address()?;
        assert_eq!(addr3, addr4);

        // Clean up
        let _unused = std::fs::remove_dir_all(&test_dir);
        Ok(())
    }
}
