use std::{
    collections::{BTreeMap, HashMap, HashSet},
    net::{Ipv4Addr, Ipv6Addr},
};

use heed::{types::SerdeBincode, Database, RoTxn, RwTxn};
use nonempty::{nonempty, NonEmpty};
use serde::{Deserialize, Serialize};

use bip300301::{
    bitcoin::Amount as BitcoinAmount,
    bitcoin::{self, transaction::Version as BitcoinTxVersion},
    TwoWayPegData, WithdrawalBundleStatus,
};

use crate::{
    authorization::{Authorization, VerifyingKey},
    types::{
        self, constants,
        hashes::{self, BitName},
        Address, AggregatedWithdrawal, Authorized, AuthorizedTransaction,
        BatchIcannRegistrationData, BitNameDataUpdates, BlockHash, Body,
        EncryptionPubKey, FilledOutput, FilledOutputContent, FilledTransaction,
        GetAddress as _, GetValue as _, Hash, Header, InPoint, MerkleRoot,
        OutPoint, OutputContent, SpentOutput, Transaction, TxData, Txid,
        Update, Verify as _, WithdrawalBundle,
    },
};

/** Data of type `T` paired with
 *  * the txid at which it was last updated
 *  * block height at which it was last updated */
#[derive(Clone, Debug, Deserialize, Serialize)]
struct TxidStamped<T> {
    data: T,
    txid: Txid,
    height: u32,
}

/// Wrapper struct for fields that support rollbacks
#[derive(Clone, Debug, Deserialize, Serialize)]
#[repr(transparent)]
#[serde(transparent)]
struct RollBack<T>(NonEmpty<TxidStamped<T>>);

impl<T> RollBack<T> {
    fn new(value: T, txid: Txid, height: u32) -> Self {
        let txid_stamped = TxidStamped {
            data: value,
            txid,
            height,
        };
        Self(nonempty![txid_stamped])
    }

    /// push a value as the new most recent
    fn push(&mut self, value: T, txid: Txid, height: u32) {
        let txid_stamped = TxidStamped {
            data: value,
            txid,
            height,
        };
        self.0.push(txid_stamped)
    }

    /// pop the most recent value
    fn pop(&mut self) -> Option<TxidStamped<T>> {
        self.0.pop()
    }

    /** Returns the value as it was, at the specified block height.
     *  If a value was updated several times in the block, returns the
     *  last value seen in the block. */
    fn at_block_height(&self, height: u32) -> Option<&TxidStamped<T>> {
        self.0
            .iter()
            .rev()
            .find(|txid_stamped| txid_stamped.height <= height)
    }

    /// returns the most recent value, along with it's txid
    fn latest(&self) -> &TxidStamped<T> {
        self.0.last()
    }
}

/// Representation of BitName data that supports rollbacks.
/// The most recent datum is the element at the back of the vector.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BitNameData {
    /// commitment to arbitrary data
    commitment: RollBack<Option<Hash>>,
    /// set if the plain bitname is known to be an ICANN domain
    is_icann: bool,
    /// optional ipv4 addr
    ipv4_addr: RollBack<Option<Ipv4Addr>>,
    /// optional ipv6 addr
    ipv6_addr: RollBack<Option<Ipv6Addr>>,
    /// optional pubkey used for encryption
    encryption_pubkey: RollBack<Option<EncryptionPubKey>>,
    /// optional pubkey used for signing messages
    signing_pubkey: RollBack<Option<VerifyingKey>>,
    /// optional minimum paymail fee, in sats
    paymail_fee: RollBack<Option<u64>>,
}

impl BitNameData {
    // initialize from BitName data provided during a registration
    fn init(bitname_data: types::BitNameData, txid: Txid, height: u32) -> Self {
        Self {
            commitment: RollBack::new(bitname_data.commitment, txid, height),
            is_icann: false,
            ipv4_addr: RollBack::new(bitname_data.ipv4_addr, txid, height),
            ipv6_addr: RollBack::new(bitname_data.ipv6_addr, txid, height),
            encryption_pubkey: RollBack::new(
                bitname_data.encryption_pubkey,
                txid,
                height,
            ),
            signing_pubkey: RollBack::new(
                bitname_data.signing_pubkey,
                txid,
                height,
            ),
            paymail_fee: RollBack::new(bitname_data.paymail_fee, txid, height),
        }
    }

    // apply bitname data updates
    fn apply_updates(
        &mut self,
        updates: BitNameDataUpdates,
        txid: Txid,
        height: u32,
    ) {
        let Self {
            ref mut commitment,
            is_icann: _,
            ref mut ipv4_addr,
            ref mut ipv6_addr,
            ref mut encryption_pubkey,
            ref mut signing_pubkey,
            ref mut paymail_fee,
        } = self;

        // apply an update to a single data field
        fn apply_field_update<T>(
            data_field: &mut RollBack<Option<T>>,
            update: Update<T>,
            txid: Txid,
            height: u32,
        ) {
            match update {
                Update::Delete => data_field.push(None, txid, height),
                Update::Retain => (),
                Update::Set(value) => {
                    data_field.push(Some(value), txid, height)
                }
            }
        }
        apply_field_update(commitment, updates.commitment, txid, height);
        apply_field_update(ipv4_addr, updates.ipv4_addr, txid, height);
        apply_field_update(ipv6_addr, updates.ipv6_addr, txid, height);
        apply_field_update(
            encryption_pubkey,
            updates.encryption_pubkey,
            txid,
            height,
        );
        apply_field_update(
            signing_pubkey,
            updates.signing_pubkey,
            txid,
            height,
        );
        apply_field_update(paymail_fee, updates.paymail_fee, txid, height);
    }

    // revert bitname data updates
    fn revert_updates(
        &mut self,
        updates: BitNameDataUpdates,
        txid: Txid,
        height: u32,
    ) {
        // apply an update to a single data field
        fn revert_field_update<T>(
            data_field: &mut RollBack<Option<T>>,
            update: Update<T>,
            txid: Txid,
            height: u32,
        ) where
            T: std::fmt::Debug + Eq,
        {
            match update {
                Update::Delete => {
                    let popped = data_field.pop();
                    assert!(popped.is_some());
                    let popped = popped.unwrap();
                    assert!(popped.data.is_none());
                    assert_eq!(popped.txid, txid);
                    assert_eq!(popped.height, height)
                }
                Update::Retain => (),
                Update::Set(value) => {
                    let popped = data_field.pop();
                    assert!(popped.is_some());
                    let popped = popped.unwrap();
                    assert!(popped.data.is_some());
                    assert_eq!(popped.data.unwrap(), value);
                    assert_eq!(popped.txid, txid);
                    assert_eq!(popped.height, height)
                }
            }
        }

        let Self {
            ref mut commitment,
            is_icann: _,
            ref mut ipv4_addr,
            ref mut ipv6_addr,
            ref mut encryption_pubkey,
            ref mut signing_pubkey,
            ref mut paymail_fee,
        } = self;
        revert_field_update(paymail_fee, updates.paymail_fee, txid, height);
        revert_field_update(
            signing_pubkey,
            updates.signing_pubkey,
            txid,
            height,
        );
        revert_field_update(
            encryption_pubkey,
            updates.encryption_pubkey,
            txid,
            height,
        );
        revert_field_update(ipv6_addr, updates.ipv6_addr, txid, height);
        revert_field_update(ipv4_addr, updates.ipv4_addr, txid, height);
        revert_field_update(commitment, updates.commitment, txid, height);
    }

    /** Returns the Bitname data as it was, at the specified block height.
     *  If a value was updated several times in the block, returns the
     *  last value seen in the block.
     *  Returns `None` if the data did not exist at the specified block
     *  height. */
    pub fn at_block_height(&self, height: u32) -> Option<types::BitNameData> {
        Some(types::BitNameData {
            commitment: self.commitment.at_block_height(height)?.data,
            ipv4_addr: self.ipv4_addr.at_block_height(height)?.data,
            ipv6_addr: self.ipv6_addr.at_block_height(height)?.data,
            encryption_pubkey: self
                .encryption_pubkey
                .at_block_height(height)?
                .data,
            signing_pubkey: self.signing_pubkey.at_block_height(height)?.data,
            paymail_fee: self.paymail_fee.at_block_height(height)?.data,
        })
    }

    /// get the current bitname data
    pub fn current(&self) -> types::BitNameData {
        types::BitNameData {
            commitment: self.commitment.latest().data,
            ipv4_addr: self.ipv4_addr.latest().data,
            ipv6_addr: self.ipv6_addr.latest().data,
            encryption_pubkey: self.encryption_pubkey.latest().data,
            signing_pubkey: self.signing_pubkey.latest().data,
            paymail_fee: self.paymail_fee.latest().data,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum InvalidHeaderError {
    #[error("expected block hash {expected}, but computed {computed}")]
    BlockHash {
        expected: BlockHash,
        computed: BlockHash,
    },
    #[error("expected previous sidechain block hash {expected}, but received {received}")]
    PrevSideHash {
        expected: BlockHash,
        received: BlockHash,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to verify authorization")]
    AuthorizationError,
    #[error("bad coinbase output content")]
    BadCoinbaseOutputContent,
    #[error("bitname {name_hash} already registered")]
    BitNameAlreadyRegistered { name_hash: BitName },
    #[error("bitname {name_hash} already registered as an ICANN name")]
    BitNameAlreadyIcann { name_hash: BitName },
    #[error("bundle too heavy {weight} > {max_weight}")]
    BundleTooHeavy { weight: u64, max_weight: u64 },
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
    #[error("invalid header: {0}")]
    InvalidHeader(InvalidHeaderError),
    #[error("failed to compute merkle root")]
    MerkleRoot,
    #[error("missing BitName {name_hash}")]
    MissingBitName { name_hash: BitName },
    #[error(
        "Missing BitName data for {name_hash} at block height {block_height}"
    )]
    MissingBitNameData {
        name_hash: BitName,
        block_height: u32,
    },
    #[error("missing BitName input {name_hash}")]
    MissingBitNameInput { name_hash: BitName },
    #[error("missing BitName reservation {txid}")]
    MissingReservation { txid: Txid },
    #[error("no BitNames to update")]
    NoBitNamesToUpdate,
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
    #[error("utxo double spent")]
    UtxoDoubleSpent,
    #[error("wrong public key for address")]
    WrongPubKeyForAddress,
}

/// Unit key. LMDB can't use zero-sized keys, so this encodes to a single byte
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct UnitKey;

impl<'de> Deserialize<'de> for UnitKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Deserialize any byte (ignoring it) and return UnitKey
        let _ = u8::deserialize(deserializer)?;
        Ok(UnitKey)
    }
}

impl Serialize for UnitKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // Always serialize to the same arbitrary byte
        serializer.serialize_u8(0x69)
    }
}

#[derive(Clone)]
pub struct State {
    /// Current tip
    tip: Database<SerdeBincode<UnitKey>, SerdeBincode<BlockHash>>,
    /// Current height
    height: Database<SerdeBincode<UnitKey>, SerdeBincode<u32>>,
    /// associates tx hashes with bitname reservation commitments
    pub bitname_reservations: Database<SerdeBincode<Txid>, SerdeBincode<Hash>>,
    /// associates bitname IDs (name hashes) with bitname data
    pub bitnames: Database<SerdeBincode<BitName>, SerdeBincode<BitNameData>>,
    pub utxos: Database<SerdeBincode<OutPoint>, SerdeBincode<FilledOutput>>,
    pub stxos: Database<SerdeBincode<OutPoint>, SerdeBincode<SpentOutput>>,
    /// Pending withdrawal bundle and block height
    pub pending_withdrawal_bundle:
        Database<SerdeBincode<UnitKey>, SerdeBincode<(WithdrawalBundle, u32)>>,
    /// Mapping from block height to withdrawal bundle and status
    pub withdrawal_bundles: Database<
        SerdeBincode<u32>,
        SerdeBincode<(WithdrawalBundle, WithdrawalBundleStatus)>,
    >,
    /// deposit blocks and the height at which they were applied, keyed sequentially
    pub deposit_blocks:
        Database<SerdeBincode<u32>, SerdeBincode<(bitcoin::BlockHash, u32)>>,
}

impl State {
    pub const NUM_DBS: u32 = 9;
    pub const WITHDRAWAL_BUNDLE_FAILURE_GAP: u32 = 5;

    pub fn new(env: &heed::Env) -> Result<Self, Error> {
        let mut rwtxn = env.write_txn()?;
        let tip = env.create_database(&mut rwtxn, Some("tip"))?;
        let height = env.create_database(&mut rwtxn, Some("height"))?;
        let bitname_reservations =
            env.create_database(&mut rwtxn, Some("bitname_reservations"))?;
        let bitnames = env.create_database(&mut rwtxn, Some("bitnames"))?;
        let utxos = env.create_database(&mut rwtxn, Some("utxos"))?;
        let stxos = env.create_database(&mut rwtxn, Some("stxos"))?;
        let pending_withdrawal_bundle =
            env.create_database(&mut rwtxn, Some("pending_withdrawal_bundle"))?;
        let withdrawal_bundles =
            env.create_database(&mut rwtxn, Some("withdrawal_bundles"))?;
        let deposit_blocks =
            env.create_database(&mut rwtxn, Some("deposit_blocks"))?;
        rwtxn.commit()?;
        Ok(Self {
            tip,
            height,
            bitname_reservations,
            bitnames,
            utxos,
            stxos,
            pending_withdrawal_bundle,
            withdrawal_bundles,
            deposit_blocks,
        })
    }

    pub fn get_tip(&self, rotxn: &RoTxn) -> Result<BlockHash, Error> {
        let tip = self.tip.get(rotxn, &UnitKey)?.unwrap_or_default();
        Ok(tip)
    }

    pub fn get_height(&self, rotxn: &RoTxn) -> Result<u32, Error> {
        let height = self.height.get(rotxn, &UnitKey)?.unwrap_or_default();
        Ok(height)
    }

    /// Return the Bitname data. Returns an error if it does not exist.
    fn get_bitname(
        &self,
        txn: &RoTxn,
        bitname: &BitName,
    ) -> Result<BitNameData, Error> {
        self.bitnames
            .get(txn, bitname)?
            .ok_or(Error::MissingBitName {
                name_hash: *bitname,
            })
    }

    /// Resolve bitname data at the specified block height, if it exists.
    pub fn try_get_bitname_data_at_block_height(
        &self,
        txn: &RoTxn,
        bitname: &BitName,
        height: u32,
    ) -> Result<Option<types::BitNameData>, heed::Error> {
        let res = self
            .bitnames
            .get(txn, bitname)?
            .and_then(|bitname_data| bitname_data.at_block_height(height));
        Ok(res)
    }

    /** Resolve bitname data at the specified block height.
     * Returns an error if it does not exist. */
    pub fn get_bitname_data_at_block_height(
        &self,
        txn: &RoTxn,
        bitname: &BitName,
        height: u32,
    ) -> Result<types::BitNameData, Error> {
        self.get_bitname(txn, bitname)?
            .at_block_height(height)
            .ok_or(Error::MissingBitNameData {
                name_hash: *bitname,
                block_height: height,
            })
    }

    /// resolve current bitname data, if it exists
    pub fn try_get_current_bitname_data(
        &self,
        txn: &RoTxn,
        bitname: &BitName,
    ) -> Result<Option<types::BitNameData>, heed::Error> {
        let res = self
            .bitnames
            .get(txn, bitname)?
            .map(|bitname_data| bitname_data.current());
        Ok(res)
    }

    /// Resolve current bitname data. Returns an error if it does not exist.
    pub fn get_current_bitname_data(
        &self,
        txn: &RoTxn,
        bitname: &BitName,
    ) -> Result<types::BitNameData, Error> {
        self.try_get_current_bitname_data(txn, bitname)?.ok_or(
            Error::MissingBitName {
                name_hash: *bitname,
            },
        )
    }

    pub fn get_utxos(
        &self,
        txn: &RoTxn,
    ) -> Result<HashMap<OutPoint, FilledOutput>, Error> {
        let mut utxos = HashMap::new();
        for item in self.utxos.iter(txn)? {
            let (outpoint, output) = item?;
            utxos.insert(outpoint, output);
        }
        Ok(utxos)
    }

    pub fn get_utxos_by_addresses(
        &self,
        txn: &RoTxn,
        addresses: &HashSet<Address>,
    ) -> Result<HashMap<OutPoint, FilledOutput>, Error> {
        let mut utxos = HashMap::new();
        for item in self.utxos.iter(txn)? {
            let (outpoint, output) = item?;
            if addresses.contains(&output.address) {
                utxos.insert(outpoint, output);
            }
        }
        Ok(utxos)
    }

    /// Get the latest failed withdrawal bundle, and the height at which it failed
    fn get_latest_failed_withdrawal_bundle(
        &self,
        rotxn: &RoTxn,
    ) -> Result<Option<(u32, WithdrawalBundle)>, Error> {
        for item in self.withdrawal_bundles.rev_iter(rotxn)? {
            if let (height, (bundle, WithdrawalBundleStatus::Failed)) = item? {
                let res = Some((height, bundle));
                return Ok(res);
            }
        }
        Ok(None)
    }

    fn fill_transaction(
        &self,
        rotxn: &RoTxn,
        transaction: &Transaction,
    ) -> Result<FilledTransaction, Error> {
        let mut spent_utxos = vec![];
        for input in &transaction.inputs {
            let utxo = self
                .utxos
                .get(rotxn, input)?
                .ok_or(Error::NoUtxo { outpoint: *input })?;
            spent_utxos.push(utxo);
        }
        Ok(FilledTransaction {
            spent_utxos,
            transaction: transaction.clone(),
        })
    }

    /// Fill a transaction that has already been applied
    pub fn fill_transaction_from_stxos(
        &self,
        rotxn: &RoTxn,
        tx: Transaction,
    ) -> Result<FilledTransaction, Error> {
        let txid = tx.txid();
        let mut spent_utxos = vec![];
        // fill inputs last-to-first
        for (vin, input) in tx.inputs.iter().enumerate().rev() {
            let stxo = self
                .stxos
                .get(rotxn, input)?
                .ok_or(Error::NoStxo { outpoint: *input })?;
            assert_eq!(
                stxo.inpoint,
                InPoint::Regular {
                    txid,
                    vin: vin as u32
                }
            );
            spent_utxos.push(stxo.output);
        }
        spent_utxos.reverse();
        Ok(FilledTransaction {
            spent_utxos,
            transaction: tx,
        })
    }

    pub fn fill_authorized_transaction(
        &self,
        txn: &RoTxn,
        transaction: AuthorizedTransaction,
    ) -> Result<Authorized<FilledTransaction>, Error> {
        let filled_tx = self.fill_transaction(txn, &transaction.transaction)?;
        let authorizations = transaction.authorizations;
        Ok(Authorized {
            transaction: filled_tx,
            authorizations,
        })
    }

    fn collect_withdrawal_bundle(
        &self,
        txn: &RoTxn,
        block_height: u32,
    ) -> Result<Option<WithdrawalBundle>, Error> {
        use bitcoin::blockdata::{opcodes, script};
        // Weight of a bundle with 0 outputs.
        const BUNDLE_0_WEIGHT: u64 = 504;
        // Weight of a single output.
        const OUTPUT_WEIGHT: u64 = 128;
        // Turns out to be 3121.
        const MAX_BUNDLE_OUTPUTS: usize =
            ((bitcoin::policy::MAX_STANDARD_TX_WEIGHT as u64 - BUNDLE_0_WEIGHT)
                / OUTPUT_WEIGHT) as usize;

        // Aggregate all outputs by destination.
        // destination -> (value, mainchain fee, spent_utxos)
        let mut address_to_aggregated_withdrawal = HashMap::<
            bitcoin::Address<bitcoin::address::NetworkUnchecked>,
            AggregatedWithdrawal,
        >::new();
        for item in self.utxos.iter(txn)? {
            let (outpoint, output) = item?;
            if let FilledOutputContent::BitcoinWithdrawal {
                value,
                ref main_address,
                main_fee,
            } = output.content
            {
                let aggregated = address_to_aggregated_withdrawal
                    .entry(main_address.clone())
                    .or_insert(AggregatedWithdrawal {
                        spend_utxos: HashMap::new(),
                        main_address: main_address.clone(),
                        value: 0,
                        main_fee: 0,
                    });
                // Add up all values.
                aggregated.value += value;
                // Set maximum mainchain fee.
                if main_fee > aggregated.main_fee {
                    aggregated.main_fee = main_fee;
                }
                aggregated.spend_utxos.insert(outpoint, output);
            }
        }
        if address_to_aggregated_withdrawal.is_empty() {
            return Ok(None);
        }
        let mut aggregated_withdrawals: Vec<_> =
            address_to_aggregated_withdrawal.into_values().collect();
        aggregated_withdrawals.sort_by_key(|a| std::cmp::Reverse(a.clone()));
        let mut fee = 0;
        let mut spend_utxos = BTreeMap::<OutPoint, FilledOutput>::new();
        let mut bundle_outputs = vec![];
        for aggregated in &aggregated_withdrawals {
            if bundle_outputs.len() > MAX_BUNDLE_OUTPUTS {
                break;
            }
            let bundle_output = bitcoin::TxOut {
                value: BitcoinAmount::from_sat(aggregated.value),
                script_pubkey: aggregated
                    .main_address
                    .payload()
                    .script_pubkey(),
            };
            spend_utxos.extend(aggregated.spend_utxos.clone());
            bundle_outputs.push(bundle_output);
            fee += aggregated.main_fee;
        }
        let txin = bitcoin::TxIn {
            script_sig: script::Builder::new()
                // OP_FALSE == OP_0
                .push_opcode(opcodes::OP_FALSE)
                .into_script(),
            ..bitcoin::TxIn::default()
        };
        // Create return dest output.
        // The destination string for the change of a WT^
        let script = script::Builder::new()
            .push_opcode(opcodes::all::OP_RETURN)
            .push_slice([68; 1])
            .into_script();
        let return_dest_txout = bitcoin::TxOut {
            value: BitcoinAmount::ZERO,
            script_pubkey: script,
        };
        // Create mainchain fee output.
        let script = script::Builder::new()
            .push_opcode(opcodes::all::OP_RETURN)
            .push_slice(fee.to_le_bytes())
            .into_script();
        let mainchain_fee_txout = bitcoin::TxOut {
            value: BitcoinAmount::ZERO,
            script_pubkey: script,
        };
        // Create inputs commitment.
        let inputs: Vec<OutPoint> = [
            // Commit to inputs.
            spend_utxos.keys().copied().collect(),
            // Commit to block height.
            vec![OutPoint::Regular {
                txid: [0; 32].into(),
                vout: block_height,
            }],
        ]
        .concat();
        let commitment = hashes::hash(&inputs);
        let script = script::Builder::new()
            .push_opcode(opcodes::all::OP_RETURN)
            .push_slice(commitment)
            .into_script();
        let inputs_commitment_txout = bitcoin::TxOut {
            value: BitcoinAmount::ZERO,
            script_pubkey: script,
        };
        let transaction = bitcoin::Transaction {
            version: BitcoinTxVersion::TWO,
            lock_time: bitcoin::blockdata::locktime::absolute::LockTime::ZERO,
            input: vec![txin],
            output: [
                vec![
                    return_dest_txout,
                    mainchain_fee_txout,
                    inputs_commitment_txout,
                ],
                bundle_outputs,
            ]
            .concat(),
        };
        if transaction.weight().to_wu()
            > bitcoin::policy::MAX_STANDARD_TX_WEIGHT as u64
        {
            Err(Error::BundleTooHeavy {
                weight: transaction.weight().to_wu(),
                max_weight: bitcoin::policy::MAX_STANDARD_TX_WEIGHT as u64,
            })?;
        }
        Ok(Some(WithdrawalBundle {
            spend_utxos,
            transaction,
        }))
    }

    /// Get pending withdrawal bundle and block height
    pub fn get_pending_withdrawal_bundle(
        &self,
        txn: &RoTxn,
    ) -> Result<Option<(WithdrawalBundle, u32)>, Error> {
        Ok(self.pending_withdrawal_bundle.get(txn, &UnitKey)?)
    }

    /// Check that
    /// * If the tx is a BitName reservation, then the number of bitname
    ///   reservations in the outputs is exactly one more than the number of
    ///   bitname reservations in the inputs.
    /// * If the tx is a BitName
    ///   registration, then the number of bitname reservations in the outputs
    ///   is exactly one less than the number of bitname reservations in the
    ///   inputs.
    /// * Otherwise, the number of bitname reservations in the outputs
    ///   is exactly equal to the number of bitname reservations in the inputs.
    pub fn validate_reservations(
        &self,
        tx: &FilledTransaction,
    ) -> Result<(), Error> {
        let n_reservation_inputs: usize = tx.spent_reservations().count();
        let n_reservation_outputs: usize = tx.reservation_outputs().count();
        if tx.is_reservation() {
            if n_reservation_outputs == n_reservation_inputs + 1 {
                return Ok(());
            }
        } else if tx.is_registration() {
            if n_reservation_inputs == n_reservation_outputs + 1 {
                return Ok(());
            }
        } else if n_reservation_inputs == n_reservation_outputs {
            return Ok(());
        }
        Err(Error::UnbalancedReservations {
            n_reservation_inputs,
            n_reservation_outputs,
        })
    }

    /// Check that
    /// * If the tx is a BitName registration, then the number of bitnames
    ///   in the outputs is exactly one more than the number of bitnames in the
    ///   inputs.
    /// * Otherwise, the number of bitnames in the outputs is equal to
    ///   the number of bitnames in the inputs.
    /// * If the tx is a BitName registration, then the newly registered
    ///   BitName must be unregistered.
    /// * If the tx is a BitName update, then there must be at least one
    ///   BitName input and output
    /// * If the tx is a Batch Icann registration, then there must be at least
    ///   as many bitname outputs as there are registered names.
    pub fn validate_bitnames(
        &self,
        rotxn: &RoTxn,
        tx: &FilledTransaction,
    ) -> Result<(), Error> {
        let n_bitname_inputs: usize = tx.spent_bitnames().count();
        let n_bitname_outputs: usize = tx.bitname_outputs().count();
        if tx.is_update() && (n_bitname_inputs < 1 || n_bitname_outputs < 1) {
            return Err(Error::NoBitNamesToUpdate);
        };
        if let Some(batch_icann_data) = tx.batch_icann_data() {
            if n_bitname_outputs < batch_icann_data.plain_names.len() {
                return Err(Error::TooFewBitNameOutputs);
            }
        }
        if let Some(name_hash) = tx.registration_name_hash() {
            if self.bitnames.get(rotxn, &name_hash)?.is_some() {
                return Err(Error::BitNameAlreadyRegistered { name_hash });
            }
            if n_bitname_outputs == n_bitname_inputs + 1 {
                return Ok(());
            };
        } else if n_bitname_outputs == n_bitname_inputs {
            return Ok(());
        };
        Err(Error::UnbalancedBitNames {
            n_bitname_inputs,
            n_bitname_outputs,
        })
    }

    /// If the tx is a batch icann registration, check that
    /// * The signature is valid over the tx
    /// * Each of the declared plain names is a valid ICANN domain name
    pub fn validate_batch_icann(
        &self,
        tx: &FilledTransaction,
    ) -> Result<(), Error> {
        if let Some(batch_icann_data) = tx.batch_icann_data() {
            // validate plain names
            for plain_name in batch_icann_data.plain_names.iter() {
                // check ascii
                if !plain_name.is_ascii() {
                    return Err(Error::IcannNameInvalid {
                        plain_name: plain_name.clone(),
                    });
                }
                // at most one seperator
                if plain_name.chars().filter(|char| *char == '.').count() > 1 {
                    return Err(Error::IcannNameInvalid {
                        plain_name: plain_name.clone(),
                    });
                }
                if addr::parse_domain_name(plain_name).is_err() {
                    return Err(Error::IcannNameInvalid {
                        plain_name: plain_name.clone(),
                    });
                }
            }
            // validate signature
            let msg_hash = hashes::hash(&(
                &tx.transaction.inputs,
                &tx.transaction.outputs,
                &batch_icann_data.plain_names,
            ));
            constants::BATCH_ICANN_VERIFYING_KEY
                .verify_strict(&msg_hash, &batch_icann_data.signature)?;
        }
        Ok(())
    }

    /// Validates a filled transaction, and returns the fee
    pub fn validate_filled_transaction(
        &self,
        rotxn: &RoTxn,
        tx: &FilledTransaction,
    ) -> Result<u64, Error> {
        let () = self.validate_reservations(tx)?;
        let () = self.validate_bitnames(rotxn, tx)?;
        let () = self.validate_batch_icann(tx)?;
        tx.fee().ok_or(Error::NotEnoughValueIn)
    }

    pub fn validate_transaction(
        &self,
        rotxn: &RoTxn,
        transaction: &AuthorizedTransaction,
    ) -> Result<u64, Error> {
        let filled_transaction =
            self.fill_transaction(rotxn, &transaction.transaction)?;
        for (authorization, spent_utxo) in transaction
            .authorizations
            .iter()
            .zip(filled_transaction.spent_utxos.iter())
        {
            if authorization.get_address() != spent_utxo.address {
                return Err(Error::WrongPubKeyForAddress);
            }
        }
        if Authorization::verify_transaction(transaction).is_err() {
            return Err(Error::AuthorizationError);
        }
        let fee =
            self.validate_filled_transaction(rotxn, &filled_transaction)?;
        Ok(fee)
    }

    /// Validate a block, returning the merkle root and fees
    pub fn validate_block(
        &self,
        rotxn: &RoTxn,
        header: &Header,
        body: &Body,
    ) -> Result<(u64, MerkleRoot), Error> {
        let tip_hash = self.get_tip(rotxn)?;
        if header.prev_side_hash != tip_hash {
            let err = InvalidHeaderError::PrevSideHash {
                expected: tip_hash,
                received: header.prev_side_hash,
            };
            return Err(Error::InvalidHeader(err));
        };
        let mut coinbase_value: u64 = 0;
        for output in &body.coinbase {
            coinbase_value += output.get_value();
        }
        let mut total_fees: u64 = 0;
        let mut spent_utxos = HashSet::new();
        let filled_txs: Vec<_> = body
            .transactions
            .iter()
            .map(|t| self.fill_transaction(rotxn, t))
            .collect::<Result<_, _>>()?;
        for filled_tx in &filled_txs {
            for input in &filled_tx.transaction.inputs {
                if spent_utxos.contains(input) {
                    return Err(Error::UtxoDoubleSpent);
                }
                spent_utxos.insert(*input);
            }
            total_fees += self.validate_filled_transaction(rotxn, filled_tx)?;
        }
        if coinbase_value > total_fees {
            return Err(Error::NotEnoughFees);
        }
        let merkle_root = Body::compute_merkle_root(
            body.coinbase.as_slice(),
            filled_txs.as_slice(),
        )
        .ok_or(Error::MerkleRoot)?;
        if merkle_root != header.merkle_root {
            let err = Error::InvalidBody {
                expected: header.merkle_root,
                computed: merkle_root,
            };
            return Err(err);
        }
        let spent_utxos = filled_txs
            .iter()
            .flat_map(|t| t.spent_utxos_requiring_auth().into_iter());
        for (authorization, spent_utxo) in
            body.authorizations.iter().zip(spent_utxos)
        {
            if authorization.get_address() != spent_utxo.address {
                return Err(Error::WrongPubKeyForAddress);
            }
        }
        if Authorization::verify_body(body).is_err() {
            return Err(Error::AuthorizationError);
        }
        Ok((total_fees, merkle_root))
    }

    pub fn get_last_deposit_block_hash(
        &self,
        rotxn: &RoTxn,
    ) -> Result<Option<bitcoin::BlockHash>, Error> {
        let block_hash = self
            .deposit_blocks
            .last(rotxn)?
            .map(|(_, (block_hash, _))| block_hash);
        Ok(block_hash)
    }

    pub fn connect_two_way_peg_data(
        &self,
        rwtxn: &mut RwTxn,
        two_way_peg_data: &TwoWayPegData,
    ) -> Result<(), Error> {
        let block_height = self.get_height(rwtxn)?;
        // Handle deposits.
        if let Some(deposit_block_hash) = two_way_peg_data.deposit_block_hash {
            let deposit_block_seq_idx = self
                .deposit_blocks
                .last(rwtxn)?
                .map_or(0, |(seq_idx, _)| seq_idx + 1);
            self.deposit_blocks.put(
                rwtxn,
                &deposit_block_seq_idx,
                &(deposit_block_hash, block_height - 1),
            )?;
        }
        for deposit in &two_way_peg_data.deposits {
            if let Ok(address) = deposit.output.address.parse() {
                let outpoint = OutPoint::Deposit(deposit.outpoint);
                let output = FilledOutput::new(
                    address,
                    FilledOutputContent::Bitcoin(deposit.output.value),
                );
                self.utxos.put(rwtxn, &outpoint, &output)?;
            }
        }

        // Handle withdrawals.
        let last_withdrawal_bundle_failure_height = self
            .get_latest_failed_withdrawal_bundle(rwtxn)?
            .map(|(height, _bundle)| height)
            .unwrap_or_default();
        if block_height - last_withdrawal_bundle_failure_height
            > Self::WITHDRAWAL_BUNDLE_FAILURE_GAP
            && self
                .pending_withdrawal_bundle
                .get(rwtxn, &UnitKey)?
                .is_none()
        {
            if let Some(bundle) =
                self.collect_withdrawal_bundle(rwtxn, block_height)?
            {
                for (outpoint, spend_output) in &bundle.spend_utxos {
                    self.utxos.delete(rwtxn, outpoint)?;
                    let txid = bundle.transaction.txid();
                    let spent_output = SpentOutput {
                        output: spend_output.clone(),
                        inpoint: InPoint::Withdrawal { txid },
                    };
                    self.stxos.put(rwtxn, outpoint, &spent_output)?;
                }
                self.pending_withdrawal_bundle.put(
                    rwtxn,
                    &UnitKey,
                    &(bundle, block_height),
                )?;
            }
        }
        for (txid, status) in &two_way_peg_data.bundle_statuses {
            if let Some((bundle, bundle_block_height)) =
                self.pending_withdrawal_bundle.get(rwtxn, &UnitKey)?
            {
                if bundle.transaction.txid() != *txid {
                    continue;
                }
                assert_eq!(bundle_block_height, block_height);
                self.withdrawal_bundles.put(
                    rwtxn,
                    &block_height,
                    &(bundle.clone(), *status),
                )?;
                self.pending_withdrawal_bundle.delete(rwtxn, &UnitKey)?;
                if let WithdrawalBundleStatus::Failed = status {
                    for (outpoint, output) in &bundle.spend_utxos {
                        self.stxos.delete(rwtxn, outpoint)?;
                        self.utxos.put(rwtxn, outpoint, output)?;
                    }
                }
            }
        }
        Ok(())
    }

    pub fn disconnect_two_way_peg_data(
        &self,
        rwtxn: &mut RwTxn,
        two_way_peg_data: &TwoWayPegData,
    ) -> Result<(), Error> {
        let block_height = self.get_height(rwtxn)?;
        // Restore pending withdrawal bundle
        for (txid, status) in two_way_peg_data.bundle_statuses.iter().rev() {
            if let Some((
                latest_bundle_height,
                (latest_bundle, latest_bundle_status),
            )) = self.withdrawal_bundles.last(rwtxn)?
            {
                if latest_bundle.transaction.txid() != *txid {
                    continue;
                }
                assert_eq!(*status, latest_bundle_status);
                assert_eq!(latest_bundle_height, block_height);
                self.withdrawal_bundles
                    .delete(rwtxn, &latest_bundle_height)?;
                self.pending_withdrawal_bundle.put(
                    rwtxn,
                    &UnitKey,
                    &(latest_bundle.clone(), latest_bundle_height),
                )?;
                if *status == WithdrawalBundleStatus::Failed {
                    for (outpoint, output) in
                        latest_bundle.spend_utxos.into_iter().rev()
                    {
                        let spent_output = SpentOutput {
                            output: output.clone(),
                            inpoint: InPoint::Withdrawal { txid: *txid },
                        };
                        self.stxos.put(rwtxn, &outpoint, &spent_output)?;
                        if self.utxos.delete(rwtxn, &outpoint)? {
                            return Err(Error::NoUtxo { outpoint });
                        };
                    }
                }
            }
        }
        // Handle withdrawals.
        let last_withdrawal_bundle_failure_height = self
            .get_latest_failed_withdrawal_bundle(rwtxn)?
            .map(|(height, _bundle)| height)
            .unwrap_or_default();
        if block_height - last_withdrawal_bundle_failure_height
            > Self::WITHDRAWAL_BUNDLE_FAILURE_GAP
            && let Some((bundle, bundle_height)) =
                self.pending_withdrawal_bundle.get(rwtxn, &UnitKey)?
            && bundle_height == block_height
        {
            self.pending_withdrawal_bundle.delete(rwtxn, &UnitKey)?;
            for (outpoint, output) in bundle.spend_utxos.into_iter().rev() {
                if !self.stxos.delete(rwtxn, &outpoint)? {
                    return Err(Error::NoStxo { outpoint });
                };
                self.utxos.put(rwtxn, &outpoint, &output)?;
            }
        }
        // Handle deposits.
        if let Some(deposit_block_hash) = two_way_peg_data.deposit_block_hash {
            let (
                last_deposit_block_seq_idx,
                (last_deposit_block_hash, last_deposit_block_height),
            ) = self
                .deposit_blocks
                .last(rwtxn)?
                .ok_or(Error::NoDepositBlock)?;
            assert_eq!(deposit_block_hash, last_deposit_block_hash);
            assert_eq!(block_height - 1, last_deposit_block_height);
            if !self
                .deposit_blocks
                .delete(rwtxn, &last_deposit_block_seq_idx)?
            {
                return Err(Error::NoDepositBlock);
            };
        }
        for deposit in two_way_peg_data.deposits.iter().rev() {
            if let Ok(_address) = deposit.output.address.parse::<Address>() {
                let outpoint = OutPoint::Deposit(deposit.outpoint);
                if !self.utxos.delete(rwtxn, &outpoint)? {
                    return Err(Error::NoUtxo { outpoint });
                }
            }
        }
        Ok(())
    }

    // apply bitname registration
    fn apply_bitname_registration(
        &self,
        rwtxn: &mut RwTxn,
        filled_tx: &FilledTransaction,
        name_hash: BitName,
        bitname_data: &types::BitNameData,
        height: u32,
    ) -> Result<(), Error> {
        // Find the reservation to burn
        let implied_commitment =
            filled_tx.implied_reservation_commitment().expect(
                "A BitName registration tx should have an implied commitment",
            );
        let burned_reservation_txid =
            filled_tx.spent_reservations().find_map(|(_, filled_output)| {
                let (txid, commitment) = filled_output.reservation_data()
                    .expect("A spent reservation should correspond to a commitment");
                if *commitment == implied_commitment {
                    Some(txid)
                } else {
                    None
                }
            }).expect("A BitName registration tx should correspond to a burned reservation");
        if !self
            .bitname_reservations
            .delete(rwtxn, burned_reservation_txid)?
        {
            return Err(Error::MissingReservation {
                txid: *burned_reservation_txid,
            });
        }
        let bitname_data =
            BitNameData::init(bitname_data.clone(), filled_tx.txid(), height);
        self.bitnames.put(rwtxn, &name_hash, &bitname_data)?;
        Ok(())
    }

    fn revert_bitname_registration(
        &self,
        rwtxn: &mut RwTxn,
        filled_tx: &FilledTransaction,
        name_hash: BitName,
    ) -> Result<(), Error> {
        if !self.bitnames.delete(rwtxn, &name_hash)? {
            return Err(Error::MissingBitName { name_hash });
        }
        // Find the reservation to restore
        let implied_commitment =
            filled_tx.implied_reservation_commitment().expect(
                "A BitName registration tx should have an implied commitment",
            );
        let burned_reservation_txid =
            filled_tx.spent_reservations().find_map(|(_, filled_output)| {
                let (txid, commitment) = filled_output.reservation_data()
                    .expect("A spent reservation should correspond to a commitment");
                if *commitment == implied_commitment {
                    Some(txid)
                } else {
                    None
                }
            }).expect("A BitName registration tx should correspond to a burned reservation");
        self.bitname_reservations.put(
            rwtxn,
            burned_reservation_txid,
            &implied_commitment,
        )?;
        Ok(())
    }

    // apply bitname updates
    fn apply_bitname_updates(
        &self,
        rwtxn: &mut RwTxn,
        filled_tx: &FilledTransaction,
        bitname_updates: BitNameDataUpdates,
        height: u32,
    ) -> Result<(), Error> {
        // the updated bitname is the BitName that corresponds to the last
        // bitname output, or equivalently, the BitName corresponding to the
        // last bitname input
        let updated_bitname = filled_tx
            .spent_bitnames()
            .next_back()
            .ok_or(Error::NoBitNamesToUpdate)?
            .1
            .bitname()
            .expect("should only contain BitName outputs");
        let mut bitname_data = self
            .bitnames
            .get(rwtxn, updated_bitname)?
            .ok_or(Error::MissingBitName {
                name_hash: *updated_bitname,
            })?;
        bitname_data.apply_updates(bitname_updates, filled_tx.txid(), height);
        self.bitnames.put(rwtxn, updated_bitname, &bitname_data)?;
        Ok(())
    }

    fn revert_bitname_updates(
        &self,
        rwtxn: &mut RwTxn,
        filled_tx: &FilledTransaction,
        bitname_updates: BitNameDataUpdates,
        height: u32,
    ) -> Result<(), Error> {
        // the updated bitname is the BitName that corresponds to the last
        // bitname output, or equivalently, the BitName corresponding to the
        // last bitname input
        let updated_bitname = filled_tx
            .spent_bitnames()
            .next_back()
            .ok_or(Error::NoBitNamesToUpdate)?
            .1
            .bitname()
            .expect("should only contain BitName outputs");
        let mut bitname_data = self
            .bitnames
            .get(rwtxn, updated_bitname)?
            .ok_or(Error::MissingBitName {
                name_hash: *updated_bitname,
            })?;
        bitname_data.revert_updates(bitname_updates, filled_tx.txid(), height);
        self.bitnames.put(rwtxn, updated_bitname, &bitname_data)?;
        Ok(())
    }

    // apply batch icann registration
    fn apply_batch_icann(
        &self,
        rwtxn: &mut RwTxn,
        filled_tx: &FilledTransaction,
        batch_icann_data: &BatchIcannRegistrationData,
    ) -> Result<(), Error> {
        let name_hashes = batch_icann_data.plain_names.iter().map(|name| {
            let hash = blake3::hash(name.as_bytes());
            BitName(Hash::from(hash))
        });
        let mut spent_bitnames = filled_tx.spent_bitnames();
        for name_hash in name_hashes {
            // search for the bitname to be registered as an ICANN domain
            // exists in the inputs
            let found_bitname = spent_bitnames.any(|(_, outpoint)| {
                let bitname = outpoint.bitname()
                    .expect("spent bitname input should correspond to a known name hash");
                *bitname == name_hash
            });
            if found_bitname {
                let mut bitname_data = self
                    .bitnames
                    .get(rwtxn, &name_hash)?
                    .ok_or(Error::MissingBitName { name_hash })?;
                if bitname_data.is_icann {
                    return Err(Error::BitNameAlreadyIcann { name_hash });
                }
                bitname_data.is_icann = true;
                self.bitnames.put(rwtxn, &name_hash, &bitname_data)?;
            } else {
                return Err(Error::MissingBitNameInput { name_hash });
            }
        }
        Ok(())
    }

    // revert batch icann registration
    fn revert_batch_icann(
        &self,
        rwtxn: &mut RwTxn,
        filled_tx: &FilledTransaction,
        batch_icann_data: &BatchIcannRegistrationData,
    ) -> Result<(), Error> {
        let name_hashes = batch_icann_data.plain_names.iter().map(|name| {
            let hash = blake3::hash(name.as_bytes());
            BitName(Hash::from(hash))
        });
        let mut spent_bitnames = filled_tx.spent_bitnames();
        for name_hash in name_hashes.into_iter().rev() {
            // search for the bitname to be registered as an ICANN domain
            // exists in the inputs
            let found_bitname = spent_bitnames.any(|(_, outpoint)| {
                let bitname = outpoint.bitname()
                    .expect("spent bitname input should correspond to a known name hash");
                *bitname == name_hash
            });
            if found_bitname {
                let mut bitname_data = self
                    .bitnames
                    .get(rwtxn, &name_hash)?
                    .ok_or(Error::MissingBitName { name_hash })?;
                assert!(!bitname_data.is_icann);
                bitname_data.is_icann = false;
                self.bitnames.put(rwtxn, &name_hash, &bitname_data)?;
            } else {
                return Err(Error::MissingBitNameInput { name_hash });
            }
        }
        Ok(())
    }

    pub fn connect_block(
        &self,
        rwtxn: &mut RwTxn,
        header: &Header,
        body: &Body,
    ) -> Result<MerkleRoot, Error> {
        let height = self.get_height(rwtxn)?;
        let tip_hash = self.get_tip(rwtxn)?;
        if tip_hash != header.prev_side_hash {
            let err = InvalidHeaderError::PrevSideHash {
                expected: tip_hash,
                received: header.prev_side_hash,
            };
            return Err(Error::InvalidHeader(err));
        }
        for (vout, output) in body.coinbase.iter().enumerate() {
            let outpoint = OutPoint::Coinbase {
                merkle_root: header.merkle_root,
                vout: vout as u32,
            };
            let filled_content = match output.content.clone() {
                OutputContent::Value(value) => {
                    FilledOutputContent::Bitcoin(value)
                }
                OutputContent::Withdrawal {
                    value,
                    main_fee,
                    main_address,
                } => FilledOutputContent::BitcoinWithdrawal {
                    value,
                    main_fee,
                    main_address,
                },
                OutputContent::BitName | OutputContent::BitNameReservation => {
                    return Err(Error::BadCoinbaseOutputContent);
                }
            };
            let filled_output = FilledOutput {
                address: output.address,
                content: filled_content,
                memo: output.memo.clone(),
            };
            self.utxos.put(rwtxn, &outpoint, &filled_output)?;
        }
        let mut filled_txs: Vec<FilledTransaction> = Vec::new();
        for transaction in &body.transactions {
            let filled_tx = self.fill_transaction(rwtxn, transaction)?;
            let txid = filled_tx.txid();
            for (vin, input) in filled_tx.inputs().iter().enumerate() {
                let spent_output = self
                    .utxos
                    .get(rwtxn, input)?
                    .ok_or(Error::NoUtxo { outpoint: *input })?;
                let spent_output = SpentOutput {
                    output: spent_output,
                    inpoint: InPoint::Regular {
                        txid,
                        vin: vin as u32,
                    },
                };
                self.utxos.delete(rwtxn, input)?;
                self.stxos.put(rwtxn, input, &spent_output)?;
            }
            let filled_outputs = filled_tx
                .filled_outputs()
                .ok_or(Error::FillTxOutputContentsFailed)?;
            for (vout, filled_output) in filled_outputs.iter().enumerate() {
                let outpoint = OutPoint::Regular {
                    txid,
                    vout: vout as u32,
                };
                self.utxos.put(rwtxn, &outpoint, filled_output)?;
            }
            match &transaction.data {
                None => (),
                Some(TxData::BitNameReservation { commitment }) => {
                    self.bitname_reservations.put(rwtxn, &txid, commitment)?;
                }
                Some(TxData::BitNameRegistration {
                    name_hash,
                    revealed_nonce: _,
                    bitname_data,
                }) => {
                    let () = self.apply_bitname_registration(
                        rwtxn,
                        &filled_tx,
                        *name_hash,
                        bitname_data,
                        height,
                    )?;
                }
                Some(TxData::BitNameUpdate(bitname_updates)) => {
                    let () = self.apply_bitname_updates(
                        rwtxn,
                        &filled_tx,
                        (**bitname_updates).clone(),
                        height,
                    )?;
                }
                Some(TxData::BatchIcann(batch_icann_data)) => {
                    let () = self.apply_batch_icann(
                        rwtxn,
                        &filled_tx,
                        batch_icann_data,
                    )?;
                }
            }
            filled_txs.push(filled_tx);
        }
        let merkle_root = Body::compute_merkle_root(
            body.coinbase.as_slice(),
            filled_txs.as_slice(),
        )
        .ok_or(Error::MerkleRoot)?;
        if merkle_root != header.merkle_root {
            let err = Error::InvalidBody {
                expected: header.merkle_root,
                computed: merkle_root,
            };
            return Err(err);
        }
        let block_hash = header.hash();
        self.tip.put(rwtxn, &UnitKey, &block_hash)?;
        self.height.put(rwtxn, &UnitKey, &(height + 1))?;
        Ok(merkle_root)
    }

    pub fn disconnect_tip(
        &self,
        rwtxn: &mut RwTxn,
        header: &Header,
        body: &Body,
    ) -> Result<(), Error> {
        let tip_hash = self.get_tip(rwtxn)?;
        if tip_hash != header.hash() {
            let err = InvalidHeaderError::BlockHash {
                expected: tip_hash,
                computed: header.hash(),
            };
            return Err(Error::InvalidHeader(err));
        }
        let height = self.get_height(rwtxn)?;
        // revert txs, last-to-first
        let mut filled_txs: Vec<FilledTransaction> = Vec::new();
        body.transactions.iter().rev().try_for_each(|tx| {
            let txid = tx.txid();
            let filled_tx =
                self.fill_transaction_from_stxos(rwtxn, tx.clone())?;
            // revert transaction effects
            match &tx.data {
                None => (),
                Some(TxData::BitNameReservation { .. }) => {
                    if !self.bitname_reservations.delete(rwtxn, &txid)? {
                        return Err(Error::MissingReservation { txid });
                    }
                }
                Some(TxData::BitNameRegistration {
                    name_hash,
                    revealed_nonce: _,
                    bitname_data: _,
                }) => {
                    let () = self.revert_bitname_registration(
                        rwtxn, &filled_tx, *name_hash,
                    )?;
                }
                Some(TxData::BitNameUpdate(bitname_updates)) => {
                    let () = self.revert_bitname_updates(
                        rwtxn,
                        &filled_tx,
                        (**bitname_updates).clone(),
                        height - 1,
                    )?;
                }
                Some(TxData::BatchIcann(batch_icann_data)) => {
                    let () = self.revert_batch_icann(
                        rwtxn,
                        &filled_tx,
                        batch_icann_data,
                    )?;
                }
            }
            filled_txs.push(filled_tx);
            // delete UTXOs, last-to-first
            tx.outputs.iter().enumerate().rev().try_for_each(
                |(vout, _output)| {
                    let outpoint = OutPoint::Regular {
                        txid,
                        vout: vout as u32,
                    };
                    if self.utxos.delete(rwtxn, &outpoint)? {
                        Ok(())
                    } else {
                        Err(Error::NoUtxo { outpoint })
                    }
                },
            )?;
            // unspend STXOs, last-to-first
            tx.inputs.iter().rev().try_for_each(|outpoint| {
                if let Some(spent_output) = self.stxos.get(rwtxn, outpoint)? {
                    self.stxos.delete(rwtxn, outpoint)?;
                    self.utxos.put(rwtxn, outpoint, &spent_output.output)?;
                    Ok(())
                } else {
                    Err(Error::NoStxo {
                        outpoint: *outpoint,
                    })
                }
            })
        })?;
        filled_txs.reverse();
        // delete coinbase UTXOs, last-to-first
        body.coinbase.iter().enumerate().rev().try_for_each(
            |(vout, _output)| {
                let outpoint = OutPoint::Coinbase {
                    merkle_root: header.merkle_root,
                    vout: vout as u32,
                };
                if self.utxos.delete(rwtxn, &outpoint)? {
                    Ok(())
                } else {
                    Err(Error::NoUtxo { outpoint })
                }
            },
        )?;
        let merkle_root = Body::compute_merkle_root(
            body.coinbase.as_slice(),
            filled_txs.as_slice(),
        )
        .ok_or(Error::MerkleRoot)?;
        if merkle_root != header.merkle_root {
            let err = Error::InvalidBody {
                expected: header.merkle_root,
                computed: merkle_root,
            };
            return Err(err);
        }
        self.tip.put(rwtxn, &UnitKey, &header.prev_side_hash)?;
        self.height.put(rwtxn, &UnitKey, &(height - 1))?;
        Ok(())
    }

    /// Get total sidechain wealth in Bitcoin
    pub fn sidechain_wealth(
        &self,
        rotxn: &RoTxn,
    ) -> Result<BitcoinAmount, Error> {
        let mut total_deposit_utxo_value: u64 = 0;
        self.utxos.iter(rotxn)?.try_for_each(|utxo| {
            let (outpoint, output) = utxo?;
            if let OutPoint::Deposit(_) = outpoint {
                total_deposit_utxo_value += output.get_value();
            }
            Ok::<_, Error>(())
        })?;
        let mut total_deposit_stxo_value: u64 = 0;
        let mut total_withdrawal_stxo_value: u64 = 0;
        self.stxos.iter(rotxn)?.try_for_each(|stxo| {
            let (outpoint, spent_output) = stxo?;
            if let OutPoint::Deposit(_) = outpoint {
                total_deposit_stxo_value += spent_output.output.get_value();
            }
            if let InPoint::Withdrawal { .. } = spent_output.inpoint {
                total_withdrawal_stxo_value += spent_output.output.get_value();
            }
            Ok::<_, Error>(())
        })?;

        let total_wealth_sats: u64 = (total_deposit_utxo_value
            + total_deposit_stxo_value)
            - total_withdrawal_stxo_value;
        let total_wealth = BitcoinAmount::from_sat(total_wealth_sats);
        Ok(total_wealth)
    }
}
