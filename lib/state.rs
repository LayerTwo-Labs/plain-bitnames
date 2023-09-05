use std::{
    collections::{HashMap, HashSet},
    net::{Ipv4Addr, Ipv6Addr},
};

use heed::types::*;
use heed::{Database, RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use bip300301::TwoWayPegData;
use bip300301::{bitcoin, WithdrawalBundleStatus};

use crate::authorization::{Authorization, PublicKey};
use crate::types::{self, *};

/// Representation of BitName data that supports rollbacks.
/// The most recent datum is the element at the back of the vector.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BitNameData {
    /// commitment to arbitrary data
    commitment: Vec<Option<Hash>>,
    /// set if the plain bitname is known to be an ICANN domain
    is_icann: bool,
    /// optional ipv4 addr
    ipv4_addr: Vec<Option<Ipv4Addr>>,
    /// optional ipv6 addr
    ipv6_addr: Vec<Option<Ipv6Addr>>,
    /// optional pubkey used for encryption
    encryption_pubkey: Vec<Option<EncryptionPubKey>>,
    /// optional pubkey used for signing messages
    signing_pubkey: Vec<Option<PublicKey>>,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to verify authorization")]
    AuthorizationError,
    #[error("bad coinbase output content")]
    BadCoinbaseOutputContent,
    #[error("bitname {name_hash:?} already registered")]
    BitNameAlreadyRegistered { name_hash: Hash },
    #[error("bitname {name_hash:?} already registered as an ICANN name")]
    BitNameAlreadyIcann { name_hash: Hash },
    #[error("bundle too heavy {weight} > {max_weight}")]
    BundleTooHeavy { weight: u64, max_weight: u64 },
    #[error("failed to fill tx output contents: invalid transaction")]
    FillTxOutputContentsFailed,
    #[error("heed error")]
    Heed(#[from] heed::Error),
    #[error("invalid ICANN name: {plain_name}")]
    IcannNameInvalid { plain_name: String },
    #[error("missing BitName {name_hash:?}")]
    MissingBitName { name_hash: Hash },
    #[error("missing BitName input {name_hash:?}")]
    MissingBitNameInput { name_hash: Hash },
    #[error("missing BitName reservation {txid}")]
    MissingReservation { txid: Txid },
    #[error("no BitNames to update")]
    NoBitNamesToUpdate,
    #[error("total fees less than coinbase value")]
    NotEnoughFees,
    #[error("value in is less than value out")]
    NotEnoughValueIn,
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

#[derive(Clone)]
pub struct State {
    /// associates tx hashes with bitname reservation commitments
    pub bitname_reservations: Database<SerdeBincode<Txid>, SerdeBincode<Hash>>,
    /// associates bitname IDs (name hashes) with bitname data
    pub bitnames: Database<SerdeBincode<Hash>, SerdeBincode<BitNameData>>,
    pub utxos: Database<SerdeBincode<OutPoint>, SerdeBincode<FilledOutput>>,
    pub pending_withdrawal_bundle:
        Database<OwnedType<u32>, SerdeBincode<WithdrawalBundle>>,
    pub last_withdrawal_bundle_failure_height:
        Database<OwnedType<u32>, OwnedType<u32>>,
    pub last_deposit_block:
        Database<OwnedType<u32>, SerdeBincode<bitcoin::BlockHash>>,
}

impl BitNameData {
    // initialize from BitName data provided during a registration
    fn init(bitname_data: types::BitNameData) -> Self {
        Self {
            commitment: vec![bitname_data.commitment],
            is_icann: false,
            ipv4_addr: vec![bitname_data.ipv4_addr],
            ipv6_addr: vec![bitname_data.ipv6_addr],
            encryption_pubkey: vec![bitname_data.encryption_pubkey],
            signing_pubkey: vec![bitname_data.signing_pubkey],
        }
    }

    // apply bitname data updates
    fn apply_updates(&mut self, updates: BitNameDataUpdates) {
        // apply an update to a single data field
        fn apply_field_update<T>(
            data_field: &mut Vec<Option<T>>,
            update: Update<T>,
        ) {
            match update {
                Update::Delete => data_field.push(None),
                Update::Retain => (),
                Update::Set(value) => data_field.push(Some(value)),
            }
        }
        apply_field_update(&mut self.commitment, updates.commitment);
        apply_field_update(&mut self.ipv4_addr, updates.ipv4_addr);
        apply_field_update(&mut self.ipv6_addr, updates.ipv6_addr);
        apply_field_update(
            &mut self.encryption_pubkey,
            updates.encryption_pubkey,
        );
        apply_field_update(&mut self.signing_pubkey, updates.signing_pubkey);
    }
}

impl State {
    pub const NUM_DBS: u32 = 6;
    pub const WITHDRAWAL_BUNDLE_FAILURE_GAP: u32 = 4;

    pub fn new(env: &heed::Env) -> Result<Self, Error> {
        let bitname_reservations =
            env.create_database(Some("bitname_reservations"))?;
        let bitnames = env.create_database(Some("bitnames"))?;
        let utxos = env.create_database(Some("utxos"))?;
        let pending_withdrawal_bundle =
            env.create_database(Some("pending_withdrawal_bundle"))?;
        let last_withdrawal_bundle_failure_height =
            env.create_database(Some("last_withdrawal_bundle_failure_height"))?;
        let last_deposit_block =
            env.create_database(Some("last_deposit_block"))?;
        Ok(Self {
            bitname_reservations,
            bitnames,
            utxos,
            pending_withdrawal_bundle,
            last_withdrawal_bundle_failure_height,
            last_deposit_block,
        })
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

    pub fn fill_transaction(
        &self,
        txn: &RoTxn,
        transaction: &Transaction,
    ) -> Result<FilledTransaction, Error> {
        let mut spent_utxos = vec![];
        for input in &transaction.inputs {
            let utxo = self
                .utxos
                .get(txn, input)?
                .ok_or(Error::NoUtxo { outpoint: *input })?;
            spent_utxos.push(utxo);
        }
        Ok(FilledTransaction {
            spent_utxos,
            transaction: transaction.clone(),
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
                        spent_utxos: HashMap::new(),
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
                aggregated.spent_utxos.insert(outpoint, output);
            }
        }
        if address_to_aggregated_withdrawal.is_empty() {
            return Ok(None);
        }
        let mut aggregated_withdrawals: Vec<_> =
            address_to_aggregated_withdrawal.into_values().collect();
        aggregated_withdrawals.sort_by_key(|a| std::cmp::Reverse(a.clone()));
        let mut fee = 0;
        let mut spent_utxos = HashMap::<OutPoint, FilledOutput>::new();
        let mut bundle_outputs = vec![];
        for aggregated in &aggregated_withdrawals {
            if bundle_outputs.len() > MAX_BUNDLE_OUTPUTS {
                break;
            }
            let bundle_output = bitcoin::TxOut {
                value: aggregated.value,
                script_pubkey: aggregated.main_address.payload.script_pubkey(),
            };
            spent_utxos.extend(aggregated.spent_utxos.clone());
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
            value: 0,
            script_pubkey: script,
        };
        // Create mainchain fee output.
        let script = script::Builder::new()
            .push_opcode(opcodes::all::OP_RETURN)
            .push_slice(fee.to_le_bytes())
            .into_script();
        let mainchain_fee_txout = bitcoin::TxOut {
            value: 0,
            script_pubkey: script,
        };
        // Create inputs commitment.
        let inputs: Vec<OutPoint> = [
            // Commit to inputs.
            spent_utxos.keys().copied().collect(),
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
            value: 0,
            script_pubkey: script,
        };
        let transaction = bitcoin::Transaction {
            version: 2,
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
            spent_utxos,
            transaction,
        }))
    }

    pub fn get_pending_withdrawal_bundle(
        &self,
        txn: &RoTxn,
    ) -> Result<Option<WithdrawalBundle>, Error> {
        Ok(self.pending_withdrawal_bundle.get(txn, &0)?)
    }

    /// Check that
    /// * If the tx is a BitName reservation, then the number of bitname
    /// reservations in the outputs is exactly one more than the number of
    /// bitname reservations in the inputs. If the tx is a BitName
    /// registration, then the number of bitname reservations in the outputs
    /// is exactly one less than the number of bitname reservations in the
    /// inputs. Otherwise, the number of bitname reservations in the outputs
    /// is exactly equal to the number of bitname reservations in the inputs.
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
    /// in the outputs is exactly one more than the number of bitnames in the
    /// inputs. Otherwise, the number of bitnames in the outputs is equal to
    /// the number of bitnames in the inputs.
    /// * If the tx is a BitName registration, then the newly registered
    /// BitName must be unregistered.
    /// * If the tx is a BitName update, then there must be at least one
    /// BitName input and output
    /// * If the tx is a Batch Icann registration, then there must be at least
    /// as many bitname outputs as there are registered names.
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
            constants::BATCH_ICANN_PUBKEY
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

    pub fn validate_body(
        &self,
        rotxn: &RoTxn,
        body: &Body,
    ) -> Result<u64, Error> {
        let mut coinbase_value: u64 = 0;
        for output in &body.coinbase {
            coinbase_value += output.get_value();
        }
        let mut total_fees: u64 = 0;
        let mut spent_utxos = HashSet::new();
        let filled_transactions: Vec<_> = body
            .transactions
            .iter()
            .map(|t| self.fill_transaction(rotxn, t))
            .collect::<Result<_, _>>()?;
        for filled_transaction in &filled_transactions {
            for input in &filled_transaction.transaction.inputs {
                if spent_utxos.contains(input) {
                    return Err(Error::UtxoDoubleSpent);
                }
                spent_utxos.insert(*input);
            }
            total_fees +=
                self.validate_filled_transaction(rotxn, filled_transaction)?;
        }
        if coinbase_value > total_fees {
            return Err(Error::NotEnoughFees);
        }
        let spent_utxos = filled_transactions
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
        Ok(total_fees)
    }

    pub fn get_last_deposit_block_hash(
        &self,
        txn: &RoTxn,
    ) -> Result<Option<bitcoin::BlockHash>, Error> {
        Ok(self.last_deposit_block.get(txn, &0)?)
    }

    pub fn connect_two_way_peg_data(
        &self,
        txn: &mut RwTxn,
        two_way_peg_data: &TwoWayPegData,
        block_height: u32,
    ) -> Result<(), Error> {
        // Handle deposits.
        if let Some(deposit_block_hash) = two_way_peg_data.deposit_block_hash {
            self.last_deposit_block.put(txn, &0, &deposit_block_hash)?;
        }
        for (outpoint, deposit) in &two_way_peg_data.deposits {
            if let Ok(address) = deposit.address.parse() {
                let outpoint = OutPoint::Deposit(*outpoint);
                let output = FilledOutput::new(
                    address,
                    FilledOutputContent::Bitcoin(deposit.value),
                );
                self.utxos.put(txn, &outpoint, &output)?;
            }
        }

        // Handle withdrawals.
        let last_withdrawal_bundle_failure_height = self
            .last_withdrawal_bundle_failure_height
            .get(txn, &0)?
            .unwrap_or(0);
        if (block_height + 1) - last_withdrawal_bundle_failure_height
            > Self::WITHDRAWAL_BUNDLE_FAILURE_GAP
            && self.pending_withdrawal_bundle.get(txn, &0)?.is_none()
        {
            if let Some(bundle) =
                self.collect_withdrawal_bundle(txn, block_height + 1)?
            {
                for outpoint in bundle.spent_utxos.keys() {
                    self.utxos.delete(txn, outpoint)?;
                }
                self.pending_withdrawal_bundle.put(txn, &0, &bundle)?;
            }
        }
        for (txid, status) in &two_way_peg_data.bundle_statuses {
            if let Some(bundle) = self.pending_withdrawal_bundle.get(txn, &0)? {
                if bundle.transaction.txid() != *txid {
                    continue;
                }
                match status {
                    WithdrawalBundleStatus::Failed => {
                        self.last_withdrawal_bundle_failure_height.put(
                            txn,
                            &0,
                            &(block_height + 1),
                        )?;
                        self.pending_withdrawal_bundle.delete(txn, &0)?;
                        for (outpoint, output) in &bundle.spent_utxos {
                            self.utxos.put(txn, outpoint, output)?;
                        }
                    }
                    WithdrawalBundleStatus::Confirmed => {
                        self.pending_withdrawal_bundle.delete(txn, &0)?;
                    }
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
        name_hash: Hash,
        bitname_data: &types::BitNameData,
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
        let bitname_data = BitNameData::init(bitname_data.clone());
        self.bitnames.put(rwtxn, &name_hash, &bitname_data)?;
        Ok(())
    }

    // apply bitname updates
    fn apply_bitname_updates(
        &self,
        rwtxn: &mut RwTxn,
        filled_tx: &FilledTransaction,
        bitname_updates: BitNameDataUpdates,
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
        bitname_data.apply_updates(bitname_updates);
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
        let name_hashes = batch_icann_data
            .plain_names
            .iter()
            .map(|name| Hash::from(blake3::hash(name.as_bytes())));
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

    pub fn connect_body(
        &self,
        txn: &mut RwTxn,
        body: &Body,
    ) -> Result<(), Error> {
        let merkle_root = body.compute_merkle_root();
        for (vout, output) in body.coinbase.iter().enumerate() {
            let outpoint = OutPoint::Coinbase {
                merkle_root,
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
            self.utxos.put(txn, &outpoint, &filled_output)?;
        }
        for transaction in &body.transactions {
            let filled_tx = self.fill_transaction(txn, transaction)?;
            let txid = filled_tx.txid();
            for input in filled_tx.inputs() {
                self.utxos.delete(txn, input)?;
            }
            let filled_outputs = filled_tx
                .filled_outputs()
                .ok_or(Error::FillTxOutputContentsFailed)?;
            for (vout, filled_output) in filled_outputs.iter().enumerate() {
                let outpoint = OutPoint::Regular {
                    txid,
                    vout: vout as u32,
                };
                self.utxos.put(txn, &outpoint, filled_output)?;
            }
            match &transaction.data {
                None => (),
                Some(TxData::BitNameReservation { commitment }) => {
                    self.bitname_reservations.put(txn, &txid, commitment)?;
                }
                Some(TxData::BitNameRegistration {
                    name_hash,
                    revealed_nonce: _,
                    bitname_data,
                }) => {
                    let () = self.apply_bitname_registration(
                        txn,
                        &filled_tx,
                        *name_hash,
                        bitname_data,
                    )?;
                }
                Some(TxData::BitNameUpdate(bitname_updates)) => {
                    let () = self.apply_bitname_updates(
                        txn,
                        &filled_tx,
                        (**bitname_updates).clone(),
                    )?;
                }
                Some(TxData::BatchIcann(batch_icann_data)) => {
                    let () = self.apply_batch_icann(
                        txn,
                        &filled_tx,
                        batch_icann_data,
                    )?;
                }
            }
        }
        Ok(())
    }
}