use std::collections::{BTreeMap, HashMap, HashSet};

use futures::Stream;
use heed::{types::SerdeBincode, Database, RoTxn, RwTxn};

use crate::{
    authorization::Authorization,
    types::{
        self, constants,
        hashes::{self, BitName},
        proto::mainchain::TwoWayPegData,
        Address, AggregatedWithdrawal, AmountOverflowError, Authorized,
        AuthorizedTransaction, BatchIcannRegistrationData, BitNameDataUpdates,
        BitNameSeqId, BlockHash, Body, FilledOutput, FilledOutputContent,
        FilledTransaction, GetAddress as _, GetValue as _, Hash, Header,
        InPoint, M6id, MerkleRoot, OutPoint, OutputContent, SpentOutput,
        Transaction, TxData, Txid, Verify as _, WithdrawalBundle,
        WithdrawalBundleStatus,
    },
    util::{EnvExt, UnitKey, Watchable, WatchableDb},
};

mod bitname_data;
pub mod error;
mod rollback;

use bitname_data::BitNameData;
pub use error::Error;
use rollback::{HeightStamped, RollBack};

pub const WITHDRAWAL_BUNDLE_FAILURE_GAP: u32 = 4;

type WithdrawalBundlesDb = Database<
    SerdeBincode<M6id>,
    SerdeBincode<(
        WithdrawalBundle,
        RollBack<HeightStamped<WithdrawalBundleStatus>>,
    )>,
>;

#[derive(Clone)]
pub struct State {
    /// Current tip
    tip: WatchableDb<SerdeBincode<UnitKey>, SerdeBincode<BlockHash>>,
    /// Current height
    height: Database<SerdeBincode<UnitKey>, SerdeBincode<u32>>,
    /// Associates tx hashes with bitname reservation commitments
    pub bitname_reservations: Database<SerdeBincode<Txid>, SerdeBincode<Hash>>,
    /// Associates BitName sequence numbers with BitName IDs (name hashes)
    pub bitname_seq_to_bitname: Database<BitNameSeqId, SerdeBincode<BitName>>,
    /// Associates bitname IDs (name hashes) with bitname data
    pub bitnames: Database<SerdeBincode<BitName>, SerdeBincode<BitNameData>>,
    pub utxos: Database<SerdeBincode<OutPoint>, SerdeBincode<FilledOutput>>,
    pub stxos: Database<SerdeBincode<OutPoint>, SerdeBincode<SpentOutput>>,
    /// Pending withdrawal bundle and block height
    pub pending_withdrawal_bundle:
        Database<SerdeBincode<UnitKey>, SerdeBincode<(WithdrawalBundle, u32)>>,
    latest_failed_withdrawal_bundle: Database<
        SerdeBincode<UnitKey>,
        SerdeBincode<RollBack<HeightStamped<M6id>>>,
    >,
    withdrawal_bundles: WithdrawalBundlesDb,
    /// deposit blocks and the height at which they were applied, keyed sequentially
    pub deposit_blocks:
        Database<SerdeBincode<u32>, SerdeBincode<(bitcoin::BlockHash, u32)>>,
    /// withdrawal bundle event blocks and the height at which they were applied, keyed sequentially
    pub withdrawal_bundle_event_blocks:
        Database<SerdeBincode<u32>, SerdeBincode<(bitcoin::BlockHash, u32)>>,
}

impl State {
    pub const NUM_DBS: u32 = 12;

    pub fn new(env: &heed::Env) -> Result<Self, Error> {
        let mut rwtxn = env.write_txn()?;
        let tip = env.create_watchable_db(&mut rwtxn, "tip")?;
        let height = env.create_database(&mut rwtxn, Some("height"))?;
        let bitname_reservations =
            env.create_database(&mut rwtxn, Some("bitname_reservations"))?;
        let bitname_seq_to_bitname =
            env.create_database(&mut rwtxn, Some("bitname_seq_to_bitname"))?;
        let bitnames = env.create_database(&mut rwtxn, Some("bitnames"))?;
        let utxos = env.create_database(&mut rwtxn, Some("utxos"))?;
        let stxos = env.create_database(&mut rwtxn, Some("stxos"))?;
        let pending_withdrawal_bundle =
            env.create_database(&mut rwtxn, Some("pending_withdrawal_bundle"))?;
        let latest_failed_withdrawal_bundle = env.create_database(
            &mut rwtxn,
            Some("latest_failed_withdrawal_bundle"),
        )?;
        let withdrawal_bundles =
            env.create_database(&mut rwtxn, Some("withdrawal_bundles"))?;
        let deposit_blocks =
            env.create_database(&mut rwtxn, Some("deposit_blocks"))?;
        let withdrawal_bundle_event_blocks = env.create_database(
            &mut rwtxn,
            Some("withdrawal_bundle_event_blocks"),
        )?;
        rwtxn.commit()?;
        Ok(Self {
            tip,
            height,
            bitname_reservations,
            bitname_seq_to_bitname,
            bitnames,
            utxos,
            stxos,
            pending_withdrawal_bundle,
            latest_failed_withdrawal_bundle,
            withdrawal_bundles,
            withdrawal_bundle_event_blocks,
            deposit_blocks,
        })
    }

    pub fn try_get_tip(
        &self,
        rotxn: &RoTxn,
    ) -> Result<Option<BlockHash>, Error> {
        let tip = self.tip.try_get(rotxn, &UnitKey)?;
        Ok(tip)
    }

    pub fn try_get_height(&self, rotxn: &RoTxn) -> Result<Option<u32>, Error> {
        let height = self.height.get(rotxn, &UnitKey)?;
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
    pub fn get_latest_failed_withdrawal_bundle(
        &self,
        rotxn: &RoTxn,
    ) -> Result<Option<(u32, WithdrawalBundle)>, Error> {
        let Some(latest_failed_m6id) =
            self.latest_failed_withdrawal_bundle.get(rotxn, &UnitKey)?
        else {
            return Ok(None);
        };
        let latest_failed_m6id = latest_failed_m6id.latest().value;
        let (bundle, bundle_status) = self.withdrawal_bundles.get(rotxn, &latest_failed_m6id)?
            .expect("Inconsistent DBs: latest failed m6id should exist in withdrawal_bundles");
        let bundle_status = bundle_status.latest();
        assert_eq!(bundle_status.value, WithdrawalBundleStatus::Failed);
        Ok(Some((bundle_status.height, bundle)))
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
                        value: bitcoin::Amount::ZERO,
                        main_fee: bitcoin::Amount::ZERO,
                    });
                // Add up all values.
                aggregated.value = aggregated
                    .value
                    .checked_add(value)
                    .ok_or(AmountOverflowError)?;
                aggregated.main_fee = aggregated
                    .main_fee
                    .checked_add(main_fee)
                    .ok_or(AmountOverflowError)?;
                aggregated.spend_utxos.insert(outpoint, output);
            }
        }
        if address_to_aggregated_withdrawal.is_empty() {
            return Ok(None);
        }
        let mut aggregated_withdrawals: Vec<_> =
            address_to_aggregated_withdrawal.into_values().collect();
        aggregated_withdrawals.sort_by_key(|a| std::cmp::Reverse(a.clone()));
        let mut fee = bitcoin::Amount::ZERO;
        let mut spend_utxos = BTreeMap::<OutPoint, FilledOutput>::new();
        let mut bundle_outputs = vec![];
        for aggregated in &aggregated_withdrawals {
            if bundle_outputs.len() > MAX_BUNDLE_OUTPUTS {
                break;
            }
            let bundle_output = bitcoin::TxOut {
                value: aggregated.value,
                script_pubkey: aggregated
                    .main_address
                    .assume_checked_ref()
                    .script_pubkey(),
            };
            spend_utxos.extend(aggregated.spend_utxos.clone());
            bundle_outputs.push(bundle_output);
            fee += aggregated.main_fee;
        }
        let bundle = WithdrawalBundle::new(
            block_height,
            fee,
            spend_utxos,
            bundle_outputs,
        )?;
        if bundle.tx().weight().to_wu()
            > bitcoin::policy::MAX_STANDARD_TX_WEIGHT as u64
        {
            Err(Error::BundleTooHeavy {
                weight: bundle.tx().weight().to_wu(),
                max_weight: bitcoin::policy::MAX_STANDARD_TX_WEIGHT as u64,
            })?;
        }
        Ok(Some(bundle))
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
                .0
                .verify_strict(&msg_hash, &batch_icann_data.signature)?;
        }
        Ok(())
    }

    /// Validates a filled transaction, and returns the fee
    pub fn validate_filled_transaction(
        &self,
        rotxn: &RoTxn,
        tx: &FilledTransaction,
    ) -> Result<bitcoin::Amount, Error> {
        let () = self.validate_reservations(tx)?;
        let () = self.validate_bitnames(rotxn, tx)?;
        let () = self.validate_batch_icann(tx)?;
        tx.fee()?.ok_or(Error::NotEnoughValueIn)
    }

    pub fn validate_transaction(
        &self,
        rotxn: &RoTxn,
        transaction: &AuthorizedTransaction,
    ) -> Result<bitcoin::Amount, Error> {
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
    ) -> Result<(bitcoin::Amount, MerkleRoot), Error> {
        let tip_hash = self.try_get_tip(rotxn)?;
        if header.prev_side_hash != tip_hash {
            let err = error::InvalidHeader::PrevSideHash {
                expected: tip_hash,
                received: header.prev_side_hash,
            };
            return Err(Error::InvalidHeader(err));
        };
        let mut coinbase_value = bitcoin::Amount::ZERO;
        for output in &body.coinbase {
            coinbase_value = coinbase_value
                .checked_add(output.get_value())
                .ok_or(AmountOverflowError)?;
        }
        let mut total_fees = bitcoin::Amount::ZERO;
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
            total_fees = total_fees
                .checked_add(
                    self.validate_filled_transaction(rotxn, filled_tx)?,
                )
                .ok_or(AmountOverflowError)?;
        }
        if coinbase_value > total_fees {
            return Err(Error::NotEnoughFees);
        }
        let merkle_root = Body::compute_merkle_root(
            body.coinbase.as_slice(),
            filled_txs.as_slice(),
        )?
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

    pub fn get_last_withdrawal_bundle_event_block_hash(
        &self,
        rotxn: &RoTxn,
    ) -> Result<Option<bitcoin::BlockHash>, Error> {
        let block_hash = self
            .withdrawal_bundle_event_blocks
            .last(rotxn)?
            .map(|(_, (block_hash, _))| block_hash);
        Ok(block_hash)
    }

    pub fn connect_two_way_peg_data(
        &self,
        rwtxn: &mut RwTxn,
        two_way_peg_data: &TwoWayPegData,
    ) -> Result<(), Error> {
        let block_height = self.try_get_height(rwtxn)?.ok_or(Error::NoTip)?;
        tracing::trace!(%block_height, "Connecting 2WPD...");
        // Handle deposits.
        if let Some(latest_deposit_block_hash) =
            two_way_peg_data.latest_deposit_block_hash()
        {
            let deposit_block_seq_idx = self
                .deposit_blocks
                .last(rwtxn)?
                .map_or(0, |(seq_idx, _)| seq_idx + 1);
            self.deposit_blocks.put(
                rwtxn,
                &deposit_block_seq_idx,
                &(latest_deposit_block_hash, block_height),
            )?;
        }
        for deposit in two_way_peg_data
            .deposits()
            .flat_map(|(_, deposits)| deposits)
        {
            let outpoint = OutPoint::Deposit(deposit.outpoint);
            let output = deposit.output.clone();
            self.utxos.put(rwtxn, &outpoint, &output)?;
        }

        // Handle withdrawals
        if let Some(latest_withdrawal_bundle_event_block_hash) =
            two_way_peg_data.latest_withdrawal_bundle_event_block_hash()
        {
            let withdrawal_bundle_event_block_seq_idx = self
                .withdrawal_bundle_event_blocks
                .last(rwtxn)?
                .map_or(0, |(seq_idx, _)| seq_idx + 1);
            self.withdrawal_bundle_event_blocks.put(
                rwtxn,
                &withdrawal_bundle_event_block_seq_idx,
                &(*latest_withdrawal_bundle_event_block_hash, block_height),
            )?;
        }
        let last_withdrawal_bundle_failure_height = self
            .get_latest_failed_withdrawal_bundle(rwtxn)?
            .map(|(height, _bundle)| height)
            .unwrap_or_default();
        if block_height - last_withdrawal_bundle_failure_height
            >= WITHDRAWAL_BUNDLE_FAILURE_GAP
            && self
                .pending_withdrawal_bundle
                .get(rwtxn, &UnitKey)?
                .is_none()
        {
            if let Some(bundle) =
                self.collect_withdrawal_bundle(rwtxn, block_height)?
            {
                let m6id = bundle.compute_m6id();
                self.pending_withdrawal_bundle.put(
                    rwtxn,
                    &UnitKey,
                    &(bundle, block_height),
                )?;
                tracing::trace!(
                    %block_height,
                    %m6id,
                    "Stored pending withdrawal bundle"
                );
            }
        }
        for (_, event) in two_way_peg_data.withdrawal_bundle_events() {
            match event.status {
                WithdrawalBundleStatus::Submitted => {
                    let Some((bundle, bundle_block_height)) =
                        self.pending_withdrawal_bundle.get(rwtxn, &UnitKey)?
                    else {
                        if let Some((_bundle, bundle_status)) =
                            self.withdrawal_bundles.get(rwtxn, &event.m6id)?
                        {
                            // Already applied
                            assert_eq!(
                                bundle_status.earliest().value,
                                WithdrawalBundleStatus::Submitted
                            );
                            continue;
                        }
                        return Err(Error::UnknownWithdrawalBundle {
                            m6id: event.m6id,
                        });
                    };
                    assert_eq!(bundle_block_height, block_height - 1);
                    if bundle.compute_m6id() != event.m6id {
                        return Err(Error::UnknownWithdrawalBundle {
                            m6id: event.m6id,
                        });
                    }
                    tracing::debug!(
                        %block_height,
                        m6id = %event.m6id,
                        "Withdrawal bundle successfully submitted"
                    );
                    for (outpoint, spend_output) in bundle.spend_utxos() {
                        self.utxos.delete(rwtxn, outpoint)?;
                        let spent_output = SpentOutput {
                            output: spend_output.clone(),
                            inpoint: InPoint::Withdrawal { m6id: event.m6id },
                        };
                        self.stxos.put(rwtxn, outpoint, &spent_output)?;
                    }
                    self.withdrawal_bundles.put(
                        rwtxn,
                        &event.m6id,
                        &(
                            bundle,
                            RollBack::<HeightStamped<_>>::new(
                                WithdrawalBundleStatus::Submitted,
                                block_height,
                            ),
                        ),
                    )?;
                    self.pending_withdrawal_bundle.delete(rwtxn, &UnitKey)?;
                }
                WithdrawalBundleStatus::Confirmed => {
                    let Some((bundle, mut bundle_status)) =
                        self.withdrawal_bundles.get(rwtxn, &event.m6id)?
                    else {
                        return Err(Error::UnknownWithdrawalBundle {
                            m6id: event.m6id,
                        });
                    };
                    if bundle_status.latest().value
                        == WithdrawalBundleStatus::Confirmed
                    {
                        // Already applied
                        continue;
                    } else {
                        assert_eq!(
                            bundle_status.latest().value,
                            WithdrawalBundleStatus::Submitted
                        );
                    }
                    bundle_status
                        .push(WithdrawalBundleStatus::Confirmed, block_height)
                        .expect("Push confirmed status should be valid");
                    self.withdrawal_bundles.put(
                        rwtxn,
                        &event.m6id,
                        &(bundle, bundle_status),
                    )?;
                }
                WithdrawalBundleStatus::Failed => {
                    tracing::debug!(
                        %block_height,
                        m6id = %event.m6id,
                        "Handling failed withdrawal bundle");
                    let Some((bundle, mut bundle_status)) =
                        self.withdrawal_bundles.get(rwtxn, &event.m6id)?
                    else {
                        return Err(Error::UnknownWithdrawalBundle {
                            m6id: event.m6id,
                        });
                    };
                    if bundle_status.latest().value
                        == WithdrawalBundleStatus::Failed
                    {
                        // Already applied
                        continue;
                    } else {
                        assert_eq!(
                            bundle_status.latest().value,
                            WithdrawalBundleStatus::Submitted
                        );
                    }
                    bundle_status
                        .push(WithdrawalBundleStatus::Failed, block_height)
                        .expect("Push failed status should be valid");
                    for (outpoint, output) in bundle.spend_utxos() {
                        self.stxos.delete(rwtxn, outpoint)?;
                        self.utxos.put(rwtxn, outpoint, output)?;
                    }
                    let latest_failed_m6id =
                        if let Some(mut latest_failed_m6id) = self
                            .latest_failed_withdrawal_bundle
                            .get(rwtxn, &UnitKey)?
                        {
                            latest_failed_m6id
                                .push(event.m6id, block_height)
                                .expect(
                                    "Push latest failed m6id should be valid",
                                );
                            latest_failed_m6id
                        } else {
                            RollBack::<HeightStamped<_>>::new(
                                event.m6id,
                                block_height,
                            )
                        };
                    self.latest_failed_withdrawal_bundle.put(
                        rwtxn,
                        &UnitKey,
                        &latest_failed_m6id,
                    )?;
                    self.withdrawal_bundles.put(
                        rwtxn,
                        &event.m6id,
                        &(bundle, bundle_status),
                    )?;
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
        let block_height = self
            .try_get_height(rwtxn)?
            .expect("Height should not be None");
        // Restore pending withdrawal bundle
        for (_, event) in two_way_peg_data.withdrawal_bundle_events().rev() {
            match event.status {
                WithdrawalBundleStatus::Submitted => {
                    let Some((bundle, bundle_status)) =
                        self.withdrawal_bundles.get(rwtxn, &event.m6id)?
                    else {
                        if let Some((bundle, _)) = self
                            .pending_withdrawal_bundle
                            .get(rwtxn, &UnitKey)?
                            && bundle.compute_m6id() == event.m6id
                        {
                            // Already applied
                            continue;
                        }
                        return Err(Error::UnknownWithdrawalBundle {
                            m6id: event.m6id,
                        });
                    };
                    let bundle_status = bundle_status.latest();
                    assert_eq!(
                        bundle_status.value,
                        WithdrawalBundleStatus::Submitted
                    );
                    assert_eq!(bundle_status.height, block_height);
                    for (outpoint, output) in bundle.spend_utxos().iter().rev()
                    {
                        if !self.stxos.delete(rwtxn, outpoint)? {
                            return Err(Error::NoStxo {
                                outpoint: *outpoint,
                            });
                        };
                        self.utxos.put(rwtxn, outpoint, output)?;
                    }
                    self.pending_withdrawal_bundle.put(
                        rwtxn,
                        &UnitKey,
                        &(bundle, bundle_status.height - 1),
                    )?;
                    self.withdrawal_bundles.delete(rwtxn, &event.m6id)?;
                }
                WithdrawalBundleStatus::Confirmed => {
                    let Some((bundle, bundle_status)) =
                        self.withdrawal_bundles.get(rwtxn, &event.m6id)?
                    else {
                        return Err(Error::UnknownWithdrawalBundle {
                            m6id: event.m6id,
                        });
                    };
                    let (prev_bundle_status, latest_bundle_status) =
                        bundle_status.pop();
                    if latest_bundle_status.value
                        == WithdrawalBundleStatus::Submitted
                    {
                        // Already applied
                        continue;
                    } else {
                        assert_eq!(
                            latest_bundle_status.value,
                            WithdrawalBundleStatus::Confirmed
                        );
                    }
                    assert_eq!(latest_bundle_status.height, block_height);
                    let prev_bundle_status = prev_bundle_status
                        .expect("Pop confirmed bundle status should be valid");
                    assert_eq!(
                        prev_bundle_status.latest().value,
                        WithdrawalBundleStatus::Submitted
                    );
                    self.withdrawal_bundles.put(
                        rwtxn,
                        &event.m6id,
                        &(bundle, prev_bundle_status),
                    )?;
                }
                WithdrawalBundleStatus::Failed => {
                    let Some((bundle, bundle_status)) =
                        self.withdrawal_bundles.get(rwtxn, &event.m6id)?
                    else {
                        return Err(Error::UnknownWithdrawalBundle {
                            m6id: event.m6id,
                        });
                    };
                    let (prev_bundle_status, latest_bundle_status) =
                        bundle_status.pop();
                    if latest_bundle_status.value
                        == WithdrawalBundleStatus::Submitted
                    {
                        // Already applied
                        continue;
                    } else {
                        assert_eq!(
                            latest_bundle_status.value,
                            WithdrawalBundleStatus::Failed
                        );
                    }
                    assert_eq!(latest_bundle_status.height, block_height);
                    let prev_bundle_status = prev_bundle_status
                        .expect("Pop failed bundle status should be valid");
                    assert_eq!(
                        prev_bundle_status.latest().value,
                        WithdrawalBundleStatus::Submitted
                    );
                    for (outpoint, output) in bundle.spend_utxos().iter().rev()
                    {
                        let spent_output = SpentOutput {
                            output: output.clone(),
                            inpoint: InPoint::Withdrawal { m6id: event.m6id },
                        };
                        self.stxos.put(rwtxn, outpoint, &spent_output)?;
                        if self.utxos.delete(rwtxn, outpoint)? {
                            return Err(Error::NoUtxo {
                                outpoint: *outpoint,
                            });
                        };
                    }
                    self.withdrawal_bundles.put(
                        rwtxn,
                        &event.m6id,
                        &(bundle, prev_bundle_status),
                    )?;
                    let (prev_latest_failed_m6id, latest_failed_m6id) = self
                        .latest_failed_withdrawal_bundle
                        .get(rwtxn, &UnitKey)?
                        .expect("latest failed withdrawal bundle should exist")
                        .pop();
                    assert_eq!(latest_failed_m6id.value, event.m6id);
                    assert_eq!(latest_failed_m6id.height, block_height);
                    if let Some(prev_latest_failed_m6id) =
                        prev_latest_failed_m6id
                    {
                        self.latest_failed_withdrawal_bundle.put(
                            rwtxn,
                            &UnitKey,
                            &prev_latest_failed_m6id,
                        )?;
                    } else {
                        self.latest_failed_withdrawal_bundle
                            .delete(rwtxn, &UnitKey)?;
                    }
                }
            }
        }
        // Handle withdrawals
        if let Some(latest_withdrawal_bundle_event_block_hash) =
            two_way_peg_data.latest_withdrawal_bundle_event_block_hash()
        {
            let (
                last_withdrawal_bundle_event_block_seq_idx,
                (
                    last_withdrawal_bundle_event_block_hash,
                    last_withdrawal_bundle_event_block_height,
                ),
            ) = self
                .withdrawal_bundle_event_blocks
                .last(rwtxn)?
                .ok_or(Error::NoWithdrawalBundleEventBlock)?;
            assert_eq!(
                *latest_withdrawal_bundle_event_block_hash,
                last_withdrawal_bundle_event_block_hash
            );
            assert_eq!(
                block_height - 1,
                last_withdrawal_bundle_event_block_height
            );
            if !self
                .deposit_blocks
                .delete(rwtxn, &last_withdrawal_bundle_event_block_seq_idx)?
            {
                return Err(Error::NoWithdrawalBundleEventBlock);
            };
        }
        let last_withdrawal_bundle_failure_height = self
            .get_latest_failed_withdrawal_bundle(rwtxn)?
            .map(|(height, _bundle)| height)
            .unwrap_or_default();
        if block_height - last_withdrawal_bundle_failure_height
            > WITHDRAWAL_BUNDLE_FAILURE_GAP
            && let Some((bundle, bundle_height)) =
                self.pending_withdrawal_bundle.get(rwtxn, &UnitKey)?
            && bundle_height == block_height - 1
        {
            self.pending_withdrawal_bundle.delete(rwtxn, &UnitKey)?;
            for (outpoint, output) in bundle.spend_utxos().iter().rev() {
                if !self.stxos.delete(rwtxn, outpoint)? {
                    return Err(Error::NoStxo {
                        outpoint: *outpoint,
                    });
                };
                self.utxos.put(rwtxn, outpoint, output)?;
            }
        }
        // Handle deposits
        if let Some(latest_deposit_block_hash) =
            two_way_peg_data.latest_deposit_block_hash()
        {
            let (
                last_deposit_block_seq_idx,
                (last_deposit_block_hash, last_deposit_block_height),
            ) = self
                .deposit_blocks
                .last(rwtxn)?
                .ok_or(Error::NoDepositBlock)?;
            assert_eq!(latest_deposit_block_hash, last_deposit_block_hash);
            assert_eq!(block_height - 1, last_deposit_block_height);
            if !self
                .deposit_blocks
                .delete(rwtxn, &last_deposit_block_seq_idx)?
            {
                return Err(Error::NoDepositBlock);
            };
        }
        for deposit in two_way_peg_data
            .deposits()
            .flat_map(|(_, deposits)| deposits)
            .rev()
        {
            let outpoint = OutPoint::Deposit(deposit.outpoint);
            if !self.utxos.delete(rwtxn, &outpoint)? {
                return Err(Error::NoUtxo { outpoint });
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
        bitname_data: &types::MutableBitNameData,
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
        let next_seq_id = self
            .bitname_seq_to_bitname
            .last(rwtxn)?
            .map(|(seq, _)| seq.next())
            .unwrap_or(BitNameSeqId::new(0));
        self.bitname_seq_to_bitname
            .put(rwtxn, &next_seq_id, &name_hash)?;
        let bitname_data = BitNameData::init(
            bitname_data.clone(),
            filled_tx.txid(),
            height,
            next_seq_id,
        );
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
        let (last_seq_id, latest_registered_bitname) = self
            .bitname_seq_to_bitname
            .last(rwtxn)?
            .expect("A registered bitname should have a seq id");
        assert_eq!(latest_registered_bitname, name_hash);
        self.bitname_seq_to_bitname.delete(rwtxn, &last_seq_id)?;

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
        let height = self.try_get_height(rwtxn)?.map_or(0, |height| height + 1);
        let tip_hash = self.try_get_tip(rwtxn)?;
        if tip_hash != header.prev_side_hash {
            let err = error::InvalidHeader::PrevSideHash {
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
                OutputContent::Bitcoin(value) => {
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
        )?
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
        self.height.put(rwtxn, &UnitKey, &height)?;
        Ok(merkle_root)
    }

    pub fn disconnect_tip(
        &self,
        rwtxn: &mut RwTxn,
        header: &Header,
        body: &Body,
    ) -> Result<(), Error> {
        let tip_hash =
            self.tip.try_get(rwtxn, &UnitKey)?.ok_or(Error::NoTip)?;
        if tip_hash != header.hash() {
            let err = error::InvalidHeader::BlockHash {
                expected: tip_hash,
                computed: header.hash(),
            };
            return Err(Error::InvalidHeader(err));
        }
        let height = self
            .try_get_height(rwtxn)?
            .expect("Height should not be None");
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
        )?
        .ok_or(Error::MerkleRoot)?;
        if merkle_root != header.merkle_root {
            let err = Error::InvalidBody {
                expected: header.merkle_root,
                computed: merkle_root,
            };
            return Err(err);
        }
        match (header.prev_side_hash, height) {
            (None, 0) => {
                self.tip.delete(rwtxn, &UnitKey)?;
                self.height.delete(rwtxn, &UnitKey)?;
            }
            (None, _) | (_, 0) => return Err(Error::NoTip),
            (Some(prev_side_hash), height) => {
                self.tip.put(rwtxn, &UnitKey, &prev_side_hash)?;
                self.height.put(rwtxn, &UnitKey, &(height - 1))?;
            }
        }
        Ok(())
    }

    /// Get total sidechain wealth in Bitcoin
    pub fn sidechain_wealth(
        &self,
        rotxn: &RoTxn,
    ) -> Result<bitcoin::Amount, Error> {
        let mut total_deposit_utxo_value = bitcoin::Amount::ZERO;
        self.utxos.iter(rotxn)?.try_for_each(|utxo| {
            let (outpoint, output) = utxo?;
            if let OutPoint::Deposit(_) = outpoint {
                total_deposit_utxo_value = total_deposit_utxo_value
                    .checked_add(output.get_value())
                    .ok_or(AmountOverflowError)?;
            }
            Ok::<_, Error>(())
        })?;
        let mut total_deposit_stxo_value = bitcoin::Amount::ZERO;
        let mut total_withdrawal_stxo_value = bitcoin::Amount::ZERO;
        self.stxos.iter(rotxn)?.try_for_each(|stxo| {
            let (outpoint, spent_output) = stxo?;
            if let OutPoint::Deposit(_) = outpoint {
                total_deposit_stxo_value = total_deposit_stxo_value
                    .checked_add(spent_output.output.get_value())
                    .ok_or(AmountOverflowError)?;
            }
            if let InPoint::Withdrawal { .. } = spent_output.inpoint {
                total_withdrawal_stxo_value = total_deposit_stxo_value
                    .checked_add(spent_output.output.get_value())
                    .ok_or(AmountOverflowError)?;
            }
            Ok::<_, Error>(())
        })?;

        let total_wealth: bitcoin::Amount = total_deposit_utxo_value
            .checked_add(total_deposit_stxo_value)
            .ok_or(AmountOverflowError)?
            .checked_sub(total_withdrawal_stxo_value)
            .ok_or(AmountOverflowError)?;
        Ok(total_wealth)
    }
}

impl Watchable<()> for State {
    type WatchStream = impl Stream<Item = ()>;

    /// Get a signal that notifies whenever the tip changes
    fn watch(&self) -> Self::WatchStream {
        tokio_stream::wrappers::WatchStream::new(self.tip.watch())
    }
}
