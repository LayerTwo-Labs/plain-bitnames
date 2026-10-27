//! Sidechain state as of the current sidechain tip

use std::collections::{HashMap, HashSet};

use fallible_iterator::FallibleIterator as _;
use heed::types::SerdeBincode;
use sneed::{
    DatabaseUnique, RoDatabaseUnique, RoTxn, RwTxn, UnitKey,
    db::error as db_error,
};

use crate::{
    types::{
        Address, AmountOverflowError, Authorized, AuthorizedTransaction,
        BlockHash, Body, CoinbaseTxid, FilledOutput, FilledTransaction,
        GetAddress as _, GetValue as _, Header, InPoint, M6id, MerkleRoot,
        OutPoint, OutPointKey, SpentOutput, Transaction, VERSION, Version,
        WithdrawalBundle, WithdrawalBundleStatus,
        authorization::{self, BatchVerificationContext},
        constants, hashes,
        proto::mainchain::TwoWayPegData,
        state::WithdrawalBundleInfo,
        transaction::outpoint::{COINBASE_MATURITY, DEPOSIT_MATURITY},
    },
    util::Watchable,
};

mod bitnames;
mod block;
pub mod error;
mod rollback;
mod two_way_peg_data;

pub use error::Error;
use rollback::{HeightStamped, RollBack};

/// Gap (in sidechain blocks) between an unsuccessful withdrawal bundle
/// (one that failed, or a stale pending bundle that was dropped without
/// being submitted) and the construction of the next bundle.
/// Also used as the submission timeout for pending bundles.
pub const WITHDRAWAL_BUNDLE_FAILURE_GAP: u32 = 4;

/// Prevalidated block data containing computed values from validation
/// to avoid redundant computation during connection
pub struct PrevalidatedBlock {
    pub filled_transactions: Vec<FilledTransaction>,
    pub computed_merkle_root: MerkleRoot,
    pub total_fees: bitcoin::Amount,
    pub coinbase_value: bitcoin::Amount,
    pub next_height: u32, // Precomputed next height to avoid DB read in write txn
}

type WithdrawalBundlesDb = DatabaseUnique<
    SerdeBincode<M6id>,
    SerdeBincode<(
        WithdrawalBundleInfo,
        RollBack<HeightStamped<WithdrawalBundleStatus>>,
    )>,
>;

#[derive(Clone)]
pub struct State {
    bitnames: bitnames::Dbs,
    /// Sidechain heights for each coinbase txid
    pub coinbase_height:
        DatabaseUnique<SerdeBincode<CoinbaseTxid>, SerdeBincode<u32>>,
    /// deposit blocks and the height at which they were applied, keyed sequentially
    deposit_blocks: DatabaseUnique<
        SerdeBincode<u32>,
        SerdeBincode<(bitcoin::BlockHash, u32)>,
    >,
    /// Mainchain heights for each deposit txid
    pub deposit_mainchain_height:
        DatabaseUnique<SerdeBincode<bitcoin::Txid>, SerdeBincode<u32>>,
    /// Dropped pending withdrawal bundles (most recent last)
    dropped_withdrawal_bundles:
        DatabaseUnique<UnitKey, SerdeBincode<RollBack<HeightStamped<M6id>>>>,
    /// Current height
    height: DatabaseUnique<UnitKey, SerdeBincode<u32>>,
    /// Latest failed (known) withdrawal bundle
    latest_failed_withdrawal_bundle:
        DatabaseUnique<UnitKey, SerdeBincode<RollBack<HeightStamped<M6id>>>>,
    /// Pending withdrawal bundle. MUST exist in withdrawal_bundles
    pending_withdrawal_bundle: DatabaseUnique<UnitKey, SerdeBincode<M6id>>,
    pub stxos: DatabaseUnique<OutPointKey, SerdeBincode<SpentOutput>>,
    /// Current tip
    tip: DatabaseUnique<UnitKey, SerdeBincode<BlockHash>>,
    pub utxos: DatabaseUnique<OutPointKey, SerdeBincode<FilledOutput>>,
    _version: DatabaseUnique<UnitKey, SerdeBincode<Version>>,
    /// withdrawal bundle event blocks and the height at which they were applied, keyed sequentially
    withdrawal_bundle_event_blocks: DatabaseUnique<
        SerdeBincode<u32>,
        SerdeBincode<(bitcoin::BlockHash, u32)>,
    >,
    /// Withdrawal bundles and their status.
    /// Some withdrawal bundles may be unknown.
    /// in which case they are `None`.
    withdrawal_bundles: WithdrawalBundlesDb,
}

impl State {
    pub const NUM_DBS: u32 = bitnames::Dbs::NUM_DBS + 13;

    pub fn new<Tls>(env: &sneed::Env<Tls>) -> Result<Self, Error> {
        let mut rwtxn = env.write_txn()?;
        let bitnames = bitnames::Dbs::new(env, &mut rwtxn)?;
        let coinbase_height =
            DatabaseUnique::create(env, &mut rwtxn, "coinbase_height")?;
        let deposit_blocks =
            DatabaseUnique::create(env, &mut rwtxn, "deposit_blocks")?;
        let deposit_mainchain_height = DatabaseUnique::create(
            env,
            &mut rwtxn,
            "deposit_mainchain_height",
        )?;
        let dropped_withdrawal_bundles = DatabaseUnique::create(
            env,
            &mut rwtxn,
            "dropped_withdrawal_bundles",
        )?;
        let height = DatabaseUnique::create(env, &mut rwtxn, "height")?;
        let latest_failed_withdrawal_bundle = DatabaseUnique::create(
            env,
            &mut rwtxn,
            "latest_failed_withdrawal_bundle",
        )?;
        let pending_withdrawal_bundle = DatabaseUnique::create(
            env,
            &mut rwtxn,
            "pending_withdrawal_bundle",
        )?;
        let stxos = DatabaseUnique::create(env, &mut rwtxn, "stxos")?;
        let tip = DatabaseUnique::create(env, &mut rwtxn, "tip")?;
        let utxos = DatabaseUnique::create(env, &mut rwtxn, "utxos")?;
        let version = DatabaseUnique::create(env, &mut rwtxn, "state_version")?;
        match version.try_get(&rwtxn, &())? {
            Some(db_version)
                if db_version
                    < Version {
                        major: 0,
                        minor: 19,
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
        };
        let withdrawal_bundle_event_blocks = DatabaseUnique::create(
            env,
            &mut rwtxn,
            "withdrawal_bundle_event_blocks",
        )?;
        let withdrawal_bundles =
            DatabaseUnique::create(env, &mut rwtxn, "withdrawal_bundles")?;
        rwtxn.commit()?;
        Ok(Self {
            bitnames,
            coinbase_height,
            deposit_blocks,
            deposit_mainchain_height,
            dropped_withdrawal_bundles,
            height,
            latest_failed_withdrawal_bundle,
            pending_withdrawal_bundle,
            stxos,
            tip,
            utxos,
            _version: version,
            withdrawal_bundle_event_blocks,
            withdrawal_bundles,
        })
    }

    pub fn bitnames(&self) -> &bitnames::Dbs {
        &self.bitnames
    }

    pub fn deposit_blocks(
        &self,
    ) -> &RoDatabaseUnique<
        SerdeBincode<u32>,
        SerdeBincode<(bitcoin::BlockHash, u32)>,
    > {
        &self.deposit_blocks
    }

    pub fn stxos(
        &self,
    ) -> &RoDatabaseUnique<OutPointKey, SerdeBincode<SpentOutput>> {
        &self.stxos
    }

    pub fn withdrawal_bundle_event_blocks(
        &self,
    ) -> &RoDatabaseUnique<
        SerdeBincode<u32>,
        SerdeBincode<(bitcoin::BlockHash, u32)>,
    > {
        &self.withdrawal_bundle_event_blocks
    }

    pub fn try_get_tip(
        &self,
        rotxn: &RoTxn,
    ) -> Result<Option<BlockHash>, Error> {
        let tip = self.tip.try_get(rotxn, &())?;
        Ok(tip)
    }

    pub fn try_get_height(&self, rotxn: &RoTxn) -> Result<Option<u32>, Error> {
        let height = self.height.try_get(rotxn, &())?;
        Ok(height)
    }

    pub fn get_stxos(
        &self,
        rotxn: &RoTxn,
    ) -> Result<HashMap<OutPoint, SpentOutput>, Error> {
        let stxos = self
            .stxos
            .iter(rotxn)?
            .map(|(outpoint_key, spent_output)| {
                Ok((outpoint_key.into(), spent_output))
            })
            .collect()?;
        Ok(stxos)
    }

    pub fn get_stxos_by_addresses(
        &self,
        rotxn: &RoTxn,
        addresses: &HashSet<Address>,
    ) -> Result<HashMap<OutPoint, SpentOutput>, db_error::Iter> {
        let stxos: HashMap<OutPoint, _> = self
            .stxos
            .iter(rotxn)?
            .filter_map(|(key, output)| {
                if addresses.contains(&output.output.address) {
                    Ok(Some((key.into(), output)))
                } else {
                    Ok(None)
                }
            })
            .collect()?;
        Ok(stxos)
    }

    pub fn get_utxos(
        &self,
        rotxn: &RoTxn,
    ) -> Result<HashMap<OutPoint, FilledOutput>, Error> {
        let utxos: HashMap<OutPoint, FilledOutput> = self
            .utxos
            .iter(rotxn)?
            .map(|(outpoint_key, output)| {
                Ok((OutPoint::from(outpoint_key), output))
            })
            .collect()?;
        Ok(utxos)
    }

    pub fn get_utxos_by_addresses(
        &self,
        rotxn: &RoTxn,
        addresses: &HashSet<Address>,
    ) -> Result<HashMap<OutPoint, FilledOutput>, Error> {
        let utxos: HashMap<OutPoint, FilledOutput> = self
            .utxos
            .iter(rotxn)?
            .filter(|(_, output)| Ok(addresses.contains(&output.address)))
            .map(|(outpoint_key, output)| {
                Ok((OutPoint::from(outpoint_key), output))
            })
            .collect()?;
        Ok(utxos)
    }

    /// Get the latest failed withdrawal bundle, and the height at which it failed
    pub fn get_latest_failed_withdrawal_bundle(
        &self,
        rotxn: &RoTxn,
    ) -> Result<Option<(u32, M6id)>, Error> {
        let Some(latest_failed_m6id) =
            self.latest_failed_withdrawal_bundle.try_get(rotxn, &())?
        else {
            return Ok(None);
        };
        let latest_failed_m6id = latest_failed_m6id.latest().value;
        let (_bundle, bundle_status) = self.withdrawal_bundles.try_get(rotxn, &latest_failed_m6id)?
            .unwrap_or_else(||
                panic!("Inconsistent DBs: latest failed m6id {latest_failed_m6id} should exist in withdrawal_bundles")
            );
        let failed_height = bundle_status
            .iter()
            .rev()
            .find_map(|status| match status.value {
                WithdrawalBundleStatus::Failed => Some(status.height),
                WithdrawalBundleStatus::Confirmed
                | WithdrawalBundleStatus::Dropped
                | WithdrawalBundleStatus::Pending
                | WithdrawalBundleStatus::Submitted
                | WithdrawalBundleStatus::SubmittedUnexpected => None,
            })
            .unwrap_or_else(|| {
                panic!("missing failure status for {latest_failed_m6id}")
            });
        Ok(Some((failed_height, latest_failed_m6id)))
    }

    pub fn try_get_withdrawal_bundle(
        &self,
        rotxn: &RoTxn,
        m6id: &M6id,
    ) -> Result<
        Option<(WithdrawalBundleInfo, WithdrawalBundleStatus)>,
        db_error::TryGet,
    > {
        let Some((bundle_info, bundle_status)) =
            self.withdrawal_bundles.try_get(rotxn, m6id)?
        else {
            return Ok(None);
        };
        Ok(Some((bundle_info, bundle_status.latest().value)))
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
                .try_get(rotxn, &OutPointKey::from(input))?
                .ok_or(error::NoUtxo { outpoint: *input })?;
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
                .try_get(rotxn, &OutPointKey::from(input))?
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

    /// Get pending withdrawal bundle and block height
    pub fn try_get_pending_withdrawal_bundle(
        &self,
        rotxn: &RoTxn,
    ) -> Result<Option<(WithdrawalBundle, u32)>, Error> {
        let Some(m6id) = self.pending_withdrawal_bundle.try_get(rotxn, &())?
        else {
            return Ok(None);
        };
        let (bundle_info, bundle_status) =
            self.withdrawal_bundles.get(rotxn, &m6id)?;
        let bundle = match bundle_info {
            WithdrawalBundleInfo::Known(bundle) => bundle,
            WithdrawalBundleInfo::Unknown
            | WithdrawalBundleInfo::UnknownConfirmed { spend_utxos: _ } => {
                return Err(error::PendingWithdrawalBundleUnknown(m6id).into());
            }
        };
        let height = bundle_status.latest().height;
        Ok(Some((bundle, height)))
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
            return Err(error::BitName::NoBitNamesToUpdate.into());
        };
        if let Some(batch_icann_data) = tx.batch_icann_data()
            && n_bitname_outputs < batch_icann_data.plain_names.len()
        {
            return Err(Error::TooFewBitNameOutputs);
        }
        if let Some(name_hash) = tx.registration_name_hash() {
            if self.bitnames.try_get_bitname(rotxn, &name_hash)?.is_some() {
                return Err(Error::BitNameAlreadyRegistered { name_hash });
            }
            // A registration must burn the reservation that commits to it,
            // i.e. a spent reservation whose commitment equals
            // keyed_hash(revealed_nonce, name_hash). Without this check,
            // `apply_registration` would later fail to find the reservation
            // to burn.
            if let Some(implied_commitment) =
                tx.implied_reservation_commitment()
            {
                let burns_matching_reservation =
                    tx.spent_reservations().any(|(_, filled_output)| {
                        filled_output.reservation_commitment()
                            == Some(&implied_commitment)
                    });
                if !burns_matching_reservation {
                    return Err(error::BitName::NoReservationForRegistration {
                        bitname: name_hash,
                    }
                    .into());
                }
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
            if !authorization::verify(
                &batch_icann_data.signature,
                &constants::BATCH_ICANN_VERIFYING_KEY,
                authorization::Dst::Arbitrary,
                &msg_hash,
            ) {
                return Err(Error::InvalidBatchIcannRegistrationSignature);
            }
        }
        Ok(())
    }

    fn validate_tx_input_maturity(
        &self,
        rotxn: &RoTxn,
        main_height: u32,
        outpoint: &OutPoint,
    ) -> Result<(), Error> {
        match outpoint {
            OutPoint::Coinbase { txid, vout: _ } => {
                let coinbase_height = self.coinbase_height.get(rotxn, txid)?;
                let spend_height =
                    self.try_get_height(rotxn)?.map_or(0, |height| height + 1);
                if let Some(height_diff) =
                    spend_height.checked_sub(coinbase_height)
                    && height_diff >= COINBASE_MATURITY
                {
                    Ok(())
                } else {
                    Err(error::ImmatureOutPoint::Coinbase.into())
                }
            }
            OutPoint::Deposit(bitcoin::OutPoint { txid, vout: _ }) => {
                let deposit_height =
                    self.deposit_mainchain_height.get(rotxn, txid)?;
                if let Some(height_diff) =
                    main_height.checked_sub(deposit_height)
                    && height_diff >= DEPOSIT_MATURITY
                {
                    Ok(())
                } else {
                    Err(error::ImmatureOutPoint::Deposit.into())
                }
            }
            OutPoint::Regular { .. }
            | OutPoint::UnsuccessfulWithdrawal { .. } => Ok(()),
        }
    }

    /// Validates a filled transaction, and returns the fee
    pub fn validate_filled_transaction(
        &self,
        rotxn: &RoTxn,
        main_height: u32,
        tx: &FilledTransaction,
    ) -> Result<bitcoin::Amount, Error> {
        let () = self.validate_reservations(tx)?;
        let () = self.validate_bitnames(rotxn, tx)?;
        let () = self.validate_batch_icann(tx)?;
        for outpoint in tx.inputs() {
            let () =
                self.validate_tx_input_maturity(rotxn, main_height, outpoint)?;
        }
        let fee = tx.fee()?;
        Ok(fee)
    }

    pub fn validate_transaction(
        &self,
        rotxn: &RoTxn,
        batch_verification_ctxt: &BatchVerificationContext,
        main_height: u32,
        transaction: &AuthorizedTransaction,
    ) -> Result<bitcoin::Amount, Error> {
        let filled_transaction =
            self.fill_transaction(rotxn, &transaction.transaction)?;
        // Pairing authorizations with spent UTXOs via `zip` silently ignores
        // trailing inputs when there are too few authorizations. Require an
        // exact count so that every input requiring authorization is covered.
        let n_authorizations_required =
            filled_transaction.spent_utxos_requiring_auth().len();
        if transaction.authorizations.len() != n_authorizations_required {
            return Err(Error::WrongNumberOfAuthorizations {
                expected: n_authorizations_required,
                received: transaction.authorizations.len(),
            });
        }
        for (authorization, spent_utxo) in transaction
            .authorizations
            .iter()
            .zip(filled_transaction.spent_utxos.iter())
        {
            if authorization.get_address() != spent_utxo.address {
                return Err(Error::WrongPubKeyForAddress);
            }
        }
        let () = authorization::verify_authorized_transaction(
            batch_verification_ctxt,
            transaction,
        )?;
        let fee = self.validate_filled_transaction(
            rotxn,
            main_height,
            &filled_transaction,
        )?;
        Ok(fee)
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

    /// Get total sidechain wealth in Bitcoin
    pub fn sidechain_wealth(
        &self,
        rotxn: &RoTxn,
    ) -> Result<bitcoin::Amount, Error> {
        // Outpoints that bring value into the sidechain: mainchain
        // deposits, and outputs recreated from unsuccessful withdrawal
        // bundles, which re-enter the sidechain's accounting there.
        fn is_inflow_outpoint(outpoint: &OutPoint) -> bool {
            matches!(
                outpoint,
                OutPoint::Deposit(_) | OutPoint::UnsuccessfulWithdrawal { .. }
            )
        }
        let mut total_inflow_utxo_value = bitcoin::Amount::ZERO;
        self.utxos.iter(rotxn)?.map_err(Error::from).for_each(
            |(outpoint_key, output)| {
                let outpoint: OutPoint = outpoint_key.into();
                if is_inflow_outpoint(&outpoint) {
                    total_inflow_utxo_value = total_inflow_utxo_value
                        .checked_add(output.get_value())
                        .ok_or(AmountOverflowError)?;
                }
                Ok::<_, Error>(())
            },
        )?;
        let mut total_inflow_stxo_value = bitcoin::Amount::ZERO;
        let mut total_withdrawal_stxo_value = bitcoin::Amount::ZERO;
        self.stxos.iter(rotxn)?.map_err(Error::from).for_each(
            |(outpoint_key, spent_output)| {
                let outpoint: OutPoint = outpoint_key.into();
                if is_inflow_outpoint(&outpoint) {
                    total_inflow_stxo_value = total_inflow_stxo_value
                        .checked_add(spent_output.output.get_value())
                        .ok_or(AmountOverflowError)?;
                }
                if let InPoint::Withdrawal { .. } = spent_output.inpoint {
                    total_withdrawal_stxo_value = total_withdrawal_stxo_value
                        .checked_add(spent_output.output.get_value())
                        .ok_or(AmountOverflowError)?;
                }
                Ok::<_, Error>(())
            },
        )?;

        let total_wealth: bitcoin::Amount = total_inflow_utxo_value
            .checked_add(total_inflow_stxo_value)
            .ok_or(AmountOverflowError)?
            .checked_sub(total_withdrawal_stxo_value)
            .ok_or(AmountOverflowError)?;
        Ok(total_wealth)
    }

    #[inline(always)]
    pub fn validate_block(
        &self,
        rotxn: &RoTxn,
        batch_verification_ctxt: &BatchVerificationContext,
        header: &Header,
        prev_main_height: u32,
        body: &Body,
    ) -> Result<(bitcoin::Amount, MerkleRoot), Error> {
        block::validate(
            batch_verification_ctxt,
            self,
            rotxn,
            header,
            prev_main_height,
            body,
        )
    }

    #[inline(always)]
    pub fn connect_block(
        &self,
        rwtxn: &mut RwTxn,
        header: &Header,
        body: &Body,
    ) -> Result<MerkleRoot, Error> {
        block::connect(self, rwtxn, header, body)
    }

    /// Prevalidate a block and return computed values for efficient connection
    #[inline(always)]
    pub fn prevalidate_block(
        &self,
        rotxn: &RoTxn,
        batch_verification_ctxt: &BatchVerificationContext,
        header: &Header,
        prev_main_height: u32,
        body: &Body,
    ) -> Result<PrevalidatedBlock, Error> {
        block::prevalidate(
            batch_verification_ctxt,
            self,
            rotxn,
            header,
            prev_main_height,
            body,
        )
    }

    /// Connect a block using prevalidated data to avoid recomputation.
    #[inline(always)]
    pub fn connect_prevalidated_block(
        &self,
        rwtxn: &mut RwTxn,
        header: &Header,
        body: &Body,
        prevalidated: PrevalidatedBlock,
    ) -> Result<MerkleRoot, Error> {
        block::connect_prevalidated(self, rwtxn, header, body, prevalidated)
    }

    /// Convenience: prevalidate then connect using the same write
    /// transaction, in production order: the block's transactions, then
    /// the header, then withdrawal bundle construction.
    /// 2WPD events MUST be connected BEFORE calling this function.
    pub fn apply_block(
        &self,
        rwtxn: &mut RwTxn,
        batch_verification_ctxt: &BatchVerificationContext,
        header: &Header,
        prev_main_height: u32,
        body: &Body,
    ) -> Result<(), Error> {
        let prevalidated = self.prevalidate_block(
            rwtxn,
            batch_verification_ctxt,
            header,
            prev_main_height,
            body,
        )?;
        let _: MerkleRoot =
            self.connect_prevalidated_block(rwtxn, header, body, prevalidated)?;
        let () = self.connect_header(rwtxn, header)?;
        let () = self.maybe_create_withdrawal_bundle(rwtxn)?;
        Ok(())
    }

    /// Connect a block header: update the tip, height, and coinbase
    /// height.
    /// MUST be applied AFTER the block's transactions, and BEFORE
    /// withdrawal bundle construction.
    pub fn connect_header(
        &self,
        rwtxn: &mut RwTxn,
        header: &Header,
    ) -> Result<(), Error> {
        block::connect_header(self, rwtxn, header)
    }

    /// Disconnect the tip block's body (txs and coinbase).
    /// The tip, height, and coinbase height are NOT rolled back here;
    /// see `disconnect_tip_header`.
    pub fn disconnect_tip_body(
        &self,
        rwtxn: &mut RwTxn,
        header: &Header,
        body: &Body,
    ) -> Result<(), Error> {
        block::disconnect_tip_body(self, rwtxn, header, body)
    }

    /// Disconnect the tip block's header: roll back the coinbase
    /// height, tip, and height.
    /// MUST be applied AFTER disconnecting the block's transactions and
    /// 2WPD.
    pub fn disconnect_tip_header(
        &self,
        rwtxn: &mut RwTxn,
        header: &Header,
    ) -> Result<(), Error> {
        block::disconnect_tip_header(self, rwtxn, header)
    }

    /// Connect 2WPD events (deposits, withdrawal bundle events, and
    /// dropping stale pending bundles).
    /// MUST be applied BEFORE the block's transactions.
    pub fn connect_two_way_peg_data(
        &self,
        rwtxn: &mut RwTxn,
        two_way_peg_data: &TwoWayPegData,
    ) -> Result<(), Error> {
        two_way_peg_data::connect(self, rwtxn, two_way_peg_data)
    }

    /// Disconnect 2WPD events.
    /// MUST be applied AFTER disconnecting the block's transactions.
    pub fn disconnect_two_way_peg_data(
        &self,
        rwtxn: &mut RwTxn,
        two_way_peg_data: &TwoWayPegData,
    ) -> Result<(), Error> {
        two_way_peg_data::disconnect(self, rwtxn, two_way_peg_data)
    }

    /// Construct a new pending withdrawal bundle if due, spending the
    /// selected withdrawal outputs.
    /// MUST be applied AFTER the block's transactions.
    pub fn maybe_create_withdrawal_bundle(
        &self,
        rwtxn: &mut RwTxn,
    ) -> Result<(), Error> {
        two_way_peg_data::maybe_create_withdrawal_bundle(self, rwtxn)
    }

    /// Undo a withdrawal bundle constructed at the current height,
    /// unspending its selected outputs.
    /// MUST be applied BEFORE disconnecting the block's transactions.
    pub fn disconnect_withdrawal_bundle_creation(
        &self,
        rwtxn: &mut RwTxn,
    ) -> Result<(), Error> {
        two_way_peg_data::disconnect_withdrawal_bundle_creation(self, rwtxn)
    }

    /// Check whether a stale pending bundle would be dropped while
    /// connecting 2WPD events at `block_height`.
    pub fn stale_pending_bundle_drop_due(
        &self,
        rotxn: &RoTxn,
        block_height: u32,
    ) -> Result<bool, Error> {
        let Some((_bundle, pending_height)) =
            self.try_get_pending_withdrawal_bundle(rotxn)?
        else {
            return Ok(false);
        };
        Ok(block_height - pending_height >= WITHDRAWAL_BUNDLE_FAILURE_GAP)
    }
}

impl Watchable<()> for State {
    type WatchStream = tokio_stream::wrappers::WatchStream<()>;

    /// Get a signal that notifies whenever the tip changes
    fn watch(&self) -> Self::WatchStream {
        tokio_stream::wrappers::WatchStream::new(self.tip.watch().clone())
    }
}

#[cfg(test)]
mod test {
    use crate::{
        state::{Error, State, error},
        types::{
            Address, AuthorizedTransaction, BitName, FilledOutput,
            FilledOutputContent, FilledTransaction, Hash, InPoint,
            MutableBitNameData, OutPoint, OutPointKey, Output, OutputContent,
            SpentOutput, Transaction, TxData, Txid,
            authorization::{
                self, BatchVerificationContext, SigningKey, VerifyingKey,
            },
        },
    };

    fn temp_dir(test_name: &str) -> anyhow::Result<temp_dir::TempDir> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let res = temp_dir::TempDir::with_prefix(format!(
            "bitnames-{test_name}-{}-{nanos}",
            std::process::id()
        ))?;
        Ok(res)
    }

    // open a fresh state-backed env in a unique temp dir
    pub fn temp_env(
        test_name: &str,
    ) -> anyhow::Result<(temp_dir::TempDir, sneed::Env)> {
        let temp_dir = temp_dir(test_name)?;
        let mut opts = heed::EnvOpenOptions::new();
        opts.map_size(64 * 1024 * 1024).max_dbs(State::NUM_DBS);
        let env = unsafe { sneed::Env::open(&opts, temp_dir.path()) }?;
        Ok((temp_dir, env))
    }

    pub fn fresh_state(
        test_name: &str,
    ) -> anyhow::Result<(temp_dir::TempDir, sneed::Env, State)> {
        let (temp_dir, env) = temp_env(test_name)?;
        let state = State::new(&env)?;
        Ok((temp_dir, env, state))
    }

    /// Create a bitcoin filled output
    pub fn bitcoin_filled_output(address: Address, sats: u64) -> FilledOutput {
        FilledOutput::new_bitcoin_value(
            address,
            bitcoin::Amount::from_sat(sats),
        )
    }

    /// Fund `address` with a single bitcoin UTXO of `value` sats, returning its
    /// outpoint.
    fn fund(
        env: &sneed::Env,
        state: &State,
        address: Address,
        value_sats: u64,
    ) -> OutPoint {
        let outpoint = OutPoint::Regular {
            txid: Default::default(),
            vout: 0,
        };
        let output = bitcoin_filled_output(address, value_sats);
        let mut rwtxn = env.write_txn().unwrap();
        state
            .utxos
            .put(&mut rwtxn, &OutPointKey::from(&outpoint), &output)
            .unwrap();
        rwtxn.commit().unwrap();
        outpoint
    }

    /// Build a BitName registration that registers `name_hash` with
    /// `revealed_nonce`, while spending a single reservation that commits to
    /// `reservation_commitment`.
    fn registration_tx(
        name_hash: BitName,
        revealed_nonce: Hash,
        reservation_commitment: Hash,
    ) -> FilledTransaction {
        let address = Address([0; 20]);
        let mut transaction = Transaction::new(
            vec![OutPoint::Regular {
                txid: Txid([0; 32]),
                vout: 0,
            }]
            .into(),
            vec![Output::new(address, OutputContent::BitName)].into(),
        );
        transaction.data = Some(TxData::BitNameRegistration {
            name_hash,
            revealed_nonce,
            bitname_data: Box::new(MutableBitNameData::default()),
        });
        let reservation = FilledOutput::new(
            address,
            FilledOutputContent::BitNameReservation(
                Txid([0; 32]),
                reservation_commitment,
            ),
        );
        FilledTransaction {
            transaction,
            spent_utxos: vec![reservation],
        }
    }

    /// A transaction that spends an input without supplying an authorization
    /// for it must be rejected. Otherwise the `zip` of authorizations and
    /// spent UTXOs silently skips the unauthorized input, allowing any UTXO to
    /// be spent without a signature.
    #[test]
    fn validate_transaction_rejects_missing_authorization() -> anyhow::Result<()>
    {
        let (_temp_dir, env, state) = fresh_state("auth_count")?;
        let mut rng = rand::rng();
        let batch_verification_ctxt = BatchVerificationContext::new(&mut rng);

        let signing_key = SigningKey::new(&mut rng);
        let verifying_key = VerifyingKey::from(&signing_key);
        let address = authorization::get_address(verifying_key);
        let outpoint = fund(&env, &state, address, 1000);

        let transaction = Transaction::new(
            vec![outpoint].into(),
            vec![bitcoin_filled_output(address, 900).into()].into(),
        );

        // The attack: spend the input while providing no authorization for it.
        let unauthorized = AuthorizedTransaction {
            transaction: transaction.clone(),
            authorizations: Vec::new(),
        };
        let rotxn = env.read_txn()?;
        let err = state
            .validate_transaction(
                &rotxn,
                &batch_verification_ctxt,
                0,
                &unauthorized,
            )
            .expect_err("tx with no authorizations must be rejected");
        anyhow::ensure!(
            matches!(
                err,
                Error::WrongNumberOfAuthorizations {
                    expected: 1,
                    received: 0
                }
            ),
            "unexpected error: {err:?}"
        );

        // The same transaction with a valid authorization is accepted.
        let authorized = authorization::authorize(
            rng,
            &[(address, &signing_key)],
            transaction,
        )?;
        state
            .validate_transaction(
                &rotxn,
                &batch_verification_ctxt,
                0,
                &authorized,
            )
            .expect("correctly authorized tx should validate");
        Ok(())
    }

    /// A registration whose spent reservation does not commit to the
    /// registered name must be rejected. Otherwise it passes validation and
    /// later panics in `apply_registration`, which fails to find the
    /// reservation to burn.
    #[test]
    fn validate_bitnames_rejects_registration_without_matching_reservation()
    -> anyhow::Result<()> {
        let (_temp_dir, env, state) = fresh_state("registration")?;
        let rotxn = env.read_txn()?;
        let name_hash = BitName([7; 32]);
        let revealed_nonce: Hash = [3; 32];
        let implied_commitment: Hash =
            blake3::keyed_hash(&revealed_nonce, &name_hash.0).into();

        // The reservation commits to something other than the registered name.
        let mismatched_commitment: Hash = [0; 32];
        assert_ne!(mismatched_commitment, implied_commitment);
        let tx =
            registration_tx(name_hash, revealed_nonce, mismatched_commitment);
        let err = state.validate_bitnames(&rotxn, &tx).expect_err(
            "registration without a matching reservation must be rejected",
        );
        anyhow::ensure!(
            matches!(
                err,
                Error::BitName(
                    error::BitName::NoReservationForRegistration { bitname }
                ) if bitname == name_hash
            ),
            "unexpected error: {err:?}"
        );

        // The same registration burning the matching reservation is accepted.
        let tx = registration_tx(name_hash, revealed_nonce, implied_commitment);
        state.validate_bitnames(&rotxn, &tx).expect(
            "registration burning the matching reservation should validate",
        );
        Ok(())
    }

    #[test]
    fn sidechain_wealth() -> anyhow::Result<()> {
        use std::str::FromStr;

        use bitcoin::hashes::Hash as _;

        let (_temp_dir, env, state) = fresh_state("sidechain-wealth")?;
        {
            let mut rwtxn = env.write_txn()?;

            // One unspent DEPOSIT UTXO: 50 sats.
            let deposit_utxo_op = OutPoint::Deposit(bitcoin::OutPoint {
                txid: bitcoin::Txid::from_str(
                    "0000000000000000000000000000000000000000000000000000000000000001",
                )?,
                vout: 0,
            });
            state.utxos.put(
                &mut rwtxn,
                &OutPointKey::from(&deposit_utxo_op),
                &bitcoin_filled_output(Address::ALL_ZEROS, 50),
            )?;

            // Two spent DEPOSIT STXOs: 100 + 100 sats.
            for (i, sats) in [(2u8, 100u64), (3u8, 100u64)] {
                let op = OutPoint::Deposit(bitcoin::OutPoint {
                    txid: bitcoin::Txid::from_byte_array([i; 32]),
                    vout: 0,
                });
                let stxo = SpentOutput {
                    output: bitcoin_filled_output(Address::ALL_ZEROS, sats),
                    inpoint: InPoint::Regular {
                        txid: [i; 32].into(),
                        vin: 0,
                    },
                };
                state
                    .stxos
                    .put(&mut rwtxn, &OutPointKey::from(&op), &stxo)?;
            }

            // Two WITHDRAWAL STXOs: 10 + 10 sats
            for (i, sats) in [(4u8, 10u64), (5u8, 10u64)] {
                let op = OutPoint::Regular {
                    txid: [i; 32].into(),
                    vout: 0,
                };
                let stxo = SpentOutput {
                    output: bitcoin_filled_output(Address::ALL_ZEROS, sats),
                    inpoint: InPoint::Withdrawal {
                        m6id: crate::types::M6id(
                            bitcoin::Txid::from_byte_array([i; 32]),
                        ),
                    },
                };
                state
                    .stxos
                    .put(&mut rwtxn, &OutPointKey::from(&op), &stxo)?;
            }

            rwtxn.commit()?;
        }

        let rotxn = env.read_txn()?;
        let sidechain_wealth = state.sidechain_wealth(&rotxn)?;

        // Correct value: deposit UTXO 50 + deposit STXOs 200 - withdrawal
        // STXOs 20 = 230 sats.
        let expected_sidechain_wealth = bitcoin::Amount::from_sat(230);
        anyhow::ensure!(
            sidechain_wealth == expected_sidechain_wealth,
            "Expected sidechain wealth ({}), but computed ({})",
            expected_sidechain_wealth,
            sidechain_wealth,
        );
        Ok(())
    }
}
