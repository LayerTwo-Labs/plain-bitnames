//! Connect and disconnect two-way peg data

use std::collections::{BTreeMap, HashMap};

use fallible_iterator::FallibleIterator;
use sneed::{RoTxn, RwTxn};

use crate::{
    state::{
        Error, State, WITHDRAWAL_BUNDLE_FAILURE_GAP, WithdrawalBundleInfo,
        error,
        rollback::{HeightStamped, RollBack},
    },
    types::{
        AggregatedWithdrawal, AmountOverflowError, FilledOutput,
        FilledOutputContent, InPoint, M6id, OutPoint, OutPointKey, SpentOutput,
        WithdrawalBundle, WithdrawalBundleEvent, WithdrawalBundleEventStatus,
        WithdrawalBundleStatus, WithdrawalOutputContent,
        proto::mainchain::{BlockEvent, TwoWayPegData},
    },
};

/// Check whether a new withdrawal bundle should be constructed at
/// `block_height`: the failure gap has passed since the latest
/// unsuccessful (failed or dropped) bundle, and no bundle is pending.
pub(crate) fn withdrawal_bundle_creation_due(
    state: &State,
    rotxn: &RoTxn,
    block_height: u32,
) -> Result<bool, Error> {
    let last_failure_height = state
        .get_latest_failed_withdrawal_bundle(rotxn)?
        .map(|(height, _bundle)| height)
        .unwrap_or_default();
    let last_drop_height = state
        .dropped_withdrawal_bundles
        .try_get(rotxn, &())?
        .map(|dropped| dropped.latest().height)
        .unwrap_or_default();
    let last_unsuccessful_height = last_failure_height.max(last_drop_height);
    Ok(
        block_height - last_unsuccessful_height
            >= WITHDRAWAL_BUNDLE_FAILURE_GAP
            && state
                .pending_withdrawal_bundle
                .try_get(rotxn, &())?
                .is_none(),
    )
}

/// Aggregate one candidate withdrawal output by destination:
/// destination -> (value, mainchain fee, spent_utxos)
pub(crate) fn aggregate_withdrawal(
    address_to_aggregated_withdrawal: &mut HashMap<
        bitcoin::Address<bitcoin::address::NetworkUnchecked>,
        AggregatedWithdrawal,
    >,
    outpoint: OutPoint,
    output: FilledOutput,
) -> Result<(), Error> {
    if let FilledOutputContent::BitcoinWithdrawal(WithdrawalOutputContent {
        value,
        ref main_address,
        main_fee,
    }) = output.content
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
    Ok(())
}

/// Select and build a withdrawal bundle from withdrawals aggregated by
/// destination, ordered by fee density (highest first).
pub(crate) fn bundle_from_aggregated(
    address_to_aggregated_withdrawal: HashMap<
        bitcoin::Address<bitcoin::address::NetworkUnchecked>,
        AggregatedWithdrawal,
    >,
    block_height: u32,
) -> Result<Option<WithdrawalBundle>, Error> {
    if address_to_aggregated_withdrawal.is_empty() {
        return Ok(None);
    }
    let mut aggregated_withdrawals: Vec<_> =
        address_to_aggregated_withdrawal.into_values().collect();
    aggregated_withdrawals.sort_by_key(|a| std::cmp::Reverse(a.clone()));
    let mut fee = bitcoin::Amount::ZERO;
    let mut spend_utxos = BTreeMap::<OutPoint, FilledOutput>::new();
    let mut bundle_outputs = Vec::new();
    let mut bundle_txouts_size: u32 = 0;
    for aggregated in &aggregated_withdrawals {
        let script_pubkey =
            aggregated.main_address.assume_checked_ref().script_pubkey();
        let Ok(n_outputs) = u32::try_from(bundle_outputs.len() + 1) else {
            break;
        };
        let Ok(spk_size) = u32::try_from(script_pubkey.len()) else {
            // This SPK is invalid, but others might be ok
            continue;
        };
        let Some(txout_size) = WithdrawalBundle::txout_size(spk_size) else {
            // This SPK is invalid, but others might be ok
            continue;
        };
        if let Some(sum_txout_sizes) =
            bundle_txouts_size.checked_add(txout_size)
        {
            bundle_txouts_size = sum_txout_sizes;
        } else {
            break;
        };
        if WithdrawalBundle::predict_weight(n_outputs, bundle_txouts_size)
            .is_none()
        {
            break;
        }
        let bundle_output = bitcoin::TxOut {
            value: aggregated.value,
            script_pubkey,
        };
        spend_utxos.extend(aggregated.spend_utxos.clone());
        bundle_outputs.push(bundle_output);
        fee += aggregated.main_fee;
    }
    let bundle =
        WithdrawalBundle::new(block_height, fee, spend_utxos, bundle_outputs)?;
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

/// Collect the withdrawal outputs that a new bundle would spend,
/// aggregating while iterating over the DB entries.
fn collect_withdrawal_bundle(
    state: &State,
    rotxn: &RoTxn,
    block_height: u32,
) -> Result<Option<WithdrawalBundle>, Error> {
    let mut aggregated = HashMap::new();
    let mut candidates = state.utxos.iter(rotxn)?;
    while let Some((outpoint_key, output)) = candidates.next()? {
        aggregate_withdrawal(&mut aggregated, outpoint_key.into(), output)?;
    }
    bundle_from_aggregated(aggregated, block_height)
}

/// Recreate the outputs spent by an unsuccessful (failed or dropped)
/// withdrawal bundle as new UTXOs at `OutPoint::UnsuccessfulWithdrawal`
/// outpoints.
/// The original outputs remain spent by the bundle; their STXO records are
/// untouched.
fn recreate_bundle_outputs(
    state: &State,
    rwtxn: &mut RwTxn,
    block_height: u32,
    m6id: M6id,
    bundle: &WithdrawalBundle,
) -> Result<(), Error> {
    for (vout, (_outpoint, output)) in bundle.spend_utxos().iter().enumerate() {
        let vout = u32::try_from(vout).expect("bundle outputs fit in u32");
        let recreated_outpoint = OutPoint::UnsuccessfulWithdrawal {
            m6id,
            height: block_height,
            vout,
        };
        state.utxos.put(
            rwtxn,
            &OutPointKey::from(&recreated_outpoint),
            output,
        )?;
    }
    Ok(())
}

/// Delete the outputs recreated from an unsuccessful (failed or
/// dropped) withdrawal bundle, last-to-first. The original outputs
/// remain spent by the bundle; their STXO records are untouched.
fn delete_recreated_outputs(
    state: &State,
    rwtxn: &mut RwTxn,
    block_height: u32,
    m6id: M6id,
    bundle: &WithdrawalBundle,
) -> Result<(), Error> {
    for vout in 0..bundle.spend_utxos().len() {
        let recreated_outpoint = OutPoint::UnsuccessfulWithdrawal {
            m6id,
            height: block_height,
            vout: vout as u32,
        };
        let recreated_key = OutPointKey::from(&recreated_outpoint);
        if !state.utxos.delete(rwtxn, &recreated_key)? {
            return Err(error::NoUtxo {
                outpoint: recreated_outpoint,
            }
            .into());
        }
    }
    Ok(())
}

/// Drop a stale pending withdrawal bundle: if it was not submitted
/// within `WITHDRAWAL_BUNDLE_FAILURE_GAP` blocks, mark it dropped and
/// recreate its outputs, so that the block's transactions can spend
/// them and, if unspent, they can be included in the fresh bundle
/// constructed after the block's transactions.
fn maybe_drop_stale_pending_bundle(
    state: &State,
    rwtxn: &mut RwTxn,
    block_height: u32,
) -> Result<(), Error> {
    let Some(m6id) = state.pending_withdrawal_bundle.try_get(rwtxn, &())?
    else {
        return Ok(());
    };
    let (bundle, mut bundle_status) =
        state.withdrawal_bundles.get(rwtxn, &m6id)?;
    debug_assert_eq!(
        bundle_status.latest().value,
        WithdrawalBundleStatus::Pending
    );
    let pending_height = bundle_status.latest().height;
    if block_height - pending_height < WITHDRAWAL_BUNDLE_FAILURE_GAP {
        return Ok(());
    }
    let bundle = match bundle {
        WithdrawalBundleInfo::Known(bundle) => bundle,
        WithdrawalBundleInfo::Unknown
        | WithdrawalBundleInfo::UnknownConfirmed { .. } => {
            return Err(error::PendingWithdrawalBundleUnknown(m6id).into());
        }
    };
    recreate_bundle_outputs(state, rwtxn, block_height, m6id, &bundle)?;
    state.pending_withdrawal_bundle.delete(rwtxn, &())?;
    bundle_status
        .push(WithdrawalBundleStatus::Dropped, block_height)
        .expect("push dropped status should be valid");
    state.withdrawal_bundles.put(
        rwtxn,
        &m6id,
        &(WithdrawalBundleInfo::Known(bundle), bundle_status),
    )?;
    // Record the drop so that it can be found again on disconnect.
    let dropped = if let Some(mut dropped) =
        state.dropped_withdrawal_bundles.try_get(rwtxn, &())?
    {
        dropped
            .push(m6id, block_height)
            .expect("push dropped m6id should be valid");
        dropped
    } else {
        RollBack::<HeightStamped<_>>::new(m6id, block_height)
    };
    state.dropped_withdrawal_bundles.put(rwtxn, &(), &dropped)?;
    tracing::warn!(
        %block_height,
        %m6id,
        "Pending withdrawal bundle dropped: not submitted in time"
    );
    Ok(())
}

/// Undo a stale-bundle drop performed at `block_height`, if any:
/// delete the recreated outputs and restore the pending marker.
/// Drops are connected after the block's events, so they are undone
/// before disconnecting the events.
fn disconnect_dropped_bundle(
    state: &State,
    rwtxn: &mut RwTxn,
    block_height: u32,
) -> Result<(), Error> {
    let Some(dropped) = state.dropped_withdrawal_bundles.try_get(rwtxn, &())?
    else {
        return Ok(());
    };
    if dropped.latest().height != block_height {
        return Ok(());
    }
    let m6id = dropped.latest().value;
    let (prev_dropped, _latest_dropped) = dropped.pop();
    if let Some(prev_dropped) = prev_dropped {
        state
            .dropped_withdrawal_bundles
            .put(rwtxn, &(), &prev_dropped)?;
    } else {
        state.dropped_withdrawal_bundles.delete(rwtxn, &())?;
    }
    let (bundle, bundle_status) = state
        .withdrawal_bundles
        .try_get(rwtxn, &m6id)?
        .ok_or(Error::UnknownWithdrawalBundle { m6id })?;
    let (prev_bundle_status, latest_bundle_status) = bundle_status.pop();
    assert_eq!(latest_bundle_status.value, WithdrawalBundleStatus::Dropped);
    assert_eq!(latest_bundle_status.height, block_height);
    let prev_bundle_status =
        prev_bundle_status.expect("pop dropped bundle status should be valid");
    assert_eq!(
        prev_bundle_status.latest().value,
        WithdrawalBundleStatus::Pending
    );
    let bundle = match bundle {
        WithdrawalBundleInfo::Known(bundle) => bundle,
        WithdrawalBundleInfo::Unknown
        | WithdrawalBundleInfo::UnknownConfirmed { .. } => {
            return Err(error::PendingWithdrawalBundleUnknown(m6id).into());
        }
    };
    delete_recreated_outputs(state, rwtxn, block_height, m6id, &bundle)?;
    state.pending_withdrawal_bundle.put(rwtxn, &(), &m6id)?;
    state.withdrawal_bundles.put(
        rwtxn,
        &m6id,
        &(WithdrawalBundleInfo::Known(bundle), prev_bundle_status),
    )?;
    Ok(())
}

fn connect_withdrawal_bundle_submitted(
    state: &State,
    rwtxn: &mut RwTxn,
    block_height: u32,
    event_block_hash: &bitcoin::BlockHash,
    m6id: M6id,
) -> Result<(), error::ConnectWithdrawalBundleSubmitted> {
    if let Some(bundle_m6id) =
        state.pending_withdrawal_bundle.try_get(rwtxn, &())?
        && bundle_m6id == m6id
    {
        tracing::debug!(
            %block_height,
            %m6id,
            "Pending withdrawal bundle submission confirmed"
        );
        let (bundle, mut bundle_status) = state
            .withdrawal_bundles
            .try_get(rwtxn, &m6id)?
            .ok_or(error::PendingWithdrawalBundleUnknown(m6id))?;
        let bundle = match bundle {
            WithdrawalBundleInfo::Known(bundle) => bundle,
            WithdrawalBundleInfo::Unknown
            | WithdrawalBundleInfo::UnknownConfirmed { spend_utxos: _ } => {
                let err = error::PendingWithdrawalBundleUnknown(m6id);
                return Err(err.into());
            }
        };
        // The bundle's spend_utxos were already spent when the bundle
        // was created; only the status changes here.
        for outpoint in bundle.spend_utxos().keys() {
            debug_assert!(
                state
                    .utxos
                    .try_get(rwtxn, &OutPointKey::from(outpoint))?
                    .is_none(),
                "pending bundle output {outpoint} should already be spent"
            );
        }
        assert_eq!(
            bundle_status.latest().value,
            WithdrawalBundleStatus::Pending
        );
        bundle_status
            .push(WithdrawalBundleStatus::Submitted, block_height)
            .expect("push submitted status should be valid");
        state.withdrawal_bundles.put(
            rwtxn,
            &m6id,
            &(WithdrawalBundleInfo::Known(bundle), bundle_status),
        )?;
        state.pending_withdrawal_bundle.delete(rwtxn, &())?;
    } else if let Some((bundle, mut bundle_status)) =
        state.withdrawal_bundles.try_get(rwtxn, &m6id)?
    {
        match (&bundle, bundle_status.latest().value) {
            (_, WithdrawalBundleStatus::Confirmed) => {
                let err = error::ConnectWithdrawalBundleSubmitted::ConfirmedResubmitted {
                    event_block_hash: *event_block_hash,
                    m6id
                };
                return Err(err);
            }
            (
                _,
                WithdrawalBundleStatus::Submitted
                | WithdrawalBundleStatus::SubmittedUnexpected,
            ) => {
                let err =
                    error::ConnectWithdrawalBundleSubmitted::Resubmitted {
                        event_block_hash: *event_block_hash,
                        m6id,
                        submitted_block_height: bundle_status.latest().height,
                    };
                return Err(err);
            }
            (
                WithdrawalBundleInfo::Known(_),
                WithdrawalBundleStatus::Dropped,
            ) => {
                tracing::warn!(%event_block_hash, %m6id, "dropped bundle submitted");
            }
            (
                WithdrawalBundleInfo::Unknown
                | WithdrawalBundleInfo::UnknownConfirmed { spend_utxos: _ },
                WithdrawalBundleStatus::Dropped,
            ) => {
                let err =
                    error::ConnectWithdrawalBundleSubmitted::UnknownDropped {
                        m6id,
                        dropped_block_height: bundle_status.latest().height,
                    };
                return Err(err);
            }
            (
                WithdrawalBundleInfo::Known(_),
                WithdrawalBundleStatus::Pending,
            ) => {
                let err =
                    error::ConnectWithdrawalBundleSubmitted::DroppedPending(
                        m6id,
                    );
                return Err(err);
            }
            (
                WithdrawalBundleInfo::Unknown
                | WithdrawalBundleInfo::UnknownConfirmed { spend_utxos: _ },
                WithdrawalBundleStatus::Pending,
            ) => {
                let err =
                    error::ConnectWithdrawalBundleSubmitted::UnknownPending {
                        m6id,
                        pending_block_height: bundle_status.latest().height,
                    };
                return Err(err);
            }
            (
                WithdrawalBundleInfo::Known(_) | WithdrawalBundleInfo::Unknown,
                WithdrawalBundleStatus::Failed,
            ) => {
                tracing::warn!(%event_block_hash, %m6id, "failed bundle resubmitted");
            }
            (
                WithdrawalBundleInfo::UnknownConfirmed { spend_utxos: _ },
                WithdrawalBundleStatus::Failed,
            ) => {
                let err = error::ConnectWithdrawalBundleSubmitted::UnknownConfirmedFailed {
                    m6id,
                    failed_block_height: bundle_status.latest().height,
                };
                return Err(err);
            }
        }
        bundle_status
            .push(WithdrawalBundleStatus::SubmittedUnexpected, block_height)
            .expect("push submitted unexpected status should be valid");
        state
            .withdrawal_bundles
            .put(rwtxn, &m6id, &(bundle, bundle_status))?
    } else {
        tracing::warn!(
            %event_block_hash,
            %m6id,
            "Unknown withdrawal bundle submitted"
        );
        state.withdrawal_bundles.put(
            rwtxn,
            &m6id,
            &(
                WithdrawalBundleInfo::Unknown,
                RollBack::<HeightStamped<_>>::new(
                    WithdrawalBundleStatus::Submitted,
                    block_height,
                ),
            ),
        )?;
    };
    Ok(())
}

fn connect_withdrawal_bundle_confirmed(
    state: &State,
    rwtxn: &mut RwTxn,
    block_height: u32,
    event_block_hash: &bitcoin::BlockHash,
    m6id: M6id,
) -> Result<(), Error> {
    let (mut bundle, mut bundle_status) = state
        .withdrawal_bundles
        .try_get(rwtxn, &m6id)?
        .ok_or(Error::UnknownWithdrawalBundle { m6id })?;
    if bundle_status.latest().value == WithdrawalBundleStatus::Confirmed {
        // Already applied
        return Ok(());
    }
    assert!(matches!(
        bundle_status.latest().value,
        WithdrawalBundleStatus::Submitted
            | WithdrawalBundleStatus::SubmittedUnexpected
    ));
    match &bundle {
        WithdrawalBundleInfo::UnknownConfirmed { spend_utxos: _ } => {
            return Err(Error::UnknownWithdrawalBundleReconfirmed {
                event_block_hash: *event_block_hash,
                m6id,
            });
        }
        WithdrawalBundleInfo::Unknown => {
            // If an unknown bundle is confirmed, all UTXOs older than the
            // bundle submission are potentially spent.
            // This is only accepted in the case that block height is 0,
            // and so no UTXOs could possibly have been double-spent yet.
            // In this case, ALL UTXOs are considered spent.
            if block_height == 0 {
                tracing::warn!(
                    %event_block_hash,
                    %m6id,
                    "Unknown withdrawal bundle confirmed, marking all UTXOs as spent"
                );
                let utxos: BTreeMap<OutPoint, FilledOutput> = state
                    .utxos
                    .iter(rwtxn)
                    .map_err(Error::from)?
                    .map(|(key, output)| Ok((key.into(), output)))
                    .collect()?;
                for (outpoint, output) in &utxos {
                    let spent_output = SpentOutput {
                        output: output.clone(),
                        inpoint: InPoint::Withdrawal { m6id },
                    };
                    state.stxos.put(
                        rwtxn,
                        &OutPointKey::from(outpoint),
                        &spent_output,
                    )?;
                }
                state.utxos.clear(rwtxn)?;
                bundle = WithdrawalBundleInfo::UnknownConfirmed {
                    spend_utxos: utxos,
                };
            } else {
                return Err(Error::UnknownWithdrawalBundleConfirmed {
                    event_block_hash: *event_block_hash,
                    m6id,
                });
            }
        }
        WithdrawalBundleInfo::Known(_) => {
            if matches!(
                bundle_status.latest().value,
                WithdrawalBundleStatus::SubmittedUnexpected
            ) {
                // A previously failed or dropped bundle was confirmed.
                // Its outputs were already spent when it was created,
                // and recreated when it became unsuccessful; confirming
                // it would pay the mainchain without removing the
                // recreated claims.
                return Err(Error::UnexpectedWithdrawalBundleConfirmed {
                    event_block_hash: *event_block_hash,
                    m6id,
                });
            }
        }
    }
    bundle_status
        .push(WithdrawalBundleStatus::Confirmed, block_height)
        .expect("Push confirmed status should be valid");
    state
        .withdrawal_bundles
        .put(rwtxn, &m6id, &(bundle, bundle_status))?;
    Ok(())
}

fn connect_withdrawal_bundle_failed(
    state: &State,
    rwtxn: &mut RwTxn,
    block_height: u32,
    m6id: M6id,
) -> Result<(), Error> {
    tracing::debug!(
        %block_height,
        %m6id,
        "Handling failed withdrawal bundle");
    let (bundle, mut bundle_status) = state
        .withdrawal_bundles
        .try_get(rwtxn, &m6id)?
        .ok_or_else(|| Error::UnknownWithdrawalBundle { m6id })?;
    if bundle_status.latest().value == WithdrawalBundleStatus::Failed {
        // Already applied
        return Ok(());
    }
    assert!(matches!(
        bundle_status.latest().value,
        WithdrawalBundleStatus::Submitted
            | WithdrawalBundleStatus::SubmittedUnexpected
    ));
    match &bundle {
        WithdrawalBundleInfo::Unknown
        | WithdrawalBundleInfo::UnknownConfirmed { .. } => (),
        WithdrawalBundleInfo::Known(bundle) => 'known: {
            if matches!(
                bundle_status.latest().value,
                WithdrawalBundleStatus::SubmittedUnexpected
            ) {
                break 'known;
            }
            // Recreate the spent outputs at outpoints derived from the
            // failed bundle's M6ID and the current block height, so
            // that they are spendable again (e.g. to cancel the
            // withdrawal). The original outputs remain spent by the
            // bundle.
            let () = recreate_bundle_outputs(
                state,
                rwtxn,
                block_height,
                m6id,
                bundle,
            )?;
            let latest_failed_m6id = if let Some(mut latest_failed_m6id) =
                state.latest_failed_withdrawal_bundle.try_get(rwtxn, &())?
            {
                latest_failed_m6id
                    .push(m6id, block_height)
                    .expect("Push latest failed m6id should be valid");
                latest_failed_m6id
            } else {
                RollBack::<HeightStamped<_>>::new(m6id, block_height)
            };
            state.latest_failed_withdrawal_bundle.put(
                rwtxn,
                &(),
                &latest_failed_m6id,
            )?;
        }
    }
    bundle_status
        .push(WithdrawalBundleStatus::Failed, block_height)
        .expect("Push failed status should be valid");
    state
        .withdrawal_bundles
        .put(rwtxn, &m6id, &(bundle, bundle_status))?;
    Ok(())
}

fn connect_withdrawal_bundle_event(
    state: &State,
    rwtxn: &mut RwTxn,
    block_height: u32,
    event_block_hash: &bitcoin::BlockHash,
    event: &WithdrawalBundleEvent,
) -> Result<(), Error> {
    match event.status {
        WithdrawalBundleEventStatus::Submitted => {
            connect_withdrawal_bundle_submitted(
                state,
                rwtxn,
                block_height,
                event_block_hash,
                event.m6id,
            )
            .map_err(Error::ConnectWithdrawalBundleSubmitted)
        }
        WithdrawalBundleEventStatus::Confirmed => {
            connect_withdrawal_bundle_confirmed(
                state,
                rwtxn,
                block_height,
                event_block_hash,
                event.m6id,
            )
        }
        WithdrawalBundleEventStatus::Failed => {
            connect_withdrawal_bundle_failed(
                state,
                rwtxn,
                block_height,
                event.m6id,
            )
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn connect_2wpd_event(
    state: &State,
    rwtxn: &mut RwTxn,
    block_height: u32,
    latest_deposit_block_hash: &mut Option<bitcoin::BlockHash>,
    latest_withdrawal_bundle_event_block_hash: &mut Option<bitcoin::BlockHash>,
    event_block_hash: bitcoin::BlockHash,
    event_block_height: u32,
    event: &BlockEvent,
) -> Result<(), Error> {
    match event {
        BlockEvent::Deposit(deposit) => {
            state.deposit_mainchain_height.put(
                rwtxn,
                &deposit.outpoint.txid,
                &event_block_height,
            )?;
            let outpoint = OutPoint::Deposit(deposit.outpoint);
            let output = deposit.output.clone();
            state
                .utxos
                .put(rwtxn, &OutPointKey::from(&outpoint), &output)?;
            *latest_deposit_block_hash = Some(event_block_hash);
        }
        BlockEvent::WithdrawalBundle(withdrawal_bundle_event) => {
            let () = connect_withdrawal_bundle_event(
                state,
                rwtxn,
                block_height,
                &event_block_hash,
                withdrawal_bundle_event,
            )?;
            *latest_withdrawal_bundle_event_block_hash = Some(event_block_hash);
        }
    }
    Ok(())
}

pub fn connect(
    state: &State,
    rwtxn: &mut RwTxn,
    two_way_peg_data: &TwoWayPegData,
) -> Result<(), Error> {
    // 2WPD is connected BEFORE the block's transactions; the block
    // being connected is one higher than the current tip (0 at
    // genesis).
    let block_height =
        state.try_get_height(rwtxn)?.map_or(0, |height| height + 1);
    tracing::trace!(%block_height, "Connecting 2WPD...");
    // Handle deposits.
    let mut latest_deposit_block_hash = None;
    let mut latest_withdrawal_bundle_event_block_hash = None;
    for (event_block_hash, event_block_info) in &two_way_peg_data.block_info {
        for event in &event_block_info.inner.events {
            let () = connect_2wpd_event(
                state,
                rwtxn,
                block_height,
                &mut latest_deposit_block_hash,
                &mut latest_withdrawal_bundle_event_block_hash,
                *event_block_hash,
                event_block_info.height,
                event,
            )?;
        }
    }
    // Handle deposits.
    if let Some(latest_deposit_block_hash) = latest_deposit_block_hash {
        let deposit_block_seq_idx = state
            .deposit_blocks
            .last(rwtxn)?
            .map_or(0, |(seq_idx, _)| seq_idx + 1);
        state.deposit_blocks.put(
            rwtxn,
            &deposit_block_seq_idx,
            &(latest_deposit_block_hash, block_height),
        )?;
    }
    // Handle withdrawals
    if let Some(latest_withdrawal_bundle_event_block_hash) =
        latest_withdrawal_bundle_event_block_hash
    {
        let withdrawal_bundle_event_block_seq_idx = state
            .withdrawal_bundle_event_blocks
            .last(rwtxn)?
            .map_or(0, |(seq_idx, _)| seq_idx + 1);
        state.withdrawal_bundle_event_blocks.put(
            rwtxn,
            &withdrawal_bundle_event_block_seq_idx,
            &(latest_withdrawal_bundle_event_block_hash, block_height),
        )?;
    }
    // Drop a stale pending bundle: if it was not submitted within
    // WITHDRAWAL_BUNDLE_FAILURE_GAP blocks, recreate its outputs so
    // that this block's txs can spend them and, if unspent, they can
    // be included in the fresh bundle constructed after this block's
    // txs.
    let () = maybe_drop_stale_pending_bundle(state, rwtxn, block_height)?;
    Ok(())
}

/// Construct a new pending withdrawal bundle if due, spending the
/// selected withdrawal outputs.
/// MUST be applied AFTER the block's transactions have been connected.
pub fn maybe_create_withdrawal_bundle(
    state: &State,
    rwtxn: &mut RwTxn,
) -> Result<(), Error> {
    let block_height = state.try_get_height(rwtxn)?.ok_or(Error::NoTip)?;
    if !withdrawal_bundle_creation_due(state, rwtxn, block_height)? {
        return Ok(());
    }
    let Some(bundle) = collect_withdrawal_bundle(state, rwtxn, block_height)?
    else {
        return Ok(());
    };
    let m6id = bundle.compute_m6id();
    // Spend the selected outputs.
    for (outpoint, output) in bundle.spend_utxos() {
        let key = OutPointKey::from(outpoint);
        if !state.utxos.delete(rwtxn, &key)? {
            return Err(error::NoUtxo {
                outpoint: *outpoint,
            }
            .into());
        }
        let spent_output = SpentOutput {
            output: output.clone(),
            inpoint: InPoint::Withdrawal { m6id },
        };
        state.stxos.put(rwtxn, &key, &spent_output)?;
    }
    state.pending_withdrawal_bundle.put(rwtxn, &(), &m6id)?;
    let bundle_status = if let Some((_bundle, mut bundle_status)) =
        state.withdrawal_bundles.try_get(rwtxn, &m6id)?
    {
        bundle_status
            .push(WithdrawalBundleStatus::Pending, block_height)
            .expect("push pending status should be valid");
        bundle_status
    } else {
        RollBack::<HeightStamped<_>>::new(
            WithdrawalBundleStatus::Pending,
            block_height,
        )
    };
    state.withdrawal_bundles.put(
        rwtxn,
        &m6id,
        &(WithdrawalBundleInfo::Known(bundle), bundle_status),
    )?;
    tracing::trace!(
        %block_height,
        %m6id,
        "Stored pending withdrawal bundle"
    );
    Ok(())
}

fn disconnect_withdrawal_bundle_submitted(
    state: &State,
    rwtxn: &mut RwTxn,
    block_height: u32,
    m6id: M6id,
) -> Result<(), Error> {
    let Some((bundle, bundle_status)) =
        state.withdrawal_bundles.try_get(rwtxn, &m6id)?
    else {
        if let Some(pending_bundle_m6id) =
            state.pending_withdrawal_bundle.try_get(rwtxn, &())?
            && pending_bundle_m6id == m6id
        {
            // Already applied
            return Ok(());
        } else {
            return Err(Error::UnknownWithdrawalBundle { m6id });
        }
    };
    let (bundle_status, latest_bundle_status) = bundle_status.pop();
    assert!(matches!(
        latest_bundle_status.value,
        WithdrawalBundleStatus::Submitted
            | WithdrawalBundleStatus::SubmittedUnexpected
    ));
    assert_eq!(latest_bundle_status.height, block_height);
    match &bundle {
        WithdrawalBundleInfo::Unknown
        | WithdrawalBundleInfo::UnknownConfirmed { .. } => (),
        WithdrawalBundleInfo::Known(_bundle) => {
            if let Some(bundle_status) = &bundle_status
                && bundle_status.latest().value
                    == WithdrawalBundleStatus::Pending
            {
                // The bundle's outputs remain spent; only the pending
                // marker is restored.
                state.pending_withdrawal_bundle.put(rwtxn, &(), &m6id)?;
            }
        }
    }
    if let Some(bundle_status) = bundle_status {
        state
            .withdrawal_bundles
            .put(rwtxn, &m6id, &(bundle, bundle_status))?;
    } else {
        state.withdrawal_bundles.delete(rwtxn, &m6id)?;
    }
    Ok(())
}

fn disconnect_withdrawal_bundle_confirmed(
    state: &State,
    rwtxn: &mut RwTxn,
    block_height: u32,
    m6id: M6id,
) -> Result<(), Error> {
    let (mut bundle, bundle_status) = state
        .withdrawal_bundles
        .try_get(rwtxn, &m6id)?
        .ok_or_else(|| Error::UnknownWithdrawalBundle { m6id })?;
    let (prev_bundle_status, latest_bundle_status) = bundle_status.pop();
    if matches!(
        latest_bundle_status.value,
        WithdrawalBundleStatus::Submitted
            | WithdrawalBundleStatus::SubmittedUnexpected
    ) {
        // Already applied
        return Ok(());
    }
    assert_eq!(
        latest_bundle_status.value,
        WithdrawalBundleStatus::Confirmed
    );
    assert_eq!(latest_bundle_status.height, block_height);
    let prev_bundle_status = prev_bundle_status
        .expect("Pop confirmed bundle status should be valid");
    assert!(matches!(
        prev_bundle_status.latest().value,
        WithdrawalBundleStatus::Submitted
            | WithdrawalBundleStatus::SubmittedUnexpected
    ));
    match &bundle {
        // Confirming a known bundle never changes the UTXO set: its
        // outputs were already spent when it was created. Confirming an
        // unexpected bundle is an error on connect, so it can never
        // need disconnecting.
        WithdrawalBundleInfo::Known(_) => (),
        WithdrawalBundleInfo::UnknownConfirmed { spend_utxos } => {
            for (outpoint, output) in spend_utxos {
                let outpoint_key = OutPointKey::from(outpoint);
                state.utxos.put(rwtxn, &outpoint_key, output)?;
                if !state.stxos.delete(rwtxn, &outpoint_key)? {
                    return Err(Error::NoStxo {
                        outpoint: *outpoint,
                    });
                };
            }
            bundle = WithdrawalBundleInfo::Unknown;
        }
        WithdrawalBundleInfo::Unknown => (),
    }
    state.withdrawal_bundles.put(
        rwtxn,
        &m6id,
        &(bundle, prev_bundle_status),
    )?;
    Ok(())
}

fn disconnect_withdrawal_bundle_failed(
    state: &State,
    rwtxn: &mut RwTxn,
    block_height: u32,
    m6id: M6id,
) -> Result<(), Error> {
    let (bundle, bundle_status) = state
        .withdrawal_bundles
        .try_get(rwtxn, &m6id)?
        .ok_or_else(|| Error::UnknownWithdrawalBundle { m6id })?;
    let (prev_bundle_status, latest_bundle_status) = bundle_status.pop();
    if latest_bundle_status.value == WithdrawalBundleStatus::Submitted {
        // Already applied
        return Ok(());
    } else {
        assert_eq!(latest_bundle_status.value, WithdrawalBundleStatus::Failed);
    }
    assert_eq!(latest_bundle_status.height, block_height);
    let prev_bundle_status =
        prev_bundle_status.expect("Pop failed bundle status should be valid");
    assert!(matches!(
        prev_bundle_status.latest().value,
        WithdrawalBundleStatus::Submitted
            | WithdrawalBundleStatus::SubmittedUnexpected
    ));
    match &bundle {
        WithdrawalBundleInfo::Unknown
        | WithdrawalBundleInfo::UnknownConfirmed { .. } => (),
        WithdrawalBundleInfo::Known(bundle) => 'known: {
            if matches!(
                prev_bundle_status.latest().value,
                WithdrawalBundleStatus::SubmittedUnexpected
            ) {
                break 'known;
            }
            // Delete the outputs recreated from the failed bundle. The
            // original outputs remain spent by the bundle; their STXO
            // records are untouched.
            delete_recreated_outputs(state, rwtxn, block_height, m6id, bundle)?;
            let (prev_latest_failed_m6id, latest_failed_m6id) = state
                .latest_failed_withdrawal_bundle
                .try_get(rwtxn, &())?
                .expect("latest failed withdrawal bundle should exist")
                .pop();
            assert_eq!(latest_failed_m6id.value, m6id);
            assert_eq!(latest_failed_m6id.height, block_height);
            if let Some(prev_latest_failed_m6id) = prev_latest_failed_m6id {
                state.latest_failed_withdrawal_bundle.put(
                    rwtxn,
                    &(),
                    &prev_latest_failed_m6id,
                )?;
            } else {
                state.latest_failed_withdrawal_bundle.delete(rwtxn, &())?;
            }
        }
    }
    state.withdrawal_bundles.put(
        rwtxn,
        &m6id,
        &(bundle, prev_bundle_status),
    )?;
    Ok(())
}

fn disconnect_withdrawal_bundle_event(
    state: &State,
    rwtxn: &mut RwTxn,
    block_height: u32,
    event: &WithdrawalBundleEvent,
) -> Result<(), Error> {
    match event.status {
        WithdrawalBundleEventStatus::Submitted => {
            disconnect_withdrawal_bundle_submitted(
                state,
                rwtxn,
                block_height,
                event.m6id,
            )
        }
        WithdrawalBundleEventStatus::Confirmed => {
            disconnect_withdrawal_bundle_confirmed(
                state,
                rwtxn,
                block_height,
                event.m6id,
            )
        }
        WithdrawalBundleEventStatus::Failed => {
            disconnect_withdrawal_bundle_failed(
                state,
                rwtxn,
                block_height,
                event.m6id,
            )
        }
    }
}

fn disconnect_event(
    state: &State,
    rwtxn: &mut RwTxn,
    block_height: u32,
    latest_deposit_block_hash: &mut Option<bitcoin::BlockHash>,
    latest_withdrawal_bundle_event_block_hash: &mut Option<bitcoin::BlockHash>,
    event_block_hash: bitcoin::BlockHash,
    event: &BlockEvent,
) -> Result<(), Error> {
    match event {
        BlockEvent::Deposit(deposit) => {
            state
                .deposit_mainchain_height
                .delete(rwtxn, &deposit.outpoint.txid)?;
            let outpoint = OutPoint::Deposit(deposit.outpoint);
            if !state.utxos.delete(rwtxn, &OutPointKey::from(&outpoint))? {
                return Err(error::NoUtxo { outpoint }.into());
            }
            // Blocks are iterated in reverse here, so the first event block
            // hash seen is the latest. Keep it to match what `connect` stored.
            if latest_deposit_block_hash.is_none() {
                *latest_deposit_block_hash = Some(event_block_hash);
            }
        }
        BlockEvent::WithdrawalBundle(withdrawal_bundle_event) => {
            let () = disconnect_withdrawal_bundle_event(
                state,
                rwtxn,
                block_height,
                withdrawal_bundle_event,
            )?;
            // Blocks are iterated in reverse here, so the first event block
            // hash seen is the latest. Keep it to match what `connect` stored.
            if latest_withdrawal_bundle_event_block_hash.is_none() {
                *latest_withdrawal_bundle_event_block_hash =
                    Some(event_block_hash);
            }
        }
    }
    Ok(())
}

pub fn disconnect(
    state: &State,
    rwtxn: &mut RwTxn,
    two_way_peg_data: &TwoWayPegData,
) -> Result<(), Error> {
    let block_height = state
        .try_get_height(rwtxn)?
        .expect("Height should not be None");
    let mut latest_deposit_block_hash = None;
    let mut latest_withdrawal_bundle_event_block_hash = None;
    // Undo a stale-bundle drop performed at this height. Drops are
    // connected after the block's events, so they are undone before
    // disconnecting the events.
    let () = disconnect_dropped_bundle(state, rwtxn, block_height)?;
    for (event_block_hash, event_block_info) in
        two_way_peg_data.block_info.iter().rev()
    {
        for event in event_block_info.inner.events.iter().rev() {
            let () = disconnect_event(
                state,
                rwtxn,
                block_height,
                &mut latest_deposit_block_hash,
                &mut latest_withdrawal_bundle_event_block_hash,
                *event_block_hash,
                event,
            )?;
        }
    }
    // Handle withdrawals
    if let Some(latest_withdrawal_bundle_event_block_hash) =
        latest_withdrawal_bundle_event_block_hash
    {
        let (
            last_withdrawal_bundle_event_block_seq_idx,
            (
                last_withdrawal_bundle_event_block_hash,
                last_withdrawal_bundle_event_block_height,
            ),
        ) = state
            .withdrawal_bundle_event_blocks
            .last(rwtxn)?
            .ok_or(Error::NoWithdrawalBundleEventBlock)?;
        assert_eq!(
            latest_withdrawal_bundle_event_block_hash,
            last_withdrawal_bundle_event_block_hash
        );
        assert_eq!(block_height, last_withdrawal_bundle_event_block_height);
        if !state
            .withdrawal_bundle_event_blocks
            .delete(rwtxn, &last_withdrawal_bundle_event_block_seq_idx)?
        {
            return Err(Error::NoWithdrawalBundleEventBlock);
        };
    }
    // Handle deposits.
    if let Some(latest_deposit_block_hash) = latest_deposit_block_hash {
        let (
            last_deposit_block_seq_idx,
            (last_deposit_block_hash, last_deposit_block_height),
        ) = state
            .deposit_blocks
            .last(rwtxn)?
            .ok_or(Error::NoDepositBlock)?;
        assert_eq!(latest_deposit_block_hash, last_deposit_block_hash);
        assert_eq!(block_height, last_deposit_block_height);
        if !state
            .deposit_blocks
            .delete(rwtxn, &last_deposit_block_seq_idx)?
        {
            return Err(Error::NoDepositBlock);
        };
    }
    Ok(())
}

/// Undo a withdrawal bundle constructed at the current height,
/// unspending its selected outputs last-to-first.
/// MUST be applied BEFORE disconnecting the block's transactions.
pub fn disconnect_withdrawal_bundle_creation(
    state: &State,
    rwtxn: &mut RwTxn,
) -> Result<(), Error> {
    let block_height = state.try_get_height(rwtxn)?.ok_or(Error::NoTip)?;
    let Some(bundle_m6id) =
        state.pending_withdrawal_bundle.try_get(rwtxn, &())?
    else {
        return Ok(());
    };
    let (bundle, bundle_status) = state
        .withdrawal_bundles
        .try_get(rwtxn, &bundle_m6id)?
        .ok_or(error::PendingWithdrawalBundleUnknown(bundle_m6id))?;
    // Only undo a bundle created at this height: it is then still
    // Pending — a Submitted event at this height is disconnected later,
    // and would have cleared the pending marker anyway.
    if bundle_status.latest().value != WithdrawalBundleStatus::Pending
        || bundle_status.latest().height != block_height
    {
        return Ok(());
    }
    let bundle = match bundle {
        WithdrawalBundleInfo::Known(bundle) => bundle,
        WithdrawalBundleInfo::Unknown
        | WithdrawalBundleInfo::UnknownConfirmed { .. } => {
            return Err(
                error::PendingWithdrawalBundleUnknown(bundle_m6id).into()
            );
        }
    };
    for (outpoint, output) in bundle.spend_utxos().iter().rev() {
        let key = OutPointKey::from(outpoint);
        if !state.stxos.delete(rwtxn, &key)? {
            return Err(Error::NoStxo {
                outpoint: *outpoint,
            });
        }
        state.utxos.put(rwtxn, &key, output)?;
    }
    state.pending_withdrawal_bundle.delete(rwtxn, &())?;
    if let (Some(bundle_status), _latest_bundle_status) = bundle_status.pop() {
        state.withdrawal_bundles.put(
            rwtxn,
            &bundle_m6id,
            &(WithdrawalBundleInfo::Known(bundle), bundle_status),
        )?;
    } else {
        state.withdrawal_bundles.delete(rwtxn, &bundle_m6id)?;
    }
    Ok(())
}

#[cfg(test)]
mod test;
