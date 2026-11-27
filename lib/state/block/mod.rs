//! Connect and disconnect blocks

use fallible_iterator::FallibleIterator as _;
use nonempty::NonEmpty;
use rayon::prelude::ParallelSliceMut as _;
use sneed::{RoTxn, RwTxn};
use std::collections::{BTreeMap, HashSet};

use crate::{
    state::{
        Error, PrevalidatedBlock, State, bitnames::PrunedBitNameReservation,
        error,
    },
    types::{
        AmountOverflowError, BitName, BlockHash, Body, FilledOutput,
        FilledOutputContent, FilledTransaction, GetAddress as _, GetValue as _,
        Header, InPoint, MerkleRoot, OutPoint, OutPointKey, OutputContent,
        SpentOutput, TxData,
        authorization::{self, BatchVerificationContext},
        constants,
        state::BitNameReservationPosition,
    },
};

/// Calculate total number of inputs across all transactions in a block body
fn calculate_total_inputs(body: &Body) -> usize {
    body.transactions.iter().map(|t| t.inputs.len()).sum()
}

fn validate_unique_bitname_registrations(body: &Body) -> Result<(), Error> {
    let mut names = HashSet::new();
    for name_hash in body
        .transactions
        .iter()
        .filter_map(|tx| tx.registration_name_hash())
    {
        if !names.insert(name_hash) {
            return Err(Error::AmbiguousBitNameRegistration { name_hash });
        }
    }
    Ok(())
}

/// Find the incumbent UTXO replaced by a registration challenge, and the
/// inpoint of the reservation that authorizes the challenge.
fn replaced_bitname_registration(
    state: &State,
    rotxn: &RoTxn,
    filled_tx: &FilledTransaction,
    bitname: &BitName,
) -> Result<Option<(OutPoint, FilledOutput, InPoint)>, Error> {
    if state.bitnames.try_get_bitname(rotxn, bitname)?.is_none() {
        return Ok(None);
    }
    let outpoint = state
        .bitnames
        .try_get_bitname_outpoint(rotxn, bitname)?
        .ok_or(error::BitName::MissingRegistrationUtxo { bitname: *bitname })?;
    let output = state
        .utxos
        .try_get(rotxn, &OutPointKey::from(&outpoint))?
        .ok_or(error::NoUtxo { outpoint })?;
    let implied_commitment = filled_tx
        .implied_reservation_commitment()
        .expect("a registration should have an implied commitment");
    let vin = filled_tx
        .spent_inputs()
        .enumerate()
        .find_map(|(vin, (_, output))| {
            let (_, commitment) = output.reservation_data()?;
            (*commitment == implied_commitment).then_some(vin as u32)
        })
        .ok_or(error::BitName::NoReservationForRegistration {
            bitname: *bitname,
        })?;
    let inpoint = InPoint::Regular {
        txid: filled_tx.txid(),
        vin,
    };
    Ok(Some((outpoint, output, inpoint)))
}

fn prune_expired_bitname_reservations(
    state: &State,
    rwtxn: &mut RwTxn,
    block_hash: &BlockHash,
    main_height: u32,
) -> Result<(), Error> {
    let Some(max_reservation_height) =
        main_height.checked_sub(constants::MAX_RESERVATION_AGE)
    else {
        return Ok(());
    };
    let expired_outpoints = state
        .bitnames
        .reservation_outpoints_through_initial_mainchain_height(
            rwtxn,
            max_reservation_height,
        )?;
    let mut pruned: Option<NonEmpty<_>> = None;
    expired_outpoints
        .map_err(Error::from)
        .for_each(|outpoint| {
            let output = state
                .utxos
                .try_get(rwtxn, &OutPointKey::from(&outpoint))?
                .ok_or(error::NoUtxo { outpoint })?;
            let (reservation_txid, _) = output
                .reservation_data()
                .expect("expiry index entries should refer to reservations");
            let Some(position) = state
                .bitnames
                .try_get_reservation_heights(rwtxn, reservation_txid)?
            else {
                return Err(error::BitName::MissingReservation {
                    txid: *reservation_txid,
                }
                .into());
            };
            let pruned_reservation = PrunedBitNameReservation {
                outpoint,
                output,
                heights: position,
            };
            match pruned.as_mut() {
                Some(pruned) => pruned.push(pruned_reservation),
                None => pruned = Some(NonEmpty::new(pruned_reservation)),
            }
            Ok(())
        })?;
    if let Some(pruned) = pruned {
        for reservation in &pruned {
            let outpoint_key = OutPointKey::from(&reservation.outpoint);
            if !state.utxos.delete(rwtxn, &outpoint_key)? {
                return Err(error::NoUtxo {
                    outpoint: reservation.outpoint,
                }
                .into());
            }
        }
        let () = state
            .bitnames
            .put_pruned_reservations(rwtxn, block_hash, pruned)?;
    }
    Ok(())
}

fn restore_pruned_bitname_reservations(
    state: &State,
    rwtxn: &mut RwTxn,
    block_hash: &crate::types::BlockHash,
) -> Result<(), Error> {
    if let Some(pruned) = state
        .bitnames()
        .restore_pruned_reservations(rwtxn, block_hash)?
    {
        for reservation in pruned.into_iter().rev() {
            state.utxos.put(
                rwtxn,
                &OutPointKey::from(&reservation.outpoint),
                &reservation.output,
            )?;
        }
    }
    Ok(())
}

/// Validate a block, returning the merkle root and fees
pub fn validate(
    batch_verification_context: &BatchVerificationContext,
    state: &State,
    rotxn: &RoTxn,
    header: &Header,
    prev_main_height: u32,
    body: &Body,
) -> Result<(bitcoin::Amount, MerkleRoot), Error> {
    let body_size =
        borsh::object_length(&body).map_err(Error::BorshSerialize)?;
    if body_size > Body::MAX_SIZE {
        return Err(Error::BodyTooLarge);
    }
    let () = validate_unique_bitname_registrations(body)?;

    let tip_hash = state.try_get_tip(rotxn)?;
    if header.prev_side_hash != tip_hash {
        let err = error::InvalidHeader::PrevSideHash {
            expected: tip_hash,
            received: header.prev_side_hash,
        };
        return Err(Error::InvalidHeader(err));
    };
    let mut coinbase_value = bitcoin::Amount::ZERO;
    for output in &body.coinbase.outputs {
        coinbase_value = coinbase_value
            .checked_add(output.get_value())
            .ok_or(AmountOverflowError)?;
    }
    let mut total_fees = bitcoin::Amount::ZERO;
    let total_inputs = calculate_total_inputs(body);

    // Pre-allocate filled transactions Vec
    let filled_txs: Vec<_> = body
        .transactions
        .iter()
        .map(|t| state.fill_transaction(rotxn, t))
        .collect::<Result<_, _>>()?;

    // Collect all inputs as fixed-width keys for efficient double-spend detection via sort-and-scan
    let mut all_input_keys = Vec::with_capacity(total_inputs);
    for filled_transaction in &filled_txs {
        for outpoint in &filled_transaction.transaction.inputs {
            all_input_keys.push(OutPointKey::from_outpoint(outpoint));
        }
    }

    // Sort and check for duplicate outpoints (double-spend detection)
    all_input_keys.par_sort_unstable();
    if all_input_keys.windows(2).any(|w| w[0] == w[1]) {
        return Err(Error::UtxoDoubleSpent);
    }

    // Process transactions for fee validation
    for filled_tx in &filled_txs {
        total_fees = total_fees
            .checked_add(state.validate_filled_transaction(
                rotxn,
                prev_main_height,
                filled_tx,
            )?)
            .ok_or(AmountOverflowError)?;
    }
    if coinbase_value > total_fees {
        return Err(Error::NotEnoughFees);
    }
    let merkle_root = Body::compute_merkle_root(
        &body.coinbase,
        filled_txs.as_slice(),
        &body.authorizations,
    )?;
    if merkle_root != header.merkle_root {
        let err = Error::InvalidBody {
            expected: header.merkle_root,
            computed: merkle_root,
        };
        return Err(err);
    }
    // The authorization and address checks below pair authorizations with
    // spent UTXOs positionally via `zip`, which silently ignores any trailing
    // inputs when there are fewer authorizations than inputs requiring one.
    // Require an exact count so that every input requiring authorization is
    // covered by a provided authorization.
    let n_authorizations_required: usize = filled_txs
        .iter()
        .map(|t| t.spent_utxos_requiring_auth().len())
        .sum();
    if body.authorizations.len() != n_authorizations_required {
        return Err(Error::WrongNumberOfAuthorizations {
            expected: n_authorizations_required,
            received: body.authorizations.len(),
        });
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
    let () =
        authorization::verify_authorizations(batch_verification_context, body)?;
    Ok((total_fees, merkle_root))
}

/// Prevalidate a block, returning a PrevalidatedBlock with computed values
/// to avoid redundant computation during connection
pub fn prevalidate(
    batch_verification_ctxt: &BatchVerificationContext,
    state: &State,
    rotxn: &RoTxn,
    header: &Header,
    prev_main_height: u32,
    body: &Body,
) -> Result<PrevalidatedBlock, Error> {
    let body_size =
        borsh::object_length(&body).map_err(Error::BorshSerialize)?;
    if body_size > Body::MAX_SIZE {
        return Err(Error::BodyTooLarge);
    }
    let () = validate_unique_bitname_registrations(body)?;

    let tip_hash = state.try_get_tip(rotxn)?;
    if header.prev_side_hash != tip_hash {
        let err = error::InvalidHeader::PrevSideHash {
            expected: tip_hash,
            received: header.prev_side_hash,
        };
        return Err(Error::InvalidHeader(err));
    };
    let next_height = state.try_get_height(rotxn)?.map_or(0, |h| h + 1);

    let mut coinbase_value = bitcoin::Amount::ZERO;
    for output in &body.coinbase.outputs {
        coinbase_value = coinbase_value
            .checked_add(output.get_value())
            .ok_or(AmountOverflowError)?;
    }
    let mut total_fees = bitcoin::Amount::ZERO;
    let total_inputs = calculate_total_inputs(body);

    // Pre-allocate filled transactions Vec
    let filled_transactions: Vec<_> = body
        .transactions
        .iter()
        .map(|t| state.fill_transaction(rotxn, t))
        .collect::<Result<_, _>>()?;

    // Collect all inputs as fixed-width keys for efficient double-spend detection via sort-and-scan
    let mut all_input_keys = Vec::with_capacity(total_inputs);
    for filled_transaction in &filled_transactions {
        for outpoint in &filled_transaction.transaction.inputs {
            all_input_keys.push(OutPointKey::from_outpoint(outpoint));
        }
    }

    // Sort and check for duplicate outpoints (double-spend detection)
    all_input_keys.par_sort_unstable();
    if all_input_keys.windows(2).any(|w| w[0] == w[1]) {
        return Err(Error::UtxoDoubleSpent);
    }

    // Process transactions for fee validation
    for filled_transaction in &filled_transactions {
        total_fees = total_fees
            .checked_add(state.validate_filled_transaction(
                rotxn,
                prev_main_height,
                filled_transaction,
            )?)
            .ok_or(AmountOverflowError)?;
    }
    if coinbase_value > total_fees {
        return Err(Error::NotEnoughFees);
    }
    let computed_merkle_root = Body::compute_merkle_root(
        &body.coinbase,
        filled_transactions.as_slice(),
        &body.authorizations,
    )?;
    if computed_merkle_root != header.merkle_root {
        let err = Error::InvalidBody {
            expected: header.merkle_root,
            computed: computed_merkle_root,
        };
        return Err(err);
    }
    // The authorization and address checks below pair authorizations with
    // spent UTXOs positionally via `zip`, which silently ignores any trailing
    // inputs when there are fewer authorizations than inputs requiring one.
    // Require an exact count so that every input requiring authorization is
    // covered by a provided authorization.
    let n_authorizations_required: usize = filled_transactions
        .iter()
        .map(|t| t.spent_utxos_requiring_auth().len())
        .sum();
    if body.authorizations.len() != n_authorizations_required {
        return Err(Error::WrongNumberOfAuthorizations {
            expected: n_authorizations_required,
            received: body.authorizations.len(),
        });
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
    let () =
        authorization::verify_authorizations(batch_verification_ctxt, body)?;
    Ok(PrevalidatedBlock {
        filled_transactions,
        computed_merkle_root,
        total_fees,
        coinbase_value,
        next_height,
        prev_main_height,
    })
}

/// Connect a prevalidated block using precomputed values
/// to avoid redundant computation
pub fn connect_prevalidated(
    state: &State,
    rwtxn: &mut RwTxn,
    header: &Header,
    body: &Body,
    prevalidated: PrevalidatedBlock,
) -> Result<MerkleRoot, Error> {
    // Use precomputed height and merkle root (validation already done in prevalidate)
    let height = prevalidated.next_height;
    let prev_main_height = prevalidated.prev_main_height;
    let merkle_root = prevalidated.computed_merkle_root;
    let coinbase_txid = header.compute_coinbase_txid();

    // Accumulate DB mutations to apply in sorted key order for better locality
    let mut utxo_deletes: BTreeMap<OutPointKey, ()> = BTreeMap::new();
    let mut stxo_puts: BTreeMap<OutPointKey, SpentOutput> = BTreeMap::new();
    let mut utxo_puts: BTreeMap<OutPointKey, FilledOutput> = BTreeMap::new();

    // Handle coinbase outputs (accumulate puts)
    for (vout, output) in body.coinbase.outputs.iter().enumerate() {
        let outpoint = OutPoint::Coinbase {
            txid: coinbase_txid,
            vout: vout as u32,
        };
        let filled_content = match output.content.clone() {
            OutputContent::Bitcoin(value) => {
                FilledOutputContent::Bitcoin(value)
            }
            OutputContent::Withdrawal(withdrawal) => {
                FilledOutputContent::BitcoinWithdrawal(withdrawal)
            }
            OutputContent::BitName | OutputContent::BitNameReservation => {
                return Err(Error::BadCoinbaseOutputContent);
            }
        };
        let filled_output = FilledOutput {
            address: output.address,
            content: filled_content,
            memo: output.memo.clone(),
        };
        utxo_puts.insert(OutPointKey::from(&outpoint), filled_output);
    }

    // Process transactions using precomputed filled_transactions
    for (tx_index, (transaction, filled_tx)) in body
        .transactions
        .iter()
        .zip(&prevalidated.filled_transactions)
        .enumerate()
    {
        let txid = filled_tx.txid();
        // Accumulate input deletes and STXO puts
        for (vin, input) in filled_tx.inputs().iter().enumerate() {
            let key = OutPointKey::from(input);
            let spent_output = state
                .utxos
                .try_get(rwtxn, &key)?
                .ok_or(error::NoUtxo { outpoint: *input })?;
            let () = state
                .bitnames
                .delete_reservation_outpoint_at_initial_height(
                    rwtxn,
                    input,
                    &spent_output,
                )?;
            let () = state.bitnames.delete_bitname_outpoint(
                rwtxn,
                input,
                &spent_output,
            )?;
            let spent_output = SpentOutput {
                output: spent_output,
                inpoint: InPoint::Regular {
                    txid,
                    vin: vin as u32,
                },
            };
            utxo_deletes.insert(key, ());
            stxo_puts.insert(key, spent_output);
        }

        let replaced_registration = match &transaction.data {
            Some(TxData::BitNameRegistration { name_hash, .. }) => {
                replaced_bitname_registration(
                    state, rwtxn, filled_tx, name_hash,
                )?
            }
            _ => None,
        };
        let replaced_outpoint = replaced_registration
            .as_ref()
            .map(|(outpoint, _, _)| *outpoint);
        if let Some((outpoint, output, inpoint)) = replaced_registration {
            let () = state
                .bitnames
                .delete_bitname_outpoint(rwtxn, &outpoint, &output)?;
            let key = OutPointKey::from(&outpoint);
            utxo_deletes.insert(key, ());
            stxo_puts.insert(key, SpentOutput { output, inpoint });
        }

        // Accumulate output UTXO puts
        let filled_outputs = filled_tx
            .filled_outputs()
            .ok_or(Error::FillTxOutputContentsFailed)?;
        for (vout, filled_output) in filled_outputs.iter().enumerate() {
            let outpoint = OutPoint::Regular {
                txid,
                vout: vout as u32,
            };
            utxo_puts
                .insert(OutPointKey::from(&outpoint), filled_output.clone());
        }

        // Bitname-specific DB updates (apply now; separate DB tree)
        match &transaction.data {
            None => (),
            Some(TxData::BitNameReservation { commitment }) => {
                state.bitnames.put_reservation(
                    rwtxn,
                    &txid,
                    commitment,
                    BitNameReservationPosition {
                        sidechain: height,
                        mainchain: prev_main_height,
                        tx_index: tx_index as u32,
                    },
                )?;
            }
            Some(TxData::BitNameRegistration {
                name_hash,
                revealed_nonce: _,
                bitname_data,
            }) => {
                let () = state.bitnames.apply_registration(
                    rwtxn,
                    filled_tx,
                    *name_hash,
                    bitname_data,
                    height,
                    replaced_outpoint,
                )?;
            }
            Some(TxData::BitNameUpdate(bitname_updates)) => {
                let () = state.bitnames.apply_updates(
                    rwtxn,
                    filled_tx,
                    (**bitname_updates).clone(),
                    height,
                )?;
            }
            Some(TxData::BatchIcann(batch_icann_data)) => {
                let () = state.bitnames.apply_batch_icann(
                    rwtxn,
                    filled_tx,
                    batch_icann_data,
                )?;
            }
        }
        for (vout, output) in filled_outputs.iter().enumerate() {
            let outpoint = OutPoint::Regular {
                txid,
                vout: vout as u32,
            };
            let () =
                state.bitnames.put_reservation_outpoint_at_initial_height(
                    rwtxn, &outpoint, output,
                )?;
            let () = state
                .bitnames
                .put_bitname_outpoint(rwtxn, &outpoint, output)?;
        }
    }

    // Apply accumulated DB mutations in sorted key order
    for key in utxo_deletes.keys() {
        state.utxos.delete(rwtxn, key)?;
    }
    for (key, spent_output) in &stxo_puts {
        state.stxos.put(rwtxn, key, spent_output)?;
    }
    for (key, output) in &utxo_puts {
        state.utxos.put(rwtxn, key, output)?;
    }
    let () = prune_expired_bitname_reservations(
        state,
        rwtxn,
        &header.hash(),
        prev_main_height,
    )?;

    // NOTE: the tip, height, and coinbase height are NOT updated here;
    // that happens after the block's transactions, in `connect_header`.

    Ok(merkle_root)
}

/// Connect a block header: update the tip, height, and coinbase
/// height.
/// MUST be applied AFTER the block's transactions, and BEFORE
/// withdrawal bundle construction.
pub fn connect_header(
    state: &State,
    rwtxn: &mut RwTxn,
    header: &Header,
) -> Result<(), Error> {
    let block_hash = header.hash();
    let height = state.try_get_height(rwtxn)?.map_or(0, |height| height + 1);
    state.tip.put(rwtxn, &(), &block_hash)?;
    let coinbase_txid = header.compute_coinbase_txid();
    state.coinbase_height.put(rwtxn, &coinbase_txid, &height)?;
    state.height.put(rwtxn, &(), &height)?;
    Ok(())
}

pub fn connect(
    state: &State,
    rwtxn: &mut RwTxn,
    header: &Header,
    body: &Body,
    prev_main_height: u32,
) -> Result<MerkleRoot, Error> {
    let height = state.try_get_height(rwtxn)?.map_or(0, |height| height + 1);
    let tip_hash = state.try_get_tip(rwtxn)?;
    if tip_hash != header.prev_side_hash {
        let err = error::InvalidHeader::PrevSideHash {
            expected: tip_hash,
            received: header.prev_side_hash,
        };
        return Err(Error::InvalidHeader(err));
    }
    let coinbase_txid = header.compute_coinbase_txid();
    for (vout, output) in body.coinbase.outputs.iter().enumerate() {
        let outpoint = OutPoint::Coinbase {
            txid: coinbase_txid,
            vout: vout as u32,
        };
        let filled_content = match output.content.clone() {
            OutputContent::Bitcoin(value) => {
                FilledOutputContent::Bitcoin(value)
            }
            OutputContent::Withdrawal(withdrawal) => {
                FilledOutputContent::BitcoinWithdrawal(withdrawal)
            }
            OutputContent::BitName | OutputContent::BitNameReservation => {
                return Err(Error::BadCoinbaseOutputContent);
            }
        };
        let filled_output = FilledOutput {
            address: output.address,
            content: filled_content,
            memo: output.memo.clone(),
        };
        state.utxos.put(
            rwtxn,
            &OutPointKey::from(&outpoint),
            &filled_output,
        )?;
    }
    let mut filled_txs: Vec<FilledTransaction> = Vec::new();
    for (tx_index, transaction) in body.transactions.iter().enumerate() {
        let filled_tx = state.fill_transaction(rwtxn, transaction)?;
        let txid = filled_tx.txid();
        for (vin, input) in filled_tx.inputs().iter().enumerate() {
            let spent_output = state
                .utxos
                .try_get(rwtxn, &OutPointKey::from(input))?
                .ok_or(error::NoUtxo { outpoint: *input })?;
            let () = state
                .bitnames
                .delete_reservation_outpoint_at_initial_height(
                    rwtxn,
                    input,
                    &spent_output,
                )?;
            let () = state.bitnames.delete_bitname_outpoint(
                rwtxn,
                input,
                &spent_output,
            )?;
            let spent_output = SpentOutput {
                output: spent_output,
                inpoint: InPoint::Regular {
                    txid,
                    vin: vin as u32,
                },
            };
            state.utxos.delete(rwtxn, &OutPointKey::from(input))?;
            state
                .stxos
                .put(rwtxn, &OutPointKey::from(input), &spent_output)?;
        }
        let replaced_registration = match &transaction.data {
            Some(TxData::BitNameRegistration { name_hash, .. }) => {
                replaced_bitname_registration(
                    state, rwtxn, &filled_tx, name_hash,
                )?
            }
            _ => None,
        };
        let replaced_outpoint = replaced_registration
            .as_ref()
            .map(|(outpoint, _, _)| *outpoint);
        if let Some((outpoint, output, inpoint)) = replaced_registration {
            let () = state
                .bitnames
                .delete_bitname_outpoint(rwtxn, &outpoint, &output)?;
            let key = OutPointKey::from(&outpoint);
            state.utxos.delete(rwtxn, &key)?;
            state
                .stxos
                .put(rwtxn, &key, &SpentOutput { output, inpoint })?;
        }
        let filled_outputs = filled_tx
            .filled_outputs()
            .ok_or(Error::FillTxOutputContentsFailed)?;
        for (vout, filled_output) in filled_outputs.iter().enumerate() {
            let outpoint = OutPoint::Regular {
                txid,
                vout: vout as u32,
            };
            state.utxos.put(
                rwtxn,
                &OutPointKey::from(&outpoint),
                filled_output,
            )?;
        }
        match &transaction.data {
            None => (),
            Some(TxData::BitNameReservation { commitment }) => {
                state.bitnames.put_reservation(
                    rwtxn,
                    &txid,
                    commitment,
                    BitNameReservationPosition {
                        sidechain: height,
                        mainchain: prev_main_height,
                        tx_index: tx_index as u32,
                    },
                )?;
            }
            Some(TxData::BitNameRegistration {
                name_hash,
                revealed_nonce: _,
                bitname_data,
            }) => {
                let () = state.bitnames.apply_registration(
                    rwtxn,
                    &filled_tx,
                    *name_hash,
                    bitname_data,
                    height,
                    replaced_outpoint,
                )?;
            }
            Some(TxData::BitNameUpdate(bitname_updates)) => {
                let () = state.bitnames.apply_updates(
                    rwtxn,
                    &filled_tx,
                    (**bitname_updates).clone(),
                    height,
                )?;
            }
            Some(TxData::BatchIcann(batch_icann_data)) => {
                let () = state.bitnames.apply_batch_icann(
                    rwtxn,
                    &filled_tx,
                    batch_icann_data,
                )?;
            }
        }
        for (vout, output) in filled_outputs.iter().enumerate() {
            let outpoint = OutPoint::Regular {
                txid,
                vout: vout as u32,
            };
            let () =
                state.bitnames.put_reservation_outpoint_at_initial_height(
                    rwtxn, &outpoint, output,
                )?;
            let () = state
                .bitnames
                .put_bitname_outpoint(rwtxn, &outpoint, output)?;
        }
        filled_txs.push(filled_tx);
    }
    let merkle_root = Body::compute_merkle_root(
        &body.coinbase,
        filled_txs.as_slice(),
        &body.authorizations,
    )?;
    if merkle_root != header.merkle_root {
        let err = Error::InvalidBody {
            expected: header.merkle_root,
            computed: merkle_root,
        };
        return Err(err);
    }
    let block_hash = header.hash();
    state.tip.put(rwtxn, &(), &block_hash)?;
    state.coinbase_height.put(rwtxn, &coinbase_txid, &height)?;
    state.height.put(rwtxn, &(), &height)?;
    let () = prune_expired_bitname_reservations(
        state,
        rwtxn,
        &block_hash,
        prev_main_height,
    )?;
    Ok(merkle_root)
}

pub fn disconnect_tip_body(
    state: &State,
    rwtxn: &mut RwTxn,
    header: &Header,
    body: &Body,
) -> Result<(), Error> {
    let tip_hash = state.tip.try_get(rwtxn, &())?.ok_or(Error::NoTip)?;
    let block_hash = header.hash();
    if tip_hash != block_hash {
        let err = error::InvalidHeader::BlockHash {
            expected: tip_hash,
            computed: block_hash,
        };
        return Err(Error::InvalidHeader(err));
    }
    let height = state
        .try_get_height(rwtxn)?
        .expect("Height should not be None");
    // Pruning is applied after transactions during connection, so restore
    // pruned reservations before reverting transactions.
    let () = restore_pruned_bitname_reservations(state, rwtxn, &block_hash)?;
    // revert txs, last-to-first
    let mut filled_txs: Vec<FilledTransaction> = Vec::new();
    body.transactions.iter().rev().try_for_each(|tx| {
        let txid = tx.txid();
        let filled_tx = state.fill_transaction_from_stxos(rwtxn, tx.clone())?;
        let filled_outputs = filled_tx
            .filled_outputs()
            .ok_or(Error::FillTxOutputContentsFailed)?;
        for (vout, output) in filled_outputs.iter().enumerate() {
            let outpoint = OutPoint::Regular {
                txid,
                vout: vout as u32,
            };
            let () = state
                .bitnames
                .delete_reservation_outpoint_at_initial_height(
                    rwtxn, &outpoint, output,
                )?;
            let () = state
                .bitnames
                .delete_bitname_outpoint(rwtxn, &outpoint, output)?;
        }
        // revert transaction effects
        match &tx.data {
            None => (),
            #[allow(clippy::collapsible_match, reason = "false positive")]
            Some(TxData::BitNameReservation { .. }) => {
                if !state.bitnames.delete_reservation(rwtxn, &txid)? {
                    let err = error::BitName::MissingReservation { txid };
                    return Err(err.into());
                }
            }
            Some(TxData::BitNameRegistration {
                name_hash,
                revealed_nonce: _,
                bitname_data,
            }) => {
                let replaced_outpoint = state.bitnames.revert_registration(
                    rwtxn,
                    &filled_tx,
                    *name_hash,
                    bitname_data,
                    height,
                )?;
                if let Some(outpoint) = replaced_outpoint {
                    let outpoint_key = OutPointKey::from(&outpoint);
                    let spent_output = state
                        .stxos
                        .try_get(rwtxn, &outpoint_key)?
                        .ok_or(Error::NoStxo { outpoint })?;
                    state.stxos.delete(rwtxn, &outpoint_key)?;
                    state.utxos.put(
                        rwtxn,
                        &outpoint_key,
                        &spent_output.output,
                    )?;
                    let () = state.bitnames.put_bitname_outpoint(
                        rwtxn,
                        &outpoint,
                        &spent_output.output,
                    )?;
                }
            }
            Some(TxData::BitNameUpdate(bitname_updates)) => {
                let () = state.bitnames.revert_updates(
                    rwtxn,
                    &filled_tx,
                    (**bitname_updates).clone(),
                    height,
                )?;
            }
            Some(TxData::BatchIcann(batch_icann_data)) => {
                let () = state.bitnames.revert_batch_icann(
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
                if state.utxos.delete(rwtxn, &OutPointKey::from(&outpoint))? {
                    Ok::<_, Error>(())
                } else {
                    Err(error::NoUtxo { outpoint }.into())
                }
            },
        )?;
        // unspend STXOs, last-to-first
        tx.inputs.iter().rev().try_for_each(|outpoint| {
            if let Some(spent_output) =
                state.stxos.try_get(rwtxn, &OutPointKey::from(outpoint))?
            {
                let () =
                    state.bitnames.put_reservation_outpoint_at_initial_height(
                        rwtxn,
                        outpoint,
                        &spent_output.output,
                    )?;
                let () = state.bitnames.put_bitname_outpoint(
                    rwtxn,
                    outpoint,
                    &spent_output.output,
                )?;
                state.stxos.delete(rwtxn, &OutPointKey::from(outpoint))?;
                state.utxos.put(
                    rwtxn,
                    &OutPointKey::from(outpoint),
                    &spent_output.output,
                )?;
                Ok(())
            } else {
                Err(Error::NoStxo {
                    outpoint: *outpoint,
                })
            }
        })
    })?;
    filled_txs.reverse();
    {
        let coinbase_txid = header.compute_coinbase_txid();
        // delete coinbase UTXOs, last-to-first
        body.coinbase
            .outputs
            .iter()
            .enumerate()
            .rev()
            .try_for_each(|(vout, _output)| {
                let outpoint = OutPoint::Coinbase {
                    txid: coinbase_txid,
                    vout: vout as u32,
                };
                if state.utxos.delete(rwtxn, &OutPointKey::from(&outpoint))? {
                    Ok::<_, Error>(())
                } else {
                    Err(error::NoUtxo { outpoint }.into())
                }
            })?;
    }
    let merkle_root = Body::compute_merkle_root(
        &body.coinbase,
        filled_txs.as_slice(),
        &body.authorizations,
    )?;
    if merkle_root != header.merkle_root {
        let err = Error::InvalidBody {
            expected: header.merkle_root,
            computed: merkle_root,
        };
        return Err(err);
    }
    // NOTE: the tip, height, and coinbase height are NOT rolled back
    // here; that happens after 2WPD is disconnected, in
    // `disconnect_tip_header`.
    Ok(())
}

/// Disconnect the tip block's header: roll back the coinbase height,
/// tip, and height.
/// MUST be applied AFTER disconnecting the block's transactions and
/// 2WPD.
pub fn disconnect_tip_header(
    state: &State,
    rwtxn: &mut RwTxn,
    header: &Header,
) -> Result<(), Error> {
    let coinbase_txid = header.compute_coinbase_txid();
    state.coinbase_height.delete(rwtxn, &coinbase_txid)?;
    let height = state
        .try_get_height(rwtxn)?
        .expect("Height should not be None");
    match (header.prev_side_hash, height) {
        (None, 0) => {
            state.tip.delete(rwtxn, &())?;
            state.height.delete(rwtxn, &())?;
        }
        (None, _) | (_, 0) => return Err(Error::NoTip),
        (Some(prev_side_hash), height) => {
            state.tip.put(rwtxn, &(), &prev_side_hash)?;
            state.height.put(rwtxn, &(), &(height - 1))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod test;
