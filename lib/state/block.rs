//! Connect and disconnect blocks

use rayon::prelude::*;
use sneed::{RoTxn, RwTxn};
use std::collections::BTreeMap;

use crate::{
    state::{Error, PrevalidatedBlock, State, error},
    types::{
        AmountOverflowError, Authorization, Body, FilledOutput,
        FilledOutputContent, FilledTransaction, GetAddress as _, GetValue as _,
        Header, InPoint, MerkleRoot, OutPoint, OutPointKey, OutputContent,
        SpentOutput, TxData, Verify as _,
    },
};

/// Calculate total number of inputs across all transactions in a block body
fn calculate_total_inputs(body: &Body) -> usize {
    body.transactions.iter().map(|t| t.inputs.len()).sum()
}

/// Validate a block, returning the merkle root and fees
pub fn validate(
    state: &State,
    rotxn: &RoTxn,
    header: &Header,
    body: &Body,
) -> Result<(bitcoin::Amount, MerkleRoot), Error> {
    let tip_hash = state.try_get_tip(rotxn)?;
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
            .checked_add(state.validate_filled_transaction(rotxn, filled_tx)?)
            .ok_or(AmountOverflowError)?;
    }
    if coinbase_value > total_fees {
        return Err(Error::NotEnoughFees);
    }
    let merkle_root = Body::compute_merkle_root(
        body.coinbase.as_slice(),
        filled_txs.as_slice(),
    )?;
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

/// Prevalidate a block, returning a PrevalidatedBlock with computed values
/// to avoid redundant computation during connection
pub fn prevalidate(
    state: &State,
    rotxn: &RoTxn,
    header: &Header,
    body: &Body,
) -> Result<PrevalidatedBlock, Error> {
    let tip_hash = state.try_get_tip(rotxn)?;
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
            .checked_add(
                state.validate_filled_transaction(rotxn, filled_transaction)?,
            )
            .ok_or(AmountOverflowError)?;
    }
    if coinbase_value > total_fees {
        return Err(Error::NotEnoughFees);
    }
    let computed_merkle_root = Body::compute_merkle_root(
        body.coinbase.as_slice(),
        filled_transactions.as_slice(),
    )?;
    if computed_merkle_root != header.merkle_root {
        let err = Error::InvalidBody {
            expected: header.merkle_root,
            computed: computed_merkle_root,
        };
        return Err(err);
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
    let height = state.try_get_height(rotxn)?.map_or(0, |height| height + 1);

    Ok(PrevalidatedBlock {
        filled_transactions,
        computed_merkle_root,
        total_fees,
        coinbase_value,
        next_height: height,
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
    let merkle_root = prevalidated.computed_merkle_root;

    // Accumulate DB mutations to apply in sorted key order for better locality
    let mut utxo_deletes: BTreeMap<OutPointKey, ()> = BTreeMap::new();
    let mut stxo_puts: BTreeMap<OutPointKey, SpentOutput> = BTreeMap::new();
    let mut utxo_puts: BTreeMap<OutPointKey, FilledOutput> = BTreeMap::new();

    // Handle coinbase outputs (accumulate puts)
    for (vout, output) in body.coinbase.iter().enumerate() {
        let outpoint = OutPoint::Coinbase {
            merkle_root: header.merkle_root,
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
    for (transaction, filled_tx) in body
        .transactions
        .iter()
        .zip(&prevalidated.filled_transactions)
    {
        let txid = filled_tx.txid();
        // Accumulate input deletes and STXO puts
        for (vin, input) in filled_tx.inputs().iter().enumerate() {
            let key = OutPointKey::from(input);
            let spent_output = state
                .utxos
                .try_get(rwtxn, &key)?
                .ok_or(Error::NoUtxo { outpoint: *input })?;
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
                state.bitnames.put_reservation(rwtxn, &txid, commitment)?;
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

    // Update tip and height
    let block_hash = header.hash();
    state.tip.put(rwtxn, &(), &block_hash)?;
    state.height.put(rwtxn, &(), &height)?;

    Ok(merkle_root)
}

/// Apply a block by combining validation and connection in a single transaction
/// This avoids the double B-tree traversal and reduces LMDB commit overhead
pub fn apply_block(
    state: &State,
    rwtxn: &mut RwTxn,
    header: &Header,
    body: &Body,
) -> Result<(), Error> {
    // Prevalidate the block using the same transaction
    let prevalidated = prevalidate(state, rwtxn, header, body)?;

    // Connect the block using precomputed values
    let _merkle_root =
        connect_prevalidated(state, rwtxn, header, body, prevalidated)?;

    Ok(())
}

pub fn connect(
    state: &State,
    rwtxn: &mut RwTxn,
    header: &Header,
    body: &Body,
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
    for (vout, output) in body.coinbase.iter().enumerate() {
        let outpoint = OutPoint::Coinbase {
            merkle_root: header.merkle_root,
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
    for transaction in &body.transactions {
        let filled_tx = state.fill_transaction(rwtxn, transaction)?;
        let txid = filled_tx.txid();
        for (vin, input) in filled_tx.inputs().iter().enumerate() {
            let spent_output = state
                .utxos
                .try_get(rwtxn, &OutPointKey::from(input))?
                .ok_or(Error::NoUtxo { outpoint: *input })?;
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
                state.bitnames.put_reservation(rwtxn, &txid, commitment)?;
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
        filled_txs.push(filled_tx);
    }
    let merkle_root = Body::compute_merkle_root(
        body.coinbase.as_slice(),
        filled_txs.as_slice(),
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
    state.height.put(rwtxn, &(), &height)?;
    Ok(merkle_root)
}

pub fn disconnect_tip(
    state: &State,
    rwtxn: &mut RwTxn,
    header: &Header,
    body: &Body,
) -> Result<(), Error> {
    let tip_hash = state.tip.try_get(rwtxn, &())?.ok_or(Error::NoTip)?;
    if tip_hash != header.hash() {
        let err = error::InvalidHeader::BlockHash {
            expected: tip_hash,
            computed: header.hash(),
        };
        return Err(Error::InvalidHeader(err));
    }
    let height = state
        .try_get_height(rwtxn)?
        .expect("Height should not be None");
    // revert txs, last-to-first
    let mut filled_txs: Vec<FilledTransaction> = Vec::new();
    body.transactions.iter().rev().try_for_each(|tx| {
        let txid = tx.txid();
        let filled_tx = state.fill_transaction_from_stxos(rwtxn, tx.clone())?;
        // revert transaction effects
        match &tx.data {
            None => (),
            Some(TxData::BitNameReservation { .. }) => {
                if !state.bitnames.delete_reservation(rwtxn, &txid)? {
                    let err = error::BitName::MissingReservation { txid };
                    return Err(err.into());
                }
            }
            Some(TxData::BitNameRegistration {
                name_hash,
                revealed_nonce: _,
                bitname_data: _,
            }) => {
                let () = state
                    .bitnames
                    .revert_registration(rwtxn, &filled_tx, *name_hash)?;
            }
            Some(TxData::BitNameUpdate(bitname_updates)) => {
                let () = state.bitnames.revert_updates(
                    rwtxn,
                    &filled_tx,
                    (**bitname_updates).clone(),
                    height - 1,
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
                    Ok(())
                } else {
                    Err(Error::NoUtxo { outpoint })
                }
            },
        )?;
        // unspend STXOs, last-to-first
        tx.inputs.iter().rev().try_for_each(|outpoint| {
            if let Some(spent_output) =
                state.stxos.try_get(rwtxn, &OutPointKey::from(outpoint))?
            {
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
    // delete coinbase UTXOs, last-to-first
    body.coinbase.iter().enumerate().rev().try_for_each(
        |(vout, _output)| {
            let outpoint = OutPoint::Coinbase {
                merkle_root: header.merkle_root,
                vout: vout as u32,
            };
            if state.utxos.delete(rwtxn, &OutPointKey::from(&outpoint))? {
                Ok(())
            } else {
                Err(Error::NoUtxo { outpoint })
            }
        },
    )?;
    let merkle_root = Body::compute_merkle_root(
        body.coinbase.as_slice(),
        filled_txs.as_slice(),
    )?;
    if merkle_root != header.merkle_root {
        let err = Error::InvalidBody {
            expected: header.merkle_root,
            computed: merkle_root,
        };
        return Err(err);
    }
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
