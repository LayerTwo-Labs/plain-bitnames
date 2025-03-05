//! Connect and disconnect blocks

use std::collections::HashSet;

use sneed::{RoTxn, RwTxn};

use crate::{
    state::{error, Error, State},
    types::{
        AmountOverflowError, Authorization, Body, FilledOutput,
        FilledOutputContent, FilledTransaction, GetAddress as _, GetValue as _,
        Header, InPoint, MerkleRoot, OutPoint, OutputContent, SpentOutput,
        TxData, Verify as _,
    },
};

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
    let mut spent_utxos = HashSet::new();
    let filled_txs: Vec<_> = body
        .transactions
        .iter()
        .map(|t| state.fill_transaction(rotxn, t))
        .collect::<Result<_, _>>()?;
    for filled_tx in &filled_txs {
        for input in &filled_tx.transaction.inputs {
            if spent_utxos.contains(input) {
                return Err(Error::UtxoDoubleSpent);
            }
            spent_utxos.insert(*input);
        }
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
        state.utxos.put(rwtxn, &outpoint, &filled_output)?;
    }
    let mut filled_txs: Vec<FilledTransaction> = Vec::new();
    for transaction in &body.transactions {
        let filled_tx = state.fill_transaction(rwtxn, transaction)?;
        let txid = filled_tx.txid();
        for (vin, input) in filled_tx.inputs().iter().enumerate() {
            let spent_output = state
                .utxos
                .try_get(rwtxn, input)?
                .ok_or(Error::NoUtxo { outpoint: *input })?;
            let spent_output = SpentOutput {
                output: spent_output,
                inpoint: InPoint::Regular {
                    txid,
                    vin: vin as u32,
                },
            };
            state.utxos.delete(rwtxn, input)?;
            state.stxos.put(rwtxn, input, &spent_output)?;
        }
        let filled_outputs = filled_tx
            .filled_outputs()
            .ok_or(Error::FillTxOutputContentsFailed)?;
        for (vout, filled_output) in filled_outputs.iter().enumerate() {
            let outpoint = OutPoint::Regular {
                txid,
                vout: vout as u32,
            };
            state.utxos.put(rwtxn, &outpoint, filled_output)?;
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
                if state.utxos.delete(rwtxn, &outpoint)? {
                    Ok(())
                } else {
                    Err(Error::NoUtxo { outpoint })
                }
            },
        )?;
        // unspend STXOs, last-to-first
        tx.inputs.iter().rev().try_for_each(|outpoint| {
            if let Some(spent_output) = state.stxos.try_get(rwtxn, outpoint)? {
                state.stxos.delete(rwtxn, outpoint)?;
                state.utxos.put(rwtxn, outpoint, &spent_output.output)?;
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
            if state.utxos.delete(rwtxn, &outpoint)? {
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
