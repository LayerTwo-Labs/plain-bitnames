use bitcoin::hashes::Hash as _;

use crate::{
    state::{
        block::{connect, disconnect_tip_body, validate},
        test::fresh_state,
    },
    types::{
        BitName, BitNameDataUpdates, BitNameSeqId, BlockHash, Body, Coinbase,
        FilledOutput, FilledOutputContent, FilledTransaction, Hash, Header,
        MerkleRoot, MutableBitNameData, OutPoint, OutPointKey, Output,
        OutputContent, Transaction, TxData, Update,
        authorization::{
            self, BatchVerificationContext, SigningKey, VerifyingKey,
        },
    },
};

fn header(
    prev_side_hash: Option<BlockHash>,
    merkle_root: MerkleRoot,
) -> Header {
    Header {
        merkle_root,
        prev_side_hash,
        prev_main_hash: bitcoin::BlockHash::from_byte_array([0; 32]),
    }
}

fn all_retained_updates() -> BitNameDataUpdates {
    BitNameDataUpdates {
        commitment: Update::Retain,
        socket_addr_v4: Update::Retain,
        socket_addr_v6: Update::Retain,
        paymail_fee_sats: Update::Retain,
        xpubkey: Update::Retain,
    }
}

#[test]
fn disconnect_bitname_data_update() -> anyhow::Result<()> {
    let (_temp_dir, env, state) =
        fresh_state("disconnect_bitname_data_update")?;
    let mut rng = rand::rng();
    let batch_verification_ctxt = BatchVerificationContext::new(&mut rng);

    let signing_key = SigningKey::new(&mut rng);
    let verifying_key = VerifyingKey::from(&signing_key);
    let address = authorization::get_address(verifying_key);

    let name_hash: Hash = [1; 32];
    let revealed_nonce: Hash = [2; 32];
    let commitment: Hash =
        blake3::keyed_hash(&revealed_nonce, &name_hash).into();
    let reservation_txid = [3; 32].into();
    let bitname = BitName(name_hash);
    let bitname_outpoint = OutPoint::Regular {
        txid: [5; 32].into(),
        vout: 0,
    };

    {
        let mut rwtxn = env.write_txn()?;
        state.bitnames.put_reservation(
            &mut rwtxn,
            &reservation_txid,
            &commitment,
        )?;
        let registration_tx = Transaction {
            inputs: vec![OutPoint::Regular {
                txid: reservation_txid,
                vout: 0,
            }]
            .into(),
            outputs: Vec::new().into(),
            memo: Vec::new(),
            data: Some(TxData::BitNameRegistration {
                name_hash: bitname,
                revealed_nonce,
                bitname_data: Box::new(MutableBitNameData::default()),
            }),
        };
        let registration_filled = crate::types::FilledTransaction {
            transaction: registration_tx,
            spent_utxos: vec![FilledOutput {
                address,
                content: FilledOutputContent::BitNameReservation(
                    reservation_txid,
                    commitment,
                ),
                memo: Vec::new(),
            }],
        };
        state.bitnames.apply_registration(
            &mut rwtxn,
            &registration_filled,
            bitname,
            &MutableBitNameData::default(),
            0,
        )?;
        let seq = state.bitnames.next_seq(&rwtxn)?;
        anyhow::ensure!(seq == BitNameSeqId::new(1));
        state.utxos.put(
            &mut rwtxn,
            &OutPointKey::from_outpoint(&bitname_outpoint),
            &FilledOutput {
                address,
                content: FilledOutputContent::BitName(bitname),
                memo: Vec::new(),
            },
        )?;
        rwtxn.commit()?;
    }

    let genesis_body = Body {
        coinbase: Coinbase::default(),
        transactions: Vec::new(),
        authorizations: Vec::new(),
    };
    let genesis_merkle_root = Body::compute_merkle_root::<FilledTransaction>(
        &genesis_body.coinbase,
        &[],
        &genesis_body.authorizations,
    )?;
    let genesis_header = header(None, genesis_merkle_root);
    {
        let mut rwtxn = env.write_txn()?;
        connect(&state, &mut rwtxn, &genesis_header, &genesis_body)?;
        rwtxn.commit()?;
    }

    let mut updates = all_retained_updates();
    updates.commitment = Update::Set([9; 32]);
    let update_tx = Transaction {
        inputs: vec![bitname_outpoint].into(),
        outputs: vec![Output::new(address, OutputContent::BitName)].into(),
        memo: Vec::new(),
        data: Some(TxData::BitNameUpdate(Box::new(updates))),
    };
    let filled_update_tx = {
        let rotxn = env.read_txn()?;
        state.fill_transaction(&rotxn, &update_tx)?
    };
    let authorized_update = authorization::authorize(
        &mut rng,
        &[(address, &signing_key)],
        update_tx,
    )?;
    let update_body = Body::new(vec![authorized_update], Coinbase::default());
    let update_merkle_root = Body::compute_merkle_root(
        &update_body.coinbase,
        &[filled_update_tx],
        &update_body.authorizations,
    )?;
    let update_header = header(Some(genesis_header.hash()), update_merkle_root);
    let main_height = 9999;

    {
        let rotxn = env.read_txn()?;
        validate(
            &batch_verification_ctxt,
            &state,
            &rotxn,
            &update_header,
            main_height,
            &update_body,
        )?;
    }
    {
        let mut rwtxn = env.write_txn()?;
        connect(&state, &mut rwtxn, &update_header, &update_body)?;
        rwtxn.commit()?;
    }

    let mut rwtxn = env.write_txn()?;
    let () =
        disconnect_tip_body(&state, &mut rwtxn, &update_header, &update_body)?;
    Ok(())
}
