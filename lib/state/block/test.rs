use bitcoin::hashes::Hash as _;
use fallible_iterator::FallibleIterator as _;

use crate::{
    state::{
        Error,
        block::{
            connect, disconnect_tip_body, disconnect_tip_header, validate,
        },
        error,
        test::fresh_state,
    },
    types::{
        Address, BitName, BitNameDataUpdates, BitNameSeqId, BlockHash, Body,
        Coinbase, FilledOutput, FilledOutputContent, FilledTransaction, Hash,
        Header, InPoint, MerkleRoot, MutableBitNameData, OutPoint, OutPointKey,
        Output, OutputContent, Transaction, TxData, Txid, Update,
        authorization::{
            self, BatchVerificationContext, SigningKey, VerifyingKey,
        },
        constants,
        state::BitNameReservationPosition,
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

fn filled_registration(
    address: Address,
    bitname: BitName,
    revealed_nonce: Hash,
    reservation_txid: Txid,
    bitname_data: MutableBitNameData,
) -> FilledTransaction {
    let commitment: Hash =
        blake3::keyed_hash(&revealed_nonce, &bitname.0).into();
    let reservation_outpoint = OutPoint::Regular {
        txid: reservation_txid,
        vout: 0,
    };
    let mut transaction = Transaction::new(
        vec![reservation_outpoint].into(),
        vec![Output::new(address, OutputContent::BitName)].into(),
    );
    transaction.data = Some(TxData::BitNameRegistration {
        name_hash: bitname,
        revealed_nonce,
        bitname_data: Box::new(bitname_data),
    });
    FilledTransaction {
        transaction,
        spent_utxos: vec![FilledOutput::new(
            address,
            FilledOutputContent::BitNameReservation(
                reservation_txid,
                commitment,
            ),
        )],
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
        let () = state.bitnames.put_reservation(
            &mut rwtxn,
            &reservation_txid,
            &commitment,
            BitNameReservationPosition {
                mainchain: 0,
                sidechain: 0,
                tx_index: 0,
            },
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
        let () = state.bitnames.apply_registration(
            &mut rwtxn,
            &registration_filled,
            bitname,
            &MutableBitNameData::default(),
            0,
            None,
        )?;
        let seq = state.bitnames.next_seq(&rwtxn)?;
        anyhow::ensure!(seq == BitNameSeqId::new(1));
        let bitname_output = FilledOutput {
            address,
            content: FilledOutputContent::BitName(bitname),
            memo: Vec::new(),
        };
        state.utxos.put(
            &mut rwtxn,
            &OutPointKey::from_outpoint(&bitname_outpoint),
            &bitname_output,
        )?;
        let () = state.bitnames.put_bitname_outpoint(
            &mut rwtxn,
            &bitname_outpoint,
            &bitname_output,
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
        connect(&state, &mut rwtxn, &genesis_header, &genesis_body, 0)?;
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
        connect(
            &state,
            &mut rwtxn,
            &update_header,
            &update_body,
            main_height,
        )?;
        rwtxn.commit()?;
    }

    let mut rwtxn = env.write_txn()?;
    let () =
        disconnect_tip_body(&state, &mut rwtxn, &update_header, &update_body)?;
    Ok(())
}

#[test]
fn bitname_maturity_boundaries() -> anyhow::Result<()> {
    let (_temp_dir, env, state) = fresh_state("bitname_maturity")?;
    let address = Address::ALL_ZEROS;
    let reservation_txid = Txid([1; 32]);
    let commitment = [2; 32];
    {
        let mut rwtxn = env.write_txn()?;
        state.bitnames.put_reservation(
            &mut rwtxn,
            &reservation_txid,
            &commitment,
            BitNameReservationPosition {
                mainchain: 100,
                sidechain: 0,
                tx_index: 0,
            },
        )?;
        rwtxn.commit()?;
    }
    let reservation = FilledOutput::new(
        address,
        FilledOutputContent::BitNameReservation(reservation_txid, commitment),
    );
    let reservation_outpoint = OutPoint::Regular {
        txid: reservation_txid,
        vout: 0,
    };
    let reservation_transfer = FilledTransaction {
        transaction: Transaction::new(
            vec![reservation_outpoint].into(),
            vec![Output::new(address, OutputContent::BitNameReservation)]
                .into(),
        ),
        spent_utxos: vec![reservation],
    };
    let bitname = BitName([3; 32]);
    let registration_reservation_txid = Txid([4; 32]);
    let registration = filled_registration(
        address,
        bitname,
        [5; 32],
        registration_reservation_txid,
        MutableBitNameData::default(),
    );
    {
        let mut rwtxn = env.write_txn()?;
        state.bitnames.put_reservation(
            &mut rwtxn,
            &registration_reservation_txid,
            registration.spent_utxos[0]
                .reservation_commitment()
                .unwrap(),
            BitNameReservationPosition {
                mainchain: 100,
                sidechain: 0,
                tx_index: 0,
            },
        )?;
        rwtxn.commit()?;
    }
    {
        let rotxn = env.read_txn()?;
        state.validate_filled_transaction(
            &rotxn,
            101,
            &reservation_transfer,
        )?;
        let err = state
            .validate_filled_transaction(&rotxn, 101, &registration)
            .expect_err(
                "an immature reservation must not be used for registration",
            );
        anyhow::ensure!(matches!(
            err,
            Error::ImmatureOutPoint(
                error::ImmatureOutPoint::BitNameReservation
            )
        ));
    }
    {
        let mut rwtxn = env.write_txn()?;
        state.height.put(&mut rwtxn, &(), &0)?;
        rwtxn.commit()?;
    }
    {
        let rotxn = env.read_txn()?;
        state.validate_filled_transaction(&rotxn, 101, &registration)?;
        state.validate_filled_transaction(
            &rotxn,
            101,
            &reservation_transfer,
        )?;
        state.validate_filled_transaction(
            &rotxn,
            100 + constants::MAX_RESERVATION_AGE,
            &reservation_transfer,
        )?;
        let err = state
            .validate_filled_transaction(
                &rotxn,
                100 + constants::MAX_RESERVATION_AGE + 1,
                &reservation_transfer,
            )
            .expect_err(
                "a reservation must expire after the max reservation age",
            );
        anyhow::ensure!(matches!(
            err,
            Error::BitNameReservationExpired { txid } if txid == reservation_txid
        ));
    }

    {
        let mut rwtxn = env.write_txn()?;
        let () = state.bitnames.apply_registration(
            &mut rwtxn,
            &registration,
            bitname,
            &MutableBitNameData::default(),
            0,
            None,
        )?;
        rwtxn.commit()?;
    }
    let bitname_outpoint = OutPoint::Regular {
        txid: registration.txid(),
        vout: 0,
    };
    let bitname_transfer = FilledTransaction {
        transaction: Transaction::new(
            vec![bitname_outpoint].into(),
            vec![Output::new(address, OutputContent::BitName)].into(),
        ),
        spent_utxos: vec![FilledOutput::new(
            address,
            FilledOutputContent::BitName(bitname),
        )],
    };
    let rotxn = env.read_txn()?;
    let err = state
        .validate_filled_transaction(
            &rotxn,
            100 + constants::MAX_RESERVATION_AGE,
            &bitname_transfer,
        )
        .expect_err("an immature registration must not be spendable");
    anyhow::ensure!(matches!(
        err,
        Error::ImmatureOutPoint(error::ImmatureOutPoint::BitNameRegistration)
    ));
    state.validate_filled_transaction(
        &rotxn,
        100 + constants::MAX_RESERVATION_AGE + 1,
        &bitname_transfer,
    )?;
    Ok(())
}

#[test]
fn expired_reservation_pruning_roundtrip() -> anyhow::Result<()> {
    let (_temp_dir, env, state) = fresh_state("reservation_pruning")?;
    let mut rng = rand::rng();
    let batch_verification_ctxt = BatchVerificationContext::new(&mut rng);
    let signing_key = SigningKey::new(&mut rng);
    let address = authorization::get_address(VerifyingKey::from(&signing_key));
    let reservation_txid = Txid([1; 32]);
    let commitment = [2; 32];
    let position = BitNameReservationPosition {
        mainchain: 0,
        sidechain: 0,
        tx_index: 0,
    };
    let outpoint = OutPoint::Regular {
        txid: reservation_txid,
        vout: 0,
    };
    let output = FilledOutput::new(
        address,
        FilledOutputContent::BitNameReservation(reservation_txid, commitment),
    );
    {
        let mut rwtxn = env.write_txn()?;
        state
            .utxos
            .put(&mut rwtxn, &OutPointKey::from(&outpoint), &output)?;
        let () = state.bitnames.put_reservation(
            &mut rwtxn,
            &reservation_txid,
            &commitment,
            position,
        )?;
        let () = state.bitnames.put_reservation_outpoint_at_initial_height(
            &mut rwtxn, &outpoint, &output,
        )?;
        rwtxn.commit()?;
    }

    let transfer = Transaction::new(
        vec![outpoint].into(),
        vec![Output::new(address, OutputContent::BitNameReservation)].into(),
    );
    let filled_transfer = FilledTransaction {
        transaction: transfer,
        spent_utxos: vec![output.clone()],
    };
    let authorized_transfer = authorization::authorize(
        &mut rng,
        &[(address, &signing_key)],
        filled_transfer.transaction.clone(),
    )?;
    let transfer_body =
        Body::new(vec![authorized_transfer], Coinbase::default());
    let transfer_merkle_root = Body::compute_merkle_root(
        &transfer_body.coinbase,
        std::slice::from_ref(&filled_transfer),
        &transfer_body.authorizations,
    )?;
    let transfer_header = header(None, transfer_merkle_root);
    let transferred_outpoint = OutPoint::Regular {
        txid: filled_transfer.txid(),
        vout: 0,
    };

    let prune_body = Body {
        coinbase: Coinbase::default(),
        transactions: Vec::new(),
        authorizations: Vec::new(),
    };
    let prune_merkle_root = Body::compute_merkle_root::<FilledTransaction>(
        &prune_body.coinbase,
        &[],
        &prune_body.authorizations,
    )?;
    let prune_header = header(Some(transfer_header.hash()), prune_merkle_root);

    let mut rwtxn = env.write_txn()?;
    let () = state.apply_block(
        &mut rwtxn,
        &batch_verification_ctxt,
        &transfer_header,
        0,
        &transfer_body,
    )?;
    anyhow::ensure!(
        state
            .utxos
            .try_get(&rwtxn, &OutPointKey::from(&outpoint))?
            .is_none()
    );
    anyhow::ensure!(
        state
            .utxos
            .try_get(&rwtxn, &OutPointKey::from(&transferred_outpoint))?
            == Some(output.clone())
    );
    anyhow::ensure!(
        state
            .bitnames
            .reservation_outpoints_through_initial_mainchain_height(&rwtxn, 0)?
            .collect::<Vec<_>>()?
            == vec![transferred_outpoint]
    );

    state.apply_block(
        &mut rwtxn,
        &batch_verification_ctxt,
        &prune_header,
        constants::MAX_RESERVATION_AGE,
        &prune_body,
    )?;
    anyhow::ensure!(
        state
            .utxos
            .try_get(&rwtxn, &OutPointKey::from(&transferred_outpoint))?
            .is_none()
    );
    anyhow::ensure!(
        state
            .bitnames
            .try_get_reservation_heights(&rwtxn, &reservation_txid)?
            .is_none()
    );
    anyhow::ensure!(
        state
            .bitnames
            .reservation_outpoints_through_initial_mainchain_height(&rwtxn, 0)?
            .next()?
            .is_none()
    );

    let () =
        disconnect_tip_body(&state, &mut rwtxn, &prune_header, &prune_body)?;
    let () = disconnect_tip_header(&state, &mut rwtxn, &prune_header)?;
    anyhow::ensure!(
        state
            .utxos
            .try_get(&rwtxn, &OutPointKey::from(&transferred_outpoint))?
            == Some(output.clone())
    );
    anyhow::ensure!(
        state
            .bitnames
            .reservation_outpoints_through_initial_mainchain_height(&rwtxn, 0)?
            .collect::<Vec<_>>()?
            == vec![transferred_outpoint]
    );

    let () = disconnect_tip_body(
        &state,
        &mut rwtxn,
        &transfer_header,
        &transfer_body,
    )?;
    let () = disconnect_tip_header(&state, &mut rwtxn, &transfer_header)?;
    anyhow::ensure!(
        state.utxos.try_get(&rwtxn, &OutPointKey::from(&outpoint))?
            == Some(output)
    );
    anyhow::ensure!(
        state
            .utxos
            .try_get(&rwtxn, &OutPointKey::from(&transferred_outpoint))?
            .is_none()
    );
    anyhow::ensure!(
        state
            .bitnames
            .try_get_reservation_heights(&rwtxn, &reservation_txid)?
            == Some(position)
    );
    anyhow::ensure!(
        state
            .bitnames
            .reservation_outpoints_through_initial_mainchain_height(&rwtxn, 0)?
            .collect::<Vec<_>>()?
            == vec![outpoint]
    );
    Ok(())
}

#[test]
fn registration_challenge_roundtrip() -> anyhow::Result<()> {
    let (_temp_dir, env, state) = fresh_state("registration_challenge")?;
    let mut rng = rand::rng();
    let batch_verification_ctxt = BatchVerificationContext::new(&mut rng);
    let signing_key = SigningKey::new(&mut rng);
    let address = authorization::get_address(VerifyingKey::from(&signing_key));
    let bitname = BitName([1; 32]);
    let initial_data = MutableBitNameData {
        commitment: Some([9; 32]),
        ..Default::default()
    };
    let challenge_data = MutableBitNameData {
        commitment: Some([8; 32]),
        ..Default::default()
    };
    let older = filled_registration(
        address,
        bitname,
        [2; 32],
        Txid([2; 32]),
        challenge_data.clone(),
    );
    let newer = filled_registration(
        address,
        bitname,
        [3; 32],
        Txid([3; 32]),
        initial_data.clone(),
    );
    let incumbent_outpoint = OutPoint::Regular {
        txid: Txid([4; 32]),
        vout: 0,
    };
    let incumbent_output =
        FilledOutput::new(address, FilledOutputContent::BitName(bitname));
    let initial_seq_id = {
        let mut rwtxn = env.write_txn()?;
        let () = state.bitnames.put_reservation(
            &mut rwtxn,
            older.spent_utxos[0].reservation_data().unwrap().0,
            older.spent_utxos[0].reservation_commitment().unwrap(),
            BitNameReservationPosition {
                mainchain: 100,
                sidechain: 0,
                tx_index: 0,
            },
        )?;
        let () = state.bitnames.put_reservation(
            &mut rwtxn,
            newer.spent_utxos[0].reservation_data().unwrap().0,
            newer.spent_utxos[0].reservation_commitment().unwrap(),
            BitNameReservationPosition {
                mainchain: 100,
                sidechain: 0,
                tx_index: 1,
            },
        )?;
        let () = state.bitnames.apply_registration(
            &mut rwtxn,
            &newer,
            bitname,
            &initial_data,
            1,
            None,
        )?;
        state.utxos.put(
            &mut rwtxn,
            &OutPointKey::from(&incumbent_outpoint),
            &incumbent_output,
        )?;
        let () = state.bitnames.put_bitname_outpoint(
            &mut rwtxn,
            &incumbent_outpoint,
            &incumbent_output,
        )?;
        state.utxos.put(
            &mut rwtxn,
            &OutPointKey::from(&older.transaction.inputs.0[0]),
            &older.spent_utxos[0],
        )?;
        state.bitnames.put_reservation_outpoint_at_initial_height(
            &mut rwtxn,
            &older.transaction.inputs.0[0],
            &older.spent_utxos[0],
        )?;
        state.height.put(&mut rwtxn, &(), &1)?;
        state.tip.put(&mut rwtxn, &(), &[5; 32].into())?;
        let seq_id = state.bitnames.get_bitname(&rwtxn, &bitname)?.seq_id;
        rwtxn.commit()?;
        seq_id
    };

    let too_new = filled_registration(
        address,
        bitname,
        [6; 32],
        Txid([6; 32]),
        MutableBitNameData::default(),
    );
    {
        let mut rwtxn = env.write_txn()?;
        let () = state.bitnames.put_reservation(
            &mut rwtxn,
            too_new.spent_utxos[0].reservation_data().unwrap().0,
            too_new.spent_utxos[0].reservation_commitment().unwrap(),
            BitNameReservationPosition {
                mainchain: 100,
                sidechain: 0,
                tx_index: 2,
            },
        )?;
        let err = state
            .validate_bitnames(&rwtxn, 102, &too_new)
            .expect_err("a newer reservation must not replace a registration");
        anyhow::ensure!(matches!(
            err,
            Error::BitNameReservationNotOlder { name_hash } if name_hash == bitname
        ));
    }

    let authorized = authorization::authorize(
        &mut rng,
        &[(address, &signing_key)],
        older.transaction.clone(),
    )?;
    let body = Body::new(vec![authorized], Coinbase::default());
    let merkle_root = Body::compute_merkle_root(
        &body.coinbase,
        std::slice::from_ref(&older),
        &body.authorizations,
    )?;
    let header = header(Some([5; 32].into()), merkle_root);
    {
        let rotxn = env.read_txn()?;
        validate(
            &batch_verification_ctxt,
            &state,
            &rotxn,
            &header,
            102,
            &body,
        )?;
    }
    {
        let mut rwtxn = env.write_txn()?;
        connect(&state, &mut rwtxn, &header, &body, 102)?;
        let incumbent_key = OutPointKey::from(&incumbent_outpoint);
        anyhow::ensure!(state.utxos.try_get(&rwtxn, &incumbent_key)?.is_none());
        let incumbent_stxo = state
            .stxos
            .try_get(&rwtxn, &incumbent_key)?
            .expect("the invalidated incumbent should have an STXO");
        anyhow::ensure!(
            incumbent_stxo.inpoint
                == InPoint::Regular {
                    txid: older.txid(),
                    vin: 0,
                }
        );
        anyhow::ensure!(
            state.bitnames.try_get_bitname_outpoint(&rwtxn, &bitname)?
                == Some(OutPoint::Regular {
                    txid: older.txid(),
                    vout: 0,
                })
        );
        let current = state.bitnames.get_bitname(&rwtxn, &bitname)?;
        anyhow::ensure!(current.seq_id == initial_seq_id);
        anyhow::ensure!(
            current.reservation_heights.latest().data
                == BitNameReservationPosition {
                    mainchain: 100,
                    sidechain: 0,
                    tx_index: 0,
                }
        );
        anyhow::ensure!(
            current.current().mutable_data.commitment
                == challenge_data.commitment
        );
        anyhow::ensure!(
            state.bitnames.next_seq(&rwtxn)? == initial_seq_id.next()
        );
        rwtxn.commit()?;
    }
    {
        let mut rwtxn = env.write_txn()?;
        let () = disconnect_tip_body(&state, &mut rwtxn, &header, &body)?;
        let incumbent_key = OutPointKey::from(&incumbent_outpoint);
        anyhow::ensure!(
            state.utxos.try_get(&rwtxn, &incumbent_key)?
                == Some(incumbent_output)
        );
        anyhow::ensure!(state.stxos.try_get(&rwtxn, &incumbent_key)?.is_none());
        anyhow::ensure!(
            state.bitnames.try_get_bitname_outpoint(&rwtxn, &bitname)?
                == Some(incumbent_outpoint)
        );
        let current = state.bitnames.get_bitname(&rwtxn, &bitname)?;
        anyhow::ensure!(current.seq_id == initial_seq_id);
        anyhow::ensure!(
            current.reservation_heights.latest().data
                == BitNameReservationPosition {
                    mainchain: 100,
                    sidechain: 0,
                    tx_index: 1,
                }
        );
        anyhow::ensure!(
            current.current().mutable_data.commitment
                == initial_data.commitment
        );
        anyhow::ensure!(
            state.bitnames.try_get_reservation_heights(
                &rwtxn,
                older.spent_utxos[0].reservation_data().unwrap().0,
            )? == Some(BitNameReservationPosition {
                mainchain: 100,
                sidechain: 0,
                tx_index: 0,
            })
        );
        anyhow::ensure!(
            state
                .bitnames
                .reservation_outpoints_through_initial_mainchain_height(
                    &rwtxn, 100
                )?
                .collect::<Vec<_>>()?
                == vec![older.transaction.inputs.0[0]]
        );
    }
    Ok(())
}
