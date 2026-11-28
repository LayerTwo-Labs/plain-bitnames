use std::collections::BTreeMap;

use bitcoin::{
    Network,
    hashes::Hash as _,
    secp256k1::{Secp256k1, SecretKey},
};
use hashlink::LinkedHashMap;

use crate::{
    state::{
        State, WITHDRAWAL_BUNDLE_FAILURE_GAP, WithdrawalBundleInfo,
        rollback::{HeightStamped, RollBack},
        test::{bitcoin_filled_output, fresh_state},
        two_way_peg_data::{
            collect_withdrawal_bundle, connect,
            connect_withdrawal_bundle_confirmed,
            connect_withdrawal_bundle_failed,
            connect_withdrawal_bundle_submitted, disconnect,
            disconnect_withdrawal_bundle_failed,
            maybe_create_withdrawal_bundle,
        },
    },
    types::{
        Address, Coinbase, FilledOutput, FilledOutputContent,
        FilledTransaction, InPoint, M6id, OutPoint, OutPointKey, SpentOutput,
        Transaction, Txid, WithdrawalBundle, WithdrawalBundleEvent,
        WithdrawalBundleEventStatus, WithdrawalBundleStatus,
        WithdrawalOutputContent,
        proto::mainchain::{
            BlockEvent, BlockInfo, Deposit, TwoWayPegData, two_way_peg_data,
        },
    },
};

// a failed known bundle recreates its outputs at
// `OutPoint::UnsuccessfulWithdrawal` outpoints, so disconnecting the
// failure must delete the recreations; the original STXO record
// remains untouched
#[test]
fn disconnect_failed_bundle_removes_recreated_utxo() -> anyhow::Result<()> {
    let (_temp_dir, env, state) =
        fresh_state("disconnect_failed_bundle_removes_recreated_utxo")?;
    let outpoint = OutPoint::Regular {
        txid: Txid::from([1; 32]),
        vout: 0,
    };
    let output = bitcoin_filled_output(Address::ALL_ZEROS, 1000);
    let key = OutPointKey::from(&outpoint);
    let bundle = {
        let mut spend_utxos = BTreeMap::new();
        spend_utxos.insert(outpoint, output.clone());
        WithdrawalBundle::new(
            1,
            bitcoin::Amount::ZERO,
            spend_utxos,
            Vec::new(),
        )?
    };
    let m6id = bundle.compute_m6id();
    let recreated_outpoint = OutPoint::UnsuccessfulWithdrawal {
        m6id,
        height: 1,
        vout: 0,
    };
    {
        let mut bundle_status = RollBack::<HeightStamped<_>>::new(
            WithdrawalBundleStatus::Submitted,
            0,
        );
        bundle_status
            .push(WithdrawalBundleStatus::Failed, 1)
            .unwrap();
        let mut rwtxn = env.write_txn()?;
        state.withdrawal_bundles.put(
            &mut rwtxn,
            &m6id,
            &(WithdrawalBundleInfo::Known(bundle), bundle_status),
        )?;
        state.latest_failed_withdrawal_bundle.put(
            &mut rwtxn,
            &(),
            &RollBack::<HeightStamped<_>>::new(m6id, 1),
        )?;
        // the bundle spent the original output at creation...
        let spent_output = SpentOutput {
            output: output.clone(),
            inpoint: InPoint::Withdrawal { m6id },
        };
        state.stxos.put(&mut rwtxn, &key, &spent_output)?;
        // ...and the failure recreated it at a new outpoint
        state.utxos.put(
            &mut rwtxn,
            &OutPointKey::from(&recreated_outpoint),
            &output,
        )?;
        rwtxn.commit()?;
    }

    let mut rwtxn = env.write_txn()?;
    disconnect_withdrawal_bundle_failed(&state, &mut rwtxn, 1, m6id)?;
    anyhow::ensure!(
        state
            .utxos
            .try_get(&rwtxn, &OutPointKey::from(&recreated_outpoint))?
            .is_none()
    );
    let stxo = state.stxos.get(&rwtxn, &key)?;
    anyhow::ensure!(stxo.inpoint == InPoint::Withdrawal { m6id });
    Ok(())
}

fn withdrawal_output(
    main_address: bitcoin::Address<bitcoin::address::NetworkUnchecked>,
) -> FilledOutput {
    FilledOutput {
        address: Address::ALL_ZEROS,
        content: FilledOutputContent::BitcoinWithdrawal(
            WithdrawalOutputContent {
                value: bitcoin::Amount::from_sat(1000),
                main_fee: bitcoin::Amount::from_sat(300),
                main_address,
            },
        ),
        memo: Vec::new(),
    }
}

// constructing a withdrawal bundle spends the selected outputs
#[test]
fn maybe_create_withdrawal_bundle_spends_outputs() -> anyhow::Result<()> {
    let (_temp_dir, env, state) =
        fresh_state("maybe_create_withdrawal_bundle_spends_outputs")?;
    let mut rwtxn = env.write_txn()?;
    state
        .height
        .put(&mut rwtxn, &(), &WITHDRAWAL_BUNDLE_FAILURE_GAP)?;
    let withdrawal_outpoint = OutPoint::Regular {
        txid: Txid::from([1; 32]),
        vout: 0,
    };
    let withdrawal_output = withdrawal_output(regtest_p2wpkh_address(1));
    let value_outpoint = OutPoint::Regular {
        txid: Txid::from([2; 32]),
        vout: 0,
    };
    state.utxos.put(
        &mut rwtxn,
        &OutPointKey::from(&withdrawal_outpoint),
        &withdrawal_output,
    )?;
    state.utxos.put(
        &mut rwtxn,
        &OutPointKey::from(&value_outpoint),
        &bitcoin_filled_output(Address::ALL_ZEROS, 50),
    )?;
    maybe_create_withdrawal_bundle(&state, &mut rwtxn)?;
    // the withdrawal output is spent by the bundle...
    anyhow::ensure!(
        state
            .utxos
            .try_get(&rwtxn, &OutPointKey::from(&withdrawal_outpoint))?
            .is_none()
    );
    let pending_m6id = state
        .pending_withdrawal_bundle
        .try_get(&rwtxn, &())?
        .expect("pending bundle should exist");
    let stxo = state
        .stxos
        .get(&rwtxn, &OutPointKey::from(&withdrawal_outpoint))?;
    anyhow::ensure!(stxo.inpoint == InPoint::Withdrawal { m6id: pending_m6id });
    // ...while the value output is untouched
    anyhow::ensure!(
        state
            .utxos
            .try_get(&rwtxn, &OutPointKey::from(&value_outpoint))?
            .is_some()
    );
    // the pending bundle is well-formed and spends the output
    let (bundle, height) =
        state.try_get_pending_withdrawal_bundle(&rwtxn)?.unwrap();
    anyhow::ensure!(height == WITHDRAWAL_BUNDLE_FAILURE_GAP);
    anyhow::ensure!(bundle.spend_utxos().len() == 1);
    anyhow::ensure!(bundle.spend_utxos().contains_key(&withdrawal_outpoint));
    rwtxn.commit()?;
    Ok(())
}

// failing a submitted bundle recreates its outputs at
// `OutPoint::UnsuccessfulWithdrawal` outpoints; the recreations are
// spendable
#[test]
fn failed_bundle_recreates_spendable_outputs() -> anyhow::Result<()> {
    let (_temp_dir, env, state) =
        fresh_state("failed_bundle_recreates_spendable_outputs")?;
    let mut rwtxn = env.write_txn()?;
    state
        .height
        .put(&mut rwtxn, &(), &WITHDRAWAL_BUNDLE_FAILURE_GAP)?;
    let withdrawal_outpoint = OutPoint::Regular {
        txid: Txid::from([1; 32]),
        vout: 0,
    };
    let withdrawal_output = withdrawal_output(regtest_p2wpkh_address(1));
    state.utxos.put(
        &mut rwtxn,
        &OutPointKey::from(&withdrawal_outpoint),
        &withdrawal_output,
    )?;
    maybe_create_withdrawal_bundle(&state, &mut rwtxn)?;
    let m6id = state
        .pending_withdrawal_bundle
        .try_get(&rwtxn, &())?
        .unwrap();
    // submit the bundle
    connect_withdrawal_bundle_submitted(
        &state,
        &mut rwtxn,
        WITHDRAWAL_BUNDLE_FAILURE_GAP,
        &bitcoin::BlockHash::from_byte_array([9; 32]),
        m6id,
    )?;
    // fail the bundle at the next height
    let failed_height = WITHDRAWAL_BUNDLE_FAILURE_GAP + 1;
    connect_withdrawal_bundle_failed(&state, &mut rwtxn, failed_height, m6id)?;
    // the recreated output exists, with identical content
    let recreated_outpoint = OutPoint::UnsuccessfulWithdrawal {
        m6id,
        height: failed_height,
        vout: 0,
    };
    let recreated = state
        .utxos
        .get(&rwtxn, &OutPointKey::from(&recreated_outpoint))?;
    anyhow::ensure!(recreated == withdrawal_output);
    // the original STXO record is untouched
    let stxo = state
        .stxos
        .get(&rwtxn, &OutPointKey::from(&withdrawal_outpoint))?;
    anyhow::ensure!(stxo.inpoint == InPoint::Withdrawal { m6id });
    // the recreation is spendable
    let tx = FilledTransaction {
        transaction: Transaction {
            inputs: vec![recreated_outpoint].into(),
            outputs: vec![
                bitcoin_filled_output(Address::ALL_ZEROS, 1300).into(),
            ]
            .into(),
            ..Default::default()
        },
        spent_utxos: vec![recreated],
    };
    let fee = state.validate_filled_transaction(&rwtxn, 0, &tx)?;
    anyhow::ensure!(fee == bitcoin::Amount::ZERO);
    rwtxn.commit()?;
    Ok(())
}

// a stale pending bundle is dropped while connecting 2WPD; its
// outputs are recreated and can be included in the fresh bundle
// constructed after the block's txs
#[test]
fn stale_pending_bundle_dropped_and_rebundled() -> anyhow::Result<()> {
    let (_temp_dir, env, state) =
        fresh_state("stale_pending_bundle_dropped_and_rebundled")?;
    let mut rwtxn = env.write_txn()?;
    let created_height = WITHDRAWAL_BUNDLE_FAILURE_GAP;
    state.height.put(&mut rwtxn, &(), &created_height)?;
    let withdrawal_outpoint = OutPoint::Regular {
        txid: Txid::from([1; 32]),
        vout: 0,
    };
    let withdrawal_output = withdrawal_output(regtest_p2wpkh_address(1));
    state.utxos.put(
        &mut rwtxn,
        &OutPointKey::from(&withdrawal_outpoint),
        &withdrawal_output,
    )?;
    maybe_create_withdrawal_bundle(&state, &mut rwtxn)?;
    let stale_m6id = state
        .pending_withdrawal_bundle
        .try_get(&rwtxn, &())?
        .unwrap();
    // connect 2WPD for a block GAP heights later: the stale bundle
    // is dropped before the block's txs
    let drop_height = created_height + WITHDRAWAL_BUNDLE_FAILURE_GAP;
    state.height.put(&mut rwtxn, &(), &(drop_height - 1))?;
    connect(&state, &mut rwtxn, &TwoWayPegData::default())?;
    let (_bundle, status) = state
        .try_get_withdrawal_bundle(&rwtxn, &stale_m6id)?
        .unwrap();
    anyhow::ensure!(status == WithdrawalBundleStatus::Dropped);
    anyhow::ensure!(
        state
            .pending_withdrawal_bundle
            .try_get(&rwtxn, &())?
            .is_none()
    );
    let recreated_outpoint = OutPoint::UnsuccessfulWithdrawal {
        m6id: stale_m6id,
        height: drop_height,
        vout: 0,
    };
    anyhow::ensure!(
        state
            .utxos
            .try_get(&rwtxn, &OutPointKey::from(&recreated_outpoint))?
            .is_some()
    );
    // no fresh bundle yet: the failure gap applies after a drop
    state.height.put(&mut rwtxn, &(), &drop_height)?;
    maybe_create_withdrawal_bundle(&state, &mut rwtxn)?;
    anyhow::ensure!(
        state
            .pending_withdrawal_bundle
            .try_get(&rwtxn, &())?
            .is_none()
    );
    // the recreated output is spendable in the meantime (covered
    // by failed_bundle_recreates_spendable_outputs), and is
    // included in the fresh bundle once the gap passes
    state.height.put(
        &mut rwtxn,
        &(),
        &(drop_height + WITHDRAWAL_BUNDLE_FAILURE_GAP),
    )?;
    maybe_create_withdrawal_bundle(&state, &mut rwtxn)?;
    let (bundle, _) = state.try_get_pending_withdrawal_bundle(&rwtxn)?.unwrap();
    anyhow::ensure!(bundle.compute_m6id() != stale_m6id);
    anyhow::ensure!(bundle.spend_utxos().contains_key(&recreated_outpoint));
    rwtxn.commit()?;
    Ok(())
}

// confirming a previously failed bundle is an insolvency error: its
// outputs were already spent at creation and recreated at failure
#[test]
fn unexpected_bundle_confirmed_is_insolvent_error() -> anyhow::Result<()> {
    let (_temp_dir, env, state) =
        fresh_state("unexpected_bundle_confirmed_is_insolvent_error")?;
    let mut rwtxn = env.write_txn()?;
    state
        .height
        .put(&mut rwtxn, &(), &WITHDRAWAL_BUNDLE_FAILURE_GAP)?;
    // seed a known bundle with status SubmittedUnexpected
    let outpoint = OutPoint::Regular {
        txid: Txid::from([1; 32]),
        vout: 0,
    };
    let output = bitcoin_filled_output(Address::ALL_ZEROS, 1000);
    let mut spend_utxos = BTreeMap::new();
    spend_utxos.insert(outpoint, output);
    let bundle = WithdrawalBundle::new(
        1,
        bitcoin::Amount::ZERO,
        spend_utxos,
        Vec::new(),
    )?;
    let m6id = bundle.compute_m6id();
    let mut bundle_status =
        RollBack::<HeightStamped<_>>::new(WithdrawalBundleStatus::Failed, 1);
    bundle_status
        .push(WithdrawalBundleStatus::SubmittedUnexpected, 2)
        .unwrap();
    state.withdrawal_bundles.put(
        &mut rwtxn,
        &m6id,
        &(WithdrawalBundleInfo::Known(bundle), bundle_status),
    )?;
    let res = connect_withdrawal_bundle_confirmed(
        &state,
        &mut rwtxn,
        3,
        &bitcoin::BlockHash::from_byte_array([9; 32]),
        m6id,
    );
    anyhow::ensure!(matches!(
        res,
        Err(crate::state::Error::UnexpectedWithdrawalBundleConfirmed { .. })
    ));
    Ok(())
}

// disconnecting a withdrawal bundle event must remove its
// withdrawal_bundle_event_blocks record, not a deposit_blocks record that
// happens to share the same sequence index
#[test]
fn disconnect_withdrawal_event_block_uses_correct_db() -> anyhow::Result<()> {
    let (_temp_dir, env, state) =
        fresh_state("disconnect_withdrawal_event_block_uses_correct_db")?;

    let block_height = 5u32;
    let m6id = M6id(bitcoin::Txid::from_byte_array([7; 32]));
    let event_block_hash = bitcoin::BlockHash::from_byte_array([9; 32]);
    let deposit_block_hash = bitcoin::BlockHash::from_byte_array([3; 32]);

    let mut rwtxn = env.write_txn()?;
    state.height.put(&mut rwtxn, &(), &block_height)?;
    state.withdrawal_bundles.put(
        &mut rwtxn,
        &m6id,
        &(
            WithdrawalBundleInfo::Unknown,
            RollBack::<HeightStamped<_>>::new(
                WithdrawalBundleStatus::Submitted,
                block_height,
            ),
        ),
    )?;
    state.withdrawal_bundle_event_blocks.put(
        &mut rwtxn,
        &0,
        &(event_block_hash, block_height),
    )?;
    // a deposit record at the same sequence index that must survive
    state.deposit_blocks.put(
        &mut rwtxn,
        &0,
        &(deposit_block_hash, block_height),
    )?;
    rwtxn.commit()?;

    let two_way_peg_data = {
        let mut block_info = LinkedHashMap::new();
        block_info.insert(
            event_block_hash,
            two_way_peg_data::BlockInfo {
                height: 999,
                inner: BlockInfo {
                    bmm_commitment: None,
                    events: vec![BlockEvent::WithdrawalBundle(
                        WithdrawalBundleEvent {
                            m6id,
                            status: WithdrawalBundleEventStatus::Submitted,
                        },
                    )],
                },
            },
        );
        TwoWayPegData { block_info }
    };

    let mut rwtxn = env.write_txn()?;
    disconnect(&state, &mut rwtxn, &two_way_peg_data)?;
    anyhow::ensure!(
        state
            .withdrawal_bundle_event_blocks
            .try_get(&rwtxn, &0)?
            .is_none()
    );
    anyhow::ensure!(state.deposit_blocks.try_get(&rwtxn, &0)?.is_some());
    rwtxn.commit()?;
    Ok(())
}

fn seeded_public_key(idx: u32) -> bitcoin::CompressedPublicKey {
    let secp = Secp256k1::new();
    let mut key_bytes = [0_u8; 32];
    key_bytes[28..].copy_from_slice(&idx.to_be_bytes());
    let secret_key = SecretKey::from_slice(&key_bytes)
        .expect("small non-zero integers are valid secret keys");
    let public_key =
        bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &secret_key);
    bitcoin::CompressedPublicKey(public_key)
}

fn regtest_p2wpkh_address(
    idx: u32,
) -> bitcoin::Address<bitcoin::address::NetworkUnchecked> {
    let public_key = seeded_public_key(idx);
    bitcoin::Address::p2wpkh(&public_key, Network::Regtest).into_unchecked()
}

fn with_state_with_withdrawals<R>(
    test_name: &str,
    count: u32,
    main_address: fn(
        u32,
    )
        -> bitcoin::Address<bitcoin::address::NetworkUnchecked>,
    f: impl FnOnce(&State, &mut sneed::RwTxn<'_>) -> R,
) -> anyhow::Result<R> {
    let (_temp_dir, env, state) = fresh_state(test_name)?;
    let res = {
        let mut rwtxn = env.write_txn()?;
        state.height.put(
            &mut rwtxn,
            &(),
            &crate::state::WITHDRAWAL_BUNDLE_FAILURE_GAP,
        )?;

        for idx in 1..=count {
            let mut txid_bytes = [0_u8; 32];
            txid_bytes[28..].copy_from_slice(&idx.to_be_bytes());
            let outpoint = OutPoint::Regular {
                txid: txid_bytes.into(),
                vout: 0,
            };
            let output = FilledOutput {
                address: {
                    let mut addr = [0u8; 20];
                    let idx = idx.to_be_bytes();
                    addr[..idx.len()].copy_from_slice(&idx);
                    Address::from(addr)
                },
                content: FilledOutputContent::BitcoinWithdrawal(
                    WithdrawalOutputContent {
                        value: bitcoin::Amount::from_sat(1_000),
                        main_fee: bitcoin::Amount::ZERO,
                        main_address: main_address(idx),
                    },
                ),
                memo: Vec::new(),
            };
            state.utxos.put(
                &mut rwtxn,
                &OutPointKey::from(&outpoint),
                &output,
            )?;
        }
        f(&state, &mut rwtxn)
    };
    Ok(res)
}

#[test]
fn collect_withdrawal_bundle_p2wpkh_off_by_one_does_not_exceed_weight()
-> anyhow::Result<()> {
    const CLAIMED_MAX_BUNDLE_OUTPUTS: u32 = 3_222;

    let bundle = with_state_with_withdrawals(
        "collect_withdrawal_bundle_p2wpkh_off_by_one",
        CLAIMED_MAX_BUNDLE_OUTPUTS + 1,
        regtest_p2wpkh_address,
        |state, rwtxn| collect_withdrawal_bundle(state, rwtxn, 42),
    )?;
    let bundle = match bundle {
        Ok(Some(bundle)) => bundle,
        Ok(None) => anyhow::bail!("expected a withdrawal bundle"),
        Err(err) => anyhow::bail!("unexpected collection error: {err:?}"),
    };
    let output_count = bundle.tx().output.len();
    let weight = bundle.tx().weight().to_wu();

    anyhow::ensure!(
        output_count == (CLAIMED_MAX_BUNDLE_OUTPUTS as usize + 2),
        "expected {} tx outputs including metadata, got {output_count}",
        CLAIMED_MAX_BUNDLE_OUTPUTS as usize + 2,
    );
    anyhow::ensure!(
        weight <= bitcoin::policy::MAX_STANDARD_TX_WEIGHT as u64,
        "unexpected overweight P2WPKH bundle: {weight} wu"
    );
    Ok(())
}

// connecting a deposit then disconnecting it on a reorg must round-trip
#[test]
fn deposit_reorg_round_trips() -> anyhow::Result<()> {
    use crate::types::{
        Body, FilledTransaction, Header,
        authorization::BatchVerificationContext, proto::mainchain::Deposit,
    };

    let (_temp_dir, env, state) = fresh_state("deposit_reorg_round_trips")?;
    let batch_verification_ctxt =
        BatchVerificationContext::new(&mut rand::rng());
    let empty_body = Body {
        coinbase: Coinbase::default(),
        transactions: Vec::new(),
        authorizations: Vec::new(),
    };
    let no_txs: &[FilledTransaction] = &[];
    let merkle_root = Body::compute_merkle_root(
        &empty_body.coinbase,
        no_txs,
        &empty_body.authorizations,
    )?;
    let main0 = bitcoin::BlockHash::from_byte_array([10; 32]);
    let main_height0 = 99;
    let main1 = bitcoin::BlockHash::from_byte_array([11; 32]);
    let main_height1 = 9999;

    let genesis = Header {
        merkle_root,
        prev_side_hash: None,
        prev_main_hash: main0,
    };
    {
        let mut rwtxn = env.write_txn()?;
        // production order: 2WPD events before the block body
        state
            .connect_two_way_peg_data(&mut rwtxn, &TwoWayPegData::default())?;
        state.apply_block(
            &mut rwtxn,
            &batch_verification_ctxt,
            &genesis,
            main_height0,
            &empty_body,
        )?;
        rwtxn.commit()?;
    }

    let deposit_outpoint = bitcoin::OutPoint {
        txid: bitcoin::Txid::from_byte_array([2; 32]),
        vout: 0,
    };
    let deposit_key = OutPointKey::from(&OutPoint::Deposit(deposit_outpoint));
    let deposit_twpd = {
        let mut block_info = LinkedHashMap::new();
        block_info.insert(
            main1,
            two_way_peg_data::BlockInfo {
                height: main_height1,
                inner: BlockInfo {
                    bmm_commitment: None,
                    events: vec![BlockEvent::Deposit(Deposit {
                        tx_index: 0,
                        outpoint: deposit_outpoint,
                        output: bitcoin_filled_output(Address::ALL_ZEROS, 1000),
                    })],
                },
            },
        );
        TwoWayPegData { block_info }
    };
    let block1 = {
        let mut rwtxn = env.write_txn()?;
        // production order: 2WPD events before the block body
        state.connect_two_way_peg_data(&mut rwtxn, &deposit_twpd)?;
        let block1 = Header {
            merkle_root,
            prev_side_hash: Some(genesis.hash()),
            prev_main_hash: main1,
        };
        state.apply_block(
            &mut rwtxn,
            &batch_verification_ctxt,
            &block1,
            main_height1,
            &empty_body,
        )?;
        anyhow::ensure!(state.utxos.try_get(&rwtxn, &deposit_key)?.is_some());
        anyhow::ensure!(state.deposit_blocks.last(&rwtxn)?.is_some());
        rwtxn.commit()?;
        block1
    };

    {
        let mut rwtxn = env.write_txn()?;
        // production order: undo bundle construction, then the block
        // body, then 2WPD events, then the header
        state.disconnect_withdrawal_bundle_creation(&mut rwtxn)?;
        state.disconnect_tip_body(&mut rwtxn, &block1, &empty_body)?;
        state.disconnect_two_way_peg_data(&mut rwtxn, &deposit_twpd)?;
        state.disconnect_tip_header(&mut rwtxn, &block1)?;
        anyhow::ensure!(state.utxos.try_get(&rwtxn, &deposit_key)?.is_none());
        anyhow::ensure!(state.deposit_blocks.last(&rwtxn)?.is_none());
        rwtxn.commit()?;
    }

    Ok(())
}

// A single two-way-peg batch can span multiple mainchain blocks. Connecting
// deposits from two distinct blocks then disconnecting the batch must
// restore the prior state. Before the fix, disconnect recomputed the latest
// deposit block hash by reverse iteration (yielding the oldest block) and
// panicked on the consistency assert against the newest hash connect stored.
#[test]
fn disconnect_two_deposit_blocks_restores_state() -> anyhow::Result<()> {
    fn deposit_block(salt: u8) -> (bitcoin::BlockHash, BlockInfo) {
        let dep = Deposit {
            tx_index: 0,
            outpoint: bitcoin::OutPoint {
                txid: bitcoin::Txid::from_byte_array([salt; 32]),
                vout: 0,
            },
            output: FilledOutput {
                address: Address([salt; 20]),
                content: FilledOutputContent::new_bitcoin_value(
                    bitcoin::Amount::from_sat(1000),
                ),
                memo: Vec::new(),
            },
        };
        (
            bitcoin::BlockHash::from_byte_array([salt; 32]),
            BlockInfo {
                bmm_commitment: None,
                events: vec![BlockEvent::Deposit(dep)],
            },
        )
    }
    let (_temp_dir, env, state) =
        fresh_state("disconnect_two_deposit_blocks_restores_state")?;
    let mut rwtxn = env.write_txn()?;
    // events connect before the block body: connecting the events
    // of block 10 requires height 9
    state.height.put(&mut rwtxn, &(), &9)?;

    let mut block_info = LinkedHashMap::new();
    let (h1, b1) = deposit_block(1);
    let (h2, b2) = deposit_block(2);
    block_info.insert(
        h1,
        two_way_peg_data::BlockInfo {
            height: 1,
            inner: b1,
        },
    );
    block_info.insert(
        h2,
        two_way_peg_data::BlockInfo {
            height: 2,
            inner: b2,
        },
    );
    let tdp = TwoWayPegData { block_info };

    let () = connect(&state, &mut rwtxn, &tdp)?;
    anyhow::ensure!(state.utxos.len(&rwtxn)? == 2);
    // the block body connected at height 10; events disconnect
    // after the block body, with the height still at 10
    state.height.put(&mut rwtxn, &(), &10)?;
    disconnect(&state, &mut rwtxn, &tdp)?;

    anyhow::ensure!(state.utxos.len(&rwtxn)? == 0);
    anyhow::ensure!(state.deposit_blocks.len(&rwtxn)? == 0);
    Ok(())
}
