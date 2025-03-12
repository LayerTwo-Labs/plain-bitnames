//! Test a BitName registration

use bip300301_enforcer_integration_tests::{
    integration_test::{
        activate_sidechain, deposit, fund_enforcer, propose_sidechain,
    },
    setup::{
        Mode, Network, PostSetup as EnforcerPostSetup, Sidechain as _,
        setup as setup_enforcer,
    },
    util::{AbortOnDrop, AsyncTrial},
};
use futures::{
    FutureExt as _, StreamExt as _, channel::mpsc, future::BoxFuture,
};
use plain_bitnames::types::{MutableBitNameData, Txid};
use plain_bitnames_app_rpc_api::RpcClient as _;
use tokio::time::sleep;
use tracing::Instrument as _;

use crate::{
    setup::{Init, PostSetup},
    util::BinPaths,
};

const DEPOSIT_AMOUNT: bitcoin::Amount = bitcoin::Amount::from_sat(21_000_000);
const DEPOSIT_FEE: bitcoin::Amount = bitcoin::Amount::from_sat(1_000_000);

/// Initial setup for the test
async fn setup(
    bin_paths: &BinPaths,
    res_tx: mpsc::UnboundedSender<anyhow::Result<()>>,
) -> anyhow::Result<(EnforcerPostSetup, PostSetup)> {
    let mut enforcer_post_setup = setup_enforcer(
        &bin_paths.others,
        Network::Regtest,
        Mode::Mempool,
        res_tx.clone(),
    )
    .await?;
    let () = propose_sidechain::<PostSetup>(&mut enforcer_post_setup).await?;
    tracing::info!("Proposed sidechain successfully");
    let () = activate_sidechain::<PostSetup>(&mut enforcer_post_setup).await?;
    tracing::info!("Activated sidechain successfully");
    let () = fund_enforcer::<PostSetup>(&mut enforcer_post_setup).await?;
    let mut post_setup = PostSetup::setup(
        Init {
            bitnames_app: bin_paths.bitnames.clone(),
            data_dir_suffix: None,
        },
        &enforcer_post_setup,
        res_tx,
    )
    .await?;
    let deposit_address = post_setup.get_deposit_address().await?;
    let () = deposit(
        &mut enforcer_post_setup,
        &mut post_setup,
        &deposit_address,
        DEPOSIT_AMOUNT,
        DEPOSIT_FEE,
    )
    .await?;
    tracing::info!("Deposited to sidechain successfully");
    Ok((enforcer_post_setup, post_setup))
}

const PLAINTEXT_NAME: &str = "test-bitname";

async fn register_bitname_task(
    bin_paths: BinPaths,
    res_tx: mpsc::UnboundedSender<anyhow::Result<()>>,
) -> anyhow::Result<()> {
    let (mut enforcer_post_setup, post_setup) =
        setup(&bin_paths, res_tx.clone()).await?;
    tracing::info!("Reserving BitName");
    let _: Txid = post_setup
        .rpc_client
        .reserve_bitname(PLAINTEXT_NAME.to_owned())
        .await?;
    post_setup.bmm_single(&mut enforcer_post_setup).await?;
    tracing::info!("Generating verifying key");
    let vk = post_setup.rpc_client.get_new_verifying_key().await?;
    tracing::info!("Registering BitName");
    let _: Txid = post_setup
        .rpc_client
        .register_bitname(
            PLAINTEXT_NAME.to_owned(),
            Some(MutableBitNameData {
                signing_pubkey: Some(vk),
                ..Default::default()
            }),
        )
        .await?;
    post_setup.bmm_single(&mut enforcer_post_setup).await?;
    // Cleanup
    {
        drop(post_setup);
        tracing::info!(
            "Removing {}",
            enforcer_post_setup.out_dir.path().display()
        );
        drop(enforcer_post_setup.tasks);
        // Wait for tasks to die
        sleep(std::time::Duration::from_secs(1)).await;
        enforcer_post_setup.out_dir.cleanup()?;
    }
    Ok(())
}

async fn register_bitname(bin_paths: BinPaths) -> anyhow::Result<()> {
    let (res_tx, mut res_rx) = mpsc::unbounded();
    let _test_task: AbortOnDrop<()> = tokio::task::spawn({
        let res_tx = res_tx.clone();
        async move {
            let res = register_bitname_task(bin_paths, res_tx.clone()).await;
            let _send_err: Result<(), _> = res_tx.unbounded_send(res);
        }
        .in_current_span()
    })
    .into();
    res_rx.next().await.ok_or_else(|| {
        anyhow::anyhow!("Unexpected end of test task result stream")
    })?
}

pub fn register_bitname_trial(
    bin_paths: BinPaths,
) -> AsyncTrial<BoxFuture<'static, anyhow::Result<()>>> {
    AsyncTrial::new("vote", register_bitname(bin_paths).boxed())
}
