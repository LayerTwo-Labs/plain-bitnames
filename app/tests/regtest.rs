#![feature(impl_trait_in_assoc_type)]

use std::{
    ffi::OsString,
    net::{SocketAddr, TcpListener},
    ops::Deref,
    path::Path,
};

use bip300301::{
    bitcoin::{Address as BitcoinAddress, Amount as BitcoinAmount},
    MainClient,
};
use futures::TryFutureExt;
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use tempfile::tempdir;
// Shadows #[test]
use test_log::test;

use plain_bitnames_app_rpc_api::RpcClient as BitNamesClient;

const RPC_PASS: &str = "integrationtest";
const RPC_USER: &str = "integrationtest";

#[repr(transparent)]
struct BitNamesdClient(HttpClient);

impl BitNamesdClient {
    fn new(socket_addr: SocketAddr) -> anyhow::Result<Self> {
        let client = HttpClientBuilder::default()
            .build(format!("http://{socket_addr}"))?;
        Ok(Self(client))
    }
}

impl Deref for BitNamesdClient {
    type Target = impl BitNamesClient;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[repr(transparent)]
struct MainchaindClient(HttpClient);

impl MainchaindClient {
    fn new(socket_addr: SocketAddr) -> anyhow::Result<Self> {
        use base64::Engine;
        let mut headers = jsonrpsee::http_client::HeaderMap::new();
        let auth = format!("{RPC_USER}:{RPC_PASS}");
        let header_value = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD_NO_PAD.encode(auth)
        )
        .parse()?;
        headers.insert("authorization", header_value);
        let client = HttpClientBuilder::default()
            .set_headers(headers.clone())
            .build(format!("http://{socket_addr}"))?;
        Ok(Self(client))
    }
}

impl Deref for MainchaindClient {
    type Target = impl MainClient;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

fn bitnamesd(
    data_dir: &Path,
    mainchaind_addr: SocketAddr,
    rpc_addr: SocketAddr,
) -> tokio::process::Command {
    const BITNAMESD: &str = "../target/debug/plain_bitnames_app";
    let mut cmd = tokio::process::Command::new(BITNAMESD);
    cmd.arg("--datadir")
        .arg(data_dir)
        .args(
            [
                &["--headless"][..],
                &["--log-level", "DEBUG"],
                &["--main-addr", &format!("{mainchaind_addr}")],
                &["--password-main", RPC_PASS],
                &["--user-main", RPC_USER],
                &["--rpc-addr", &format!("{rpc_addr}")],
            ]
            .concat(),
        )
        .kill_on_drop(true);
    cmd
}

fn mainchaind(data_dir: &Path, rpc_port: u16) -> tokio::process::Command {
    const MAINCHAIND: &str = "../mainchain/src/drivechaind";
    let mut cmd = tokio::process::Command::new(MAINCHAIND);
    cmd.arg({
        let mut arg = OsString::from("-datadir=");
        arg.push(data_dir);
        arg
    })
    .args([
        "-server",
        &format!("-rpcpassword={RPC_PASS}"),
        &format!("-rpcport={rpc_port}"),
        &format!("-rpcuser={RPC_USER}"),
        "-regtest",
        "-connect-0",
        "-debug",
        //format!("-printtoconsole"),
    ])
    .kill_on_drop(true);
    cmd
}

// Mine `n` blocks, and verify that the block count has increased as expected.
async fn mine_mainchain_blocks(
    mainchaind_client: &MainchaindClient,
    mainchain_addr: &BitcoinAddress,
    n_blocks: u32,
) -> anyhow::Result<()> {
    let block_count_before =
        MainClient::getblockcount(&**mainchaind_client).await?;
    let _resp = mainchaind_client
        .generate_to_address(n_blocks, mainchain_addr.as_unchecked())
        .await?;
    let block_count_after =
        MainClient::getblockcount(&**mainchaind_client).await?;
    let blocks_mined = block_count_after - block_count_before;
    anyhow::ensure!(
        n_blocks as usize == blocks_mined,
        "Expected to mine {n_blocks} blocks, but only {blocks_mined} were mined"
    );
    Ok(())
}

// Mine a block, and verify that the block count has increased as expected.
async fn mine_bitnames_block(
    bitnamesd_client: &BitNamesdClient,
    mainchaind_client: &MainchaindClient,
    mainchain_addr: &BitcoinAddress,
    fee: Option<u64>,
) -> anyhow::Result<()> {
    let block_count_before =
        BitNamesClient::getblockcount(&**bitnamesd_client).await?;
    let ((), ()) =
        futures::try_join!(bitnamesd_client.mine(fee).err_into(), async {
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            mine_mainchain_blocks(mainchaind_client, mainchain_addr, 1).await
        })?;
    let block_count_after =
        BitNamesClient::getblockcount(&**bitnamesd_client).await?;
    let blocks_mined = block_count_after - block_count_before;
    anyhow::ensure!(
        blocks_mined == 1,
        "Expected to mine 1 block, but {blocks_mined} blocks were mined"
    );
    Ok(())
}

const SIDECHAIN_NAME: &str = "BitNames";
// 0.1 BTC
const DEFAULT_TX_FEE: BitcoinAmount = BitcoinAmount::from_sat(1_000_000);

#[test(tokio::test)]
async fn regtest_test() -> anyhow::Result<()> {
    /* Initialize mainchaind and bitnamesd */

    // Setting a ctrlc handler ensures that tempdirs are dropped on ctrlc
    ctrlc::set_handler(|| ())?;
    let bitnames_datadir = tempdir()?;
    let mainchain_datadir = tempdir()?;
    // Requesting port 0 assigns an arbitrary free socket
    let bitnames_socketaddr = TcpListener::bind("127.0.0.1:0")?.local_addr()?;
    let mainchain_socketaddr =
        TcpListener::bind("127.0.0.1:0")?.local_addr()?;
    tracing::debug!(
        bitnames_datadir = %bitnames_datadir.path().display(),
        mainchain_datadir = %mainchain_datadir.path().display(),
        %bitnames_socketaddr,
        %mainchain_socketaddr
    );
    let mut bitnamesd_handle = bitnamesd(
        bitnames_datadir.path(),
        mainchain_socketaddr,
        bitnames_socketaddr,
    )
    .spawn()?;
    let mut mainchaind_handle =
        mainchaind(mainchain_datadir.path(), mainchain_socketaddr.port())
            .spawn()?;
    let bitnamesd_client = BitNamesdClient::new(bitnames_socketaddr)?;
    let mainchaind_client = MainchaindClient::new(mainchain_socketaddr)?;
    // Wait 10s to accomodate startup
    tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;

    /* Initialize Mainchain */

    let mainchain_addr = mainchaind_client
        .getnewaddress("", "legacy")
        .await?
        .assume_checked();
    tracing::debug!(%mainchain_addr);

    // Check that there are no blocks
    {
        let block_count =
            MainClient::getblockcount(&*mainchaind_client).await?;
        assert_eq!(block_count, 0, "Initial mainchain block count should be 0");
    }
    // Generate 101 blocks
    let () =
        mine_mainchain_blocks(&mainchaind_client, &mainchain_addr, 101).await?;
    {
        // Create sidechain proposal
        let sidechain_proposal = mainchaind_client
            .create_sidechain_proposal(
                plain_bitnames::node::THIS_SIDECHAIN,
                SIDECHAIN_NAME,
                "BitNames integration test",
            )
            .await?;
        // Check that sidechain proposal is cached
        let sidechain_proposals =
            mainchaind_client.list_sidechain_proposals().await?;
        assert!(
            sidechain_proposals.contains(&sidechain_proposal.info),
            "Sidechain proposal should be cached"
        );
    }
    // Mine a block
    let () =
        mine_mainchain_blocks(&mainchaind_client, &mainchain_addr, 1).await?;
    // Check that sidechain proposal was accepted, now ready for voting
    {
        let sidechain_activation_statuses =
            mainchaind_client.list_sidechain_activation_status().await?;
        assert!(
            sidechain_activation_statuses
                .iter()
                .any(|activation_status| {
                    activation_status.name == SIDECHAIN_NAME
                        && activation_status.age == 1
                        && activation_status.fail == 0
                }),
            "Sidechain proposal should be accepted and ready for voting"
        );
    }
    // Check that there are no active sidechains
    {
        let active_sidechains =
            mainchaind_client.list_active_sidechains().await?;
        assert!(
            active_sidechains.is_empty(),
            "Expected no active sidechains, but received {active_sidechains:?}"
        );
    }
    // Mine until only one more block is needed to activate the sidechain
    let () =
        mine_mainchain_blocks(&mainchaind_client, &mainchain_addr, 2016 - 2)
            .await?;
    // Check that there are still no active sidechains
    {
        let active_sidechains =
            mainchaind_client.list_active_sidechains().await?;
        assert!(
            active_sidechains.is_empty(),
            "Expected no active sidechains, but received {active_sidechains:?}"
        );
    }
    // Mine one more block to activate the sidechain
    let () =
        mine_mainchain_blocks(&mainchaind_client, &mainchain_addr, 1).await?;
    {
        let active_sidechains =
            mainchaind_client.list_active_sidechains().await?;
        let sidechain_activation_statuses =
            mainchaind_client.list_sidechain_activation_status().await?;
        tracing::debug!(?sidechain_activation_statuses);
        assert!(
            !active_sidechains.is_empty(),
            "Expected sidechain to activate"
        );
    }

    /* Initialize BitNames */
    // Set a mnemonic seed
    {
        let mnemonic_seed = bitnamesd_client.generate_mnemonic().await?;
        let () = bitnamesd_client
            .set_seed_from_mnemonic(mnemonic_seed)
            .await?;
    }
    // Generate addresses
    let bitnames_addr = bitnamesd_client.get_new_address().await?;
    let bitnames_deposit_addr = bitnamesd_client
        .format_deposit_address(bitnames_addr)
        .await?;
    // Check that there are no blocks
    {
        let block_count =
            BitNamesClient::getblockcount(&*bitnamesd_client).await?;
        assert_eq!(block_count, 0, "Initial BitNames block count should be 0");
    }
    // Mine a block
    let () = mine_bitnames_block(
        &bitnamesd_client,
        &mainchaind_client,
        &mainchain_addr,
        Some(DEFAULT_TX_FEE.to_sat()),
    )
    .await?;

    /* Sidechain Deposit */

    let _sidechain_deposit = mainchaind_client
        .createsidechaindeposit(
            plain_bitnames::node::THIS_SIDECHAIN,
            &bitnames_deposit_addr,
            BitcoinAmount::from_int_btc(10).into(),
            DEFAULT_TX_FEE.into(),
        )
        .await?;
    // Check that there are no deposits in the db
    {
        let sidechain_deposits = mainchaind_client
            .count_sidechain_deposits(plain_bitnames::node::THIS_SIDECHAIN)
            .await?;
        anyhow::ensure!(
            sidechain_deposits == 0,
            "Expected 0 sidechain deposits, but got {sidechain_deposits}"
        );
    }
    // Mine a mainchain block
    let () =
        mine_mainchain_blocks(&mainchaind_client, &mainchain_addr, 1).await?;
    // Verify that the deposit was added
    {
        let sidechain_deposits = mainchaind_client
            .count_sidechain_deposits(plain_bitnames::node::THIS_SIDECHAIN)
            .await?;
        anyhow::ensure!(
            sidechain_deposits == 1,
            "Expected 1 sidechain deposits, but got {sidechain_deposits}"
        );
    }
    // Verify that there are no deposits on BitNames
    {
        let balance = bitnamesd_client.balance().await?;
        anyhow::ensure!(balance == 0, "Expected 0 balance, but got {balance}");
    }
    // Mine a BMM block to process the deposit
    let () = mine_bitnames_block(
        &bitnamesd_client,
        &mainchaind_client,
        &mainchain_addr,
        Some(DEFAULT_TX_FEE.to_sat()),
    )
    .await?;
    // Verify that the deposit was successful
    {
        let balance = bitnamesd_client.balance().await?;
        anyhow::ensure!(balance > 0, "Expected positive balance");
    }

    /* Clean up */
    {
        let () = bitnamesd_handle
            .start_kill()
            .or(mainchaind_handle.start_kill())?;
        let (bitnamesd_output, mainchaind_output) = futures::join!(
            bitnamesd_handle.wait_with_output(),
            mainchaind_handle.wait_with_output(),
        );
        let _bitnamesd_output = bitnamesd_output?;
        let _mainchaind_output = mainchaind_output?;
    };

    Ok(())
}
