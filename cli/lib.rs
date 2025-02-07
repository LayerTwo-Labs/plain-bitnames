use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use clap::{Parser, Subcommand};
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use plain_bitnames::types::{Address, BitName, BlockHash, THIS_SIDECHAIN};
use plain_bitnames_app_rpc_api::{BitNameCommitRpcClient, RpcClient};

#[derive(Clone, Debug, Subcommand)]
#[command(arg_required_else_help(true))]
pub enum Command {
    /// Get balance in sats
    Balance,
    /// Retrieve data for a single BitName
    BitnameData { bitname_id: BitName },
    /// List all BitNames
    Bitnames,
    /// Connect to a peer
    ConnectPeer { addr: SocketAddr },
    /// Deposit to address
    CreateDeposit {
        address: Address,
        #[arg(long)]
        value_sats: u64,
        #[arg(long)]
        fee_sats: u64,
    },
    /// Format a deposit address
    FormatDepositAddress { address: Address },
    /// Generate a mnemonic seed phrase
    GenerateMnemonic,
    /// Get block data
    GetBlock { block_hash: BlockHash },
    /// Get mainchain blocks that commit to a specified block hash
    GetBmmInclusions {
        block_hash: plain_bitnames::types::BlockHash,
    },
    /// Get a new address
    GetNewAddress,
    /// Get a new encryption pubkey
    GetNewEncryptionKey,
    /// Get a new verifying key
    GetNewVerifyingKey,
    /// Get the current block count
    GetBlockcount,
    /// Get all paymail
    GetPaymail,
    /// Get wallet addresses, sorted by base58 encoding
    GetWalletAddresses,
    /// Get wallet UTXOs
    GetWalletUtxos,
    /// Get the height of the latest failed withdrawal bundle
    LatestFailedWithdrawalBundleHeight,
    /// List peers
    ListPeers,
    /// List all UTXOs
    ListUtxos,
    /// Attempt to mine a sidechain block
    Mine {
        #[arg(long)]
        fee_sats: Option<u64>,
    },
    /// List owned UTXOs
    MyUtxos,
    /// Show OpenAPI schema
    #[command(name = "openapi-schema")]
    OpenApiSchema,
    /// Get pending withdrawal bundle
    PendingWithdrawalBundle,
    /// Reserve a BitName
    ReserveBitname { plaintext_name: String },
    /// Resolve a commitment from a BitName
    ResolveCommit {
        bitname_id: BitName,
        field_name: String,
    },
    /// Set the wallet seed from a mnemonic seed phrase
    SetSeedFromMnemonic { mnemonic: String },
    /// Get total sidechain wealth
    SidechainWealth,
    /// Stop the node
    Stop,
    /// Transfer funds to the specified address
    Transfer {
        dest: Address,
        #[arg(long)]
        value_sats: u64,
        #[arg(long)]
        fee_sats: u64,
    },
    /// Initiate a withdrawal to the specified mainchain address
    Withdraw {
        mainchain_address: bitcoin::Address<bitcoin::address::NetworkUnchecked>,
        #[arg(long)]
        amount_sats: u64,
        #[arg(long)]
        fee_sats: u64,
        #[arg(long)]
        mainchain_fee_sats: u64,
    },
}

const DEFAULT_RPC_ADDR: SocketAddr = SocketAddr::new(
    IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
    6000 + THIS_SIDECHAIN as u16,
);

async fn resolve_commit(
    bitname_id: BitName,
    field_name: String,
    rpc_client: &HttpClient,
) -> anyhow::Result<Option<serde_json::Value>> {
    let bitname_data = rpc_client.bitname_data(bitname_id).await?;
    let socket_addr = bitname_data
        .mutable_data
        .socket_addr_v4
        .map(SocketAddr::from)
        .or_else(|| {
            bitname_data
                .mutable_data
                .socket_addr_v6
                .map(SocketAddr::from)
        })
        .ok_or_else(|| anyhow::anyhow!("No IP/port address resolved"))?;
    let commitment = bitname_data
        .mutable_data
        .commitment
        .ok_or_else(|| anyhow::anyhow!("No commitment resolved"))?;
    let http_client = HttpClientBuilder::default()
        .build(format!("http://{}", socket_addr))?;
    let mut bitname_commit = http_client.bitname_commit(None).await?;
    let canonical_bytes = serde_json_canonicalizer::to_vec(&bitname_commit)?;
    let canonical_hash: plain_bitnames::types::Hash =
        blake3::hash(&canonical_bytes).into();
    anyhow::ensure!(commitment == canonical_hash);
    Ok(bitname_commit.remove(&field_name))
}

#[derive(Clone, Debug, Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// address for use by the RPC server
    #[arg(default_value_t = DEFAULT_RPC_ADDR, long)]
    pub rpc_addr: SocketAddr,

    #[command(subcommand)]
    pub command: Command,
}

impl Cli {
    pub async fn run(self) -> anyhow::Result<String> {
        let rpc_client: HttpClient = HttpClientBuilder::default()
            .build(format!("http://{}", self.rpc_addr))?;
        let res = match self.command {
            Command::Balance => {
                let balance = rpc_client.balance().await?;
                serde_json::to_string_pretty(&balance)?
            }
            Command::BitnameData { bitname_id } => {
                let bitname_data = rpc_client.bitname_data(bitname_id).await?;
                serde_json::to_string_pretty(&bitname_data)?
            }
            Command::Bitnames => {
                let bitnames = rpc_client.bitnames().await?;
                serde_json::to_string_pretty(&bitnames)?
            }
            Command::ConnectPeer { addr } => {
                let () = rpc_client.connect_peer(addr).await?;
                String::default()
            }
            Command::CreateDeposit {
                address,
                value_sats,
                fee_sats,
            } => {
                let txid = rpc_client
                    .create_deposit(address, value_sats, fee_sats)
                    .await?;
                format!("{txid}")
            }
            Command::FormatDepositAddress { address } => {
                rpc_client.format_deposit_address(address).await?
            }
            Command::GenerateMnemonic => rpc_client.generate_mnemonic().await?,
            Command::GetBlock { block_hash } => {
                let block = rpc_client.get_block(block_hash).await?;
                serde_json::to_string_pretty(&block)?
            }
            Command::GetBlockcount => {
                let blockcount = rpc_client.getblockcount().await?;
                format!("{blockcount}")
            }
            Command::GetBmmInclusions { block_hash } => {
                let bmm_inclusions =
                    rpc_client.get_bmm_inclusions(block_hash).await?;
                serde_json::to_string_pretty(&bmm_inclusions)?
            }
            Command::GetNewAddress => {
                let address = rpc_client.get_new_address().await?;
                format!("{address}")
            }
            Command::GetNewEncryptionKey => {
                let epk = rpc_client.get_new_encryption_key().await?;
                format!("{epk}")
            }
            Command::GetNewVerifyingKey => {
                let vk = rpc_client.get_new_verifying_key().await?;
                format!("{vk}")
            }
            Command::GetPaymail => {
                let paymail = rpc_client.get_paymail().await?;
                serde_json::to_string_pretty(&paymail)?
            }
            Command::GetWalletAddresses => {
                let addresses = rpc_client.get_wallet_addresses().await?;
                serde_json::to_string_pretty(&addresses)?
            }
            Command::GetWalletUtxos => {
                let utxos = rpc_client.get_wallet_utxos().await?;
                serde_json::to_string_pretty(&utxos)?
            }
            Command::LatestFailedWithdrawalBundleHeight => {
                let height =
                    rpc_client.latest_failed_withdrawal_bundle_height().await?;
                serde_json::to_string_pretty(&height)?
            }
            Command::ListPeers => {
                let peers = rpc_client.list_peers().await?;
                serde_json::to_string_pretty(&peers)?
            }
            Command::ListUtxos => {
                let utxos = rpc_client.list_utxos().await?;
                serde_json::to_string_pretty(&utxos)?
            }
            Command::Mine { fee_sats } => {
                let () = rpc_client.mine(fee_sats).await?;
                String::default()
            }
            Command::MyUtxos => {
                let utxos = rpc_client.my_utxos().await?;
                serde_json::to_string_pretty(&utxos)?
            }
            Command::OpenApiSchema => {
                let openapi =
                    <plain_bitnames_app_rpc_api::RpcDoc as utoipa::OpenApi>::openapi();
                openapi.to_pretty_json()?
            }
            Command::PendingWithdrawalBundle => {
                let withdrawal_bundle =
                    rpc_client.pending_withdrawal_bundle().await?;
                serde_json::to_string_pretty(&withdrawal_bundle)?
            }
            Command::ReserveBitname { plaintext_name } => {
                let txid = rpc_client.reserve_bitname(plaintext_name).await?;
                format!("{txid}")
            }
            Command::ResolveCommit {
                bitname_id,
                field_name,
            } => {
                let res =
                    resolve_commit(bitname_id, field_name, &rpc_client).await?;
                serde_json::to_string_pretty(&res)?
            }
            Command::SetSeedFromMnemonic { mnemonic } => {
                let () = rpc_client.set_seed_from_mnemonic(mnemonic).await?;
                String::default()
            }
            Command::SidechainWealth => {
                let sidechain_wealth =
                    rpc_client.sidechain_wealth_sats().await?;
                format!("{sidechain_wealth}")
            }
            Command::Stop => {
                let () = rpc_client.stop().await?;
                String::default()
            }
            Command::Transfer {
                dest,
                value_sats,
                fee_sats,
            } => {
                let txid = rpc_client
                    .transfer(dest, value_sats, fee_sats, None)
                    .await?;
                format!("{txid}")
            }
            Command::Withdraw {
                mainchain_address,
                amount_sats,
                fee_sats,
                mainchain_fee_sats,
            } => {
                let txid = rpc_client
                    .withdraw(
                        mainchain_address,
                        amount_sats,
                        fee_sats,
                        mainchain_fee_sats,
                    )
                    .await?;
                format!("{txid}")
            }
        };
        Ok(res)
    }
}
