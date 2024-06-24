use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use bip300301::bitcoin;
use clap::{Parser, Subcommand};
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use plain_bitnames::{
    node::THIS_SIDECHAIN,
    types::{Address, BlockHash},
};
use plain_bitnames_app_rpc_api::RpcClient;

#[derive(Clone, Debug, Subcommand)]
#[command(arg_required_else_help(true))]
pub enum Command {
    /// Get balance in sats
    Balance,
    /// List all BitNames
    Bitnames,
    /// Connect to a peer
    ConnectPeer { addr: SocketAddr },
    /// Format a deposit address
    FormatDepositAddress { address: Address },
    /// Generate a mnemonic seed phrase
    GenerateMnemonic,
    /// Get block data
    GetBlock { block_hash: BlockHash },
    /// Get a new address
    GetNewAddress,
    /// Get the current block count
    GetBlockcount,
    /// Get all paymail
    GetPaymail,
    /// Get wallet addresses, sorted by base58 encoding
    GetWalletAddresses,
    /// Get wallet UTXOs
    GetWalletUtxos,
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
    /// Reserve a BitName
    ReserveBitname { plaintext_name: String },
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
                format!("{balance}")
            }
            Command::Bitnames => {
                let bitnames = rpc_client.bitnames().await?;
                serde_json::to_string_pretty(&bitnames)?
            }
            Command::ConnectPeer { addr } => {
                let () = rpc_client.connect_peer(addr).await?;
                String::default()
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
            Command::GetNewAddress => {
                let address = rpc_client.get_new_address().await?;
                format!("{address}")
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
            Command::ReserveBitname { plaintext_name } => {
                let txid = rpc_client.reserve_bitname(plaintext_name).await?;
                format!("{txid}")
            }
            Command::SetSeedFromMnemonic { mnemonic } => {
                let () = rpc_client.set_seed_from_mnemonic(mnemonic).await?;
                String::default()
            }
            Command::SidechainWealth => {
                let sidechain_wealth = rpc_client.sidechain_wealth().await?;
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
