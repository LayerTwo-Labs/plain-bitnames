//! RPC API

use std::{collections::HashMap, net::SocketAddr};

use bip300301::bitcoin;
use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use plain_bitnames::types::{
    hashes::BitName, Address, BitNameData, Block, BlockHash, FilledOutput,
    OutPoint, Transaction, TxIn, Txid,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TxInfo {
    pub confirmations: Option<u32>,
    pub fee_sats: u64,
    pub txin: Option<TxIn>,
}

#[rpc(client, server)]
pub trait Rpc {
    /// Get balance in sats
    #[method(name = "balance")]
    async fn balance(&self) -> RpcResult<u64>;

    /// List all BitNames
    #[method(name = "bitnames")]
    async fn bitnames(&self) -> RpcResult<Vec<(BitName, BitNameData)>>;

    /// Connect to a peer
    #[method(name = "connect_peer")]
    async fn connect_peer(&self, addr: SocketAddr) -> RpcResult<()>;

    /// Format a deposit address
    #[method(name = "format_deposit_address")]
    async fn format_deposit_address(
        &self,
        address: Address,
    ) -> RpcResult<String>;

    /// Generate a mnemonic seed phrase
    #[method(name = "generate_mnemonic")]
    async fn generate_mnemonic(&self) -> RpcResult<String>;

    /// Get block data
    #[method(name = "get_block")]
    async fn get_block(&self, block_hash: BlockHash) -> RpcResult<Block>;

    /// Get a new address
    #[method(name = "get_new_address")]
    async fn get_new_address(&self) -> RpcResult<Address>;

    /// Get all paymail
    #[method(name = "get_paymail")]
    async fn get_paymail(&self) -> RpcResult<HashMap<OutPoint, FilledOutput>>;

    /// Get transaction by txid
    #[method(name = "get_transaction")]
    async fn get_transaction(
        &self,
        txid: Txid,
    ) -> RpcResult<Option<Transaction>>;

    /// Get information about a transaction in the current chain
    #[method(name = "get_transaction_info")]
    async fn get_transaction_info(
        &self,
        txid: Txid,
    ) -> RpcResult<Option<TxInfo>>;

    /// Get the current block count
    #[method(name = "getblockcount")]
    async fn getblockcount(&self) -> RpcResult<u32>;

    /// Attempt to mine a sidechain block
    #[method(name = "mine")]
    async fn mine(&self, fee: Option<u64>) -> RpcResult<()>;

    /// List owned UTXOs
    #[method(name = "my_utxos")]
    async fn my_utxos(&self) -> RpcResult<Vec<FilledOutput>>;

    /// Reserve a BitName
    #[method(name = "reserve_bitname")]
    async fn reserve_bitname(&self, plain_name: String) -> RpcResult<Txid>;

    /// Set the wallet seed from a mnemonic seed phrase
    #[method(name = "set_seed_from_mnemonic")]
    async fn set_seed_from_mnemonic(&self, mnemonic: String) -> RpcResult<()>;

    /// Get total sidechain wealth
    #[method(name = "sidechain_wealth")]
    async fn sidechain_wealth(&self) -> RpcResult<bitcoin::Amount>;

    /// Stop the node
    #[method(name = "stop")]
    async fn stop(&self);

    /// Transfer funds to the specified address
    #[method(name = "transfer")]
    async fn transfer(
        &self,
        dest: Address,
        value: u64,
        fee: u64,
        memo: Option<String>,
    ) -> RpcResult<Txid>;

    /// Initiate a withdrawal to the specified mainchain address
    #[method(name = "withdraw")]
    async fn withdraw(
        &self,
        mainchain_address: bitcoin::Address<bitcoin::address::NetworkUnchecked>,
        amount_sats: u64,
        fee_sats: u64,
        mainchain_fee_sats: u64,
    ) -> RpcResult<Txid>;
}
