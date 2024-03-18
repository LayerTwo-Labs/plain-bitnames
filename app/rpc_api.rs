//! RPC API

use std::{collections::HashMap, net::SocketAddr};

use bip300301::bitcoin;
use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use plain_bitnames::types::{
    hashes::BitName, Address, BitNameData, Block, BlockHash, FilledOutput,
    OutPoint,
};

#[rpc(client, server)]
pub trait Rpc {
    /// Balance in sats
    #[method(name = "balance")]
    async fn balance(&self) -> RpcResult<u64>;

    /// List all BitNames
    #[method(name = "bitnames")]
    async fn bitnames(&self) -> RpcResult<Vec<(BitName, BitNameData)>>;

    /// Connect to a peer
    #[method(name = "connect_peer")]
    async fn connect_peer(&self, addr: SocketAddr) -> RpcResult<()>;

    #[method(name = "format_deposit_address")]
    async fn format_deposit_address(
        &self,
        address: Address,
    ) -> RpcResult<String>;

    #[method(name = "generate_mnemonic")]
    async fn generate_mnemonic(&self) -> RpcResult<String>;

    #[method(name = "get_block")]
    async fn get_block(&self, block_hash: BlockHash) -> RpcResult<Block>;

    #[method(name = "get_block_hash")]
    async fn get_block_hash(&self, height: u32) -> RpcResult<BlockHash>;

    #[method(name = "get_new_address")]
    async fn get_new_address(&self) -> RpcResult<Address>;

    #[method(name = "get_paymail")]
    async fn get_paymail(&self) -> RpcResult<HashMap<OutPoint, FilledOutput>>;

    #[method(name = "getblockcount")]
    async fn getblockcount(&self) -> RpcResult<u32>;

    #[method(name = "mine")]
    async fn mine(&self, fee: Option<u64>) -> RpcResult<()>;

    #[method(name = "my_utxos")]
    async fn my_utxos(&self) -> RpcResult<Vec<FilledOutput>>;

    #[method(name = "reserve_bitname")]
    async fn reserve_bitname(&self, plain_name: String) -> RpcResult<()>;

    #[method(name = "set_seed_from_mnemonic")]
    async fn set_seed_from_mnemonic(&self, mnemonic: String) -> RpcResult<()>;

    #[method(name = "sidechain_wealth")]
    async fn sidechain_wealth(&self) -> RpcResult<bitcoin::Amount>;

    #[method(name = "stop")]
    async fn stop(&self);

    #[method(name = "transfer")]
    async fn transfer(
        &self,
        dest: Address,
        value: u64,
        fee: u64,
        memo: Option<String>,
    ) -> RpcResult<()>;
}
