//! RPC API

use std::{collections::HashMap, net::SocketAddr};

use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use l2l_openapi::open_api;
use plain_bitnames::{
    types::{
        hashes::BitName, schema as bitnames_schema, Address, Authorization,
        BatchIcannRegistrationData, BitNameData, BitNameDataUpdates, Block,
        BlockHash, Body, EncryptionPubKey, FilledOutput, FilledOutputContent,
        Header, MerkleRoot, OutPoint, Output, OutputContent, PointedOutput,
        Transaction, TransactionData, TxIn, Txid, VerifyingKey,
    },
    wallet::Balance,
};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use utoipa::ToSchema;

mod schema;
#[cfg(test)]
mod test;

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
pub struct TxInfo {
    pub confirmations: Option<u32>,
    pub fee_sats: u64,
    pub txin: Option<TxIn>,
}

#[open_api(ref_schemas[
    bitnames_schema::BitcoinAddr, bitnames_schema::BitcoinBlockHash,
    bitnames_schema::BitcoinOutPoint, Address, Authorization,
    BatchIcannRegistrationData, BitName, BitNameData, BitNameDataUpdates,
    BlockHash, Body, FilledOutput, FilledOutputContent, Header, MerkleRoot,
    OutPoint, Output, OutputContent, Transaction, TransactionData, Txid, TxIn,
])]
#[rpc(client, server)]
pub trait Rpc {
    /// Get balance in sats
    #[open_api_method(output_schema(ToSchema))]
    #[method(name = "balance")]
    async fn balance(&self) -> RpcResult<Balance>;

    /// Retrieve data for a single BitName
    #[method(name = "bitname_data")]
    async fn bitname_data(&self, bitname_id: BitName)
        -> RpcResult<BitNameData>;

    /// List all BitNames
    #[open_api_method(output_schema(
        PartialSchema = "schema::ArrayTuple<BitName, BitNameData>"
    ))]
    #[method(name = "bitnames")]
    async fn bitnames(&self) -> RpcResult<Vec<(BitName, BitNameData)>>;

    /// Deposit to address
    #[open_api_method(output_schema(PartialSchema = "schema::BitcoinTxid"))]
    #[method(name = "create_deposit")]
    async fn create_deposit(
        &self,
        address: Address,
        value_sats: u64,
        fee_sats: u64,
    ) -> RpcResult<bitcoin::Txid>;

    /// Connect to a peer
    #[open_api_method(output_schema(ToSchema))]
    #[method(name = "connect_peer")]
    async fn connect_peer(
        &self,
        #[open_api_method_arg(schema(ToSchema = "schema::SocketAddr"))]
        addr: SocketAddr,
    ) -> RpcResult<()>;

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
    #[open_api_method(output_schema(ToSchema))]
    #[method(name = "get_block")]
    async fn get_block(&self, block_hash: BlockHash) -> RpcResult<Block>;

    /// Get a new address
    #[method(name = "get_new_address")]
    async fn get_new_address(&self) -> RpcResult<Address>;

    /// Get new encryption key
    #[method(name = "get_new_encryption_key")]
    async fn get_new_encryption_key(&self) -> RpcResult<EncryptionPubKey>;

    /// Get new verifying/signing key
    #[method(name = "get_new_verifying_key")]
    async fn get_new_verifying_key(&self) -> RpcResult<VerifyingKey>;

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

    /// Get wallet addresses, sorted by base58 encoding
    #[method(name = "get_wallet_addresses")]
    async fn get_wallet_addresses(&self) -> RpcResult<Vec<Address>>;

    /// Get wallet UTXOs
    #[method(name = "get_wallet_utxos")]
    async fn get_wallet_utxos(
        &self,
    ) -> RpcResult<Vec<PointedOutput<FilledOutput>>>;

    /// Get the current block count
    #[method(name = "getblockcount")]
    async fn getblockcount(&self) -> RpcResult<u32>;

    /// List peers
    /// TODO: Use schema::SocketAddr. Cannot get it to work. Also, add more info about peers
    #[open_api_method(output_schema(ToSchema))]
    #[method(name = "list_peers")]
    async fn list_peers(&self) -> RpcResult<Vec<String>>;

    /// List all UTXOs
    #[open_api_method(output_schema(
        ToSchema = "Vec<PointedOutput<FilledOutputContent>>"
    ))]
    #[method(name = "list_utxos")]
    async fn list_utxos(&self) -> RpcResult<Vec<PointedOutput<FilledOutput>>>;

    /// Attempt to mine a sidechain block
    #[open_api_method(output_schema(ToSchema))]
    #[method(name = "mine")]
    async fn mine(&self, fee: Option<u64>) -> RpcResult<()>;

    /// List owned UTXOs
    #[method(name = "my_utxos")]
    async fn my_utxos(&self) -> RpcResult<Vec<PointedOutput<FilledOutput>>>;

    /// Get OpenRPC schema
    #[open_api_method(output_schema(ToSchema = "schema::OpenApi"))]
    #[method(name = "openapi_schema")]
    async fn openapi_schema(&self) -> RpcResult<utoipa::openapi::OpenApi>;

    /// Reserve a BitName
    #[method(name = "reserve_bitname")]
    async fn reserve_bitname(&self, plain_name: String) -> RpcResult<Txid>;

    /// Set the wallet seed from a mnemonic seed phrase
    #[open_api_method(output_schema(ToSchema))]
    #[method(name = "set_seed_from_mnemonic")]
    async fn set_seed_from_mnemonic(&self, mnemonic: String) -> RpcResult<()>;

    /// Get total sidechain wealth in sats
    #[method(name = "sidechain_wealth")]
    async fn sidechain_wealth_sats(&self) -> RpcResult<u64>;

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
        #[open_api_method_arg(schema(
            PartialSchema = "bitnames_schema::BitcoinAddr"
        ))]
        mainchain_address: bitcoin::Address<
            bitcoin::address::NetworkUnchecked,
        >,
        amount_sats: u64,
        fee_sats: u64,
        mainchain_fee_sats: u64,
    ) -> RpcResult<Txid>;
}

/// Wrapper struct for hex-encoded bytes
#[serde_as]
#[derive(Debug, Deserialize, Serialize)]
#[repr(transparent)]
#[serde(transparent)]
pub struct HexStr(#[serde_as(as = "serde_with::hex::Hex")] pub Vec<u8>);

#[rpc(client, server)]
pub trait BitNameCommitRpc {
    #[method(name = "bitname_commit")]
    async fn bitname_commit(
        &self,
        bytes: Option<HexStr>,
    ) -> RpcResult<serde_json::Map<String, serde_json::Value>>;
}
