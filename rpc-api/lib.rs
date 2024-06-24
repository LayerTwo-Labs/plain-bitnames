//! RPC API

use std::{collections::HashMap, marker::PhantomData, net::SocketAddr};

use bip300301::bitcoin;
use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use l2l_openapi::open_api;
use plain_bitnames::types::{
    hashes::BitName, open_api_schemas, Address, Authorization,
    BatchIcannRegistrationData, BitNameData, BitNameDataUpdates, Block,
    BlockHash, Body, FilledOutput, FilledOutputContent, Header, MerkleRoot,
    OutPoint, Output, OutputContent, PointedOutput, Transaction,
    TransactionData, TxIn, Txid,
};
use serde::{Deserialize, Serialize};
use utoipa::{
    openapi::{RefOr, Schema, SchemaType},
    PartialSchema, ToSchema,
};

/// Utoipa does not support tuples at all, so these are represented as an
/// arbitrary json value
#[derive(Default)]
struct ArrayTupleSchema<A, B>(PhantomData<A>, PhantomData<B>);

impl<A, B> PartialSchema for ArrayTupleSchema<A, B> {
    fn schema() -> RefOr<Schema> {
        let obj = utoipa::openapi::Object::with_type(SchemaType::Value);
        RefOr::T(Schema::Object(obj))
    }
}

struct BitcoinAddrSchema;

impl PartialSchema for BitcoinAddrSchema {
    fn schema() -> RefOr<Schema> {
        let obj = utoipa::openapi::Object::with_type(SchemaType::String);
        RefOr::T(Schema::Object(obj))
    }
}

impl ToSchema<'static> for BitcoinAddrSchema {
    fn schema() -> (&'static str, RefOr<Schema>) {
        ("bitcoin.Address", <Self as PartialSchema>::schema())
    }
}

struct BitcoinAmountSchema;

impl PartialSchema for BitcoinAmountSchema {
    fn schema() -> RefOr<Schema> {
        let obj = utoipa::openapi::Object::with_type(SchemaType::String);
        RefOr::T(Schema::Object(obj))
    }
}

impl ToSchema<'static> for BitcoinAmountSchema {
    fn schema() -> (&'static str, RefOr<Schema>) {
        ("bitcoin.Amount", <Self as PartialSchema>::schema())
    }
}

struct BitcoinBlockHashSchema;

impl PartialSchema for BitcoinBlockHashSchema {
    fn schema() -> RefOr<Schema> {
        let obj = utoipa::openapi::Object::with_type(SchemaType::String);
        RefOr::T(Schema::Object(obj))
    }
}

impl ToSchema<'static> for BitcoinBlockHashSchema {
    fn schema() -> (&'static str, RefOr<Schema>) {
        ("bitcoin.BlockHash", <Self as PartialSchema>::schema())
    }
}

struct BitcoinOutPointSchema;

impl PartialSchema for BitcoinOutPointSchema {
    fn schema() -> RefOr<Schema> {
        let obj = utoipa::openapi::Object::new();
        RefOr::T(Schema::Object(obj))
    }
}

impl ToSchema<'static> for BitcoinOutPointSchema {
    fn schema() -> (&'static str, RefOr<Schema>) {
        ("bitcoin.OutPoint", <Self as PartialSchema>::schema())
    }
}

struct EncryptionPubKeySchema;

impl PartialSchema for EncryptionPubKeySchema {
    fn schema() -> RefOr<Schema> {
        let obj = utoipa::openapi::Object::with_type(SchemaType::String);
        RefOr::T(Schema::Object(obj))
    }
}

impl ToSchema<'static> for EncryptionPubKeySchema {
    fn schema() -> (&'static str, RefOr<Schema>) {
        ("EncryptionPubKey", <Self as PartialSchema>::schema())
    }
}

struct HashSchema;

impl PartialSchema for HashSchema {
    fn schema() -> RefOr<Schema> {
        let obj = utoipa::openapi::Object::new();
        RefOr::T(Schema::Object(obj))
    }
}

impl ToSchema<'static> for HashSchema {
    fn schema() -> (&'static str, RefOr<Schema>) {
        ("Hash", <Self as PartialSchema>::schema())
    }
}

struct Ipv4AddrSchema;

impl PartialSchema for Ipv4AddrSchema {
    fn schema() -> RefOr<Schema> {
        let obj = utoipa::openapi::Object::with_type(SchemaType::String);
        RefOr::T(Schema::Object(obj))
    }
}

impl ToSchema<'static> for Ipv4AddrSchema {
    fn schema() -> (&'static str, RefOr<Schema>) {
        ("Ipv4Addr", <Self as PartialSchema>::schema())
    }
}

struct Ipv6AddrSchema;

impl PartialSchema for Ipv6AddrSchema {
    fn schema() -> RefOr<Schema> {
        let obj = utoipa::openapi::Object::with_type(SchemaType::String);
        RefOr::T(Schema::Object(obj))
    }
}

impl ToSchema<'static> for Ipv6AddrSchema {
    fn schema() -> (&'static str, RefOr<Schema>) {
        ("Ipv6Addr", <Self as PartialSchema>::schema())
    }
}

struct OpenApiSchema;

impl PartialSchema for OpenApiSchema {
    fn schema() -> RefOr<Schema> {
        let obj = utoipa::openapi::Object::new();
        RefOr::T(Schema::Object(obj))
    }
}

impl ToSchema<'static> for OpenApiSchema {
    fn schema() -> (&'static str, RefOr<Schema>) {
        ("OpenApiSchema", <Self as PartialSchema>::schema())
    }
}

struct SocketAddrSchema;

impl PartialSchema for SocketAddrSchema {
    fn schema() -> RefOr<Schema> {
        let obj = utoipa::openapi::Object::with_type(SchemaType::String);
        RefOr::T(Schema::Object(obj))
    }
}

impl ToSchema<'static> for SocketAddrSchema {
    fn schema() -> (&'static str, RefOr<utoipa::openapi::schema::Schema>) {
        ("SocketAddr", <Self as PartialSchema>::schema())
    }
}

struct VerifyingKeySchema;

impl PartialSchema for VerifyingKeySchema {
    fn schema() -> RefOr<Schema> {
        let obj = utoipa::openapi::Object::with_type(SchemaType::String);
        RefOr::T(Schema::Object(obj))
    }
}

impl ToSchema<'static> for VerifyingKeySchema {
    fn schema() -> (&'static str, RefOr<Schema>) {
        ("VerifyingKey", <Self as PartialSchema>::schema())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
pub struct TxInfo {
    pub confirmations: Option<u32>,
    pub fee_sats: u64,
    pub txin: Option<TxIn>,
}

#[open_api(ref_schemas[
    open_api_schemas::PointedFilledOutput, open_api_schemas::PointedOutput,
    open_api_schemas::UpdateHash,
    open_api_schemas::UpdateIpv4Addr, open_api_schemas::UpdateIpv6Addr,
    open_api_schemas::UpdateEncryptionPubKey,
    open_api_schemas::UpdateVerifyingKey, open_api_schemas::UpdateU64,
    Address, Authorization, BatchIcannRegistrationData, BitcoinAddrSchema,
    BitcoinBlockHashSchema, BitcoinOutPointSchema, BitName, BitNameData,
    BitNameDataUpdates,
    BlockHash, Body, EncryptionPubKeySchema,
    FilledOutputContent, HashSchema,
    Header, Ipv4AddrSchema, Ipv6AddrSchema, MerkleRoot, OutPoint,
    Output, OutputContent, Transaction, TransactionData, Txid, TxIn,
    VerifyingKeySchema
])]
#[rpc(client, server)]
pub trait Rpc {
    /// Get balance in sats
    #[method(name = "balance")]
    async fn balance(&self) -> RpcResult<u64>;

    /// List all BitNames
    #[open_api_method(output_schema(
        PartialSchema = "ArrayTupleSchema<BitName, BitNameData>"
    ))]
    #[method(name = "bitnames")]
    async fn bitnames(&self) -> RpcResult<Vec<(BitName, BitNameData)>>;

    /// Connect to a peer
    #[open_api_method(output_schema(ToSchema))]
    #[method(name = "connect_peer")]
    async fn connect_peer(
        &self,
        #[open_api_method_arg(schema(ToSchema = "SocketAddrSchema"))]
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

    /// List all UTXOs
    #[open_api_method(output_schema(
        PartialSchema = "Vec<open_api_schemas::PointedFilledOutput>"
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
    #[open_api_method(output_schema(PartialSchema = "OpenApiSchema"))]
    #[method(name = "openapi_schema")]
    async fn openapi_schema(&self) -> RpcResult<utoipa::openapi::OpenApi>;

    /// Reserve a BitName
    #[method(name = "reserve_bitname")]
    async fn reserve_bitname(&self, plain_name: String) -> RpcResult<Txid>;

    /// Set the wallet seed from a mnemonic seed phrase
    #[open_api_method(output_schema(ToSchema))]
    #[method(name = "set_seed_from_mnemonic")]
    async fn set_seed_from_mnemonic(&self, mnemonic: String) -> RpcResult<()>;

    /// Get total sidechain wealth
    #[open_api_method(output_schema(ToSchema = "BitcoinAmountSchema"))]
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
        #[open_api_method_arg(schema(PartialSchema = "BitcoinAddrSchema"))]
        mainchain_address: bitcoin::Address<
            bitcoin::address::NetworkUnchecked,
        >,
        amount_sats: u64,
        fee_sats: u64,
        mainchain_fee_sats: u64,
    ) -> RpcResult<Txid>;
}
