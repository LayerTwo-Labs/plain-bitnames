//! RPC API

use std::{collections::HashMap, net::SocketAddr};

use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use l2l_openapi::open_api;
use plain_bitnames::{
    authorization::{Dst, Signature},
    net::{Peer, PeerConnectionStatus},
    types::{
        Address, Authorization, BatchIcannRegistrationData, BitNameData,
        BitNameDataUpdates, BitNameSeqId, BitcoinOutputContent, Block,
        BlockHash, Body, EncryptionPubKey, FilledOutput, FilledOutputContent,
        Header, InPoint, M6id, MerkleRoot, MutableBitNameData, OutPoint,
        Output, OutputContent, PointedOutput, SpentOutput, Transaction,
        TransactionData, TxIn, Txid, VerifyingKey, WithdrawalBundle,
        WithdrawalOutputContent, XEncryptionSecretKey, XVerifyingKey,
        hashes::BitName, schema as bitnames_schema,
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
    bitnames_schema::BitcoinOutPoint, bitnames_schema::BitcoinTransaction,
    bitnames_schema::SocketAddr, Address, Authorization,
    BatchIcannRegistrationData, BitcoinOutputContent, BitName,
    BitNameDataUpdates, BitNameSeqId, BlockHash, Body, EncryptionPubKey,
    FilledOutput, FilledOutputContent, Header, InPoint, M6id, MerkleRoot,
    MutableBitNameData, OutPoint, Output, OutputContent, PeerConnectionStatus,
    Signature, SpentOutput, Transaction, TransactionData, Txid, TxIn,
    VerifyingKey, WithdrawalOutputContent,
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
        #[open_api_method_arg(schema(
            ToSchema = "bitnames_schema::SocketAddr"
        ))]
        addr: SocketAddr,
    ) -> RpcResult<()>;

    /// Decrypt a message with the specified encryption key corresponding to
    /// the specified encryption pubkey.
    /// Returns a decrypted hex string.
    #[method(name = "decrypt_msg")]
    async fn decrypt_msg(
        &self,
        encryption_pubkey: EncryptionPubKey,
        ciphertext: String,
    ) -> RpcResult<String>;

    /// Encrypt a message to the specified encryption pubkey
    /// Returns the ciphertext as a hex string.
    #[method(name = "encrypt_msg")]
    async fn encrypt_msg(
        &self,
        encryption_pubkey: EncryptionPubKey,
        msg: String,
    ) -> RpcResult<String>;

    /// Delete peer from known_peers DB.
    /// Connections to the peer are not terminated.
    #[method(name = "forget_peer")]
    async fn forget_peer(
        &self,
        #[open_api_method_arg(schema(
            PartialSchema = "bitnames_schema::SocketAddr"
        ))]
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

    /// Get mainchain blocks that commit to a specified block hash
    #[open_api_method(output_schema(
        PartialSchema = "bitnames_schema::BitcoinBlockHash"
    ))]
    #[method(name = "get_bmm_inclusions")]
    async fn get_bmm_inclusions(
        &self,
        block_hash: plain_bitnames::types::BlockHash,
    ) -> RpcResult<Vec<bitcoin::BlockHash>>;

    /// Get the best known mainchain block hash
    #[open_api_method(output_schema(
        PartialSchema = "schema::Optional<bitnames_schema::BitcoinBlockHash>"
    ))]
    #[method(name = "get_best_mainchain_block_hash")]
    async fn get_best_mainchain_block_hash(
        &self,
    ) -> RpcResult<Option<bitcoin::BlockHash>>;

    /// Get the best sidechain block hash known by Bitnames
    #[open_api_method(output_schema(
        PartialSchema = "schema::Optional<BlockHash>"
    ))]
    #[method(name = "get_best_sidechain_block_hash")]
    async fn get_best_sidechain_block_hash(
        &self,
    ) -> RpcResult<Option<BlockHash>>;

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

    /// Get wallet master XVerifyingKey
    #[method(name = "get_wallet_master_xvk")]
    async fn get_wallet_master_xvk(&self) -> RpcResult<XVerifyingKey>;

    /// Get wallet master XEncryptionSecretKey
    #[method(name = "get_wallet_master_xesk")]
    async fn get_wallet_master_xesk(&self) -> RpcResult<XEncryptionSecretKey>;

    /// Get the current block count
    #[method(name = "getblockcount")]
    async fn getblockcount(&self) -> RpcResult<u32>;

    /// Get the height of the latest failed withdrawal bundle
    #[method(name = "latest_failed_withdrawal_bundle_height")]
    async fn latest_failed_withdrawal_bundle_height(
        &self,
    ) -> RpcResult<Option<u32>>;

    /// List peers
    #[method(name = "list_peers")]
    async fn list_peers(&self) -> RpcResult<Vec<Peer>>;

    /// List all STXOs
    #[open_api_method(output_schema(
        ToSchema = "Vec<PointedOutput<SpentOutput>>"
    ))]
    #[method(name = "list_stxos")]
    async fn list_stxos(&self) -> RpcResult<Vec<PointedOutput<SpentOutput>>>;

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

    /// Get pending withdrawal bundle
    #[open_api_method(output_schema(ToSchema))]
    #[method(name = "pending_withdrawal_bundle")]
    async fn pending_withdrawal_bundle(
        &self,
    ) -> RpcResult<Option<WithdrawalBundle>>;

    /// Get OpenRPC schema
    #[open_api_method(output_schema(ToSchema = "schema::OpenApi"))]
    #[method(name = "openapi_schema")]
    async fn openapi_schema(&self) -> RpcResult<utoipa::openapi::OpenApi>;

    /// Register a BitName
    #[method(name = "register_bitname")]
    async fn register_bitname(
        &self,
        plain_name: String,
        bitname_data: Option<MutableBitNameData>,
    ) -> RpcResult<Txid>;

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

    /// Sign an arbitrary message with the specified verifying key
    #[method(name = "sign_arbitrary_msg")]
    async fn sign_arbitrary_msg(
        &self,
        verifying_key: VerifyingKey,
        msg: String,
    ) -> RpcResult<Signature>;

    /// Sign an arbitrary message with the secret key for the specified address
    #[method(name = "sign_arbitrary_msg_as_addr")]
    async fn sign_arbitrary_msg_as_addr(
        &self,
        address: Address,
        msg: String,
    ) -> RpcResult<Authorization>;

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

    /// Verify a signature on a message against the specified verifying key.
    /// Returns `true` if the signature is valid
    #[method(name = "verify_signature")]
    async fn verify_signature(
        &self,
        signature: Signature,
        verifying_key: VerifyingKey,
        dst: Dst,
        msg: String,
    ) -> RpcResult<bool>;

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
