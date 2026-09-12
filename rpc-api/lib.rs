//! RPC API

mod schema;

pub mod open_api {
    use jsonrpsee::{core::RpcResult, proc_macros::rpc};
    use l2l_openapi::open_api;

    use crate::schema;

    #[open_api]
    #[rpc(client, server)]
    pub trait Rpc {
        /// Get OpenAPI schema
        #[open_api_method(output_schema(PartialSchema = "schema::OpenApi"))]
        #[method(name = "openapi_schema")]
        async fn openapi_schema(&self) -> RpcResult<utoipa::openapi::OpenApi>;
    }
}

pub mod node {
    use std::{
        collections::{HashMap, HashSet},
        net::SocketAddr,
    };

    use jsonrpsee::{core::RpcResult, proc_macros::rpc};
    use l2l_openapi::open_api;
    use plain_bitnames_types::{
        Address, Authorization, Authorized, BatchIcannRegistrationData,
        BitNameData, BitNameDataUpdates, BitNameResolution, BitNameSeqId,
        BitcoinOutputContent, Block, BlockHash, Body, EncryptionPubKey,
        FilledOutput, FilledOutputContent, Header, InPoint, M6id, MerkleRoot,
        MutableBitNameData, OutPoint, Output, OutputContent, PaymailEntry,
        PaymailRecipient, PointedOutput, SpentOutput, Transaction,
        TransactionData, TxIn, Txid, VerifyingKey, WithdrawalBundle,
        WithdrawalOutputContent,
        authorization::Signature,
        hashes::BitName,
        net::{Peer, PeerConnectionStatus, TorProxyStatus},
        schema as bitnames_schema,
    };
    use serde::{Deserialize, Serialize};
    use utoipa::ToSchema;

    use crate::{open_api, schema};

    #[open_api(ref_schemas[])]
    #[rpc(client, server, server_bounds(Self: open_api::RpcServer))]
    pub trait PrivateRpc {
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

        /// Stop the node
        #[method(name = "stop")]
        async fn stop(&self);
    }

    #[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
    pub struct TxInfo {
        pub confirmations: Option<u32>,
        pub fee_sats: u64,
        pub txin: Option<TxIn>,
    }

    #[open_api(ref_schemas[
        Address, Authorization, BatchIcannRegistrationData,
        BitcoinOutputContent, BitName, BitNameData, BitNameDataUpdates, BitNameSeqId,
        BlockHash, Body, EncryptionPubKey, FilledOutput, FilledOutputContent,
        Header, InPoint, M6id, MerkleRoot, MutableBitNameData, OutPoint,
        Output, OutputContent, PaymailRecipient, PeerConnectionStatus, Signature, SpentOutput,
        Transaction, TransactionData, Txid, TxIn, VerifyingKey,
        WithdrawalOutputContent, bitnames_schema::BitcoinAddr,
        bitnames_schema::BitcoinBlockHash, bitnames_schema::BitcoinOutPoint,
        bitnames_schema::BitcoinTransaction, bitnames_schema::SocketAddr,
    ])]
    #[rpc(client, server, server_bounds(Self: open_api::RpcServer))]
    pub trait Rpc {
        /// Retrieve data for a single BitName
        #[method(name = "bitname_data")]
        async fn bitname_data(
            &self,
            bitname_id: BitName,
        ) -> RpcResult<BitNameData>;

        /// List all BitNames
        #[open_api_method(output_schema(
            PartialSchema = "schema::ArrayTuple<BitName, BitNameData>"
        ))]
        #[method(name = "bitnames")]
        async fn bitnames(&self) -> RpcResult<Vec<(BitName, BitNameData)>>;

        /// Connect a block template for which a BMM request was included in the
        /// specified mainchain block. Returns `true` if it was accepted as the new
        /// tip.
        #[open_api_method(output_schema(ToSchema))]
        #[method(name = "connect_block")]
        async fn connect_block(
            &self,
            block: Block,
            #[open_api_method_arg(schema(
                PartialSchema = "bitnames_schema::BitcoinBlockHash"
            ))]
            main_block_hash: bitcoin::BlockHash,
        ) -> RpcResult<bool>;

        /// Retrieve BitName data at a confirmed transaction position.
        #[method(name = "bitname_data_at_position")]
        async fn bitname_data_at_position(
            &self,
            bitname: BitName,
            block_hash: BlockHash,
            tx_index: u32,
        ) -> RpcResult<BitNameData>;

        /// Resolve the current owner and mutable data of a BitName.
        #[method(name = "resolve_bitname")]
        async fn resolve_bitname(
            &self,
            bitname: BitName,
        ) -> RpcResult<BitNameResolution>;

        /// List attributed mailbox outputs, including spent and underpaid entries.
        #[method(name = "get_paymail_entries")]
        async fn get_paymail_entries(&self) -> RpcResult<Vec<PaymailEntry>>;

        /// Report whether the configured Tor tunnel can accept transactions.
        #[method(name = "tor_proxy_status")]
        async fn tor_proxy_status(&self) -> RpcResult<TorProxyStatus>;

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
            block_hash: BlockHash,
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

        /// Get all paymail
        #[method(name = "get_paymail")]
        async fn get_paymail(
            &self,
        ) -> RpcResult<HashMap<OutPoint, FilledOutput>>;

        /// Get stxos for addresses
        #[method(name = "get_stxos")]
        async fn get_stxos(
            &self,
            addresses: HashSet<Address>,
        ) -> RpcResult<Vec<PointedOutput<SpentOutput>>>;

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

        /// Get utxos for addresses
        #[method(name = "get_utxos")]
        async fn get_utxos(
            &self,
            addresses: HashSet<Address>,
        ) -> RpcResult<Vec<PointedOutput<FilledOutput>>>;

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
        async fn list_stxos(
            &self,
        ) -> RpcResult<Vec<PointedOutput<SpentOutput>>>;

        /// List all UTXOs
        #[open_api_method(output_schema(
            ToSchema = "Vec<PointedOutput<FilledOutputContent>>"
        ))]
        #[method(name = "list_utxos")]
        async fn list_utxos(
            &self,
        ) -> RpcResult<Vec<PointedOutput<FilledOutput>>>;

        /// Get pending withdrawal bundle
        #[open_api_method(output_schema(ToSchema))]
        #[method(name = "pending_withdrawal_bundle")]
        async fn pending_withdrawal_bundle(
            &self,
        ) -> RpcResult<Option<WithdrawalBundle>>;

        /// Get total sidechain wealth in sats
        #[method(name = "sidechain_wealth")]
        async fn sidechain_wealth_sats(&self) -> RpcResult<u64>;

        /// Verify and broadcast a transaction
        #[method(name = "submit_transaction")]
        async fn submit_transaction(
            &self,
            transaction: Authorized<Transaction>,
        ) -> RpcResult<Txid>;
    }
}

pub mod wallet {
    use jsonrpsee::{core::RpcResult, proc_macros::rpc};
    use l2l_openapi::open_api;
    use plain_bitnames_types::{
        Address, Authorization, Authorized, BatchIcannRegistrationData,
        BitNameDataUpdates, BitcoinOutputContent, Block, BlockHash, Body,
        EncryptionPubKey, FilledOutput, FilledOutputContent, Header,
        MerkleRoot, MutableBitNameData, OutPoint, Output, OutputContent,
        PointedOutput, Transaction, TransactionData, Txid, VerifyingKey,
        WithdrawalOutputContent, XEncryptionSecretKey, XVerifyingKey,
        authorization::{Dst, Signature},
        hashes::BitName,
        schema as bitnames_schema,
        wallet::Balance,
    };
    use serde::{Deserialize, Serialize};
    use utoipa::ToSchema;

    use crate::{open_api, schema};

    #[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
    pub struct GetBlockTemplateResponse {
        /// Block hash to commit to in a BMM request
        pub critical_hash: BlockHash,
        /// Block to pass to `connect_block` once its BMM request is included in a
        /// mainchain block
        pub block: Block,
        /// Fees collected by the transactions in the block, in sats
        pub fees_sats: u64,
    }

    #[open_api(ref_schemas[
        Address, Authorization, BatchIcannRegistrationData,
        BitcoinOutputContent, BitName, BitNameDataUpdates, Block, BlockHash,
        Body, EncryptionPubKey, FilledOutput, FilledOutputContent, Header,
        MerkleRoot, MutableBitNameData, OutPoint, Output, OutputContent,
        Signature, Transaction, TransactionData, Txid, VerifyingKey,
        WithdrawalOutputContent, bitnames_schema::BitcoinAddr,
        bitnames_schema::BitcoinBlockHash, bitnames_schema::BitcoinOutPoint,
    ])]
    #[rpc(client, server, server_bounds(Self: open_api::RpcServer))]
    pub trait Rpc {
        /// Get balance in sats
        #[open_api_method(output_schema(ToSchema))]
        #[method(name = "balance")]
        async fn balance(&self) -> RpcResult<Balance>;

        /// Deposit to address
        #[open_api_method(output_schema(
            PartialSchema = "schema::BitcoinTxid"
        ))]
        #[method(name = "create_deposit")]
        async fn create_deposit(
            &self,
            address: Address,
            value_sats: u64,
            fee_sats: u64,
        ) -> RpcResult<bitcoin::Txid>;

        /// Create a tx that transfers funds to the specified address
        #[method(name = "create_transfer")]
        async fn create_transfer(
            &self,
            dest: Address,
            value_sats: u64,
            fee_sats: u64,
            memo: Option<String>,
        ) -> RpcResult<Txid>;

        /// Creates a tx that initiates a withdrawal to the specified mainchain
        /// address
        #[method(name = "create_withdrawal")]
        async fn create_withdrawal(
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

        /// Format a deposit address
        #[method(name = "format_deposit_address")]
        async fn format_deposit_address(
            &self,
            address: Address,
        ) -> RpcResult<String>;

        /// Generate a mnemonic seed phrase
        #[method(name = "generate_mnemonic")]
        async fn generate_mnemonic(&self) -> RpcResult<String>;

        /// Assemble a block to blind merge mine, without requesting BMM for it.
        /// The caller requests BMM for `critical_hash` itself, then passes the
        /// block back to `connect_block`.
        #[open_api_method(output_schema(ToSchema))]
        #[method(name = "get_block_template")]
        async fn get_block_template(
            &self,
        ) -> RpcResult<GetBlockTemplateResponse>;

        /// Get a new address
        #[method(name = "get_new_address")]
        async fn get_new_address(&self) -> RpcResult<Address>;

        /// Get new encryption key
        #[method(name = "get_new_encryption_key")]
        async fn get_new_encryption_key(&self) -> RpcResult<EncryptionPubKey>;

        /// Get new verifying/signing key
        #[method(name = "get_new_verifying_key")]
        async fn get_new_verifying_key(&self) -> RpcResult<VerifyingKey>;

        /// Get wallet addresses, sorted by base58 encoding
        #[method(name = "get_wallet_addresses")]
        async fn get_wallet_addresses(&self) -> RpcResult<Vec<Address>>;

        /// Get wallet master XVerifyingKey
        #[method(name = "get_wallet_master_xvk")]
        async fn get_wallet_master_xvk(&self) -> RpcResult<XVerifyingKey>;

        /// Get wallet master XEncryptionSecretKey
        #[method(name = "get_wallet_master_xesk")]
        async fn get_wallet_master_xesk(
            &self,
        ) -> RpcResult<XEncryptionSecretKey>;

        /// Get wallet UTXOs
        #[method(name = "get_wallet_utxos")]
        async fn get_wallet_utxos(
            &self,
        ) -> RpcResult<Vec<PointedOutput<FilledOutput>>>;

        /// Attempt to mine a sidechain block
        #[open_api_method(output_schema(ToSchema))]
        #[method(name = "mine")]
        async fn mine(&self, fee: Option<u64>) -> RpcResult<()>;

        /// List owned UTXOs
        #[method(name = "my_utxos")]
        async fn my_utxos(&self)
        -> RpcResult<Vec<PointedOutput<FilledOutput>>>;

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
        async fn set_seed_from_mnemonic(
            &self,
            mnemonic: String,
        ) -> RpcResult<()>;

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

        /// Update mutable BitName data and submit the transaction.
        #[method(name = "update_bitname")]
        async fn update_bitname(
            &self,
            bitname: BitName,
            updates: BitNameDataUpdates,
            fee_sats: u64,
        ) -> RpcResult<Txid>;

        /// Create and submit a transfer, replaying the same transaction on keyed retries.
        #[method(name = "transfer")]
        async fn transfer(
            &self,
            dest: Address,
            value: u64,
            fee: u64,
            memo: Option<String>,
            idempotency_key: Option<String>,
        ) -> RpcResult<Txid>;

        /// Sign a transaction, and optionally broadcast it.
        #[method(name = "sign_transaction")]
        async fn sign_transaction(
            &self,
            transaction: Transaction,
            broadcast: Option<bool>,
        ) -> RpcResult<Authorized<Transaction>>;

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
    }
}

pub mod bitname_commit {
    use jsonrpsee::{core::RpcResult, proc_macros::rpc};
    use serde::{Deserialize, Serialize};
    use serde_with::serde_as;

    /// Wrapper struct for hex-encoded bytes
    #[serde_as]
    #[derive(Debug, Deserialize, Serialize)]
    #[repr(transparent)]
    #[serde(transparent)]
    pub struct HexStr(#[serde_as(as = "serde_with::hex::Hex")] pub Vec<u8>);

    #[rpc(client, server)]
    pub trait Rpc {
        #[method(name = "bitname_commit")]
        async fn bitname_commit(
            &self,
            bytes: Option<HexStr>,
        ) -> RpcResult<serde_json::Map<String, serde_json::Value>>;
    }
}

#[cfg(test)]
mod test;
