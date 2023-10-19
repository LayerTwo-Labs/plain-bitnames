use std::{borrow::Cow, net::SocketAddr};

use jsonrpsee::{
    core::{async_trait, RpcResult},
    proc_macros::rpc,
    server::Server,
    types::{ErrorObject, ResponsePayload},
};

use plain_bitnames::{
    node,
    types::{Address, Block, BlockHash, Transaction},
    wallet,
};

use crate::app::{self, App};

#[rpc(server)]
pub trait Rpc {
    #[method(name = "stop")]
    async fn stop(&self);

    #[method(name = "getblockcount")]
    async fn getblockcount(&self) -> u32;

    #[method(name = "get_block_hash")]
    async fn get_block_hash(&self, height: u32) -> RpcResult<BlockHash>;

    #[method(name = "get_block")]
    async fn get_block(&self, block_hash: BlockHash) -> RpcResult<Block>;

    #[method(name = "mine")]
    async fn mine(&self) -> RpcResult<()>;

    #[method(name = "get_new_address")]
    async fn get_new_address(&self) -> RpcResult<Address>;

    #[method(name = "generate_mnemonic")]
    async fn generate_mnemonic(&self) -> RpcResult<String>;

    #[method(name = "set_seed_from_mnemonic")]
    async fn set_seed_from_mnemonic(&self, mnemonic: String) -> RpcResult<()>;

    #[method(name = "transfer")]
    async fn transfer(
        &self,
        dest: Address,
        value: u64,
        fee: u64,
        memo: Option<String>,
    ) -> RpcResult<()>;

    #[method(name = "reserve_bitname")]
    async fn reserve_bitname(
        &self,
        plain_name: String,
    ) -> ResponsePayload<'static, ()>;
}

pub struct RpcServerImpl {
    app: App,
}

fn custom_err(err_msg: impl Into<String>) -> ErrorObject<'static> {
    ErrorObject::owned(-1, err_msg.into(), Option::<()>::None)
}

fn convert_app_err(err: app::Error) -> ErrorObject<'static> {
    custom_err(err.to_string())
}

fn convert_node_err(err: node::Error) -> ErrorObject<'static> {
    custom_err(err.to_string())
}

fn convert_wallet_err(err: wallet::Error) -> ErrorObject<'static> {
    custom_err(err.to_string())
}

#[async_trait]
impl RpcServer for RpcServerImpl {
    async fn stop(&self) {
        std::process::exit(0);
    }

    async fn getblockcount(&self) -> u32 {
        self.app.node.get_height().unwrap_or(0)
    }

    async fn get_block_hash(&self, height: u32) -> RpcResult<BlockHash> {
        let block_hash = self
            .app
            .node
            .get_header(height)
            .map_err(convert_node_err)?
            .ok_or_else(|| custom_err("block not found"))?
            .hash();
        Ok(block_hash)
    }

    async fn get_block(&self, block_hash: BlockHash) -> RpcResult<Block> {
        let block = self
            .app
            .node
            .get_block(block_hash)
            .expect("This error should have been handled properly.");
        Ok(block)
    }

    async fn mine(&self) -> RpcResult<()> {
        self.app.mine().await.map_err(convert_app_err)
    }

    async fn get_new_address(&self) -> RpcResult<Address> {
        self.app
            .wallet
            .get_new_address()
            .map_err(convert_wallet_err)
    }

    async fn generate_mnemonic(&self) -> RpcResult<String> {
        let mnemonic = bip39::Mnemonic::new(
            bip39::MnemonicType::Words12,
            bip39::Language::English,
        );
        Ok(mnemonic.to_string())
    }

    async fn set_seed_from_mnemonic(&self, mnemonic: String) -> RpcResult<()> {
        let mnemonic =
            bip39::Mnemonic::from_phrase(&mnemonic, bip39::Language::English)
                .map_err(|err| custom_err(err.to_string()))?;
        let seed = bip39::Seed::new(&mnemonic, "");
        let seed_bytes: [u8; 64] = seed.as_bytes().try_into().map_err(
            |err: <[u8; 64] as TryFrom<&[u8]>>::Error| {
                custom_err(err.to_string())
            },
        )?;
        self.app
            .wallet
            .set_seed(&seed_bytes)
            .map_err(convert_wallet_err)
    }

    async fn transfer(
        &self,
        dest: Address,
        value: u64,
        fee: u64,
        memo: Option<String>,
    ) -> RpcResult<()> {
        let memo = match memo {
            None => None,
            Some(memo) => {
                let hex = hex::decode(memo)
                    .map_err(|err| custom_err(err.to_string()))?;
                Some(hex)
            }
        };
        let tx = self
            .app
            .wallet
            .create_regular_transaction(dest, value, fee, memo)
            .map_err(convert_wallet_err)?;
        let authorized_tx =
            self.app.wallet.authorize(tx).map_err(convert_wallet_err)?;
        self.app
            .node
            .submit_transaction(&authorized_tx)
            .await
            .map_err(convert_node_err)
    }

    async fn reserve_bitname(
        &self,
        plain_name: String,
    ) -> ResponsePayload<'static, ()> {
        let mut tx = Transaction::default();
        let () = match self.app.wallet.reserve_bitname(&mut tx, &plain_name) {
            Ok(()) => (),
            Err(err) => return ResponsePayload::Error(convert_wallet_err(err)),
        };
        let authorized_tx = match self.app.wallet.authorize(tx) {
            Ok(tx) => tx,
            Err(err) => return ResponsePayload::Error(convert_wallet_err(err)),
        };
        match self.app.node.submit_transaction(&authorized_tx).await {
            Ok(()) => ResponsePayload::Result(Cow::Owned(())),
            Err(err) => ResponsePayload::Error(convert_node_err(err)),
        }
    }
}

pub async fn run_server(
    app: App,
    rpc_addr: SocketAddr,
) -> anyhow::Result<SocketAddr> {
    let server = Server::builder().build(rpc_addr).await?;

    let addr = server.local_addr()?;
    let handle = server.start(RpcServerImpl { app }.into_rpc());

    // In this example we don't care about doing shutdown so let's it run forever.
    // You may use the `ServerHandle` to shut it down or manage it yourself.
    tokio::spawn(handle.stopped());

    Ok(addr)
}
