use std::{borrow::Cow, net::SocketAddr};

use jsonrpsee::{
    core::{async_trait, RpcResult},
    proc_macros::rpc,
    server::Server,
    types::{ErrorObject, ResponsePayload},
    IntoResponse,
};

use plain_bitnames::{
    node,
    types::{Address, BlockHash, Body, Transaction},
    wallet,
};

use crate::app::{self, App};

#[derive(Debug)]
pub struct GetBlockResponse(Body);

#[rpc(server)]
pub trait Rpc {
    #[method(name = "stop")]
    async fn stop(&self);

    #[method(name = "getblockcount")]
    async fn getblockcount(&self) -> u32;

    #[method(name = "get_block")]
    async fn get_block(&self, block_hash: BlockHash) -> GetBlockResponse;

    #[method(name = "mine")]
    async fn mine(&self) -> RpcResult<()>;

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

impl IntoResponse for GetBlockResponse {
    type Output = Body;

    fn into_response(self) -> ResponsePayload<'static, Self::Output> {
        ResponsePayload::result(self.0)
    }
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

    async fn get_block(&self, block_hash: BlockHash) -> GetBlockResponse {
        let block = self
            .app
            .node
            .get_block(block_hash)
            .expect("This error should have been handled properly.");
        GetBlockResponse(block)
    }

    async fn mine(&self) -> RpcResult<()> {
        self.app.mine().map_err(convert_app_err)
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
