use std::net::SocketAddr;

use jsonrpsee::{
    core::async_trait, proc_macros::rpc, server::Server,
    types::ResponsePayload, IntoResponse,
};

use plain_bitnames::{
    node::Node,
    types::{BlockHash, Body},
};

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
}

pub struct RpcServerImpl {
    node: Node,
}

impl IntoResponse for GetBlockResponse {
    type Output = Body;

    fn into_response(self) -> ResponsePayload<'static, Self::Output> {
        ResponsePayload::result(self.0)
    }
}

#[async_trait]
impl RpcServer for RpcServerImpl {
    async fn stop(&self) {
        std::process::exit(0);
    }

    async fn getblockcount(&self) -> u32 {
        self.node.get_height().unwrap_or(0)
    }

    async fn get_block(&self, block_hash: BlockHash) -> GetBlockResponse {
        let block = self
            .node
            .get_block(block_hash)
            .expect("This error should have been handled properly.");
        GetBlockResponse(block)
    }
}

pub async fn run_server(
    node: Node,
    rpc_addr: SocketAddr,
) -> anyhow::Result<SocketAddr> {
    let server = Server::builder().build(rpc_addr).await?;

    let addr = server.local_addr()?;
    let handle = server.start(RpcServerImpl { node }.into_rpc());

    // In this example we don't care about doing shutdown so let's it run forever.
    // You may use the `ServerHandle` to shut it down or manage it yourself.
    tokio::spawn(handle.stopped());

    Ok(addr)
}
