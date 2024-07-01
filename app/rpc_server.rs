use std::{collections::HashMap, net::SocketAddr};

use bip300301::bitcoin;
use jsonrpsee::{
    core::{async_trait, RpcResult},
    server::Server,
    types::ErrorObject,
};

use plain_bitnames::{
    node,
    types::{
        hashes::BitName, Address, BitNameData, Block, BlockHash, FilledOutput,
        OutPoint, PointedOutput, Transaction, Txid,
    },
    wallet,
};
use plain_bitnames_app_rpc_api::{RpcServer, TxInfo};

use crate::app::{self, App};

pub struct RpcServerImpl {
    app: App,
}

fn custom_err(err_msg: impl Into<String>) -> ErrorObject<'static> {
    ErrorObject::owned(-1, err_msg.into(), Option::<()>::None)
}

fn convert_app_err(err: app::Error) -> ErrorObject<'static> {
    let err = anyhow::anyhow!(err);
    tracing::error!("{err:#}");
    custom_err(err.to_string())
}

fn convert_node_err(err: node::Error) -> ErrorObject<'static> {
    let err = anyhow::anyhow!(err);
    tracing::error!("{err:#}");
    custom_err(err.to_string())
}

fn convert_wallet_err(err: wallet::Error) -> ErrorObject<'static> {
    let err = anyhow::anyhow!(err);
    tracing::error!("{err:#}");
    custom_err(err.to_string())
}

#[async_trait]
impl RpcServer for RpcServerImpl {
    async fn balance(&self) -> RpcResult<u64> {
        self.app.wallet.get_balance().map_err(convert_wallet_err)
    }

    async fn bitnames(&self) -> RpcResult<Vec<(BitName, BitNameData)>> {
        self.app.node.bitnames().map_err(convert_node_err)
    }

    async fn connect_peer(&self, addr: SocketAddr) -> RpcResult<()> {
        self.app.node.connect_peer(addr).map_err(convert_node_err)
    }

    async fn format_deposit_address(
        &self,
        address: Address,
    ) -> RpcResult<String> {
        let deposit_address = plain_bitnames::format_deposit_address(
            node::THIS_SIDECHAIN,
            &address.to_string(),
        );
        Ok(deposit_address)
    }

    async fn generate_mnemonic(&self) -> RpcResult<String> {
        let mnemonic = bip39::Mnemonic::new(
            bip39::MnemonicType::Words12,
            bip39::Language::English,
        );
        Ok(mnemonic.to_string())
    }

    async fn get_block(&self, block_hash: BlockHash) -> RpcResult<Block> {
        let block = self
            .app
            .node
            .get_block(block_hash)
            .expect("This error should have been handled properly.");
        Ok(block)
    }

    async fn get_new_address(&self) -> RpcResult<Address> {
        self.app
            .wallet
            .get_new_address()
            .map_err(convert_wallet_err)
    }

    async fn get_paymail(&self) -> RpcResult<HashMap<OutPoint, FilledOutput>> {
        self.app.get_paymail(None).map_err(convert_app_err)
    }

    async fn get_transaction(
        &self,
        txid: Txid,
    ) -> RpcResult<Option<Transaction>> {
        self.app
            .node
            .try_get_transaction(txid)
            .map_err(convert_node_err)
    }

    async fn get_transaction_info(
        &self,
        txid: Txid,
    ) -> RpcResult<Option<TxInfo>> {
        let Some((filled_tx, txin)) = self
            .app
            .node
            .try_get_filled_transaction(txid)
            .map_err(convert_node_err)?
        else {
            return Ok(None);
        };
        let confirmations = match txin {
            Some(txin) => {
                let tip_height =
                    self.app.node.get_tip_height().map_err(convert_node_err)?;
                let height = self
                    .app
                    .node
                    .get_height(txin.block_hash)
                    .map_err(convert_node_err)?;
                Some(tip_height - height)
            }
            None => None,
        };
        let fee_sats = filled_tx.transaction.fee().unwrap();
        let res = TxInfo {
            confirmations,
            fee_sats,
            txin,
        };
        Ok(Some(res))
    }

    async fn get_wallet_addresses(&self) -> RpcResult<Vec<Address>> {
        let addrs = self
            .app
            .wallet
            .get_addresses()
            .map_err(convert_wallet_err)?;
        let mut res: Vec<_> = addrs.into_iter().collect();
        res.sort_by_key(|addr| addr.to_base58());
        Ok(res)
    }

    async fn get_wallet_utxos(
        &self,
    ) -> RpcResult<Vec<PointedOutput<FilledOutput>>> {
        let utxos = self.app.wallet.get_utxos().map_err(convert_wallet_err)?;
        let utxos = utxos
            .into_iter()
            .map(|(outpoint, output)| PointedOutput { outpoint, output })
            .collect();
        Ok(utxos)
    }

    async fn getblockcount(&self) -> RpcResult<u32> {
        self.app.node.get_tip_height().map_err(convert_node_err)
    }

    async fn list_utxos(&self) -> RpcResult<Vec<PointedOutput<FilledOutput>>> {
        let utxos = self.app.node.get_all_utxos().map_err(convert_node_err)?;
        let res = utxos
            .into_iter()
            .map(|(outpoint, output)| PointedOutput { outpoint, output })
            .collect();
        Ok(res)
    }

    async fn mine(&self, fee: Option<u64>) -> RpcResult<()> {
        let fee = fee.map(bip300301::bitcoin::Amount::from_sat);
        self.app.local_pool.spawn_pinned({
                let app = self.app.clone();
                move || async move { app.mine(fee).await.map_err(convert_app_err) }
            }).await.unwrap()
    }

    async fn my_utxos(&self) -> RpcResult<Vec<PointedOutput<FilledOutput>>> {
        let utxos = self
            .app
            .wallet
            .get_utxos()
            .map_err(convert_wallet_err)?
            .into_iter()
            .map(|(outpoint, output)| PointedOutput { outpoint, output })
            .collect();
        Ok(utxos)
    }

    async fn openapi_schema(&self) -> RpcResult<utoipa::openapi::OpenApi> {
        let res =
            <plain_bitnames_app_rpc_api::RpcDoc as utoipa::OpenApi>::openapi();
        Ok(res)
    }

    async fn reserve_bitname(&self, plain_name: String) -> RpcResult<Txid> {
        let mut tx = Transaction::default();
        let () = match self.app.wallet.reserve_bitname(&mut tx, &plain_name) {
            Ok(()) => (),
            Err(err) => return Err(convert_wallet_err(err)),
        };
        let txid = tx.txid();
        self.app.sign_and_send(tx).map_err(convert_app_err)?;
        Ok(txid)
    }

    async fn set_seed_from_mnemonic(&self, mnemonic: String) -> RpcResult<()> {
        self.app
            .wallet
            .set_seed_from_mnemonic(mnemonic.as_str())
            .map_err(convert_wallet_err)
    }

    async fn sidechain_wealth(&self) -> RpcResult<bitcoin::Amount> {
        self.app
            .node
            .get_sidechain_wealth()
            .map_err(convert_node_err)
    }

    async fn stop(&self) {
        std::process::exit(0);
    }

    async fn transfer(
        &self,
        dest: Address,
        value: u64,
        fee: u64,
        memo: Option<String>,
    ) -> RpcResult<Txid> {
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
            .create_transfer(dest, value, fee, memo)
            .map_err(convert_wallet_err)?;
        let txid = tx.txid();
        self.app.sign_and_send(tx).map_err(convert_app_err)?;
        Ok(txid)
    }

    async fn withdraw(
        &self,
        mainchain_address: bitcoin::Address<bitcoin::address::NetworkUnchecked>,
        amount_sats: u64,
        fee_sats: u64,
        mainchain_fee_sats: u64,
    ) -> RpcResult<Txid> {
        let tx = self
            .app
            .wallet
            .create_withdrawal(
                mainchain_address,
                amount_sats,
                mainchain_fee_sats,
                fee_sats,
            )
            .map_err(convert_wallet_err)?;
        let txid = tx.txid();
        self.app.sign_and_send(tx).map_err(convert_app_err)?;
        Ok(txid)
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
