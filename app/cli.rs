use clap::Parser;
use std::{net::SocketAddr, path::PathBuf};

#[derive(Clone, Debug, Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// data directory for storing blockchain data and wallet, defaults to ~/.local/share
    #[arg(short, long)]
    pub datadir: Option<PathBuf>,
    /// If specified, the gui will not launch.
    #[arg(long)]
    pub headless: bool,
    /// Log level, defaults to [`tracing::Level::Info`]
    #[arg(default_value_t = tracing::Level::INFO, long)]
    pub log_level: tracing::Level,
    /// address to connect to mainchain node RPC server, defaults to 127.0.0.1:18443
    #[arg(short, long)]
    pub main_addr: Option<String>,
    /// Path to a mnemonic seed phrase
    #[arg(long)]
    pub mnemonic_seed_phrase_path: Option<PathBuf>,
    /// address to use for P2P networking, defaults to 0.0.0.0:4000
    #[arg(short, long)]
    pub net_addr: Option<String>,
    /// mainchain node RPC password, defaults to "password"
    #[arg(short, long)]
    pub password_main: Option<String>,
    /// address for use by the RPC server exposing getblockcount and stop commands, defaults to
    /// 127.0.0.1:2020
    #[arg(short, long)]
    pub rpc_addr: Option<String>,
    /// mainchain node RPC user, defaults to "user"
    #[arg(short, long)]
    pub user_main: Option<String>,
    /// Address to use for ZMQ pub/sub, defaults to 127.0.0.1:28332
    #[cfg(all(not(target_os = "windows"), feature = "zmq"))]
    #[arg(short, long)]
    pub zmq_addr: Option<String>,
}

pub struct Config {
    pub datadir: PathBuf,
    pub headless: bool,
    pub log_level: tracing::Level,
    pub main_addr: SocketAddr,
    pub main_password: String,
    pub main_user: String,
    pub mnemonic_seed_phrase_path: Option<PathBuf>,
    pub net_addr: SocketAddr,
    pub rpc_addr: SocketAddr,
    #[cfg(all(not(target_os = "windows"), feature = "zmq"))]
    pub zmq_addr: SocketAddr,
}

impl Cli {
    pub fn get_config(self) -> anyhow::Result<Config> {
        let datadir = self
            .datadir
            .clone()
            .unwrap_or_else(|| {
                dirs::data_dir()
                    .expect("couldn't get default datadir, specify --datadir")
            })
            .join("plain_bitnames");
        const DEFAULT_MAIN_ADDR: &str = "127.0.0.1:18443";
        let main_addr: SocketAddr = self
            .main_addr
            .clone()
            .unwrap_or(DEFAULT_MAIN_ADDR.to_string())
            .parse()?;
        let main_password = self
            .password_main
            .clone()
            .unwrap_or_else(|| "password".into());
        let main_user = self.user_main.clone().unwrap_or_else(|| "user".into());
        const DEFAULT_NET_ADDR: &str = "0.0.0.0:4000";
        let net_addr: SocketAddr = self
            .net_addr
            .clone()
            .unwrap_or(DEFAULT_NET_ADDR.to_string())
            .parse()?;
        const DEFAULT_RPC_ADDR: &str = "127.0.0.1:2020";
        let rpc_addr: SocketAddr = self
            .rpc_addr
            .clone()
            .unwrap_or(DEFAULT_RPC_ADDR.to_string())
            .parse()?;
        #[cfg(all(not(target_os = "windows"), feature = "zmq"))]
        const DEFAULT_ZMQ_ADDR: &str = "127.0.0.1:28332";
        #[cfg(all(not(target_os = "windows"), feature = "zmq"))]
        let zmq_addr: SocketAddr = self
            .zmq_addr
            .clone()
            .unwrap_or(DEFAULT_ZMQ_ADDR.to_string())
            .parse()?;
        Ok(Config {
            datadir,
            headless: self.headless,
            log_level: self.log_level,
            main_addr,
            main_password,
            main_user,
            mnemonic_seed_phrase_path: self.mnemonic_seed_phrase_path,
            net_addr,
            rpc_addr,
            #[cfg(all(not(target_os = "windows"), feature = "zmq"))]
            zmq_addr,
        })
    }
}
