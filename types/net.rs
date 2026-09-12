use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

pub mod peer {
    use std::net::SocketAddr;

    use serde::{Deserialize, Serialize};
    use strum::Display;
    use utoipa::ToSchema;

    use crate::schema;

    #[derive(
        Clone, Copy, Deserialize, Display, Eq, PartialEq, Serialize, ToSchema,
    )]
    #[schema(as = PeerConnectionStatus)]
    pub enum ConnectionStatus {
        /// We're still in the process of initializing the peer connection
        Connecting,
        /// The connection is successfully established
        Connected,
    }

    /// RPC output representation for peer + state
    #[derive(Clone, Deserialize, Serialize, ToSchema)]
    pub struct Peer {
        #[schema(value_type = schema::SocketAddr)]
        pub address: SocketAddr,
        pub status: ConnectionStatus,
    }
}
pub use peer::{ConnectionStatus as PeerConnectionStatus, Peer};

#[derive(
    Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema,
)]
pub struct TorProxyStatus {
    pub tor_proxy_mode: bool,
    /// Connected loopback peers, which are the only peers permitted in Tor
    /// proxy mode.
    pub connected_tunnel_peers: u32,
}

impl TorProxyStatus {
    pub fn allows_transaction_submission(self) -> bool {
        !self.tor_proxy_mode || self.connected_tunnel_peers > 0
    }
}
