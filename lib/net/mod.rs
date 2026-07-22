use std::{
    collections::{HashMap, HashSet, hash_map},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

use fallible_iterator::FallibleIterator;
use futures::{StreamExt, channel::mpsc};
use heed::types::{SerdeBincode, Unit};
use parking_lot::RwLock;
use quinn::{ClientConfig, Endpoint, ServerConfig};
use serde::{Deserialize, Serialize};
use sneed::{DatabaseUnique, DbError, EnvError, RwTxn, RwTxnError, UnitKey};
use tokio_stream::StreamNotifyClose;
use tracing::instrument;
use utoipa::ToSchema;

use crate::{
    archive::Archive,
    state::State,
    types::{AuthorizedTransaction, Network, THIS_SIDECHAIN, VERSION, Version},
};

pub mod error;
mod peer;

pub use error::Error;
pub(crate) use peer::error::mailbox::Error as PeerConnectionMailboxError;
use peer::{
    Connection, ConnectionContext as PeerConnectionCtxt,
    ConnectionHandle as PeerConnectionHandle,
};
pub use peer::{
    ConnectionError as PeerConnectionError, Info as PeerConnectionInfo,
    InternalMessage as PeerConnectionMessage, Peer, PeerConnectionStatus,
    PeerStateId, Request as PeerRequest, ResponseMessage as PeerResponse,
    message as peer_message,
};

/// Dummy certificate verifier that treats any certificate as valid.
/// NOTE, such verification is vulnerable to MITM attacks, but convenient for testing.
#[derive(Debug)]
struct SkipServerVerification;
impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self)
    }
}
impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer,
        _intermediates: &[rustls::pki_types::CertificateDer],
        _server_name: &rustls::pki_types::ServerName,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
    {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider()
                .signature_verification_algorithms,
        )
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
    {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider()
                .signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn configure_client() -> Result<ClientConfig, error::ConfigureClient> {
    let crypto_provider = Arc::new(rustls::crypto::ring::default_provider());
    let crypto = rustls::ClientConfig::builder_with_provider(crypto_provider)
        .with_safe_default_protocol_versions()
        .map_err(error::configure_client::Inner::Rustls)?
        .dangerous()
        .with_custom_certificate_verifier(SkipServerVerification::new())
        .with_no_client_auth();
    let client_config =
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?;
    Ok(ClientConfig::new(Arc::new(client_config)))
}
/// Returns default server configuration along with its certificate.
fn configure_server() -> Result<(ServerConfig, Vec<u8>), Error> {
    let cert_key =
        rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let keypair_der = cert_key.key_pair.serialize_der();
    let priv_key = rustls::pki_types::PrivateKeyDer::Pkcs8(keypair_der.into());
    let cert_der = cert_key.cert.der().to_vec();
    let cert_chain = vec![cert_key.cert.into()];
    let mut server_config =
        ServerConfig::with_single_cert(cert_chain, priv_key)?;
    let transport_config = Arc::get_mut(&mut server_config.transport).unwrap();
    transport_config.max_concurrent_uni_streams(1_u8.into());
    Ok((server_config, cert_der))
}
/// Constructs a QUIC endpoint configured to listen for incoming connections on a certain address
/// and port.
///
/// ## Returns
///
/// - a stream of incoming QUIC connections
/// - server certificate serialized into DER format
pub fn make_server_endpoint(
    bind_addr: SocketAddr,
) -> Result<(Endpoint, Vec<u8>), Error> {
    let (server_config, server_cert) = configure_server()?;
    tracing::info!(%bind_addr, "creating server endpoint");
    let mut endpoint = Endpoint::server(server_config, bind_addr)?;
    let client_cfg = configure_client()?;
    endpoint.set_default_client_config(client_cfg);
    Ok((endpoint, server_cert))
}

// None indicates that the stream has ended
pub type PeerInfoRx =
    mpsc::UnboundedReceiver<(SocketAddr, Option<PeerConnectionInfo>)>;

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

const SIGNET_SEED_NODE_ADDRS: &[SocketAddr] = {
    const SIGNET_MINING_SERVER: SocketAddr = SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(172, 105, 148, 135)),
        4000 + THIS_SIDECHAIN as u16,
    );
    // bitnames.bip300.xyz
    const BIP300_XYZ: SocketAddr = SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(95, 217, 243, 12)),
        4000 + THIS_SIDECHAIN as u16,
    );
    &[SIGNET_MINING_SERVER, BIP300_XYZ]
};

const FORKNET_SEED_NODE_ADDRS: &[SocketAddr] = {
    // explorer.bip300.xyz
    const BIP300_XYZ: SocketAddr = SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(157, 180, 8, 224)),
        4000 + THIS_SIDECHAIN as u16,
    );
    &[BIP300_XYZ]
};

const fn seed_node_addrs(
    network: Network,
    tor_proxy_mode: bool,
) -> &'static [SocketAddr] {
    if tor_proxy_mode {
        return &[];
    }
    match network {
        Network::Signet => SIGNET_SEED_NODE_ADDRS,
        Network::Regtest => &[],
        Network::Forknet => FORKNET_SEED_NODE_ADDRS,
    }
}

fn loopback_addr(addr: SocketAddr) -> SocketAddr {
    let ip = match addr.ip() {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::LOCALHOST),
    };
    SocketAddr::new(ip, addr.port())
}

fn peer_address_allowed(tor_proxy_mode: bool, addr: SocketAddr) -> bool {
    !tor_proxy_mode || addr.ip().is_loopback()
}

fn is_connected_tunnel_peer(
    tor_proxy_mode: bool,
    addr: SocketAddr,
    status: PeerConnectionStatus,
) -> bool {
    tor_proxy_mode
        && addr.ip().is_loopback()
        && status == PeerConnectionStatus::Connected
}

fn validate_peer_address(
    tor_proxy_mode: bool,
    addr: SocketAddr,
) -> Result<(), Error> {
    if addr.ip().is_unspecified() {
        return Err(Error::UnspecfiedPeerIP(addr.ip()));
    }
    if !peer_address_allowed(tor_proxy_mode, addr) {
        return Err(Error::NonLoopbackPeerInTorProxyMode(addr));
    }
    Ok(())
}

fn queue_transaction_to_peers(
    active_peers: &HashMap<SocketAddr, PeerConnectionHandle>,
    tor_proxy_mode: bool,
    exclude: &HashSet<SocketAddr>,
    tx: &AuthorizedTransaction,
) -> usize {
    let mut queued_peers = 0;
    for (addr, peer_connection_handle) in active_peers {
        if exclude.contains(addr)
            || !peer_address_allowed(tor_proxy_mode, *addr)
        {
            continue;
        }
        match peer_connection_handle.connection_status() {
            PeerConnectionStatus::Connecting => {
                tracing::trace!(%addr, "skipping peer at {addr} because it is not fully connected");
                continue;
            }
            PeerConnectionStatus::Connected => {}
        }
        let request: PeerRequest = peer::message::PushTransactionRequest {
            transaction: tx.clone(),
        }
        .into();
        if peer_connection_handle
            .internal_message_tx
            .unbounded_send(request.into())
            .is_ok()
        {
            queued_peers += 1;
        } else {
            let txid = tx.transaction.txid();
            tracing::warn!("Failed to push tx {txid} to peer at {addr}")
        }
    }
    queued_peers
}

// Keep track of peer state
// Exchange metadata
// Bulk download
// Propagation
//
// Initial block download
//
// 1. Download headers
// 2. Download blocks
// 3. Update the state
#[derive(Clone)]
pub struct Net {
    pub server: Endpoint,
    archive: Archive,
    network: Network,
    state: State,
    active_peers: Arc<RwLock<HashMap<SocketAddr, PeerConnectionHandle>>>,
    // None indicates that the stream has ended
    peer_info_tx:
        mpsc::UnboundedSender<(SocketAddr, Option<PeerConnectionInfo>)>,
    known_peers: DatabaseUnique<SerdeBincode<SocketAddr>, Unit>,
    tor_proxy_mode: bool,
    _version: DatabaseUnique<UnitKey, SerdeBincode<Version>>,
}

impl Net {
    pub const NUM_DBS: u32 = 2;

    fn add_active_peer(
        &self,
        addr: SocketAddr,
        peer_connection_handle: PeerConnectionHandle,
    ) -> Result<(), error::AlreadyConnected> {
        tracing::trace!(%addr, "adding to active peers");
        let mut active_peers_write = self.active_peers.write();
        match active_peers_write.entry(addr) {
            hash_map::Entry::Occupied(_) => {
                tracing::error!(%addr, "already connected");
                Err(error::AlreadyConnected(addr))
            }
            hash_map::Entry::Vacant(active_peer_entry) => {
                active_peer_entry.insert(peer_connection_handle);
                Ok(())
            }
        }
    }

    pub fn remove_active_peer(&self, addr: SocketAddr) {
        tracing::trace!(%addr, "removing active peer");
        let mut active_peers_write = self.active_peers.write();
        if let Some(peer_connection) = active_peers_write.remove(&addr) {
            drop(peer_connection);
            tracing::info!(%addr, "disconnected");
        }
    }

    /// Apply the provided function to the peer connection handle,
    /// if it exists.
    pub fn try_with_active_peer_connection<F, T>(
        &self,
        addr: SocketAddr,
        f: F,
    ) -> Option<T>
    where
        F: FnMut(&PeerConnectionHandle) -> T,
    {
        let active_peers_read = self.active_peers.read();
        active_peers_read.get(&addr).map(f)
    }

    // TODO: This should have more context.
    // Last received message, connection state, etc.
    pub fn get_active_peers(&self) -> Vec<Peer> {
        self.active_peers
            .read()
            .iter()
            .map(|(addr, conn_handle)| Peer {
                address: *addr,
                status: conn_handle.connection_status(),
            })
            .collect()
    }

    pub fn tor_proxy_status(&self) -> TorProxyStatus {
        let connected_tunnel_peers = self
            .active_peers
            .read()
            .iter()
            .filter(|(addr, connection)| {
                is_connected_tunnel_peer(
                    self.tor_proxy_mode,
                    **addr,
                    connection.connection_status(),
                )
            })
            .count()
            .try_into()
            .unwrap_or(u32::MAX);
        TorProxyStatus {
            tor_proxy_mode: self.tor_proxy_mode,
            connected_tunnel_peers,
        }
    }

    #[instrument(skip_all, fields(addr), err(Debug))]
    pub fn connect_peer(
        &self,
        env: sneed::Env<heed::WithoutTls>,
        addr: SocketAddr,
    ) -> Result<(), Error> {
        // Reconnects and manual RPC connections both flow through this check.
        validate_peer_address(self.tor_proxy_mode, addr)?;
        if self.active_peers.read().contains_key(&addr) {
            tracing::error!("already connected");
            return Err(error::AlreadyConnected(addr).into());
        }
        let connecting = self.server.connect(addr, "localhost")?;
        let mut rwtxn = env.write_txn().map_err(EnvError::from)?;
        self.known_peers
            .put(&mut rwtxn, &addr, &())
            .map_err(DbError::from)?;
        rwtxn.commit().map_err(RwTxnError::from)?;
        let connection_ctxt = PeerConnectionCtxt {
            env,
            archive: self.archive.clone(),
            network: self.network,
            state: self.state.clone(),
        };
        let (connection_handle, info_rx) =
            peer::connect(connecting, connection_ctxt);
        tracing::trace!("spawning info rx");
        tokio::spawn({
            let info_rx = StreamNotifyClose::new(info_rx)
                .map(move |info| Ok((addr, info)));
            let peer_info_tx = self.peer_info_tx.clone();
            async move {
                if let Err(_send_err) = info_rx.forward(peer_info_tx).await {
                    tracing::error!("Failed to send peer connection info");
                }
            }
        });
        tracing::trace!("adding to active peers");
        self.add_active_peer(addr, connection_handle)?;
        Ok(())
    }

    /// Delete peer from known_peers DB.
    /// Connections to the peer are not terminated.
    pub fn forget_peer(
        &self,
        rwtxn: &mut RwTxn,
        addr: &SocketAddr,
    ) -> Result<bool, Error> {
        self.known_peers
            .delete(rwtxn, addr)
            .map_err(|err| DbError::from(err).into())
    }

    pub fn new(
        env: &sneed::Env<heed::WithoutTls>,
        archive: Archive,
        network: Network,
        state: State,
        bind_addr: SocketAddr,
        tor_proxy_mode: bool,
    ) -> Result<(Self, PeerInfoRx), Error> {
        let bind_addr = if tor_proxy_mode {
            loopback_addr(bind_addr)
        } else {
            bind_addr
        };
        let (server, _) = make_server_endpoint(bind_addr)?;
        let active_peers = Arc::new(RwLock::new(HashMap::new()));
        let mut rwtxn = env.write_txn()?;
        let known_peers =
            match DatabaseUnique::open(env, &rwtxn, "known_peers")? {
                Some(known_peers) => known_peers,
                None => {
                    let known_peers =
                        DatabaseUnique::create(env, &mut rwtxn, "known_peers")?;
                    for seed_node_addr in
                        seed_node_addrs(network, tor_proxy_mode)
                    {
                        known_peers.put(&mut rwtxn, seed_node_addr, &())?;
                    }
                    known_peers
                }
            };
        let version = DatabaseUnique::create(env, &mut rwtxn, "net_version")?;
        if version.try_get(&rwtxn, &())?.is_none() {
            version.put(&mut rwtxn, &(), &*VERSION)?;
        }
        rwtxn.commit()?;
        let (peer_info_tx, peer_info_rx) = mpsc::unbounded();
        let net = Net {
            server,
            archive,
            network,
            state,
            active_peers,
            peer_info_tx,
            known_peers,
            tor_proxy_mode,
            _version: version,
        };
        #[allow(clippy::let_and_return)]
        let known_peers: Vec<_> = {
            let rotxn = env.read_txn().map_err(EnvError::from)?;
            let known_peers = net
                .known_peers
                .iter(&rotxn)
                .map_err(DbError::from)?
                .filter(|(peer_addr, _)| {
                    let allowed =
                        peer_address_allowed(tor_proxy_mode, *peer_addr);
                    if !allowed {
                        tracing::info!(
                            %peer_addr,
                            "ignoring persisted direct peer in Tor proxy mode"
                        );
                    }
                    Ok(allowed)
                })
                .collect()
                .map_err(DbError::from)?;
            known_peers
        };
        let () = known_peers.into_iter().try_for_each(|(peer_addr, _)| {
            tracing::trace!(%peer_addr, "connecting to already known peer");
            match net.connect_peer(env.clone(), peer_addr) {
                Err(Error::Connect(
                    quinn::ConnectError::InvalidRemoteAddress(addr),
                )) => {
                    tracing::warn!(
                        %addr, "new net: known peer with invalid remote address, removing"
                    );
                    let mut rwtxn = env.write_txn()?;
                    net.known_peers.delete(&mut rwtxn, &peer_addr).map_err(DbError::from)?;
                    rwtxn.commit()?;
                    tracing::info!(
                        %addr,
                        "new net: removed known peer with invalid remote address"
                    );
                    Ok(())
                }
                res => res,
            }
        })
        // TODO: would be better to indicate this in the return error?
        .inspect_err(|err| {
            tracing::error!("unable to connect to known peers during net construction: {err:#}");
        })?;
        Ok((net, peer_info_rx))
    }

    /// Accept the next incoming connection. Returns Some(addr) if a connection was accepted
    /// and a new peer was added.
    pub async fn accept_incoming(
        &self,
        env: sneed::Env<heed::WithoutTls>,
    ) -> Result<Option<SocketAddr>, error::AcceptConnection> {
        tracing::debug!(
            "listening for connections on `{}`",
            self.server
                .local_addr()
                .map(|socket| socket.to_string())
                .unwrap_or("unknown address".into())
        );
        let connection = match self.server.accept().await {
            Some(conn) => {
                let remote_address = conn.remote_address();
                tracing::trace!(%remote_address, "accepting connection");
                let raw_conn = conn.await.map_err(|error| {
                    error::AcceptConnection::Connection {
                        error,
                        remote_address,
                    }
                })?;
                Connection::new(raw_conn, self.network)
            }
            None => {
                tracing::debug!("server endpoint closed");
                return Err(error::AcceptConnection::ServerEndpointClosed);
            }
        };
        let addr = connection.addr();
        tracing::trace!(%addr, "accepted incoming connection");
        if !self.peer_address_allowed(addr) {
            tracing::warn!(
                %addr,
                "refusing non-loopback connection in Tor proxy mode"
            );
            connection
                .inner
                .close(quinn::VarInt::from_u32(2), b"direct peer forbidden");
            return Ok(None);
        }
        if self.active_peers.read().contains_key(&addr) {
            tracing::info!(
                %addr, "already peered, refusing duplicate",
            );
            connection
                .inner
                .close(quinn::VarInt::from_u32(1), b"already connected");
        }
        if connection.inner.close_reason().is_some() {
            return Ok(None);
        }
        tracing::info!(%addr, "connected to new peer");
        let mut rwtxn = env.write_txn().map_err(EnvError::from)?;
        self.known_peers
            .put(&mut rwtxn, &addr, &())
            .map_err(DbError::from)?;
        rwtxn.commit().map_err(RwTxnError::from)?;
        tracing::trace!(%addr, "wrote peer to database");
        let connection_ctxt = PeerConnectionCtxt {
            env,
            archive: self.archive.clone(),
            network: self.network,
            state: self.state.clone(),
        };
        let (connection_handle, info_rx) =
            peer::handle(connection_ctxt, connection);
        tokio::spawn({
            let info_rx = StreamNotifyClose::new(info_rx)
                .map(move |info| Ok((addr, info)));
            let peer_info_tx = self.peer_info_tx.clone();
            async move {
                if let Err(_send_err) = info_rx.forward(peer_info_tx).await {
                    tracing::error!(%addr, "Failed to send peer connection info");
                }
            }
        });
        // TODO: is this the right state?
        self.add_active_peer(addr, connection_handle)?;
        Ok(Some(addr))
    }

    pub(crate) fn peer_address_allowed(&self, addr: SocketAddr) -> bool {
        peer_address_allowed(self.tor_proxy_mode, addr)
    }

    /// Attempt to push an internal message to the specified peer
    /// Returns `true` if successful
    pub fn push_internal_message(
        &self,
        message: PeerConnectionMessage,
        addr: SocketAddr,
    ) -> bool {
        let active_peers_read = self.active_peers.read();
        let Some(peer_connection_handle) = active_peers_read.get(&addr) else {
            let err = Error::MissingPeerConnection(addr);
            tracing::warn!("{:#}", anyhow::Error::from(err));
            return false;
        };

        if let Err(send_err) = peer_connection_handle
            .internal_message_tx
            .unbounded_send(message)
        {
            let message = send_err.into_inner();
            tracing::warn!(
                "Failed to push internal message to peer connection {addr}: {message:?}"
            );
            return false;
        }
        true
    }

    /// Push a tx to all active peers, except those in the provided set
    #[must_use]
    pub fn push_tx(
        &self,
        exclude: HashSet<SocketAddr>,
        tx: AuthorizedTransaction,
    ) -> usize {
        let active_peers = self.active_peers.read();
        queue_transaction_to_peers(
            &active_peers,
            self.tor_proxy_mode,
            &exclude,
            &tx,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tor_proxy_mode_forces_bind_address_to_loopback() {
        assert_eq!(
            loopback_addr("0.0.0.0:4002".parse().unwrap()),
            "127.0.0.1:4002".parse().unwrap()
        );
        assert_eq!(
            loopback_addr("[2001:db8::1]:4102".parse().unwrap()),
            "[::1]:4102".parse().unwrap()
        );
    }

    #[test]
    fn tor_proxy_mode_disables_seed_peers() {
        assert!(seed_node_addrs(Network::Signet, true).is_empty());
        assert!(!seed_node_addrs(Network::Signet, false).is_empty());
    }

    #[test]
    fn tor_proxy_mode_rejects_direct_peer_addresses() {
        let addr = "192.0.2.1:4002".parse().unwrap();
        assert!(matches!(
            validate_peer_address(true, addr),
            Err(Error::NonLoopbackPeerInTorProxyMode(rejected))
                if rejected == addr
        ));
    }

    #[test]
    fn tor_proxy_mode_filters_persisted_direct_peers() {
        let persisted = [
            "127.0.0.1:4002".parse().unwrap(),
            "192.0.2.1:4002".parse().unwrap(),
            "[::1]:4002".parse().unwrap(),
            "[2001:db8::1]:4002".parse().unwrap(),
        ];
        let filtered: Vec<_> = persisted
            .into_iter()
            .filter(|addr| peer_address_allowed(true, *addr))
            .collect();

        assert_eq!(
            filtered,
            [
                "127.0.0.1:4002".parse().unwrap(),
                "[::1]:4002".parse().unwrap(),
            ]
        );
    }

    #[test]
    fn tor_proxy_mode_allows_loopback_udp_tunnel_peers() {
        for addr in ["127.0.0.1:4002", "[::1]:4002"] {
            assert!(validate_peer_address(true, addr.parse().unwrap()).is_ok());
        }
    }

    #[test]
    fn tor_proxy_status_requires_a_connected_tunnel_for_submission() {
        let ready = TorProxyStatus {
            tor_proxy_mode: true,
            connected_tunnel_peers: 1,
        };
        assert!(
            TorProxyStatus {
                tor_proxy_mode: false,
                connected_tunnel_peers: 0,
            }
            .allows_transaction_submission()
        );
        assert!(
            !TorProxyStatus {
                tor_proxy_mode: true,
                connected_tunnel_peers: 0,
            }
            .allows_transaction_submission()
        );
        assert!(ready.allows_transaction_submission());
        assert_eq!(
            serde_json::to_value(ready).unwrap(),
            serde_json::json!({
                "tor_proxy_mode": true,
                "connected_tunnel_peers": 1,
            })
        );
    }

    #[test]
    fn only_connected_loopback_peers_count_as_tunnels() {
        let loopback = "127.0.0.1:4002".parse().unwrap();
        let direct = "192.0.2.1:4002".parse().unwrap();

        assert!(is_connected_tunnel_peer(
            true,
            loopback,
            PeerConnectionStatus::Connected
        ));
        assert!(!is_connected_tunnel_peer(
            true,
            loopback,
            PeerConnectionStatus::Connecting
        ));
        assert!(!is_connected_tunnel_peer(
            true,
            direct,
            PeerConnectionStatus::Connected
        ));
        assert!(!is_connected_tunnel_peer(
            false,
            loopback,
            PeerConnectionStatus::Connected
        ));
    }

    #[test]
    fn queued_peer_count_only_reports_successful_allowed_delivery() {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let transaction = AuthorizedTransaction {
                transaction: crate::types::Transaction::default(),
                authorizations: Vec::new(),
            };
            let loopback = "127.0.0.1:4002".parse().unwrap();

            let (connected, _connected_rx) =
                peer::test_connection_handle(PeerConnectionStatus::Connected);
            let connected_peers = HashMap::from([(loopback, connected)]);
            assert_eq!(
                queue_transaction_to_peers(
                    &connected_peers,
                    true,
                    &HashSet::new(),
                    &transaction,
                ),
                1
            );

            let (closed, closed_rx) =
                peer::test_connection_handle(PeerConnectionStatus::Connected);
            drop(closed_rx);
            let closed_peers = HashMap::from([(loopback, closed)]);
            assert_eq!(
                queue_transaction_to_peers(
                    &closed_peers,
                    true,
                    &HashSet::new(),
                    &transaction,
                ),
                0
            );

            let direct = "192.0.2.1:4002".parse().unwrap();
            let (direct_peer, _direct_rx) =
                peer::test_connection_handle(PeerConnectionStatus::Connected);
            assert_eq!(
                queue_transaction_to_peers(
                    &HashMap::from([(direct, direct_peer)]),
                    false,
                    &HashSet::new(),
                    &transaction,
                ),
                1
            );
        });
    }

    #[test]
    fn direct_mode_still_allows_non_loopback_peers() {
        let addr = "192.0.2.1:4002".parse().unwrap();
        assert!(validate_peer_address(false, addr).is_ok());
    }
}
