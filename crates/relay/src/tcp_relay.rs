//! TCP Relay для TURN (RFC 6062)
//!
//! Connect → WaitingForBind → ConnectionBind → Bound (bidirectional proxy) → Close
//!
//! Нужен клиентам за firewall, блокирующим UDP relay.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use thiserror::Error;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use tokio::time::timeout;
use tracing::{debug, info, warn};

// ---------------------------------------------------------------------------
// Constants (RFC 6062)
// ---------------------------------------------------------------------------

pub mod stun_method {
    pub const CONNECT: u16 = 0x000A;
    pub const CONNECTION_BIND: u16 = 0x000B;
    pub const CONNECTION_ATTEMPT: u16 = 0x000C;
}

pub mod stun_attr {
    pub const CONNECTION_ID: u16 = 0x002A;
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum TcpRelayError {
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("allocation not found for {0}")]
    AllocationNotFound(SocketAddr),
    #[error("connection {0} not found")]
    ConnectionNotFound(u32),
    #[error("connection to {addr} exists (id={id})")]
    AlreadyExists { addr: SocketAddr, id: u32 },
    #[error("connect to {addr} timeout ({timeout:?})")]
    ConnectTimeout { addr: SocketAddr, timeout: Duration },
    #[error("connection {0} already bound")]
    AlreadyBound(u32),
    #[error("connection {0} not owned by this client")]
    Unauthorized(u32),
    #[error("max connections reached ({0})")]
    MaxConnections(usize),
}

pub type Result<T> = std::result::Result<T, TcpRelayError>;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TcpConnectionId(u32);

impl TcpConnectionId {
    pub fn value(&self) -> u32 {
        self.0
    }
    pub fn from_raw(v: u32) -> Self {
        Self(v)
    }
    pub fn to_bytes(&self) -> [u8; 4] {
        self.0.to_be_bytes()
    }
    pub fn from_bytes(b: &[u8; 4]) -> Self {
        Self(u32::from_be_bytes(*b))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AllocationId(pub u64);

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct TcpRelayConfig {
    pub connect_timeout: Duration,
    pub idle_timeout: Duration,
    pub max_per_allocation: usize,
    pub max_total: usize,
    pub buffer_size: usize,
}

impl Default for TcpRelayConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(30),
            max_per_allocation: 10,
            max_total: 50_000,
            buffer_size: 16384,
        }
    }
}

// ---------------------------------------------------------------------------
// State Machine
// ---------------------------------------------------------------------------

enum ConnState {
    WaitingForBind {
        stream: TcpStream,
        peer: SocketAddr,
        alloc: AllocationId,
        /// Authenticated credential (long-term key) of the client whose CONNECT
        /// opened this peer connection. A ConnectionBind must present the same
        /// identity to claim it (RFC 6062 §4.4 ownership).
        owner: Vec<u8>,
    },
    /// Claimed by a ConnectionBind (success not yet sent / stream not yet
    /// attached). Holds the peer stream until the client data connection is
    /// handed over.
    Claimed {
        stream: TcpStream,
        peer: SocketAddr,
        alloc: AllocationId,
    },
    Bound {
        alloc: AllocationId,
    },
}

// ---------------------------------------------------------------------------
// Manager
// ---------------------------------------------------------------------------

pub struct TcpRelayManager {
    config: TcpRelayConfig,
    conns: Arc<RwLock<HashMap<TcpConnectionId, ConnState>>>,
    alloc_peers: Arc<RwLock<HashMap<(AllocationId, SocketAddr), TcpConnectionId>>>,
    counter: Arc<std::sync::atomic::AtomicU32>,
}

impl TcpRelayManager {
    pub fn new(config: TcpRelayConfig) -> Self {
        Self {
            config,
            conns: Arc::new(RwLock::new(HashMap::new())),
            alloc_peers: Arc::new(RwLock::new(HashMap::new())),
            counter: Arc::new(std::sync::atomic::AtomicU32::new(1)),
        }
    }

    fn next_id(&self) -> TcpConnectionId {
        TcpConnectionId(
            self.counter
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        )
    }

    /// Connect (RFC 6062 §4.3): устанавливает TCP к peer, возвращает CONNECTION-ID.
    pub async fn handle_connect(
        &self,
        alloc: AllocationId,
        peer: SocketAddr,
        owner: Vec<u8>,
    ) -> Result<TcpConnectionId> {
        // Проверяем лимит
        if self.conns.read().await.len() >= self.config.max_total {
            return Err(TcpRelayError::MaxConnections(self.config.max_total));
        }
        // Проверяем дубликат
        if let Some(&id) = self.alloc_peers.read().await.get(&(alloc, peer)) {
            return Err(TcpRelayError::AlreadyExists {
                addr: peer,
                id: id.0,
            });
        }

        let stream = timeout(self.config.connect_timeout, TcpStream::connect(peer))
            .await
            .map_err(|_| TcpRelayError::ConnectTimeout {
                addr: peer,
                timeout: self.config.connect_timeout,
            })?
            .map_err(TcpRelayError::Io)?;

        let id = self.next_id();
        self.conns.write().await.insert(
            id,
            ConnState::WaitingForBind {
                stream,
                peer,
                alloc,
                owner,
            },
        );
        self.alloc_peers.write().await.insert((alloc, peer), id);

        info!(conn = id.0, %peer, "TCP to peer established, awaiting ConnectionBind");
        self.spawn_idle_timeout(id);
        Ok(id)
    }

    /// RFC 6062 §4.4 peer-initiated: register an already-accepted peer TCP
    /// connection (the relayed listener accepted it) as pending, minting a
    /// CONNECTION-ID. Mirrors [`handle_connect`], but the stream is supplied
    /// rather than dialed. `owner` is the allocation's long-term key, so the
    /// client's later ConnectionBind is ownership-checked in [`claim`] (O#1).
    pub async fn register_incoming(
        &self,
        alloc: AllocationId,
        peer: SocketAddr,
        stream: TcpStream,
        owner: Vec<u8>,
    ) -> Result<TcpConnectionId> {
        if self.conns.read().await.len() >= self.config.max_total {
            return Err(TcpRelayError::MaxConnections(self.config.max_total));
        }
        if let Some(&id) = self.alloc_peers.read().await.get(&(alloc, peer)) {
            return Err(TcpRelayError::AlreadyExists {
                addr: peer,
                id: id.0,
            });
        }
        let id = self.next_id();
        self.conns.write().await.insert(
            id,
            ConnState::WaitingForBind {
                stream,
                peer,
                alloc,
                owner,
            },
        );
        self.alloc_peers.write().await.insert((alloc, peer), id);
        info!(conn = id.0, %peer, "TCP peer connection accepted (peer-initiated), awaiting ConnectionBind");
        self.spawn_idle_timeout(id);
        Ok(id)
    }

    /// RFC 6062 §4.4 phase 1 — atomically claim a pending peer connection for a
    /// ConnectionBind, BEFORE the success is sent. `WaitingForBind` → `Claimed`;
    /// a repeat claim or unknown id is rejected so the bridge answers 400 rather
    /// than detaching a client stream with no peer to relay to.
    pub async fn claim(&self, id: TcpConnectionId, owner: &[u8]) -> Result<()> {
        let mut c = self.conns.write().await;
        match c.remove(&id) {
            Some(ConnState::WaitingForBind {
                stream,
                peer,
                alloc,
                owner: o,
            }) => {
                // RFC 6062 §4.4 ownership (O#1): `connection_id` is a guessable
                // sequential value, so a ConnectionBind must be authenticated with
                // the SAME credentials as the CONNECT that opened this peer
                // connection — otherwise any authenticated client could hijack
                // another's pending connection. On mismatch, put the state back and
                // report as not-found so the caller cannot use this as an oracle.
                if o != owner {
                    warn!(conn = id.0, "ConnectionBind ownership mismatch — rejected");
                    c.insert(
                        id,
                        ConnState::WaitingForBind {
                            stream,
                            peer,
                            alloc,
                            owner: o,
                        },
                    );
                    return Err(TcpRelayError::Unauthorized(id.0));
                }
                // Ownership verified above; the peer connection no longer needs
                // to carry the owner into the Claimed state.
                let _ = o;
                c.insert(
                    id,
                    ConnState::Claimed {
                        stream,
                        peer,
                        alloc,
                    },
                );
                Ok(())
            }
            Some(other) => {
                c.insert(id, other);
                Err(TcpRelayError::AlreadyBound(id.0))
            }
            None => Err(TcpRelayError::ConnectionNotFound(id.0)),
        }
    }

    /// Remove any state for `id` and its `alloc_peers` mapping — used to roll a
    /// claim back when the detach handoff to the transport could not be delivered
    /// (O#2), so a `Claimed` connection that will never relay does not leak.
    /// Idempotent; a `Bound` (live relay) is left untouched.
    pub async fn release(&self, id: TcpConnectionId) {
        let removed = self.conns.write().await.remove(&id);
        match removed {
            Some(ConnState::WaitingForBind { alloc, peer, .. })
            | Some(ConnState::Claimed { alloc, peer, .. }) => {
                self.alloc_peers.write().await.remove(&(alloc, peer));
            }
            Some(other) => {
                // Bound (already relaying) — do not tear a live relay down here.
                self.conns.write().await.insert(id, other);
            }
            None => {}
        }
    }

    /// RFC 6062 §4.4 phase 2 — attach the (now raw) client data connection to its
    /// claimed peer connection and start relaying. `Claimed` → `Bound`. Generic
    /// over the client stream, so a detached TLS stream or a plaintext TCP stream
    /// both work.
    pub async fn attach_bound<S>(&self, id: TcpConnectionId, client: S) -> Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let (peer_stream, peer, alloc) = {
            let mut c = self.conns.write().await;
            match c.remove(&id) {
                Some(ConnState::Claimed {
                    stream,
                    peer,
                    alloc,
                }) => (stream, peer, alloc),
                Some(other) => {
                    c.insert(id, other);
                    return Err(TcpRelayError::AlreadyBound(id.0));
                }
                None => return Err(TcpRelayError::ConnectionNotFound(id.0)),
            }
        };

        self.conns
            .write()
            .await
            .insert(id, ConnState::Bound { alloc });
        info!(conn = id.0, "ConnectionBind attached, relaying");

        let buf_sz = self.config.buffer_size;
        let conns = self.conns.clone();
        let ap = self.alloc_peers.clone();

        tokio::spawn(async move {
            let (c2p, p2c) = bidirectional_relay(client, peer_stream, buf_sz).await;
            debug!(conn = id.0, c2p, p2c, "relay done");
            conns.write().await.remove(&id);
            ap.write().await.remove(&(alloc, peer));
        });

        Ok(())
    }

    /// Чистим все соединения аллокации при её удалении.
    pub async fn cleanup_allocation(&self, alloc: AllocationId) {
        let ids: Vec<TcpConnectionId> = {
            let c = self.conns.read().await;
            c.iter()
                .filter_map(|(&id, s)| match s {
                    ConnState::WaitingForBind { alloc: a, .. }
                    | ConnState::Claimed { alloc: a, .. }
                    | ConnState::Bound { alloc: a, .. }
                        if *a == alloc =>
                    {
                        Some(id)
                    }
                    _ => None,
                })
                .collect()
        };
        if !ids.is_empty() {
            let mut c = self.conns.write().await;
            for id in &ids {
                c.remove(id);
            }
            info!(
                alloc = alloc.0,
                n = ids.len(),
                "cleaned TCP relay connections"
            );
        }
    }

    pub async fn active_count(&self) -> usize {
        self.conns.read().await.len()
    }

    fn spawn_idle_timeout(&self, id: TcpConnectionId) {
        let t = self.config.idle_timeout;
        let conns = self.conns.clone();
        let ap = self.alloc_peers.clone();
        tokio::spawn(async move {
            tokio::time::sleep(t).await;
            let mut c = conns.write().await;
            // Reap a connection still awaiting its ConnectionBind, OR one stuck in
            // Claimed (claimed but never attached — e.g. a lost detach handoff),
            // but never a live Bound relay (O#2 defence-in-depth).
            match c.remove(&id) {
                Some(ConnState::WaitingForBind { alloc, peer, .. })
                | Some(ConnState::Claimed { alloc, peer, .. }) => {
                    ap.write().await.remove(&(alloc, peer));
                    warn!(conn = id.0, "idle timeout, removed");
                }
                Some(other) => {
                    c.insert(id, other);
                }
                None => {}
            }
        });
    }
}

async fn bidirectional_relay<C, P>(client: C, peer: P, buf_sz: usize) -> (u64, u64)
where
    C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    P: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut cr, mut cw) = tokio::io::split(client);
    let (mut pr, mut pw) = tokio::io::split(peer);

    let c2p = tokio::spawn(async move {
        let mut buf = vec![0u8; buf_sz];
        let mut total = 0u64;
        loop {
            match cr.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if tokio::io::AsyncWriteExt::write_all(&mut pw, &buf[..n])
                        .await
                        .is_err()
                    {
                        break;
                    }
                    total += n as u64;
                }
            }
        }
        let _ = tokio::io::AsyncWriteExt::shutdown(&mut pw).await;
        total
    });
    let p2c = tokio::spawn(async move {
        let mut buf = vec![0u8; buf_sz];
        let mut total = 0u64;
        loop {
            match pr.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if tokio::io::AsyncWriteExt::write_all(&mut cw, &buf[..n])
                        .await
                        .is_err()
                    {
                        break;
                    }
                    total += n as u64;
                }
            }
        }
        let _ = tokio::io::AsyncWriteExt::shutdown(&mut cw).await;
        total
    });

    (c2p.await.unwrap_or(0), p2c.await.unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_id_serde() {
        let id = TcpConnectionId(0x12345678);
        assert_eq!(TcpConnectionId::from_bytes(&id.to_bytes()), id);
    }

    #[tokio::test]
    async fn manager_empty() {
        let m = TcpRelayManager::new(TcpRelayConfig::default());
        assert_eq!(m.active_count().await, 0);
    }

    #[tokio::test]
    async fn claim_requires_matching_owner() {
        // RFC 6062 §4.4 (O#1): a ConnectionBind may only claim a peer connection
        // whose CONNECT was authenticated with the same credentials.
        let m = TcpRelayManager::new(TcpRelayConfig::default());
        // A real listener to connect to (handle_connect dials the peer).
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let peer = listener.local_addr().unwrap();
        let alloc = AllocationId(40010);
        let owner_a = vec![0xAAu8; 16];
        let id = m
            .handle_connect(alloc, peer, owner_a.clone())
            .await
            .unwrap();

        // A different credential cannot claim it, and the failed claim must not
        // consume the pending connection.
        let owner_b = vec![0xBBu8; 16];
        assert!(
            matches!(
                m.claim(id, &owner_b).await,
                Err(TcpRelayError::Unauthorized(_))
            ),
            "foreign owner must be rejected"
        );
        // The real owner still can.
        assert!(
            m.claim(id, &owner_a).await.is_ok(),
            "owner must be able to claim"
        );
    }

    #[tokio::test]
    async fn release_removes_claimed_connection() {
        // O#2: rolling back a claim (lost detach handoff) must not leak state.
        let m = TcpRelayManager::new(TcpRelayConfig::default());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let peer = listener.local_addr().unwrap();
        let owner = vec![0x11u8; 16];
        let id = m
            .handle_connect(AllocationId(40011), peer, owner.clone())
            .await
            .unwrap();
        m.claim(id, &owner).await.unwrap();
        assert_eq!(m.active_count().await, 1);
        m.release(id).await;
        assert_eq!(
            m.active_count().await,
            0,
            "release must drop the claimed connection"
        );
    }

    #[tokio::test]
    async fn register_incoming_then_owner_claims() {
        // RFC 6062 §4.4 peer-initiated: an accepted peer connection is registered
        // and can only be bound by the allocation owner.
        let m = TcpRelayManager::new(TcpRelayConfig::default());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let jc = tokio::spawn(async move { TcpStream::connect(addr).await.unwrap() });
        let (accepted, peer) = listener.accept().await.unwrap();
        let _client = jc.await.unwrap();

        let owner = vec![0x22u8; 16];
        let id = m
            .register_incoming(AllocationId(40012), peer, accepted, owner.clone())
            .await
            .unwrap();
        assert_eq!(m.active_count().await, 1);
        assert!(
            m.claim(id, &[0x00u8; 16]).await.is_err(),
            "foreign owner rejected"
        );
        assert!(
            m.claim(id, &owner).await.is_ok(),
            "owner binds the peer-initiated conn"
        );
    }
}
