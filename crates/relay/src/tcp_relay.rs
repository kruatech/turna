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
    pub fn value(&self) -> u32 { self.0 }
    pub fn to_bytes(&self) -> [u8; 4] { self.0.to_be_bytes() }
    pub fn from_bytes(b: &[u8; 4]) -> Self { Self(u32::from_be_bytes(*b)) }
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
        created: std::time::Instant,
    },
    Bound { peer: SocketAddr, alloc: AllocationId },
    Closed,
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
        TcpConnectionId(self.counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
    }

    /// Connect (RFC 6062 §4.3): устанавливает TCP к peer, возвращает CONNECTION-ID.
    pub async fn handle_connect(
        &self,
        alloc: AllocationId,
        peer: SocketAddr,
    ) -> Result<TcpConnectionId> {
        // Проверяем лимит
        if self.conns.read().await.len() >= self.config.max_total {
            return Err(TcpRelayError::MaxConnections(self.config.max_total));
        }
        // Проверяем дубликат
        if let Some(&id) = self.alloc_peers.read().await.get(&(alloc, peer)) {
            return Err(TcpRelayError::AlreadyExists { addr: peer, id: id.0 });
        }

        let stream = timeout(self.config.connect_timeout, TcpStream::connect(peer))
            .await
            .map_err(|_| TcpRelayError::ConnectTimeout { addr: peer, timeout: self.config.connect_timeout })?
            .map_err(TcpRelayError::Io)?;

        let id = self.next_id();
        self.conns.write().await.insert(id, ConnState::WaitingForBind {
            stream, peer, alloc, created: std::time::Instant::now(),
        });
        self.alloc_peers.write().await.insert((alloc, peer), id);

        info!(conn = id.0, %peer, "TCP to peer established, awaiting ConnectionBind");
        self.spawn_idle_timeout(id);
        Ok(id)
    }

    /// ConnectionBind (RFC 6062 §4.4): привязывает клиентский TCP к peer'у.
    pub async fn handle_connection_bind(
        &self,
        id: TcpConnectionId,
        client: TcpStream,
    ) -> Result<()> {
        let (peer_stream, peer, alloc) = {
            let mut c = self.conns.write().await;
            match c.remove(&id) {
                Some(ConnState::WaitingForBind { stream, peer, alloc, .. }) => (stream, peer, alloc),
                Some(ConnState::Bound { .. }) => return Err(TcpRelayError::AlreadyBound(id.0)),
                _ => return Err(TcpRelayError::ConnectionNotFound(id.0)),
            }
        };

        self.conns.write().await.insert(id, ConnState::Bound { peer, alloc });
        info!(conn = id.0, "ConnectionBind accepted, relaying");

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
            c.iter().filter_map(|(&id, s)| match s {
                ConnState::WaitingForBind { alloc: a, .. } | ConnState::Bound { alloc: a, .. } if *a == alloc => Some(id),
                _ => None,
            }).collect()
        };
        if !ids.is_empty() {
            let mut c = self.conns.write().await;
            for id in &ids { c.remove(id); }
            info!(alloc = alloc.0, n = ids.len(), "cleaned TCP relay connections");
        }
    }

    pub async fn active_count(&self) -> usize {
        self.conns.read().await.values()
            .filter(|s| !matches!(s, ConnState::Closed))
            .count()
    }

    fn spawn_idle_timeout(&self, id: TcpConnectionId) {
        let t = self.config.idle_timeout;
        let conns = self.conns.clone();
        let ap = self.alloc_peers.clone();
        tokio::spawn(async move {
            tokio::time::sleep(t).await;
            let mut c = conns.write().await;
            if let Some(ConnState::WaitingForBind { alloc, peer, .. }) = c.remove(&id) {
                ap.write().await.remove(&(alloc, peer));
                warn!(conn = id.0, "idle timeout, removed");
            }
        });
    }
}

async fn bidirectional_relay(client: TcpStream, peer: TcpStream, buf_sz: usize) -> (u64, u64) {
    let (mut cr, mut cw) = client.into_split();
    let (mut pr, mut pw) = peer.into_split();

    let c2p = tokio::spawn(async move {
        let mut buf = vec![0u8; buf_sz];
        let mut total = 0u64;
        loop {
            match cr.read(&mut buf).await { Ok(0) | Err(_) => break, Ok(n) => { if tokio::io::AsyncWriteExt::write_all(&mut pw, &buf[..n]).await.is_err() { break; } total += n as u64; } }
        }
        let _ = tokio::io::AsyncWriteExt::shutdown(&mut pw).await;
        total
    });
    let p2c = tokio::spawn(async move {
        let mut buf = vec![0u8; buf_sz];
        let mut total = 0u64;
        loop {
            match pr.read(&mut buf).await { Ok(0) | Err(_) => break, Ok(n) => { if tokio::io::AsyncWriteExt::write_all(&mut cw, &buf[..n]).await.is_err() { break; } total += n as u64; } }
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
}
