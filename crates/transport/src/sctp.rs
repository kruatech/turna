//! TURN-over-SCTP transport server (client CONTROL transport).
//!
//! SCOPE / HONESTY: no TURN RFC defines SCTP as a *relayed* transport. This is a
//! client↔server **control** transport only — STUN/TURN messages carried over an
//! SCTP association, framed with the exact same self-delimiting codec as
//! TURN-over-TCP ([`crate::tcp_tls::TcpFrameCodec`]). The relay socket to the peer
//! stays UDP (handled by the relay bridge/egress, not here).
//!
//! DESIGN: uses **one-to-one SCTP** (`SOCK_STREAM` + `IPPROTO_SCTP`), whose
//! `listen`/`accept`/`recv`/`send` semantics mirror TCP — so this module is a
//! faithful structural mirror of [`crate::tcp_tls`], minus the TLS layer (the SCTP
//! control channel here is plaintext; TLS-over-SCTP / DTLS is out of scope).
//!
//! It reuses the transport-agnostic types from `tcp_tls`
//! ([`TcpConnectionId`], [`TcpTransportEvent`], [`TcpSendCommand`],
//! [`TcpFrameCodec`]), so the relay-side `sctp_bridge` needs no new event types.
//! Therefore `feature = "sctp"` must also enable `feature = "tls"` (for those
//! shared types) — see Cargo notes in the delivery.
//!
//! REQUIREMENTS: Linux with the `sctp` kernel module (lksctp) loaded; the
//! `socket2` crate. Non-Linux targets have no SCTP here.
//!
//! Several socket-level specifics are marked `// VERIFY (on-repo):` — this is the
//! highest-uncertainty module written without a compiler; expect to iterate.

use std::collections::HashMap;
use std::mem::MaybeUninit;
use std::net::SocketAddr;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;

use bytes::BytesMut;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use thiserror::Error;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tracing::{info, instrument, warn};

use crate::tcp_tls::{TcpConnectionId, TcpFrameCodec, TcpSendCommand, TcpTransportEvent, TlsError};

/// IANA protocol number for SCTP (RFC 4960). socket2 may also expose
/// `Protocol::SCTP` on some versions; the numeric form is used to avoid a
/// version dependency. VERIFY (on-repo): `Protocol::from(IPPROTO_SCTP)` compiles
/// with the pinned socket2; if not, use `Protocol::SCTP`.
const IPPROTO_SCTP: i32 = 132;

#[derive(Debug, Error)]
pub enum SctpError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// Framing errors bubble up from the shared TURN-over-stream codec.
    #[error("framing: {0}")]
    Framing(#[from] TlsError),
    #[error("connection closed")]
    Closed,
}

pub type Result<T> = std::result::Result<T, SctpError>;

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct SctpTransportConfig {
    pub listen_addr: SocketAddr,
    pub max_frame_size: usize,
    pub read_timeout: Duration,
    pub max_connections: usize,
    /// listen(2) backlog for the SCTP one-to-one listener.
    pub backlog: i32,
}

impl Default for SctpTransportConfig {
    fn default() -> Self {
        Self {
            // No standardized TURN-over-SCTP port; operator-configured. 3478 is the
            // STUN/TURN default and is reused here for familiarity only.
            listen_addr: "0.0.0.0:3478".parse().unwrap(),
            max_frame_size: 64 * 1024,
            read_timeout: Duration::from_secs(300),
            max_connections: 10_000,
            backlog: 1024,
        }
    }
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

pub struct SctpTransportServer {
    config: SctpTransportConfig,
    conn_counter: Arc<AtomicU64>,
}

impl SctpTransportServer {
    pub fn new(config: SctpTransportConfig) -> Result<Self> {
        Ok(Self {
            config,
            conn_counter: Arc::new(AtomicU64::new(0)),
        })
    }

    /// Bind the SCTP one-to-one listener. Mirrors `TcpListener::bind` but built
    /// from a raw `socket2` socket with `IPPROTO_SCTP`.
    fn bind_listener(&self) -> Result<AsyncFd<Socket>> {
        let domain = if self.config.listen_addr.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };
        // VERIFY (on-repo): SCTP one-to-one is SOCK_STREAM + IPPROTO_SCTP.
        let sock = Socket::new(domain, Type::STREAM, Some(Protocol::from(IPPROTO_SCTP)))?;
        sock.set_reuse_address(true)?;
        sock.set_nonblocking(true)?;
        sock.bind(&SockAddr::from(self.config.listen_addr))?;
        sock.listen(self.config.backlog)?;
        Ok(AsyncFd::new(sock)?)
    }

    pub async fn run(
        self,
        event_tx: mpsc::Sender<TcpTransportEvent>,
        mut send_rx: mpsc::Receiver<TcpSendCommand>,
    ) -> Result<()> {
        let listener = self.bind_listener()?;
        info!(
            addr = %self.config.listen_addr,
            max = self.config.max_connections,
            "TURN-over-SCTP listening"
        );

        // conn_id -> per-connection writer channel (same pattern as tcp_tls).
        let conns: Arc<tokio::sync::RwLock<HashMap<TcpConnectionId, mpsc::Sender<Vec<u8>>>>> =
            Arc::new(tokio::sync::RwLock::new(HashMap::new()));

        let conns_send = conns.clone();
        tokio::spawn(async move {
            while let Some(cmd) = send_rx.recv().await {
                let c = conns_send.read().await;
                if let Some(tx) = c.get(&cmd.conn_id) {
                    let _ = tx.try_send(cmd.data);
                }
            }
        });

        loop {
            // Async accept over the raw fd. `try_io` returning Err clears readiness
            // and we loop to await the next readable edge.
            let (stream, sockaddr) = {
                let mut guard = listener.readable().await?;
                match guard.try_io(|inner| inner.get_ref().accept()) {
                    Ok(Ok(pair)) => pair,
                    Ok(Err(e)) => return Err(SctpError::Io(e)),
                    Err(_would_block) => continue,
                }
            };
            let peer: SocketAddr = match sockaddr.as_socket() {
                Some(a) => a,
                None => {
                    warn!("SCTP accept: non-IP peer address; dropping");
                    continue;
                }
            };

            {
                let c = conns.read().await;
                if c.len() >= self.config.max_connections {
                    warn!(%peer, "SCTP connection limit reached");
                    continue;
                }
            }

            let conn_id = TcpConnectionId::next(&self.conn_counter);
            let (conn_tx, conn_rx) = mpsc::channel::<Vec<u8>>(256);
            conns.write().await.insert(conn_id, conn_tx);

            let etx = event_tx.clone();
            let cfg = self.config.clone();
            let conns2 = conns.clone();

            tokio::spawn(async move {
                let reason =
                    match handle_conn(conn_id, stream, peer, &cfg, etx.clone(), conn_rx).await {
                        Ok(()) => "clean close".to_string(),
                        Err(e) => format!("{e}"),
                    };
                conns2.write().await.remove(&conn_id);
                let _ = etx
                    .send(TcpTransportEvent::ConnectionClosed {
                        conn_id,
                        peer_addr: peer,
                        reason,
                    })
                    .await;
            });
        }
    }
}

/// Async recv one chunk into `buf`. Returns bytes read (0 = peer closed).
async fn recv_chunk(afd: &AsyncFd<Socket>, buf: &mut BytesMut) -> std::io::Result<usize> {
    loop {
        let mut guard = afd.readable().await?;
        // VERIFY (on-repo): socket2 `recv` takes `&mut [MaybeUninit<u8>]`.
        let mut tmp: [MaybeUninit<u8>; 65536] = [MaybeUninit::uninit(); 65536];
        match guard.try_io(|inner| inner.get_ref().recv(&mut tmp)) {
            Ok(Ok(0)) => return Ok(0),
            Ok(Ok(n)) => {
                // SAFETY: `recv` reported `n` initialized bytes at the front.
                let filled = unsafe { std::slice::from_raw_parts(tmp.as_ptr() as *const u8, n) };
                buf.extend_from_slice(filled);
                return Ok(n);
            }
            Ok(Err(e)) => return Err(e),
            Err(_would_block) => continue,
        }
    }
}

/// Async write all of `data` (already framed) to the SCTP association.
async fn send_all(afd: &AsyncFd<Socket>, mut data: &[u8]) -> std::io::Result<()> {
    while !data.is_empty() {
        let mut guard = afd.writable().await?;
        match guard.try_io(|inner| inner.get_ref().send(data)) {
            Ok(Ok(0)) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "SCTP send returned 0",
                ))
            }
            Ok(Ok(n)) => data = &data[n..],
            Ok(Err(e)) => return Err(e),
            Err(_would_block) => continue,
        }
    }
    Ok(())
}

#[instrument(skip_all, fields(conn = %id, peer = %peer))]
async fn handle_conn(
    id: TcpConnectionId,
    stream: Socket,
    peer: SocketAddr,
    cfg: &SctpTransportConfig,
    etx: mpsc::Sender<TcpTransportEvent>,
    mut send_rx: mpsc::Receiver<Vec<u8>>,
) -> Result<()> {
    stream.set_nonblocking(true)?;
    let afd = AsyncFd::new(stream)?;

    let _ = etx
        .send(TcpTransportEvent::ConnectionOpened {
            conn_id: id,
            peer_addr: peer,
        })
        .await;

    let codec = TcpFrameCodec::new(cfg.max_frame_size);
    let mut buf = BytesMut::with_capacity(8192);

    loop {
        tokio::select! {
            res = timeout(cfg.read_timeout, recv_chunk(&afd, &mut buf)) => {
                match res {
                    Ok(Ok(0)) => return Ok(()),
                    Ok(Ok(_)) => {
                        while let Some(frame) = codec.decode(&mut buf)? {
                            etx.send(TcpTransportEvent::PacketReceived {
                                conn_id: id,
                                peer_addr: peer,
                                data: frame,
                            })
                            .await
                            .map_err(|_| SctpError::Closed)?;
                        }
                    }
                    Ok(Err(e)) => return Err(SctpError::Io(e)),
                    Err(_) => return Ok(()), // idle timeout
                }
            }
            Some(data) = send_rx.recv() => {
                let mut out = BytesMut::with_capacity(data.len());
                codec.encode(&data, &mut out)?;
                send_all(&afd, &out).await?;
            }
            else => break,
        }
    }
    Ok(())
}
