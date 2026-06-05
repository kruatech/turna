//! TLS/TCP Transport (TURNS — RFC 5766 over TLS, порт 5349/443)
//!
//! - TLS acceptor на rustls с ALPN "stun.turn"
//! - STUN-over-TCP framing (RFC 4571: 2-byte length prefix)
//! - Certificate hot-reload по mtime
//! - Connection limit, idle timeout
//! - События совместимы с UDP-транспортом (PacketProcessor не знает о типе)

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use bytes::{Buf, BufMut, BytesMut};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, instrument, warn};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum TlsError {
    #[error("I/O: {0}")]
    Io(#[from] io::Error),
    #[error("TLS config: {0}")]
    TlsConfig(#[from] rustls::Error),
    #[error("cert load {path}: {source}")]
    CertLoad { path: PathBuf, #[source] source: io::Error },
    #[error("key load {path}: {source}")]
    KeyLoad { path: PathBuf, #[source] source: io::Error },
    #[error("no private key in {0}")]
    NoKey(PathBuf),
    #[error("frame too large: {size} (max {max})")]
    FrameTooLarge { size: usize, max: usize },
    #[error("connection closed")]
    Closed,
    #[error("TLS handshake timeout ({0:?})")]
    HandshakeTimeout(Duration),
}

pub type Result<T> = std::result::Result<T, TlsError>;

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct TlsTransportConfig {
    pub listen_addr: SocketAddr,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub max_frame_size: usize,
    pub handshake_timeout: Duration,
    pub read_timeout: Duration,
    pub max_connections: usize,
    pub enable_alpn: bool,
}

impl Default for TlsTransportConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:5349".parse().unwrap(),
            cert_path: PathBuf::from("/etc/turna/tls/cert.pem"),
            key_path: PathBuf::from("/etc/turna/tls/key.pem"),
            max_frame_size: 64 * 1024,
            handshake_timeout: Duration::from_secs(5),
            read_timeout: Duration::from_secs(300),
            max_connections: 10_000,
            enable_alpn: true,
        }
    }
}

// ---------------------------------------------------------------------------
// STUN-over-TCP Frame Codec (RFC 4571: 2-byte length prefix)
// ---------------------------------------------------------------------------

pub struct TcpFrameCodec {
    max_frame_size: usize,
}

impl TcpFrameCodec {
    pub fn new(max_frame_size: usize) -> Self {
        Self { max_frame_size }
    }

    pub fn decode(&self, buf: &mut BytesMut) -> Result<Option<BytesMut>> {
        if buf.len() < 2 {
            return Ok(None);
        }
        let length = u16::from_be_bytes([buf[0], buf[1]]) as usize;
        if length > self.max_frame_size {
            return Err(TlsError::FrameTooLarge { size: length, max: self.max_frame_size });
        }
        if buf.len() < 2 + length {
            return Ok(None);
        }
        buf.advance(2);
        Ok(Some(buf.split_to(length)))
    }

    pub fn encode(&self, payload: &[u8], buf: &mut BytesMut) -> Result<()> {
        if payload.len() > self.max_frame_size {
            return Err(TlsError::FrameTooLarge { size: payload.len(), max: self.max_frame_size });
        }
        buf.reserve(2 + payload.len());
        buf.put_u16(payload.len() as u16);
        buf.put_slice(payload);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Connection ID
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TcpConnectionId(u64);

impl TcpConnectionId {
    fn next(counter: &std::sync::atomic::AtomicU64) -> Self {
        Self(counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
    }
}

impl std::fmt::Display for TcpConnectionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "tcp-{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum TcpTransportEvent {
    PacketReceived { conn_id: TcpConnectionId, peer_addr: SocketAddr, data: BytesMut },
    ConnectionOpened { conn_id: TcpConnectionId, peer_addr: SocketAddr },
    ConnectionClosed { conn_id: TcpConnectionId, peer_addr: SocketAddr, reason: String },
}

#[derive(Debug)]
pub struct TcpSendCommand {
    pub conn_id: TcpConnectionId,
    pub data: Vec<u8>,
}

// ---------------------------------------------------------------------------
// TLS Server
// ---------------------------------------------------------------------------

pub struct TlsTransportServer {
    config: TlsTransportConfig,
    tls_acceptor: TlsAcceptor,
    conn_counter: Arc<std::sync::atomic::AtomicU64>,
}

impl TlsTransportServer {
    pub fn new(config: TlsTransportConfig) -> Result<Self> {
        let tls_config = build_tls_config(&config)?;
        Ok(Self {
            config,
            tls_acceptor: TlsAcceptor::from(Arc::new(tls_config)),
            conn_counter: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        })
    }

    pub async fn run(
        self,
        event_tx: mpsc::Sender<TcpTransportEvent>,
        mut send_rx: mpsc::Receiver<TcpSendCommand>,
    ) -> Result<()> {
        let listener = TcpListener::bind(self.config.listen_addr).await?;
        info!(addr = %self.config.listen_addr, max = self.config.max_connections, "TURNS listening");

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
            let (stream, peer) = listener.accept().await?;
            {
                let c = conns.read().await;
                if c.len() >= self.config.max_connections {
                    warn!(%peer, "connection limit reached");
                    continue;
                }
            }

            let conn_id = TcpConnectionId::next(&self.conn_counter);
            let (conn_tx, conn_rx) = mpsc::channel::<Vec<u8>>(256);
            conns.write().await.insert(conn_id, conn_tx);

            let tls = self.tls_acceptor.clone();
            let etx = event_tx.clone();
            let cfg = self.config.clone();
            let conns = conns.clone();

            tokio::spawn(async move {
                let reason = match handle_conn(conn_id, stream, peer, tls, &cfg, etx.clone(), conn_rx).await {
                    Ok(()) => "clean close".into(),
                    Err(e) => format!("{e}"),
                };
                conns.write().await.remove(&conn_id);
                let _ = etx.send(TcpTransportEvent::ConnectionClosed { conn_id, peer_addr: peer, reason }).await;
            });
        }
    }
}

#[instrument(skip_all, fields(conn = %id, peer = %peer))]
async fn handle_conn(
    id: TcpConnectionId,
    stream: TcpStream,
    peer: SocketAddr,
    tls: TlsAcceptor,
    cfg: &TlsTransportConfig,
    etx: mpsc::Sender<TcpTransportEvent>,
    mut send_rx: mpsc::Receiver<Vec<u8>>,
) -> Result<()> {
    let tls_stream = timeout(cfg.handshake_timeout, tls.accept(stream))
        .await
        .map_err(|_| TlsError::HandshakeTimeout(cfg.handshake_timeout))?
        .map_err(|e| TlsError::Io(io::Error::new(io::ErrorKind::Other, e)))?;

    let _ = etx.send(TcpTransportEvent::ConnectionOpened { conn_id: id, peer_addr: peer }).await;

    let (mut rd, mut wr) = tokio::io::split(tls_stream);
    let codec = TcpFrameCodec::new(cfg.max_frame_size);
    let mut buf = BytesMut::with_capacity(8192);

    loop {
        tokio::select! {
            res = timeout(cfg.read_timeout, rd.read_buf(&mut buf)) => {
                match res {
                    Ok(Ok(0)) => return Ok(()),
                    Ok(Ok(_)) => {
                        while let Some(frame) = codec.decode(&mut buf)? {
                            etx.send(TcpTransportEvent::PacketReceived { conn_id: id, peer_addr: peer, data: frame })
                                .await.map_err(|_| TlsError::Closed)?;
                        }
                    }
                    Ok(Err(e)) => return Err(TlsError::Io(e)),
                    Err(_) => return Ok(()), // idle timeout
                }
            }
            Some(data) = send_rx.recv() => {
                let mut out = BytesMut::with_capacity(2 + data.len());
                codec.encode(&data, &mut out)?;
                wr.write_all(&out).await?;
                wr.flush().await?;
            }
            else => break,
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// TLS Helpers
// ---------------------------------------------------------------------------

fn build_tls_config(cfg: &TlsTransportConfig) -> Result<ServerConfig> {
    let certs = load_certs(&cfg.cert_path)?;
    let key = load_key(&cfg.key_path)?;
    let mut tls = ServerConfig::builder().with_no_client_auth().with_single_cert(certs, key)?;
    if cfg.enable_alpn {
        tls.alpn_protocols = vec![b"stun.turn".to_vec(), b"stun.nat-discovery".to_vec()];
    }
    Ok(tls)
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let data = std::fs::read(path).map_err(|e| TlsError::CertLoad { path: path.into(), source: e })?;
    let certs: Vec<_> = rustls_pemfile::certs(&mut io::BufReader::new(data.as_slice()))
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| TlsError::CertLoad { path: path.into(), source: e })?;
    if certs.is_empty() {
        return Err(TlsError::CertLoad { path: path.into(), source: io::Error::new(io::ErrorKind::InvalidData, "empty") });
    }
    Ok(certs)
}

fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let data = std::fs::read(path).map_err(|e| TlsError::KeyLoad { path: path.into(), source: e })?;
    let mut rdr = io::BufReader::new(data.as_slice());
    loop {
        match rustls_pemfile::read_one(&mut rdr) {
            Ok(Some(rustls_pemfile::Item::Pkcs1Key(k))) => return Ok(PrivateKeyDer::Pkcs1(k)),
            Ok(Some(rustls_pemfile::Item::Pkcs8Key(k))) => return Ok(PrivateKeyDer::Pkcs8(k)),
            Ok(Some(rustls_pemfile::Item::Sec1Key(k))) => return Ok(PrivateKeyDer::Sec1(k)),
            Ok(Some(_)) => continue,
            Ok(None) => break,
            Err(e) => return Err(TlsError::KeyLoad { path: path.into(), source: e }),
        }
    }
    Err(TlsError::NoKey(path.into()))
}

// ---------------------------------------------------------------------------
// Certificate Hot-Reload
// ---------------------------------------------------------------------------

pub struct CertReloader {
    cert_path: PathBuf,
    key_path: PathBuf,
    interval: Duration,
    enable_alpn: bool,
}

impl CertReloader {
    pub fn new(cfg: &TlsTransportConfig, interval: Duration) -> Self {
        Self { cert_path: cfg.cert_path.clone(), key_path: cfg.key_path.clone(), interval, enable_alpn: cfg.enable_alpn }
    }

    pub async fn spawn(self) -> Result<tokio::sync::watch::Receiver<Arc<ServerConfig>>> {
        let initial = self.reload()?;
        let (tx, rx) = tokio::sync::watch::channel(Arc::new(initial));
        tokio::spawn(async move {
            let mut cert_mt = mtime(&self.cert_path);
            let mut key_mt = mtime(&self.key_path);
            loop {
                tokio::time::sleep(self.interval).await;
                let new_cert = mtime(&self.cert_path);
                let new_key = mtime(&self.key_path);
                if new_cert != cert_mt || new_key != key_mt {
                    match self.reload() {
                        Ok(c) => { let _ = tx.send(Arc::new(c)); cert_mt = new_cert; key_mt = new_key; info!("TLS cert reloaded"); }
                        Err(e) => error!(%e, "cert reload failed"),
                    }
                }
            }
        });
        Ok(rx)
    }

    fn reload(&self) -> Result<ServerConfig> {
        let certs = load_certs(&self.cert_path)?;
        let key = load_key(&self.key_path)?;
        let mut tls = ServerConfig::builder().with_no_client_auth().with_single_cert(certs, key)?;
        if self.enable_alpn {
            tls.alpn_protocols = vec![b"stun.turn".to_vec(), b"stun.nat-discovery".to_vec()];
        }
        Ok(tls)
    }
}

fn mtime(path: &Path) -> Option<std::time::SystemTime> {
    std::fs::metadata(path).ok().and_then(|m| m.modified().ok())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codec_roundtrip() {
        let codec = TcpFrameCodec::new(65535);
        let mut buf = BytesMut::new();
        codec.encode(b"hello STUN", &mut buf).unwrap();
        let frame = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(&frame[..], b"hello STUN");
    }

    #[test]
    fn codec_partial() {
        let codec = TcpFrameCodec::new(65535);
        let mut buf = BytesMut::from(&[0x00, 0x0A][..]);
        assert!(codec.decode(&mut buf).unwrap().is_none());
    }

    #[test]
    fn codec_too_large() {
        let codec = TcpFrameCodec::new(100);
        let mut buf = BytesMut::new();
        assert!(codec.encode(&vec![0u8; 200], &mut buf).is_err());
    }

    #[test]
    fn codec_multi_frame() {
        let codec = TcpFrameCodec::new(65535);
        let mut buf = BytesMut::new();
        codec.encode(b"AAA", &mut buf).unwrap();
        codec.encode(b"BBB", &mut buf).unwrap();
        assert_eq!(&codec.decode(&mut buf).unwrap().unwrap()[..], b"AAA");
        assert_eq!(&codec.decode(&mut buf).unwrap().unwrap()[..], b"BBB");
        assert!(codec.decode(&mut buf).unwrap().is_none());
    }
}
