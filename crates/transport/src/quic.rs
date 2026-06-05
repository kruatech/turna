//! QUIC / WebTransport transport (RFC 9000, RFC 9220).
//!
//! WebTransport over HTTP/3: browser connects via QUIC, opens
//! bidirectional streams for signaling and unidirectional/datagrams for media.
//!
//! Advantages over WebSocket + UDP:
//! - Single connection for signaling + media
//! - Built-in encryption (TLS 1.3)
//! - Connection migration (IP change without reconnect)
//! - Head-of-line blocking only per-stream (not per-connection)
//! - Datagrams for low-latency media (no HoL blocking at all)
//!
//! Backend: quinn crate (pure Rust QUIC).
//!
//! This module provides the abstraction — quinn integration is behind
//! a feature flag to avoid pulling the dependency unconditionally.

use std::net::SocketAddr;
use std::time::Duration;

use thiserror::Error;
use tracing::info;

#[derive(Debug, Error)]
pub enum QuicError {
    #[error("connection failed: {0}")]
    Connection(String),
    #[error("stream error: {0}")]
    Stream(String),
    #[error("datagram error: {0}")]
    Datagram(String),
    #[error("tls: {0}")]
    Tls(String),
    #[error("not supported")]
    NotSupported,
}

pub type Result<T> = std::result::Result<T, QuicError>;

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct QuicConfig {
    pub listen_addr: SocketAddr,
    pub cert_path: String,
    pub key_path: String,
    /// Max concurrent bidirectional streams per connection.
    pub max_bi_streams: u64,
    /// Max concurrent unidirectional streams.
    pub max_uni_streams: u64,
    /// Enable QUIC datagrams (RFC 9221) — for low-latency media.
    pub enable_datagrams: bool,
    /// Max datagram size.
    pub max_datagram_size: usize,
    /// Idle timeout.
    pub idle_timeout: Duration,
    /// Keep-alive interval.
    pub keep_alive: Duration,
    /// Enable 0-RTT (faster reconnects, less secure).
    pub enable_0rtt: bool,
    /// ALPN protocols.
    pub alpn: Vec<String>,
}

impl Default for QuicConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:443".parse().unwrap(),
            cert_path: "/etc/turna/tls/cert.pem".into(),
            key_path: "/etc/turna/tls/key.pem".into(),
            max_bi_streams: 100,
            max_uni_streams: 100,
            enable_datagrams: true,
            max_datagram_size: 1200,
            idle_timeout: Duration::from_secs(30),
            keep_alive: Duration::from_secs(10),
            enable_0rtt: false,
            alpn: vec![
                "h3".into(),           // HTTP/3
                "webtransport".into(), // WebTransport
            ],
        }
    }
}

// ---------------------------------------------------------------------------
// WebTransport Session
// ---------------------------------------------------------------------------

/// A WebTransport session over QUIC.
///
/// Provides:
/// - Bidirectional streams (for signaling, reliable data)
/// - Unidirectional streams (for server push)
/// - Datagrams (for low-latency media, unreliable)
pub struct WebTransportSession {
    pub session_id: String,
    pub remote_addr: SocketAddr,
    pub local_addr: SocketAddr,
    /// Connection ID (for migration tracking).
    pub connection_id: Vec<u8>,
    /// Whether datagrams are available.
    pub datagrams_available: bool,
    /// ALPN negotiated.
    pub alpn: String,
    /// Creation time.
    pub created_at: std::time::Instant,
}

impl WebTransportSession {
    /// Send a datagram (unreliable, low-latency).
    /// Ideal for forwarding RTP-like media without HoL blocking.
    pub fn send_datagram(&self, _data: &[u8]) -> Result<()> {
        if !self.datagrams_available {
            return Err(QuicError::Datagram("datagrams not enabled".into()));
        }
        // In production: self.connection.send_datagram(data)
        Ok(())
    }

    /// Open a bidirectional stream (reliable, ordered).
    /// For signaling messages, data channel messages.
    pub fn open_bi_stream(&self) -> Result<BiStream> {
        Ok(BiStream {
            stream_id: rand::random(),
            session_id: self.session_id.clone(),
        })
    }

    /// Send on a unidirectional stream (reliable, server → client).
    pub fn open_uni_stream(&self) -> Result<UniStream> {
        Ok(UniStream {
            stream_id: rand::random(),
            session_id: self.session_id.clone(),
        })
    }
}

/// Bidirectional QUIC stream.
pub struct BiStream {
    pub stream_id: u64,
    pub session_id: String,
}

impl BiStream {
    pub fn send(&self, _data: &[u8]) -> Result<()> {
        // quinn: stream.write_all(data).await
        Ok(())
    }

    pub fn recv(&self, _buf: &mut [u8]) -> Result<usize> {
        // quinn: stream.read(buf).await
        Ok(0)
    }
}

/// Unidirectional QUIC stream (send only).
pub struct UniStream {
    pub stream_id: u64,
    pub session_id: String,
}

// ---------------------------------------------------------------------------
// QUIC Server (trait for quinn backend)
// ---------------------------------------------------------------------------

/// QUIC server events.
pub enum QuicEvent {
    /// New WebTransport session established.
    NewSession(WebTransportSession),
    /// Datagram received on a session.
    Datagram { session_id: String, data: Vec<u8> },
    /// Bidirectional stream opened by client.
    BiStreamOpened { session_id: String, stream_id: u64 },
    /// Stream data received.
    StreamData { session_id: String, stream_id: u64, data: Vec<u8> },
    /// Session closed.
    SessionClosed { session_id: String, reason: String },
    /// Connection migrated to new address.
    ConnectionMigrated { session_id: String, old_addr: SocketAddr, new_addr: SocketAddr },
}

/// QUIC server handle.
pub struct QuicServer {
    config: QuicConfig,
}

impl QuicServer {
    pub fn new(config: QuicConfig) -> Self {
        info!(addr = %config.listen_addr, "QUIC/WebTransport server configured");
        Self { config }
    }

    /// Start the QUIC server.
    ///
    /// In production: creates quinn::Endpoint, accepts connections,
    /// negotiates ALPN, creates WebTransportSessions.
    ///
    /// Events sent via channel for the SFU to process.
    pub async fn run(
        &self,
        _event_tx: tokio::sync::mpsc::Sender<QuicEvent>,
    ) -> Result<()> {
        info!(
            addr = %self.config.listen_addr,
            alpn = ?self.config.alpn,
            datagrams = self.config.enable_datagrams,
            "QUIC server starting"
        );

        // In production:
        // let endpoint = quinn::Endpoint::server(server_config, self.config.listen_addr)?;
        // while let Some(connecting) = endpoint.accept().await {
        //     let conn = connecting.await?;
        //     // Check ALPN → create WebTransportSession
        //     // Spawn per-session handler
        // }

        // Placeholder: wait forever
        tokio::signal::ctrl_c().await.map_err(|e| QuicError::Connection(e.to_string()))?;
        Ok(())
    }

    pub fn config(&self) -> &QuicConfig {
        &self.config
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults() {
        let c = QuicConfig::default();
        assert!(c.enable_datagrams);
        assert_eq!(c.max_datagram_size, 1200);
        assert!(c.alpn.contains(&"h3".to_string()));
    }

    #[test]
    fn session_datagram_disabled() {
        let session = WebTransportSession {
            session_id: "test".into(),
            remote_addr: "1.2.3.4:5000".parse().unwrap(),
            local_addr: "0.0.0.0:443".parse().unwrap(),
            connection_id: vec![1, 2, 3],
            datagrams_available: false,
            alpn: "h3".into(),
            created_at: std::time::Instant::now(),
        };
        assert!(session.send_datagram(b"test").is_err());
    }
}
