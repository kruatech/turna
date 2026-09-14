//! Network transport abstraction
//!
//! Provides a trait-based UDP transport with two backends:
//! - `TokioTransport`: async via epoll (all platforms)
//! - `UringTransport`: io_uring with registered buffers (Linux 5.6+)
//!
//! Enable io_uring with `--features io-uring`.

pub mod batch;
pub mod bpf_filter;
pub mod buffer;
pub mod hugepages;
pub mod migration;
pub mod probe;
pub mod quic;
pub mod ratelimit;
pub mod select;
pub mod tokio_transport;

#[cfg(all(target_os = "linux", feature = "io-uring"))]
pub mod relay_route;
#[cfg(all(target_os = "linux", feature = "io-uring"))]
pub mod uring;
#[cfg(all(target_os = "linux", feature = "io-uring"))]
pub mod worker;

#[cfg(all(target_os = "linux", feature = "af-xdp"))]
pub mod af_xdp;
#[cfg(all(target_os = "linux", feature = "af-xdp"))]
pub mod neighbor;

/// Whether this binary carries the TURNS (TLS-over-TCP) listener.
///
/// Declared here rather than in `tcp_tls` because that module is itself behind
/// the feature gate: a build without `tls` has no `tcp_tls` to read a constant
/// from, which is exactly the build that needs to answer the question. Mirrors
/// `dtls::DTLS_AVAILABLE` and `quic::QUIC_AVAILABLE`, whose modules compile
/// unconditionally and so could keep theirs inside.
pub const TLS_AVAILABLE: bool = cfg!(feature = "tls");

#[cfg(feature = "tls")]
pub mod tcp_tls;
#[cfg(feature = "tls")]
pub use tcp_tls::{
    TcpConnectionId, TcpSendCommand, TcpTransportEvent, TlsError, TlsTransportConfig,
    TlsTransportServer,
};

#[cfg(feature = "sctp")]
pub mod sctp;
#[cfg(feature = "sctp")]
pub use sctp::{SctpError, SctpTransportConfig, SctpTransportServer};

use std::net::SocketAddr;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("socket closed")]
    Closed,
    #[error("buffer exhausted")]
    BufferExhausted,
    #[error("ring full")]
    RingFull,
}

pub type Result<T> = std::result::Result<T, TransportError>;

/// Received packet descriptor — references a buffer without copying.
pub struct RecvPacket<'a> {
    pub data: &'a [u8],
    pub source: SocketAddr,
}

/// Async UDP transport trait.
#[allow(async_fn_in_trait)]
pub trait Transport: Send + Sync {
    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)>;
    async fn send_to(&self, buf: &[u8], target: SocketAddr) -> Result<usize>;
    fn local_addr(&self) -> Result<SocketAddr>;
}

// Re-export the default transport
pub use tokio_transport::TokioTransport;
/// Socket buffer sizing, applied to every socket bound after the call. See
/// `tokio_transport::apply_socket_buffers` for why the kernel's answer is
/// logged rather than assumed.
pub use tokio_transport::init_socket_buffers;

// Re-export transport selection (config preference + runtime io_uring probe).
pub use probe::{probe_io_uring, IoUringProbe};
pub use select::{resolve, TransportBackend, TransportDecision, TransportPreference};

/// Convenience: bind with best available backend.
pub async fn bind(addr: SocketAddr) -> Result<TokioTransport> {
    TokioTransport::bind(addr).await
}
pub mod gso;
#[cfg(target_os = "linux")]
pub mod numa;

pub mod dtls;
#[cfg(feature = "dtls")]
pub(crate) mod dtls_demux;
/// Stateless address validation for the demux path: a ClientHello without a
/// cookie this node issued is answered with a HelloVerifyRequest and allocates
/// nothing. See the module docs for why the pending-handshake cap was not
/// enough on its own.
#[cfg(feature = "dtls")]
pub(crate) mod dtls_cookie;
