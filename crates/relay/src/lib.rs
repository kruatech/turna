//! Relay engine — TURN packet processing and forwarding
//!
//! Two modes:
//! - `RelayServer`: async, uses tokio Transport (all platforms)
//! - `RelayHandler`: sync, implements `PacketHandler` for io_uring workers (Linux)

pub mod abuse;
pub mod peer_filter;
pub mod processor;
pub mod server;
pub mod tcp_relay;
mod udp_transactions;

pub use server::{new_client_sinks, start_relay_egress, ClientSinks, RelayEgress};
#[cfg(feature = "tls")]
pub mod tls_bridge;

#[cfg(feature = "sctp")]
pub mod sctp_bridge;

#[cfg(any(feature = "tls", feature = "sctp"))]
mod stream_retry;

#[cfg(all(target_os = "linux", feature = "io-uring"))]
pub mod handler;

pub use abuse::{AutoBan, AutoBanSettings};
pub use processor::{PacketProcessor, RateLimitSettings};
// Re-exported so a caller can build `RateLimitSettings` without taking a direct
// dependency on turna-qos. The node does not depend on that crate today, and
// adding one just to name a struct of five (burst, rate) pairs is not a trade
// worth making.
pub use server::RelayServer;
pub use turna_qos::{ByteRateLimiter, TieredLimits};
#[cfg(target_os = "linux")]
pub mod splice;

pub mod quic_bridge;
