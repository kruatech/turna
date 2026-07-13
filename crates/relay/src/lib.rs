//! Relay engine — TURN packet processing and forwarding
//!
//! Two modes:
//! - `RelayServer`: async, uses tokio Transport (all platforms)
//! - `RelayHandler`: sync, implements `PacketHandler` for io_uring workers (Linux)

pub mod node_migration;
pub mod peer_filter;
pub mod processor;
pub mod server;
pub mod tcp_relay;

pub use server::{new_client_sinks, start_relay_egress, ClientSinks, RelayEgress};
#[cfg(feature = "tls")]
pub mod tls_bridge;

#[cfg(feature = "sctp")]
pub mod sctp_bridge;

#[cfg(all(target_os = "linux", feature = "io-uring"))]
pub mod handler;

pub use processor::PacketProcessor;
pub use server::RelayServer;
#[cfg(target_os = "linux")]
pub mod splice;

pub mod quic_bridge;
