//! Relay engine — TURN packet processing and forwarding
//!
//! Two modes:
//! - `RelayServer`: async, uses tokio Transport (all platforms)
//! - `RelayHandler`: sync, implements `PacketHandler` for io_uring workers (Linux)

pub mod processor;
pub mod peer_filter;
pub mod server;
pub mod migration;

#[cfg(all(target_os = "linux", feature = "io-uring"))]
pub mod handler;

pub use processor::PacketProcessor;
pub use server::RelayServer;
#[cfg(target_os = "linux")] pub mod splice;
