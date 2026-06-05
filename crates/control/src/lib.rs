//! turna-control — gRPC management server and control plane client.
//!
//! # Quick start
//!
//! ```ignore
//! use std::sync::Arc;
//! use turna_control::{GrpcConfig, TurnCoreImpl, start_grpc_server};
//!
//! // In turna-node main.rs:
//! let core = Arc::new(
//!     TurnCoreImpl::new(store.clone(), metrics.clone(), shutdown_tx.clone())
//!         .with_config("turna.example.com", "1.2.3.4", vec!["0.0.0.0:3478".into()],
//!                      49152, 65535, 600, 3600)
//! );
//!
//! tokio::spawn(async move {
//!     if let Err(e) = start_grpc_server(GrpcConfig::default(), core).await {
//!         tracing::error!(%e, "gRPC server error");
//!     }
//! });
//! ```

pub mod grpc;
pub mod turn_core_impl;

pub use grpc::{
    start_grpc_server,
    AllocationEvent, AllocationInfo, ChannelInfo, ConfigUpdate,
    CoreError, CurrentConfig, EventType, GrpcConfig, GrpcTlsConfig,
    ServerStatsInfo, TopTalkerInfo, TurnCore,
};
pub use turn_core_impl::TurnCoreImpl;
