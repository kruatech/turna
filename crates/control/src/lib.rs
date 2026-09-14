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

// This crate contains no `unsafe`. The attribute makes that checkable by
// the compiler instead of by `docs/unsafe-audit.md`: a future change that
// introduces `unsafe` here fails to build rather than quietly widening the
// audited surface, which is confined to turna-transport and turna-relay.
#![forbid(unsafe_code)]

pub mod audit;
pub mod grpc;
pub mod rbac;
pub mod revocation;
pub mod turn_core_impl;

pub use grpc::{
    start_grpc_server, AllocationEvent, AllocationInfo, ChannelInfo, ConfigUpdate, CoreError,
    EventType, GrpcConfig, GrpcTlsConfig, ServerStatsInfo, TopTalkerInfo, TurnCore,
    UserLimitsUpdate,
};
pub use rbac::{Denial, Permission, RbacPolicy, KNOWN_PERMISSIONS};
pub use revocation::{LoadError as RevocationLoadError, RevocationList};
pub use turn_core_impl::TurnCoreImpl;
