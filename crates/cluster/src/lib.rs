//! Cluster discovery and client placement helpers.

// This crate contains no `unsafe`. The attribute makes that checkable by
// the compiler instead of by `docs/unsafe-audit.md`: a future change that
// introduces `unsafe` here fails to build rather than quietly widening the
// audited surface, which is confined to turna-transport and turna-relay.
#![forbid(unsafe_code)]

pub mod gossip;
pub mod hash_ring;

pub use hash_ring::{jump_hash, ClusterNode, HashRing};
