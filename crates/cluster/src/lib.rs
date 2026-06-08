//! Cluster discovery and client placement helpers.

pub mod gossip;
pub mod hash_ring;

pub use hash_ring::{jump_hash, ClusterNode, HashRing};
