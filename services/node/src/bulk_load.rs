//! Bulk-load allocations from the state backend at startup.
//!
//! Called once, before the writer task is attached and before the relay
//! server starts accepting traffic. Asks the backend for every allocation
//! owned by this node and rehydrates them into the in-memory store.
//!
//! See `docs/design/allocation-store-persistence.md` §4 ("Bulk-load on
//! startup") and §9 question 4 (HMAC key handling).

use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;

use tracing::{info, warn};

use turna_session::AllocationStore;
use turna_state_backend::{Backend, StoredAllocation};

/// Outcome counts from one bulk-load pass. Returned mainly for logging
/// and for tests; nothing in the live path consumes them.
#[derive(Debug, Default, Clone, Copy)]
pub struct BulkLoadStats {
    pub fetched: usize,
    pub rehydrated: usize,
    pub skipped_expired: usize,
    pub skipped_error: usize,
}

/// Fetch this node's allocations from the backend and replay them into
/// the store. Errors from individual records are logged and skipped —
/// a corrupt row should not prevent the node from starting.
///
/// Bulk-load is best-effort: if the backend is unreachable, we log and
/// return an empty result. The node still starts; new allocations will
/// be created from scratch as clients reconnect.
pub async fn bulk_load(
    backend: &Arc<Backend>,
    store: &Arc<AllocationStore>,
    node_id: &str,
) -> BulkLoadStats {
    let mut stats = BulkLoadStats::default();

    let records = match backend.find_by_node(node_id).await {
        Ok(r) => r,
        Err(e) => {
            warn!(error = ?e, node_id,
                  "bulk-load: find_by_node failed — starting with empty state");
            return stats;
        }
    };
    stats.fetched = records.len();
    info!(
        node_id,
        count = stats.fetched,
        "bulk-load: fetched records from backend"
    );

    for stored in records {
        match apply_one(store, &stored) {
            Ok(true) => stats.rehydrated += 1,
            Ok(false) => stats.skipped_expired += 1,
            Err(reason) => {
                stats.skipped_error += 1;
                warn!(relay_port = stored.relay_port,
                      id = %stored.id,
                      reason,
                      "bulk-load: failed to rehydrate one record");
            }
        }
    }

    info!(
        fetched = stats.fetched,
        rehydrated = stats.rehydrated,
        skipped_expired = stats.skipped_expired,
        skipped_error = stats.skipped_error,
        "bulk-load: complete"
    );
    stats
}

/// Apply a single `StoredAllocation` to the store. Errors are returned
/// as static strings — they go straight into a `warn!` and don't need
/// any structured handling.
///
/// `pub(crate)` so that `failover.rs` can reuse the same conversion
/// (parse stringly-typed addresses, default-expiry permissions, etc.)
/// when applying claimed allocations from dead peers.
pub(crate) fn apply_one(
    store: &Arc<AllocationStore>,
    stored: &StoredAllocation,
) -> Result<bool, &'static str> {
    let client_addr =
        SocketAddr::from_str(&stored.client_addr).map_err(|_| "invalid client_addr")?;
    let relay_addr = SocketAddr::from_str(&stored.relay_addr).map_err(|_| "invalid relay_addr")?;

    // Permissions: the stored schema is `Vec<String>` of IPs without
    // explicit expiry (see design doc §4 D5 known-limitation). We assume
    // a fresh PERMISSION_LIFETIME from now — the client will refresh
    // through normal CreatePermission flow before it matters.
    let perm_default_expiry = turna_session::epoch_ms() + 300_000; // 5 min
    let permissions = stored.permissions.iter().filter_map(|s| {
        s.parse::<std::net::IpAddr>()
            .ok()
            .map(|ip| (ip, perm_default_expiry))
    });

    let channels = stored.channels.iter().filter_map(|c| {
        SocketAddr::from_str(&c.peer_addr)
            .ok()
            .map(|addr| (c.number, addr, c.expires_at_ms))
    });

    store
        .rehydrate(
            client_addr,
            relay_addr,
            stored.user_id.clone(),
            stored.realm.clone(),
            stored.allocation_id.clone(),
            stored.migration_epoch,
            stored.created_at_ms,
            stored.expires_at_ms,
            permissions,
            channels,
        )
        .map_err(|_| "rehydrate refused (quota? port taken?)")
}

#[cfg(test)]
mod tests {
    use super::*;
    use turna_state_backend::{create_backend, BackendConfig, StoredAllocation, StoredChannel};

    fn alloc_for(node: &str, port: u16, user: &str, expires_at_ms: u64) -> StoredAllocation {
        // Client port must fit in u16. Use a deterministic mapping that
        // stays below 65535 for the relay-port range [40000, 41000).
        let client_port: u16 = 20_000u16.wrapping_add(port);
        StoredAllocation {
            id: format!("{node}:{port}"),
            relay_port: port,
            client_addr: format!("127.0.0.1:{client_port}"),
            relay_addr: format!("10.0.0.1:{port}"),
            user_id: user.into(),
            realm: "turna".into(),
            node_id: node.into(),
            allocation_id: format!("alloc-{node}-{port}"),
            migration_epoch: 3,
            created_at_ms: turna_session::epoch_ms().saturating_sub(60_000),
            expires_at_ms,
            bytes_in: 0,
            bytes_out: 0,
            packets_in: 0,
            packets_out: 0,
            permissions: vec!["10.0.0.2".into()],
            channels: vec![StoredChannel {
                number: 0x4000,
                peer_addr: "10.0.0.2:9000".into(),
                expires_at_ms,
            }],
        }
    }

    async fn fresh() -> (Arc<Backend>, Arc<AllocationStore>) {
        let b = Arc::new(create_backend(&BackendConfig::Memory).await.unwrap());
        let s = Arc::new(AllocationStore::new(40000, 41000, 10_000));
        (b, s)
    }

    /// Round-trip: store some allocations, bulk-load into a fresh store,
    /// expect them all rehydrated.
    #[tokio::test]
    async fn round_trip_basic() {
        let (backend, _writer_store) = fresh().await;
        let now = turna_session::epoch_ms();

        for port in [40010, 40011, 40012] {
            backend
                .store_allocation(&alloc_for("node-A", port, "alice", now + 600_000))
                .await
                .unwrap();
        }

        let (_, fresh_store) = fresh().await;
        let stats = bulk_load(&backend, &fresh_store, "node-A").await;

        assert_eq!(stats.fetched, 3);
        assert_eq!(stats.rehydrated, 3);
        assert_eq!(stats.skipped_expired, 0);
        assert_eq!(stats.skipped_error, 0);
        // Allocations should now be queryable.
        // Relay-port 40010 → client-port mapping is 20000 + 40010 = 60010.
        let key: SocketAddr = "127.0.0.1:60010".parse().unwrap();
        assert!(
            fresh_store.get(&key).is_some(),
            "expected client 127.0.0.1:60010 in store"
        );
    }

    /// Expired records are skipped, not rehydrated.
    #[tokio::test]
    async fn expired_records_skipped() {
        let (backend, _) = fresh().await;
        let now = turna_session::epoch_ms();

        backend
            .store_allocation(&alloc_for("node-A", 40020, "u1", now + 600_000))
            .await
            .unwrap();
        backend
            .store_allocation(&alloc_for(
                "node-A",
                40021,
                "u2",
                now.saturating_sub(60_000),
            ))
            .await
            .unwrap();

        let (_, store) = fresh().await;
        let stats = bulk_load(&backend, &store, "node-A").await;
        assert_eq!(stats.fetched, 2);
        assert_eq!(stats.rehydrated, 1);
        assert_eq!(stats.skipped_expired, 1);
    }

    /// Records of other nodes are not loaded.
    #[tokio::test]
    async fn other_nodes_ignored() {
        let (backend, _) = fresh().await;
        let now = turna_session::epoch_ms();

        backend
            .store_allocation(&alloc_for("node-A", 40030, "u1", now + 600_000))
            .await
            .unwrap();
        backend
            .store_allocation(&alloc_for("node-B", 40031, "u2", now + 600_000))
            .await
            .unwrap();

        let (_, store) = fresh().await;
        let stats = bulk_load(&backend, &store, "node-A").await;
        assert_eq!(stats.fetched, 1);
        assert_eq!(stats.rehydrated, 1);
    }

    /// Malformed addresses are skipped with a warning, not fatal.
    #[tokio::test]
    async fn malformed_addr_is_skipped_not_fatal() {
        let (backend, _) = fresh().await;
        let now = turna_session::epoch_ms();

        let good = alloc_for("node-A", 40040, "good", now + 600_000);
        let mut bad = alloc_for("node-A", 40041, "bad", now + 600_000);
        bad.client_addr = "not-an-address".into();

        backend.store_allocation(&good).await.unwrap();
        backend.store_allocation(&bad).await.unwrap();

        let (_, store) = fresh().await;
        let stats = bulk_load(&backend, &store, "node-A").await;
        assert_eq!(stats.fetched, 2);
        assert_eq!(stats.rehydrated, 1);
        assert_eq!(stats.skipped_error, 1);
    }

    /// The same record loaded twice keeps state consistent (second attempt
    /// fails because the port is already reserved — no panic, no corruption).
    #[tokio::test]
    async fn double_bulk_load_is_safe() {
        let (backend, _) = fresh().await;
        let now = turna_session::epoch_ms();
        backend
            .store_allocation(&alloc_for("node-A", 40050, "u", now + 600_000))
            .await
            .unwrap();

        let (_, store) = fresh().await;
        let s1 = bulk_load(&backend, &store, "node-A").await;
        let s2 = bulk_load(&backend, &store, "node-A").await;
        assert_eq!(s1.rehydrated, 1);
        assert_eq!(s2.skipped_error, 1, "second pass should refuse same port");
    }

    /// PR1/PR2 contract holds: rehydrate must NOT emit WriteOps. Otherwise
    /// startup would shove the entire loaded state right back into the
    /// writer queue.
    #[tokio::test]
    async fn rehydrate_does_not_emit_write_op() {
        use tokio::sync::mpsc;
        let (backend, _) = fresh().await;
        let now = turna_session::epoch_ms();
        backend
            .store_allocation(&alloc_for("node-A", 40060, "u", now + 600_000))
            .await
            .unwrap();

        let (_, store) = fresh().await;
        let (tx, mut rx) = mpsc::channel(16);
        // Attach BEFORE bulk-load to detect any unintended emit.
        store.attach_writer(tx);

        let _stats = bulk_load(&backend, &store, "node-A").await;
        assert!(
            rx.try_recv().is_err(),
            "rehydrate must not emit any WriteOp"
        );
    }

    /// RFC 8016: the persisted `allocation_id` and `migration_epoch` are
    /// restored into the in-memory store on rehydrate, so a MOBILITY-TICKET
    /// minted by the previous owner remains valid after adoption.
    #[tokio::test]
    async fn rehydrate_restores_migration_identity() {
        let (backend, _) = fresh().await;
        let now = turna_session::epoch_ms();
        backend
            .store_allocation(&alloc_for("node-A", 40090, "u", now + 600_000))
            .await
            .unwrap();

        let (_, store) = fresh().await;
        let stats = bulk_load(&backend, &store, "node-A").await;
        assert_eq!(stats.rehydrated, 1);

        // alloc_for maps relay-port P → client 127.0.0.1:(20000+P).
        let client: SocketAddr = "127.0.0.1:60090".parse().unwrap();
        let a = store.get(&client).expect("rehydrated allocation present");
        assert_eq!(
            a.allocation_id, "alloc-node-A-40090",
            "persisted allocation_id must be restored, not re-minted"
        );
        assert_eq!(
            a.migration_epoch, 3,
            "persisted migration_epoch must be restored"
        );
        // And the id index must point at the rehydrated client so ticket
        // validation (get_by_id) resolves.
        assert_eq!(store.get_by_id("alloc-node-A-40090"), Some(client));
    }
}
