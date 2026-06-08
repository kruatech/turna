//! In-memory state backend — standalone mode, no external dependencies.

use crate::*;
use dashmap::DashMap;
use std::time::Duration;

pub struct InMemoryBackend {
    allocations: DashMap<u16, StoredAllocation>,
    nodes: DashMap<String, NodeHeartbeat>,
    rooms: DashMap<String, StoredRoom>,
}

impl InMemoryBackend {
    pub fn new() -> Self {
        Self {
            allocations: DashMap::new(),
            nodes: DashMap::new(),
            rooms: DashMap::new(),
        }
    }

    pub async fn store_allocation(&self, alloc: &StoredAllocation) -> Result<()> {
        self.allocations.insert(alloc.relay_port, alloc.clone());
        Ok(())
    }

    pub async fn get_allocation(&self, relay_port: u16) -> Result<Option<StoredAllocation>> {
        Ok(self.allocations.get(&relay_port).map(|v| v.clone()))
    }

    pub async fn remove_allocation(&self, relay_port: u16) -> Result<()> {
        self.allocations.remove(&relay_port);
        Ok(())
    }

    pub async fn find_by_user(&self, user_id: &str) -> Result<Vec<StoredAllocation>> {
        Ok(self
            .allocations
            .iter()
            .filter(|e| e.value().user_id == user_id)
            .map(|e| e.value().clone())
            .collect())
    }

    pub async fn find_by_node(&self, node_id: &str) -> Result<Vec<StoredAllocation>> {
        Ok(self
            .allocations
            .iter()
            .filter(|e| e.value().node_id == node_id)
            .map(|e| e.value().clone())
            .collect())
    }

    pub async fn find_expired(&self, before_ms: u64) -> Result<Vec<StoredAllocation>> {
        Ok(self
            .allocations
            .iter()
            .filter(|e| e.value().expires_at_ms < before_ms)
            .map(|e| e.value().clone())
            .collect())
    }

    pub async fn list_allocations(
        &self,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<StoredAllocation>> {
        Ok(self
            .allocations
            .iter()
            .skip(offset)
            .take(limit)
            .map(|e| e.value().clone())
            .collect())
    }

    pub async fn count_allocations(&self) -> Result<u64> {
        Ok(self.allocations.len() as u64)
    }

    pub async fn update_bandwidth(
        &self,
        relay_port: u16,
        bytes_in: u64,
        bytes_out: u64,
        packets_in: u64,
        packets_out: u64,
    ) -> Result<()> {
        if let Some(mut alloc) = self.allocations.get_mut(&relay_port) {
            alloc.bytes_in += bytes_in;
            alloc.bytes_out += bytes_out;
            alloc.packets_in += packets_in;
            alloc.packets_out += packets_out;
        }
        Ok(())
    }

    pub async fn heartbeat(&self, hb: &NodeHeartbeat) -> Result<()> {
        self.nodes.insert(hb.node_id.clone(), hb.clone());
        Ok(())
    }

    pub async fn get_live_nodes(&self, max_age: Duration) -> Result<Vec<NodeHeartbeat>> {
        // saturating_sub: PR5's failover code calls this with a deliberately
        // huge `max_age` (≈100 years) to enumerate every node ever seen.
        // Without saturation, that would underflow `u64` and return nothing.
        let cutoff = now_ms().saturating_sub(max_age.as_millis() as u64);
        Ok(self
            .nodes
            .iter()
            .filter(|e| e.value().last_seen_ms > cutoff)
            .map(|e| e.value().clone())
            .collect())
    }

    /// Atomic compare-and-swap of `node_id`. See `Backend::claim_allocation`
    /// in `lib.rs` for the contract.
    ///
    /// Atomicity here relies on `DashMap::get_mut`, which holds a write
    /// lock on the relevant shard for the duration of the closure. Any
    /// concurrent reader or writer on the same key blocks until we
    /// release the lock at the end of the function.
    pub async fn claim_allocation(
        &self,
        relay_port: u16,
        expected_node_id: &str,
        new_node_id: &str,
    ) -> Result<bool> {
        if let Some(mut entry) = self.allocations.get_mut(&relay_port) {
            if entry.node_id == expected_node_id {
                entry.node_id = new_node_id.to_string();
                return Ok(true);
            }
            // Mismatch — someone else owns it now (raced and won, or the
            // dead node is alive again, or the orphan was already claimed).
            return Ok(false);
        }
        // No such record — already removed (TTL sweep, manual cleanup).
        Ok(false)
    }

    pub async fn store_room(&self, room: &StoredRoom) -> Result<()> {
        self.rooms.insert(room.room_id.clone(), room.clone());
        Ok(())
    }

    pub async fn get_room(&self, room_id: &str) -> Result<Option<StoredRoom>> {
        Ok(self.rooms.get(room_id).map(|v| v.clone()))
    }

    pub async fn remove_room(&self, room_id: &str) -> Result<()> {
        self.rooms.remove(room_id);
        Ok(())
    }

    pub async fn ping(&self) -> Result<()> {
        Ok(())
    }
}

impl Default for InMemoryBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_alloc(port: u16) -> StoredAllocation {
        StoredAllocation {
            id: format!("alloc-{port}"),
            relay_port: port,
            client_addr: "10.0.0.1:5000".into(),
            relay_addr: format!("10.0.0.1:{port}"),
            user_id: "alice".into(),
            realm: "turna".into(),
            node_id: "node-1".into(),
            created_at_ms: now_ms(),
            expires_at_ms: now_ms() + 86400_000,
            bytes_in: 0,
            bytes_out: 0,
            packets_in: 0,
            packets_out: 0,
            permissions: vec!["10.0.0.2".into()],
            channels: vec![],
        }
    }

    #[tokio::test]
    async fn crud() {
        let b = InMemoryBackend::new();
        b.store_allocation(&test_alloc(50000)).await.unwrap();
        assert!(b.get_allocation(50000).await.unwrap().is_some());
        assert!(b.get_allocation(50001).await.unwrap().is_none());
        b.remove_allocation(50000).await.unwrap();
        assert!(b.get_allocation(50000).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn find_by_user() {
        let b = InMemoryBackend::new();
        b.store_allocation(&test_alloc(50000)).await.unwrap();
        b.store_allocation(&test_alloc(50001)).await.unwrap();
        let found = b.find_by_user("alice").await.unwrap();
        assert_eq!(found.len(), 2);
        assert!(b.find_by_user("bob").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn bandwidth_update() {
        let b = InMemoryBackend::new();
        b.store_allocation(&test_alloc(50000)).await.unwrap();
        b.update_bandwidth(50000, 100, 200, 1, 2).await.unwrap();
        let a = b.get_allocation(50000).await.unwrap().unwrap();
        assert_eq!(a.bytes_in, 100);
        assert_eq!(a.packets_out, 2);
    }

    #[tokio::test]
    async fn heartbeat_and_nodes() {
        let b = InMemoryBackend::new();
        b.heartbeat(&NodeHeartbeat {
            node_id: "n1".into(),
            addr: "10.0.0.1:3478".into(),
            active_allocations: 5,
            total_bandwidth_bps: 1000,
            cpu_usage_pct: 10.0,
            memory_usage_pct: 20.0,
            uptime_secs: 60,
            version: "0.1.0".into(),
            last_seen_ms: now_ms(),
            draining: false,
        })
        .await
        .unwrap();
        let nodes = b.get_live_nodes(Duration::from_secs(10)).await.unwrap();
        assert_eq!(nodes.len(), 1);
    }

    /// PR5: claim CAS — happy path.
    #[tokio::test]
    async fn claim_allocation_succeeds_on_match() {
        let b = InMemoryBackend::new();
        b.store_allocation(&test_alloc(50000)).await.unwrap();
        let ok = b.claim_allocation(50000, "node-1", "node-2").await.unwrap();
        assert!(ok);
        let a = b.get_allocation(50000).await.unwrap().unwrap();
        assert_eq!(a.node_id, "node-2");
    }

    /// PR5: claim CAS — mismatch leaves the record alone.
    #[tokio::test]
    async fn claim_allocation_fails_on_mismatch() {
        let b = InMemoryBackend::new();
        b.store_allocation(&test_alloc(50001)).await.unwrap();
        // alloc's node_id is "node-1" — try to claim from a wrong expected.
        let ok = b
            .claim_allocation(50001, "node-XYZ", "node-2")
            .await
            .unwrap();
        assert!(!ok);
        let a = b.get_allocation(50001).await.unwrap().unwrap();
        assert_eq!(a.node_id, "node-1", "owner must not change on CAS mismatch");
    }

    /// PR5: claim CAS — missing record is `false`, not an error.
    #[tokio::test]
    async fn claim_allocation_missing_returns_false() {
        let b = InMemoryBackend::new();
        let ok = b.claim_allocation(50002, "node-1", "node-2").await.unwrap();
        assert!(!ok);
    }

    /// PR5: `get_live_nodes` with a huge `max_age` must not underflow.
    #[tokio::test]
    async fn get_live_nodes_saturates_on_huge_max_age() {
        let b = InMemoryBackend::new();
        b.heartbeat(&NodeHeartbeat {
            node_id: "n1".into(),
            addr: "1.2.3.4:1".into(),
            active_allocations: 0,
            total_bandwidth_bps: 0,
            cpu_usage_pct: 0.0,
            memory_usage_pct: 0.0,
            uptime_secs: 0,
            version: "v".into(),
            last_seen_ms: now_ms(),
            draining: false,
        })
        .await
        .unwrap();
        // 100 years — would underflow without saturating_sub.
        let huge = Duration::from_secs(60 * 60 * 24 * 365 * 100);
        let n = b.get_live_nodes(huge).await.unwrap();
        assert_eq!(n.len(), 1, "huge max_age must include all records");
    }
}
