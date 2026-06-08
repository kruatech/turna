use std::net::SocketAddr;

use xxhash_rust::xxh64::xxh64;

/// A TURN node that can own new client allocations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClusterNode {
    pub node_id: String,
    pub turn_addr: SocketAddr,
}

/// Stable node list used with Jump Consistent Hash.
///
/// The vector is sorted by `node_id` so every node with the same topology maps
/// a given client key to the same bucket.
#[derive(Debug, Clone, Default)]
pub struct HashRing {
    nodes: Vec<ClusterNode>,
}

impl HashRing {
    pub fn new(mut nodes: Vec<ClusterNode>) -> Self {
        nodes.sort_by(|a, b| a.node_id.cmp(&b.node_id));
        nodes.dedup_by(|a, b| a.node_id == b.node_id);
        Self { nodes }
    }

    pub fn get_node(&self, key: &str) -> Option<&ClusterNode> {
        if self.nodes.is_empty() {
            return None;
        }
        // Rendezvous (Highest-Random-Weight) hashing.
        //
        // Each node scores the key with xxh64(node_id || key); the highest
        // score wins. Unlike jump-hash-over-a-sorted-index, this remaps only
        // ~1/N of keys when a node joins/leaves regardless of where the new
        // node_id sorts, so adding a node whose id lands "in the middle" no
        // longer reshuffles unrelated keys. Ties (astronomically unlikely with
        // 64-bit scores) break on node_id for determinism across the cluster.
        self.nodes
            .iter()
            .max_by(|a, b| {
                let sa = hrw_score(&a.node_id, key);
                let sb = hrw_score(&b.node_id, key);
                sa.cmp(&sb).then_with(|| a.node_id.cmp(&b.node_id))
            })
    }

    pub fn update_nodes(&mut self, new_nodes: Vec<ClusterNode>) {
        *self = Self::new(new_nodes);
    }

    /// Owner of `key` ignoring `exclude_id` — used during lame-duck drain to
    /// hand a draining node's would-be-local clients to the next-best node.
    /// Returns `None` if no other node exists.
    pub fn get_node_excluding(&self, key: &str, exclude_id: &str) -> Option<&ClusterNode> {
        self.nodes
            .iter()
            .filter(|n| n.node_id != exclude_id)
            .max_by(|a, b| {
                let sa = hrw_score(&a.node_id, key);
                let sb = hrw_score(&b.node_id, key);
                sa.cmp(&sb).then_with(|| a.node_id.cmp(&b.node_id))
            })
    }

    pub fn nodes(&self) -> &[ClusterNode] {
        &self.nodes
    }

    /// Owned copy of the current membership, for observability surfaces
    /// (a `turnactl cluster nodes` command, a `/cluster` management endpoint, …).
    pub fn snapshot(&self) -> Vec<ClusterNode> {
        self.nodes.clone()
    }
}

/// Rendezvous (HRW) score for a `(node_id, key)` pair.
///
/// Combines node_id and key into one xxh64 hash. A separator byte avoids
/// collisions between e.g. ("ab", "c") and ("a", "bc").
fn hrw_score(node_id: &str, key: &str) -> u64 {
    let mut buf = Vec::with_capacity(node_id.len() + key.len() + 1);
    buf.extend_from_slice(node_id.as_bytes());
    buf.push(0x1f);
    buf.extend_from_slice(key.as_bytes());
    xxh64(&buf, 0)
}

/// Google Jump Consistent Hash.
///
/// Retained for reference / benchmarks. The ring uses rendezvous hashing
/// instead (see `HashRing::get_node`) because jump hash only minimises remap
/// when buckets change at the tail, which a node_id-sorted node list does not
/// guarantee.
pub fn jump_hash(mut key: u64, buckets: usize) -> usize {
    assert!(buckets > 0, "jump_hash requires at least one bucket");

    let mut b: i64 = -1;
    let mut j: i64 = 0;
    while j < buckets as i64 {
        b = j;
        key = key.wrapping_mul(2862933555777941757).wrapping_add(1);
        j = (((b + 1) as f64) * ((1u64 << 31) as f64) / (((key >> 33) + 1) as f64)) as i64;
    }
    b as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_sorts_nodes_by_id() {
        let ring = HashRing::new(vec![
            ClusterNode {
                node_id: "b".into(),
                turn_addr: "127.0.0.1:3479".parse().unwrap(),
            },
            ClusterNode {
                node_id: "a".into(),
                turn_addr: "127.0.0.1:3478".parse().unwrap(),
            },
        ]);
        assert_eq!(ring.nodes()[0].node_id, "a");
        assert_eq!(ring.nodes()[1].node_id, "b");
    }

    #[test]
    fn jump_hash_is_stable() {
        assert_eq!(jump_hash(0, 1), 0);
        assert_eq!(jump_hash(123456789, 10), jump_hash(123456789, 10));
    }

    #[test]
    fn get_node_returns_a_member() {
        let ring = HashRing::new(vec![
            ClusterNode {
                node_id: "a".into(),
                turn_addr: "127.0.0.1:3478".parse().unwrap(),
            },
            ClusterNode {
                node_id: "b".into(),
                turn_addr: "127.0.0.1:3479".parse().unwrap(),
            },
        ]);
        let node = ring.get_node("192.0.2.10:50000").unwrap();
        assert!(matches!(node.node_id.as_str(), "a" | "b"));
    }

    fn ring_of(ids: &[&str]) -> HashRing {
        HashRing::new(
            ids.iter()
                .map(|id| ClusterNode {
                    node_id: (*id).into(),
                    turn_addr: "127.0.0.1:3478".parse().unwrap(),
                })
                .collect(),
        )
    }

    #[test]
    fn hrw_remaps_about_one_over_n_even_for_middle_insertion() {
        let keys: Vec<String> = (0..20_000)
            .map(|i| format!("203.0.{}.{}:{}", i / 256 % 256, i % 256, 1024 + i % 60000))
            .collect();

        let before = ring_of(&["node-a", "node-b", "node-c"]);
        // "node-bb" sorts between b and c — the case that broke jump hash.
        let after = ring_of(&["node-a", "node-b", "node-bb", "node-c"]);

        let moved = keys
            .iter()
            .filter(|k| before.get_node(k).unwrap().node_id != after.get_node(k).unwrap().node_id)
            .count();
        let frac = moved as f64 / keys.len() as f64;
        // Ideal for 3 -> 4 nodes is ~25%. HRW stays close regardless of where
        // the new id sorts; jump-hash-over-sorted-index moved ~41% here.
        assert!(frac < 0.32, "remap fraction too high: {frac:.3}");
    }

    #[test]
    fn excluding_owner_returns_a_different_live_node() {
        let ring = ring_of(&["node-a", "node-b", "node-c"]);
        let key = "203.0.113.7:51000";
        let owner = ring.get_node(key).unwrap().node_id.clone();
        let alt = ring.get_node_excluding(key, &owner).unwrap();
        assert_ne!(alt.node_id, owner);
    }

    #[test]
    fn excluding_sole_node_returns_none() {
        let ring = ring_of(&["only"]);
        assert!(ring.get_node_excluding("k", "only").is_none());
    }
}
