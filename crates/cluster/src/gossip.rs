use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::hash_ring::ClusterNode;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone)]
pub struct GossipConfig {
    pub node_id: String,
    pub turn_addr: SocketAddr,
    pub bind_addr: SocketAddr,
    pub seeds: Vec<String>,
    pub interval: Duration,
    pub timeout: Duration,
    /// Cluster identity. Messages from a different `cluster_name` are dropped,
    /// so a stray staging node can never merge into a prod ring (like a NATS
    /// cluster name).
    pub cluster_name: String,
    /// Address this node wants peers to reach its gossip endpoint on. Unspecified
    /// (`0.0.0.0:0`) means "infer from packet source" — set it explicitly behind
    /// NAT / in Kubernetes (the NATS `cluster.advertise` analogue).
    pub advertise_addr: SocketAddr,
    /// Shared secret. When set, every datagram is HMAC-SHA256 signed and
    /// unsigned/forged packets are rejected, so a rogue host can't inject a
    /// fake node into the ring (the NATS route-authorization analogue).
    pub secret: Option<Vec<u8>>,
}

/// One peer as advertised inside a gossip message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerEntry {
    pub node_id: String,
    pub turn_addr: SocketAddr,
    pub gossip_addr: SocketAddr,
    pub seq: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GossipMessage {
    pub cluster_name: String,
    /// The sender's own identity.
    pub node_id: String,
    pub turn_addr: SocketAddr,
    pub seq: u64,
    /// Sender's advertised gossip endpoint (`0.0.0.0:0` => infer from src).
    #[serde(default = "unspecified_addr")]
    pub advertise_addr: SocketAddr,
    /// Everything the sender currently believes about the rest of the cluster.
    #[serde(default)]
    pub peers: Vec<PeerEntry>,
    /// Set on a node's final message: "I am leaving, drop me now."
    #[serde(default)]
    pub leaving: bool,
}

fn unspecified_addr() -> SocketAddr {
    "0.0.0.0:0".parse().unwrap()
}

#[derive(Debug, Clone)]
struct GossipNode {
    node_id: String,
    turn_addr: SocketAddr,
    gossip_addr: SocketAddr,
    seq: u64,
    last_seen: Instant,
}

impl GossipNode {
    fn cluster_node(&self) -> ClusterNode {
        ClusterNode {
            node_id: self.node_id.clone(),
            turn_addr: self.turn_addr,
        }
    }

    fn peer_entry(&self) -> PeerEntry {
        PeerEntry {
            node_id: self.node_id.clone(),
            turn_addr: self.turn_addr,
            gossip_addr: self.gossip_addr,
            seq: self.seq,
        }
    }
}

/// Run a small UDP anti-entropy gossip loop.
///
/// Auto-discovers the full membership from partial seeds, keeps one consistent
/// view across the cluster, removes clean shutdowns instantly (graceful leave)
/// and crashed nodes after the timeout. Optionally namespaced by `cluster_name`
/// and authenticated with an HMAC `secret`. Whenever the live topology changes,
/// `on_change` receives the full live node list, including self.
pub async fn run_gossip<F>(
    cfg: GossipConfig,
    on_change: F,
    mut shutdown: watch::Receiver<bool>,
) -> std::io::Result<()>
where
    F: Fn(Vec<ClusterNode>) + Send + Sync + 'static,
{
    let socket = UdpSocket::bind(cfg.bind_addr).await?;
    let on_change: Arc<dyn Fn(Vec<ClusterNode>) + Send + Sync> = Arc::new(on_change);

    let interval = if cfg.interval.is_zero() {
        Duration::from_secs(2)
    } else {
        cfg.interval
    };
    let timeout = if cfg.timeout.is_zero() {
        Duration::from_secs(30)
    } else {
        cfg.timeout
    };
    let tombstone_grace = interval.saturating_mul(3).max(Duration::from_secs(5));

    let mut ticker = tokio::time::interval(interval);
    let mut seq = 0u64;
    let mut peers: HashMap<String, GossipNode> = HashMap::new();
    let mut tombstones: HashMap<String, Instant> = HashMap::new();
    let mut last_topology: Vec<ClusterNode> = Vec::new();
    let mut rx_buf = vec![0u8; 65_535];

    info!(
        node_id = %cfg.node_id,
        cluster = %cfg.cluster_name,
        turn_addr = %cfg.turn_addr,
        bind_addr = %cfg.bind_addr,
        advertise = %cfg.advertise_addr,
        seeds = ?cfg.seeds,
        interval = ?interval,
        timeout = ?timeout,
        authenticated = cfg.secret.is_some(),
        "cluster gossip started"
    );
    if cfg.secret.is_none() {
        warn!(
            "cluster gossip has no shared secret; any host that can reach the \
               gossip port can inject nodes into the ring. Set cluster.secret."
        );
    }

    publish_topology(&cfg, &peers, &mut last_topology, &on_change);

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                seq = seq.wrapping_add(1);
                if let Some(frame) = encode_frame(&cfg, seq, &peers, false) {
                    broadcast(&socket, &cfg.seeds, &peers, &frame).await;
                }

                let now = Instant::now();
                let before = peers.len();
                peers.retain(|node_id, node| {
                    let live = now.duration_since(node.last_seen) <= timeout;
                    if !live {
                        info!(%node_id, "cluster gossip peer expired");
                    }
                    live
                });
                tombstones.retain(|_, until| *until > now);
                if peers.len() != before {
                    publish_topology(&cfg, &peers, &mut last_topology, &on_change);
                }
            }
            recv = socket.recv_from(&mut rx_buf) => {
                let (len, src) = match recv {
                    Ok(v) => v,
                    Err(e) => {
                        warn!(%e, "gossip recv failed");
                        continue;
                    }
                };
                let payload = match verify_frame(cfg.secret.as_deref(), &rx_buf[..len]) {
                    Some(p) => p,
                    None => {
                        debug!(%src, "gossip message failed authentication");
                        continue;
                    }
                };
                let msg: GossipMessage = match serde_json::from_slice(payload) {
                    Ok(m) => m,
                    Err(e) => {
                        debug!(%src, %e, "invalid gossip payload");
                        continue;
                    }
                };
                if msg.cluster_name != cfg.cluster_name {
                    debug!(%src, theirs = %msg.cluster_name, ours = %cfg.cluster_name,
                           "dropping gossip from a different cluster");
                    continue;
                }

                // Prefer the sender's advertised address over the packet src.
                let sender_addr = effective_addr(msg.advertise_addr, src);

                let mut changed = false;
                if msg.leaving {
                    changed |= apply_leaving(
                        &cfg.node_id, &mut peers, &mut tombstones,
                        &msg.node_id, msg.seq, tombstone_grace,
                    );
                } else {
                    changed |= observe_peer(
                        &cfg.node_id, &mut peers, &mut tombstones,
                        &msg.node_id, msg.turn_addr, sender_addr, msg.seq, true,
                    );
                }

                for entry in &msg.peers {
                    changed |= observe_peer(
                        &cfg.node_id, &mut peers, &mut tombstones,
                        &entry.node_id, entry.turn_addr, entry.gossip_addr, entry.seq, false,
                    );
                }

                if changed {
                    publish_topology(&cfg, &peers, &mut last_topology, &on_change);
                }
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    seq = seq.wrapping_add(1);
                    if let Some(frame) = encode_frame(&cfg, seq, &peers, true) {
                        broadcast(&socket, &cfg.seeds, &peers, &frame).await;
                    }
                    info!(node_id = %cfg.node_id, "cluster gossip stopped");
                    break;
                }
            }
        }
    }

    Ok(())
}

/// The address peers should use for a node: its advertised endpoint when set,
/// otherwise the source address the packet actually came from.
fn effective_addr(advertised: SocketAddr, src: SocketAddr) -> SocketAddr {
    if advertised.ip().is_unspecified() || advertised.port() == 0 {
        src
    } else {
        advertised
    }
}

fn encode_frame(
    cfg: &GossipConfig,
    seq: u64,
    peers: &HashMap<String, GossipNode>,
    leaving: bool,
) -> Option<Vec<u8>> {
    let msg = GossipMessage {
        cluster_name: cfg.cluster_name.clone(),
        node_id: cfg.node_id.clone(),
        turn_addr: cfg.turn_addr,
        seq,
        advertise_addr: cfg.advertise_addr,
        peers: peers.values().map(GossipNode::peer_entry).collect(),
        leaving,
    };
    let payload = match serde_json::to_vec(&msg) {
        Ok(p) => p,
        Err(e) => {
            warn!(%e, "failed to encode gossip message");
            return None;
        }
    };
    Some(sign_frame(cfg.secret.as_deref(), payload))
}

/// `secret` set => prepend a 32-byte HMAC-SHA256 tag; otherwise send raw JSON.
fn sign_frame(secret: Option<&[u8]>, payload: Vec<u8>) -> Vec<u8> {
    match secret {
        Some(key) => {
            let mut mac =
                <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
            mac.update(&payload);
            let tag = mac.finalize().into_bytes();
            let mut out = Vec::with_capacity(tag.len() + payload.len());
            out.extend_from_slice(&tag);
            out.extend_from_slice(&payload);
            out
        }
        None => payload,
    }
}

/// Verify and strip the HMAC tag. Returns the JSON payload, or `None` if the
/// tag is missing/invalid. Comparison is constant-time (`verify_slice`).
fn verify_frame<'a>(secret: Option<&[u8]>, buf: &'a [u8]) -> Option<&'a [u8]> {
    match secret {
        Some(key) => {
            if buf.len() < 32 {
                return None;
            }
            let (tag, payload) = buf.split_at(32);
            let mut mac = <HmacSha256 as Mac>::new_from_slice(key).ok()?;
            mac.update(payload);
            mac.verify_slice(tag).ok()?;
            Some(payload)
        }
        None => Some(buf),
    }
}

async fn broadcast(
    socket: &UdpSocket,
    seeds: &[String],
    peers: &HashMap<String, GossipNode>,
    payload: &[u8],
) {
    for seed in seeds {
        if let Err(e) = socket.send_to(payload, seed.as_str()).await {
            debug!(seed = %seed, %e, "gossip seed send failed");
        }
    }
    let peer_addrs: Vec<SocketAddr> = peers.values().map(|p| p.gossip_addr).collect();
    for addr in peer_addrs {
        if let Err(e) = socket.send_to(payload, addr).await {
            debug!(peer = %addr, %e, "gossip peer send failed");
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn observe_peer(
    local_id: &str,
    peers: &mut HashMap<String, GossipNode>,
    tombstones: &mut HashMap<String, Instant>,
    node_id: &str,
    turn_addr: SocketAddr,
    gossip_addr: SocketAddr,
    seq: u64,
    direct: bool,
) -> bool {
    if node_id == local_id {
        return false;
    }
    if direct {
        tombstones.remove(node_id);
    } else if tombstones.contains_key(node_id) {
        return false;
    }
    match peers.get_mut(node_id) {
        Some(node) => {
            let mut changed = false;
            if seq > node.seq || direct {
                if node.turn_addr != turn_addr {
                    node.turn_addr = turn_addr;
                    changed = true;
                }
                node.gossip_addr = gossip_addr;
                if seq > node.seq {
                    node.seq = seq;
                    node.last_seen = Instant::now();
                } else if direct {
                    node.last_seen = Instant::now();
                }
            }
            changed
        }
        None => {
            peers.insert(
                node_id.to_string(),
                GossipNode {
                    node_id: node_id.to_string(),
                    turn_addr,
                    gossip_addr,
                    seq,
                    last_seen: Instant::now(),
                },
            );
            info!(%node_id, %turn_addr, %gossip_addr, direct, "cluster gossip peer discovered");
            true
        }
    }
}

/// Handle a `leaving` frame with replay protection (F-8). Returns whether the
/// topology changed.
///
/// The frame is HMAC-signed, so this is not about forgery — it is replay
/// protection. A `leaving` is honoured only when its `seq` is strictly newer
/// than the last sequence recorded for the node. A node's final frame carries
/// `last_seq + 1`, so a genuine leaving is strictly greater than the seq we last
/// stored; a replayed (but genuine) stale `leaving` must not evict a node that
/// has since advanced past it.
///
/// An unknown node (no stored seq) is not acted on: there is nothing to drop,
/// and planting an unvalidatable tombstone would itself be a replay vector. A
/// stale indirect entry self-heals via the `last_seen` reaper in `run_gossip`.
fn apply_leaving(
    local_id: &str,
    peers: &mut HashMap<String, GossipNode>,
    tombstones: &mut HashMap<String, Instant>,
    node_id: &str,
    seq: u64,
    tombstone_grace: Duration,
) -> bool {
    if node_id == local_id {
        return false;
    }
    let fresh = peers.get(node_id).is_some_and(|node| seq > node.seq);
    if !fresh {
        debug!(%node_id, seq, "ignoring stale or unknown gossip leaving");
        return false;
    }
    peers.remove(node_id);
    tombstones.insert(node_id.to_string(), Instant::now() + tombstone_grace);
    info!(%node_id, seq, "cluster gossip peer left");
    true
}

fn publish_topology(
    cfg: &GossipConfig,
    peers: &HashMap<String, GossipNode>,
    last_topology: &mut Vec<ClusterNode>,
    on_change: &Arc<dyn Fn(Vec<ClusterNode>) + Send + Sync>,
) {
    let mut nodes = Vec::with_capacity(peers.len() + 1);
    nodes.push(ClusterNode {
        node_id: cfg.node_id.clone(),
        turn_addr: cfg.turn_addr,
    });
    nodes.extend(peers.values().map(GossipNode::cluster_node));
    nodes.sort_by(|a, b| a.node_id.cmp(&b.node_id));
    nodes.dedup_by(|a, b| a.node_id == b.node_id);

    if &nodes != last_topology {
        info!(nodes = nodes.len(), "cluster topology changed");
        *last_topology = nodes.clone();
        on_change(nodes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(p: u16) -> SocketAddr {
        format!("127.0.0.1:{p}").parse().unwrap()
    }

    #[test]
    fn indirect_peer_is_learned_and_changes_topology() {
        let mut peers = HashMap::new();
        let mut tomb = HashMap::new();
        let changed = observe_peer(
            "node-a",
            &mut peers,
            &mut tomb,
            "node-c",
            addr(3480),
            addr(7948),
            5,
            false,
        );
        assert!(changed);
        assert!(peers.contains_key("node-c"));
    }

    #[test]
    fn own_id_is_ignored() {
        let mut peers = HashMap::new();
        let mut tomb = HashMap::new();
        let changed = observe_peer(
            "node-a",
            &mut peers,
            &mut tomb,
            "node-a",
            addr(3478),
            addr(7946),
            9,
            true,
        );
        assert!(!changed);
        assert!(peers.is_empty());
    }

    #[test]
    fn stale_indirect_seq_does_not_refresh() {
        let mut peers = HashMap::new();
        let mut tomb = HashMap::new();
        observe_peer(
            "node-a",
            &mut peers,
            &mut tomb,
            "node-b",
            addr(3479),
            addr(7947),
            10,
            true,
        );
        let first_seen = peers["node-b"].last_seen;
        std::thread::sleep(Duration::from_millis(5));
        observe_peer(
            "node-a",
            &mut peers,
            &mut tomb,
            "node-b",
            addr(3479),
            addr(7947),
            7,
            false,
        );
        assert_eq!(peers["node-b"].last_seen, first_seen);
        assert_eq!(peers["node-b"].seq, 10);
    }

    #[test]
    fn tombstone_blocks_indirect_resurrection_but_allows_direct_rejoin() {
        let mut peers = HashMap::new();
        let mut tomb = HashMap::new();
        tomb.insert(
            "node-b".to_string(),
            Instant::now() + Duration::from_secs(60),
        );
        let c1 = observe_peer(
            "node-a",
            &mut peers,
            &mut tomb,
            "node-b",
            addr(3479),
            addr(7947),
            12,
            false,
        );
        assert!(!c1);
        assert!(peers.is_empty());
        let c2 = observe_peer(
            "node-a",
            &mut peers,
            &mut tomb,
            "node-b",
            addr(3479),
            addr(7947),
            1,
            true,
        );
        assert!(c2);
        assert!(peers.contains_key("node-b"));
        assert!(!tomb.contains_key("node-b"));
    }

    #[test]
    fn leaving_with_stale_seq_is_ignored_but_fresh_seq_evicts() {
        let mut peers = HashMap::new();
        let mut tomb = HashMap::new();
        let grace = Duration::from_secs(5);

        // Node B is known at seq=100.
        observe_peer(
            "node-a",
            &mut peers,
            &mut tomb,
            "node-b",
            addr(3479),
            addr(7947),
            100,
            true,
        );
        assert_eq!(peers["node-b"].seq, 100);

        // A replayed (stale) leaving must NOT evict it and must NOT tombstone.
        let changed = apply_leaving("node-a", &mut peers, &mut tomb, "node-b", 50, grace);
        assert!(!changed, "stale leaving must not change topology");
        assert!(
            peers.contains_key("node-b"),
            "stale leaving must not evict the peer"
        );
        assert!(
            !tomb.contains_key("node-b"),
            "stale leaving must not plant a tombstone"
        );

        // A fresh leaving (seq > stored) evicts and tombstones.
        let changed = apply_leaving("node-a", &mut peers, &mut tomb, "node-b", 101, grace);
        assert!(changed, "fresh leaving must change topology");
        assert!(
            !peers.contains_key("node-b"),
            "fresh leaving must evict the peer"
        );
        assert!(
            tomb.contains_key("node-b"),
            "fresh leaving must plant a tombstone"
        );
    }

    #[test]
    fn leaving_for_unknown_node_is_ignored() {
        let mut peers = HashMap::new();
        let mut tomb = HashMap::new();
        let changed = apply_leaving(
            "node-a",
            &mut peers,
            &mut tomb,
            "node-x",
            999,
            Duration::from_secs(5),
        );
        assert!(!changed);
        assert!(
            tomb.is_empty(),
            "an unknown-node leaving must not plant a tombstone"
        );
    }

    #[test]
    fn leaving_for_own_id_is_ignored() {
        let mut peers = HashMap::new();
        let mut tomb = HashMap::new();
        let changed = apply_leaving(
            "node-a",
            &mut peers,
            &mut tomb,
            "node-a",
            999,
            Duration::from_secs(5),
        );
        assert!(!changed);
        assert!(tomb.is_empty());
    }

    #[test]
    fn signed_frame_roundtrips_and_rejects_tampering() {
        let secret = b"super-secret".to_vec();
        let signed = sign_frame(Some(&secret), b"hello".to_vec());
        assert_eq!(verify_frame(Some(&secret), &signed), Some(&b"hello"[..]));

        // Wrong key rejected.
        assert!(verify_frame(Some(b"other"), &signed).is_none());
        // Tampered payload rejected.
        let mut bad = signed.clone();
        *bad.last_mut().unwrap() ^= 0xff;
        assert!(verify_frame(Some(&secret), &bad).is_none());
        // Too short rejected.
        assert!(verify_frame(Some(&secret), b"x").is_none());
    }

    #[test]
    fn unsigned_mode_passes_through() {
        let signed = sign_frame(None, b"payload".to_vec());
        assert_eq!(signed, b"payload");
        assert_eq!(verify_frame(None, b"payload"), Some(&b"payload"[..]));
    }

    #[test]
    fn advertised_addr_overrides_src_else_falls_back() {
        let src = addr(40000);
        // Unspecified advertise -> use src.
        assert_eq!(effective_addr("0.0.0.0:0".parse().unwrap(), src), src);
        // Explicit advertise -> use it.
        let adv: SocketAddr = "10.0.0.5:7946".parse().unwrap();
        assert_eq!(effective_addr(adv, src), adv);
    }
}
