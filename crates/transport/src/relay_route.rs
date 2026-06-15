//! Relay-socket ownership routing for the io_uring worker pool
//! (RFC 8016 sharded ownership / relay-affinity).
//!
//! A relay socket is strictly ring/worker-bound: only its owning worker may
//! send through it (registered fd, per-relay msghdr slab, in-flight SQE
//! accounting all live on one ring). After a client migration the client's
//! main-socket traffic may reshard onto a *different* worker; that worker does
//! NOT touch the socket — it forwards the send to the owner through the owner's
//! command channel. The relay socket itself never moves.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use bytes::Bytes;

pub type WorkerId = usize;
/// Multi-producer (every other worker) → single-consumer (the owner). `std`
/// mpsc is exactly this shape; `Sender` is `Clone + Send`.
pub type WorkerTx = std::sync::mpsc::Sender<WorkerCommand>;

/// A command delivered to a worker's inbound channel.
#[derive(Debug)]
pub enum WorkerCommand {
    /// A relay send routed to the OWNER of `relay_port`. The owner performs the
    /// actual `submit_relay_send`. This variant is already at its destination
    /// and MUST NOT be routed again (anti-loop is structural: the owner path
    /// never calls `route_send`).
    SendViaRelayOwned {
        allocation_id: String,
        generation: u64,
        relay_port: u16,
        peer_addr: SocketAddr,
        payload: Bytes,
    },
}

/// Owner record for a relay port.
#[derive(Clone)]
pub struct RelayOwner {
    pub worker_id: WorkerId,
    pub tx: WorkerTx,
    pub allocation_id: String,
    pub generation: u64,
}

/// What a non-owning worker should do with a relay send.
pub enum RouteDecision {
    Forward {
        tx: WorkerTx,
        cmd: WorkerCommand,
    },
    /// No route for the port — drop + count.
    Miss,
    /// Route points back at the asking worker — local relay map desynced (bug).
    SelfOwned,
}

/// Owner-side validation of an incoming `SendViaRelayOwned`.
pub enum OwnedSendOutcome {
    Send,
    StaleAllocation,
    MissingSocket,
}

/// Classify a forwarded owned-command against the owner's local per-port record
/// `(allocation_id, generation)`. Pure → unit-testable; the owner never
/// re-forwards regardless of outcome.
pub fn classify_owned_command(
    local: Option<&(String, u64)>,
    allocation_id: &str,
    generation: u64,
) -> OwnedSendOutcome {
    match local {
        None => OwnedSendOutcome::MissingSocket,
        Some((aid, g)) if aid == allocation_id && *g == generation => OwnedSendOutcome::Send,
        Some(_) => OwnedSendOutcome::StaleAllocation,
    }
}

#[derive(Debug, Default)]
pub struct RelayRouteStats {
    pub send_local: AtomicU64,
    pub send_forwarded: AtomicU64,
    pub send_forward_failed: AtomicU64,
    pub send_stale: AtomicU64,
    pub route_miss: AtomicU64,
    pub owner_cleanup_stale: AtomicU64,
}

/// A plain (non-atomic) copy of [`RelayRouteStats`] for export.
///
/// The forward path lives entirely in atomics so the hot path stays
/// lock-free; for a metrics scrape we want a flat, `Copy` value that crosses
/// crate boundaries without dragging the atomics out one by one. Loads are
/// `Relaxed` — a scrape does not need cross-counter consistency.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RelayRouteSnapshot {
    pub send_local: u64,
    pub send_forwarded: u64,
    pub send_forward_failed: u64,
    pub send_stale: u64,
    pub route_miss: u64,
    pub owner_cleanup_stale: u64,
}

impl RelayRouteStats {
    /// Relaxed snapshot of every counter.
    pub fn snapshot(&self) -> RelayRouteSnapshot {
        RelayRouteSnapshot {
            send_local: self.send_local.load(Ordering::Relaxed),
            send_forwarded: self.send_forwarded.load(Ordering::Relaxed),
            send_forward_failed: self.send_forward_failed.load(Ordering::Relaxed),
            send_stale: self.send_stale.load(Ordering::Relaxed),
            route_miss: self.route_miss.load(Ordering::Relaxed),
            owner_cleanup_stale: self.owner_cleanup_stale.load(Ordering::Relaxed),
        }
    }
}

impl RelayRouteSnapshot {
    /// Fraction of relay sends that had to be forwarded to the owning worker,
    /// i.e. `forwarded / (local + forwarded)`. This is the real per-scrape
    /// "cost of migration": 0.0 when every send is handled locally, climbing
    /// as resharded clients force cross-worker forwards. Returns 0.0 when no
    /// sends have happened yet (avoids a 0/0 NaN in the metric).
    pub fn forwarded_ratio(&self) -> f64 {
        let denom = self.send_local + self.send_forwarded;
        if denom == 0 {
            0.0
        } else {
            self.send_forwarded as f64 / denom as f64
        }
    }
}

/// Shared routing table `relay_port -> RelayOwner` plus a per-port generation
/// counter guarding against stale routing on port reuse.
pub struct RelayRoutes {
    inner: Mutex<HashMap<u16, RelayOwner>>,
    gen: Mutex<HashMap<u16, u64>>,
    pub stats: RelayRouteStats,
}

impl RelayRoutes {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(HashMap::new()),
            gen: Mutex::new(HashMap::new()),
            stats: RelayRouteStats::default(),
        })
    }

    /// Register `worker_id` as owner of `relay_port`. Bumps the per-port
    /// generation and returns it; the caller stores it locally and passes it
    /// back to `unregister_if` for conditional cleanup.
    pub fn register(
        &self,
        relay_port: u16,
        worker_id: WorkerId,
        tx: WorkerTx,
        allocation_id: String,
    ) -> u64 {
        let generation = {
            let mut g = self.gen.lock().unwrap();
            let e = g.entry(relay_port).or_insert(0);
            *e = e.wrapping_add(1);
            *e
        };
        self.inner.lock().unwrap().insert(
            relay_port,
            RelayOwner { worker_id, tx, allocation_id, generation },
        );
        generation
    }

    /// Conditional cleanup: remove the route ONLY if it still matches
    /// `(allocation_id, generation)`. Returns whether it was removed. A
    /// mismatch (port already re-owned by a newer allocation) is left intact
    /// and counted.
    pub fn unregister_if(&self, relay_port: u16, allocation_id: &str, generation: u64) -> bool {
        let mut map = self.inner.lock().unwrap();
        match map.get(&relay_port) {
            Some(o) if o.allocation_id == allocation_id && o.generation == generation => {
                map.remove(&relay_port);
                true
            }
            _ => {
                self.stats.owner_cleanup_stale.fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }

    pub fn lookup(&self, relay_port: u16) -> Option<RelayOwner> {
        self.inner.lock().unwrap().get(&relay_port).cloned()
    }

    /// Snapshot the forwarding counters for metrics export. See
    /// [`RelayRouteStats::snapshot`].
    pub fn snapshot(&self) -> RelayRouteSnapshot {
        self.stats.snapshot()
    }

    /// Decide how a non-owning worker should handle a relay send. Only called
    /// after a LOCAL relay-socket miss.
    pub fn route_send(
        &self,
        self_worker: WorkerId,
        relay_port: u16,
        peer_addr: SocketAddr,
        payload: Bytes,
    ) -> RouteDecision {
        match self.lookup(relay_port) {
            None => {
                self.stats.route_miss.fetch_add(1, Ordering::Relaxed);
                RouteDecision::Miss
            }
            Some(o) if o.worker_id == self_worker => RouteDecision::SelfOwned,
            Some(o) => RouteDecision::Forward {
                tx: o.tx.clone(),
                cmd: WorkerCommand::SendViaRelayOwned {
                    allocation_id: o.allocation_id.clone(),
                    generation: o.generation,
                    relay_port,
                    peer_addr,
                    payload,
                },
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    fn sa(s: &str) -> SocketAddr { s.parse().unwrap() }

    #[test]
    fn register_lookup_and_generation_bump() {
        let r = RelayRoutes::new();
        let (tx, _rx) = mpsc::channel();
        let g1 = r.register(40000, 1, tx.clone(), "A".into());
        assert_eq!(g1, 1);
        let o = r.lookup(40000).unwrap();
        assert_eq!(o.worker_id, 1);
        assert_eq!(o.allocation_id, "A");
        assert_eq!(o.generation, 1);
        // Re-register (port reuse) bumps generation.
        let g2 = r.register(40000, 3, tx, "B".into());
        assert_eq!(g2, 2);
        assert_eq!(r.lookup(40000).unwrap().generation, 2);
        assert_eq!(r.lookup(40000).unwrap().worker_id, 3);
    }

    #[test]
    fn conditional_unregister_matches() {
        let r = RelayRoutes::new();
        let (tx, _rx) = mpsc::channel();
        let g = r.register(40001, 1, tx, "A".into());
        assert!(r.unregister_if(40001, "A", g));
        assert!(r.lookup(40001).is_none());
    }

    #[test]
    fn stale_unregister_does_not_delete_newer_owner() {
        let r = RelayRoutes::new();
        let (tx, _rx) = mpsc::channel();
        // Allocation A on W1, gen 1.
        let g_a = r.register(40002, 1, tx.clone(), "A".into());
        // Port reused by allocation B on W3, gen 2.
        let _g_b = r.register(40002, 3, tx, "B".into());
        // Late cleanup of A must NOT remove B's route.
        assert!(!r.unregister_if(40002, "A", g_a));
        let still = r.lookup(40002).unwrap();
        assert_eq!(still.allocation_id, "B");
        assert_eq!(still.worker_id, 3);
        assert_eq!(r.stats.owner_cleanup_stale.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn route_send_miss() {
        let r = RelayRoutes::new();
        match r.route_send(2, 49999, sa("1.2.3.4:5"), Bytes::from_static(b"x")) {
            RouteDecision::Miss => {}
            _ => panic!("expected miss"),
        }
        assert_eq!(r.stats.route_miss.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn route_send_self_owned_is_flagged() {
        let r = RelayRoutes::new();
        let (tx, _rx) = mpsc::channel();
        r.register(40003, 2, tx, "A".into());
        match r.route_send(2, 40003, sa("1.2.3.4:5"), Bytes::from_static(b"x")) {
            RouteDecision::SelfOwned => {}
            _ => panic!("expected self-owned desync flag"),
        }
    }

    #[test]
    fn route_send_forwards_with_owner_identity() {
        let r = RelayRoutes::new();
        let (tx, rx) = mpsc::channel();
        let g = r.register(40004, 1, tx, "A".into());
        match r.route_send(2, 40004, sa("9.9.9.9:7"), Bytes::from_static(b"hi")) {
            RouteDecision::Forward { tx, cmd, .. } => {
                tx.send(cmd).unwrap();
                match rx.recv().unwrap() {
                    WorkerCommand::SendViaRelayOwned { allocation_id, generation, relay_port, peer_addr, payload } => {
                        assert_eq!(allocation_id, "A");
                        assert_eq!(generation, g);
                        assert_eq!(relay_port, 40004);
                        assert_eq!(peer_addr, sa("9.9.9.9:7"));
                        assert_eq!(&payload[..], b"hi");
                    }
                }
            }
            _ => panic!("expected forward"),
        }
    }

    #[test]
    fn classify_owned_command_outcomes() {
        let local = ("A".to_string(), 5u64);
        assert!(matches!(classify_owned_command(Some(&local), "A", 5), OwnedSendOutcome::Send));
        assert!(matches!(classify_owned_command(Some(&local), "A", 4), OwnedSendOutcome::StaleAllocation));
        assert!(matches!(classify_owned_command(Some(&local), "B", 5), OwnedSendOutcome::StaleAllocation));
        assert!(matches!(classify_owned_command(None, "A", 5), OwnedSendOutcome::MissingSocket));
    }

    /// Spec's stub-worker integration test (no io_uring): W1 owns P, W2 gets a
    /// relay send for P, forwards to W1; W1's fake_send fires exactly once,
    /// W2's never; the owned command is NOT re-routed.
    #[test]
    fn stub_worker_forward_fires_once_on_owner() {
        use std::sync::atomic::AtomicU64;
        let routes = RelayRoutes::new();

        // W1 (owner) thread: drains its channel, validates, fake_sends.
        let (w1_tx, w1_rx) = mpsc::channel::<WorkerCommand>();
        let w1_sends = Arc::new(AtomicU64::new(0));
        let w1_reforwards = Arc::new(AtomicU64::new(0));
        let port = 40010u16;
        let g = routes.register(port, 1, w1_tx, "A".into());

        let w1_sends_c = w1_sends.clone();
        let w1_reforwards_c = w1_reforwards.clone();
        let routes_c = routes.clone();
        let owner = std::thread::spawn(move || {
            // owner's local per-port record
            let mut owned: HashMap<u16, (String, u64)> = HashMap::new();
            owned.insert(port, ("A".into(), g));
            // process exactly one command
            let cmd = w1_rx.recv().unwrap();
            match cmd {
                WorkerCommand::SendViaRelayOwned { allocation_id, generation, relay_port, .. } => {
                    // owner MUST NOT consult the route table for owned commands
                    // (anti-loop). We assert that by counting any (illegal) re-route.
                    if let RouteDecision::Forward { .. } =
                        routes_c.route_send(1, relay_port, "0.0.0.0:0".parse().unwrap(), Bytes::new())
                    {
                        // this would be a re-forward to self — but worker_id==1==self
                        // so route_send returns SelfOwned, never Forward. Guard anyway:
                        w1_reforwards_c.fetch_add(1, Ordering::Relaxed);
                    }
                    match classify_owned_command(owned.get(&relay_port), &allocation_id, generation) {
                        OwnedSendOutcome::Send => { w1_sends_c.fetch_add(1, Ordering::Relaxed); }
                        _ => {}
                    }
                }
            }
        });

        // W2 (non-owner): local miss → route → forward to W1.
        let w2_sends = AtomicU64::new(0);
        match routes.route_send(2, port, sa("5.5.5.5:5"), Bytes::from_static(b"pkt")) {
            RouteDecision::Forward { tx, cmd, .. } => { tx.send(cmd).unwrap(); }
            _ => panic!("W2 should forward to owner"),
        }
        // W2 never sends locally.
        assert_eq!(w2_sends.load(Ordering::Relaxed), 0);

        owner.join().unwrap();
        assert_eq!(w1_sends.load(Ordering::Relaxed), 1, "owner fake_send exactly once");
        assert_eq!(w1_reforwards.load(Ordering::Relaxed), 0, "owned command must not re-forward");
    }

    #[test]
    fn snapshot_reflects_counters_and_ratio() {
        let r = RelayRoutes::new();
        // No traffic yet: ratio must be a clean 0.0, not 0/0 NaN.
        let s0 = r.snapshot();
        assert_eq!(s0, RelayRouteSnapshot::default());
        assert_eq!(s0.forwarded_ratio(), 0.0);

        // 3 local + 1 forwarded → ratio 0.25.
        r.stats.send_local.fetch_add(3, Ordering::Relaxed);
        r.stats.send_forwarded.fetch_add(1, Ordering::Relaxed);
        r.stats.route_miss.fetch_add(2, Ordering::Relaxed);
        let s = r.snapshot();
        assert_eq!(s.send_local, 3);
        assert_eq!(s.send_forwarded, 1);
        assert_eq!(s.route_miss, 2);
        assert!((s.forwarded_ratio() - 0.25).abs() < 1e-9);
    }
}
