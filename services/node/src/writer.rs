//! Write-behind writer task for `AllocationStore`.
//!
//! Drains the `WriteOp` channel, coalesces events by `relay_port` inside a
//! per-port batch, and flushes the batch to a `turna_state_backend::Backend`.
//!
//! See `docs/design/allocation-store-persistence.md` §4 for the rationale.
//!
//! ## Hot-path contract
//!
//! - The writer never back-pressures the data plane. Hot-path sends are
//!   non-blocking `try_send`s; if our channel fills, the store drops events
//!   and increments its own counter (we surface that as Prometheus metric
//!   `tarantool_writes_dropped_total`).
//! - All `Backend` errors are logged and skipped — a failing Tarantool
//!   does not crash the node; in-memory state remains authoritative.
//! - On shutdown we flush whatever is in the partial batch, then exit.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, watch};
use tokio::time::{sleep_until, Instant};
use tracing::{debug, info, warn};

use turna_health::Metrics;
use turna_session::{AllocationStore, WriteOp};
use turna_state_backend::{Backend, BackendError, StoredAllocation, StoredChannel};

// ---------------------------------------------------------------------------
// Public configuration & metrics
// ---------------------------------------------------------------------------

/// Tunable parameters for the writer task. Mirrors the fields of
/// `turna_config::PersistenceConfig` so the caller can pass them in directly.
#[derive(Debug, Clone)]
pub struct WriterConfig {
    pub channel_capacity: usize,
    pub batch_max_size: usize,
    pub batch_max_delay: Duration,
    /// Node identity stamped onto every `StoredAllocation`. Required so
    /// PR5's failover task can ask `Backend::find_by_node(my_id)` and pick
    /// up orphans.
    pub node_id: String,
}

/// Counters owned by the writer task. We bump these as we go and then
/// copy them into the shared `turna_health::Metrics` so they appear on
/// `/metrics`. The copy happens on every flush — cheap, and keeps the
/// `Metrics` struct itself decoupled from this module's internals.
#[derive(Debug, Default)]
pub struct WriterCounters {
    pub batches: AtomicU64,
    pub ops_create: AtomicU64,
    pub ops_refresh: AtomicU64,
    pub ops_remove: AtomicU64,
    pub ops_perm: AtomicU64,
    pub ops_chan: AtomicU64,
    pub coalesced: AtomicU64,
    pub backend_errors: AtomicU64,
}

// ---------------------------------------------------------------------------
// Internal batch model
// ---------------------------------------------------------------------------

/// What "happened" to an allocation inside one batch.
///
/// `New` carries the full `Create` payload — sufficient to construct a
/// `StoredAllocation` without consulting the backend.
///
/// `Touched` means we observed a Refresh/Permission/Channel but no Create
/// in this batch. To flush this correctly we must read the existing
/// allocation, merge our changes, and write it back. This is a deliberate
/// trade-off: simple and correct, at the cost of an extra round-trip per
/// touched-but-not-created port. See module docs.
///
/// `Removed` means a Remove was the last terminal event. Earlier ops for
/// this port within the same batch are discarded — that's coalescing.
#[derive(Debug)]
enum PortState {
    New(CreateData),
    Touched,
    Removed,
}

#[derive(Debug, Clone)]
struct CreateData {
    client_addr: SocketAddr,
    relay_addr: SocketAddr,
    username: String,
    /// RFC 8016 stable identity, persisted so a MOBILITY-TICKET survives a
    /// cross-node failover (see `StoredAllocation::allocation_id`).
    allocation_id: String,
    /// RFC 8016 migration generation at the time this Create/ReKey was seen.
    migration_epoch: u64,
    created_at_ms: u64,
    expires_at_ms: u64,
}

#[derive(Debug)]
struct PortBatch {
    state: PortState,
    /// Latest expires_at_ms from any Refresh seen for this port.
    /// Applied to whichever `StoredAllocation` we end up writing.
    refresh_expires: Option<u64>,
    /// RFC 8016 connection migration: the latest re-keyed client_addr for
    /// this port, if a `ReKey` was seen in this batch. When set, the flush
    /// path overrides `client_addr` on whatever `StoredAllocation` it writes
    /// so the persisted record tracks the migrated 5-tuple (and failover /
    /// rehydrate restore the client on its current address, not the stale
    /// one). The relay binding is unchanged, so only `client_addr` moves.
    rekey_addr: Option<SocketAddr>,
    /// The post-bump `migration_epoch` from a `ReKey` seen in this batch, if
    /// any. Applied to the persisted record alongside `rekey_addr` so the
    /// stored epoch tracks the in-memory one across failover.
    rekey_epoch: Option<u64>,
    /// peer_ip → expires_at_ms. Last write wins.
    perms: HashMap<IpAddr, u64>,
    /// channel_number → (peer, expires_at_ms). Last write wins.
    chans: HashMap<u16, (SocketAddr, u64)>,
}

impl PortBatch {
    fn new_touched() -> Self {
        Self {
            state: PortState::Touched,
            refresh_expires: None,
            rekey_addr: None,
            rekey_epoch: None,
            perms: HashMap::new(),
            chans: HashMap::new(),
        }
    }

    fn new_created(data: CreateData) -> Self {
        Self {
            state: PortState::New(data),
            refresh_expires: None,
            rekey_addr: None,
            rekey_epoch: None,
            perms: HashMap::new(),
            chans: HashMap::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Coalescing
// ---------------------------------------------------------------------------

/// Apply one `WriteOp` to the current batch.
///
/// Returns `true` if this op was *coalesced away* (i.e. it overwrote a
/// previous one without adding net work). We count those for visibility.
fn apply(batch: &mut HashMap<u16, PortBatch>, op: WriteOp) -> bool {
    let port = op.relay_port();
    match op {
        WriteOp::Create {
            client_addr,
            relay_addr,
            username,
            created_at_ms,
            expires_at_ms,
            allocation_id,
            migration_epoch,
            ..
        } => {
            let data = CreateData {
                client_addr,
                relay_addr,
                username,
                allocation_id,
                migration_epoch,
                created_at_ms,
                expires_at_ms,
            };
            let coalesced = matches!(
                batch.get(&port).map(|b| &b.state),
                Some(PortState::New(_)) | Some(PortState::Removed)
            );
            // Create after Remove (same port reused mid-batch) replaces.
            // Create after Create shouldn't happen but we tolerate it.
            batch.insert(port, PortBatch::new_created(data));
            coalesced
        }
        WriteOp::ReKey {
            new_client_addr,
            new_epoch,
            ..
        } => {
            // RFC 8016 re-key: the client's 5-tuple moved (Wi-Fi → cellular);
            // the relay binding is unchanged. We must make the persisted
            // record track the new client_addr, covering two cases:
            //
            //   1. A Create for this port is still pending in *this* batch
            //      (not yet flushed): patch its address in place so
            //      `build_stored` writes the fresh one — the backend never
            //      sees the stale address at all.
            //   2. The record was flushed in an earlier batch (the common
            //      migration case): record `rekey_addr` so the flush reads
            //      the existing record and rewrites `client_addr` before
            //      storing it back (see `flush_port`'s `Touched` path).
            //
            // If no batch entry exists yet we create a `Touched` carrier so
            // case 2 fires. A subsequent Create in the same batch replaces
            // the entry (and resets `rekey_addr`), which is correct: the
            // Create's own `client_addr` is then authoritative.
            match batch.get_mut(&port) {
                Some(pb) => {
                    pb.rekey_addr = Some(new_client_addr);
                    pb.rekey_epoch = Some(new_epoch);
                    if let PortState::New(data) = &mut pb.state {
                        data.client_addr = new_client_addr;
                        data.migration_epoch = new_epoch;
                    }
                    // Folded into an existing batch entry — no net-new port.
                    true
                }
                None => {
                    let mut pb = PortBatch::new_touched();
                    pb.rekey_addr = Some(new_client_addr);
                    pb.rekey_epoch = Some(new_epoch);
                    batch.insert(port, pb);
                    // Net-new entry: a backend read-modify-write will happen.
                    false
                }
            }
        }

        WriteOp::Remove { .. } => {
            // Remove wipes any earlier work for this port.
            // Special case: if there was a Create in this same batch,
            // the allocation never made it to the backend — there's
            // nothing to remove there. We drop the port entirely.
            match batch.remove(&port) {
                Some(PortBatch {
                    state: PortState::New(_),
                    ..
                }) => {
                    // Create+Remove in same batch → no backend roundtrip.
                    true
                }
                Some(_) => {
                    // Touched+Remove → still need to issue Remove to
                    // delete whatever the backend already has.
                    let mut pb = PortBatch::new_touched();
                    pb.state = PortState::Removed;
                    batch.insert(port, pb);
                    true
                }
                None => {
                    let mut pb = PortBatch::new_touched();
                    pb.state = PortState::Removed;
                    batch.insert(port, pb);
                    false
                }
            }
        }
        WriteOp::Refresh { expires_at_ms, .. } => {
            let pb = batch.entry(port).or_insert_with(PortBatch::new_touched);
            let coalesced = pb.refresh_expires.is_some();
            pb.refresh_expires = Some(expires_at_ms);
            // If we'd previously marked this Removed, we can't "un-remove"
            // — but in practice Refresh-after-Remove is a bug upstream;
            // we just record the refresh and let the Removed state win
            // unless a future Create overrides it.
            coalesced
        }
        WriteOp::Permission {
            peer_ip,
            expires_at_ms,
            ..
        } => {
            let pb = batch.entry(port).or_insert_with(PortBatch::new_touched);
            
            pb.perms.insert(peer_ip, expires_at_ms).is_some()
        }
        WriteOp::Channel {
            number,
            peer_addr,
            expires_at_ms,
            ..
        } => {
            let pb = batch.entry(port).or_insert_with(PortBatch::new_touched);
            
            pb
                .chans
                .insert(number, (peer_addr, expires_at_ms))
                .is_some()
        }
    }
}

// ---------------------------------------------------------------------------
// Flush
// ---------------------------------------------------------------------------

async fn flush_port(
    backend: &Backend,
    node_id: &str,
    realm: &str,
    port: u16,
    batch: PortBatch,
    counters: &WriterCounters,
) -> Result<(), BackendError> {
    match batch.state {
        PortState::Removed => {
            counters.ops_remove.fetch_add(1, Ordering::Relaxed);
            backend.remove_allocation(port).await
        }
        PortState::New(data) => {
            counters.ops_create.fetch_add(1, Ordering::Relaxed);
            let expires = batch.refresh_expires.unwrap_or(data.expires_at_ms);
            // `data.client_addr` already reflects any in-batch ReKey (patched
            // in `apply`), so `build_stored` writes the migrated address.
            let stored = build_stored(
                node_id,
                realm,
                port,
                &data,
                expires,
                &batch.perms,
                &batch.chans,
            );
            backend.store_allocation(&stored).await
        }
        PortState::Touched => {
            // No Create in this batch — read existing record, merge our
            // refresh/perms/channels, write back. One extra RTT.
            let existing = match backend.get_allocation(port).await? {
                Some(a) => a,
                None => {
                    // The allocation was already gone in the backend
                    // (cleaned up by another node, or never persisted
                    // because Create was lost upstream). Nothing to do.
                    debug!(port, "Touched batch but no backend record — skipping");
                    return Ok(());
                }
            };
            let mut merged = existing;
            if let Some(exp) = batch.refresh_expires {
                merged.expires_at_ms = exp;
                counters.ops_refresh.fetch_add(1, Ordering::Relaxed);
            }
            // RFC 8016 re-key: the persisted record was written before the
            // client migrated. Rewrite `client_addr` to the new 5-tuple so a
            // later failover/rehydrate restores the client on its current
            // address. The relay binding (relay_addr / relay_port) is
            // untouched — only the client side moves.
            if let Some(addr) = batch.rekey_addr {
                merged.client_addr = addr.to_string();
                debug!(port, new_client = %addr, "persisting migrated client_addr");
            }
            if let Some(ep) = batch.rekey_epoch {
                merged.migration_epoch = ep;
            }
            // Permissions: replace if a newer expiry was emitted.
            // Stored as plain Vec<String>; we keep that shape but dedupe.
            apply_perms(&mut merged.permissions, &batch.perms, counters);
            apply_chans(&mut merged.channels, &batch.chans, counters);
            backend.store_allocation(&merged).await
        }
    }
}

fn build_stored(
    node_id: &str,
    realm: &str,
    port: u16,
    data: &CreateData,
    expires_at_ms: u64,
    perms: &HashMap<IpAddr, u64>,
    chans: &HashMap<u16, (SocketAddr, u64)>,
) -> StoredAllocation {
    StoredAllocation {
        id: format!("{node_id}:{port}"),
        relay_port: port,
        allocation_id: data.allocation_id.clone(),
        migration_epoch: data.migration_epoch,
        client_addr: data.client_addr.to_string(),
        relay_addr: data.relay_addr.to_string(),
        user_id: data.username.clone(),
        realm: realm.to_string(),
        node_id: node_id.to_string(),
        created_at_ms: data.created_at_ms,
        expires_at_ms,
        bytes_in: 0,
        bytes_out: 0,
        packets_in: 0,
        packets_out: 0,
        permissions: perms.keys().map(|ip| ip.to_string()).collect(),
        channels: chans
            .iter()
            .map(|(&n, &(addr, exp))| StoredChannel {
                number: n,
                peer_addr: addr.to_string(),
                expires_at_ms: exp,
            })
            .collect(),
    }
}

fn apply_perms(dst: &mut Vec<String>, src: &HashMap<IpAddr, u64>, counters: &WriterCounters) {
    if src.is_empty() {
        return;
    }
    counters
        .ops_perm
        .fetch_add(src.len() as u64, Ordering::Relaxed);
    // The schema stores permissions as Vec<String> of IPs without expiry
    // (StoredAllocation::permissions is just IPs). We just merge unique.
    use std::collections::BTreeSet;
    let mut set: BTreeSet<String> = dst.drain(..).collect();
    for ip in src.keys() {
        set.insert(ip.to_string());
    }
    dst.extend(set);
}

fn apply_chans(
    dst: &mut Vec<StoredChannel>,
    src: &HashMap<u16, (SocketAddr, u64)>,
    counters: &WriterCounters,
) {
    if src.is_empty() {
        return;
    }
    counters
        .ops_chan
        .fetch_add(src.len() as u64, Ordering::Relaxed);
    // Overwrite by channel number.
    dst.retain(|c| !src.contains_key(&c.number));
    for (&number, &(peer, expires_at_ms)) in src {
        dst.push(StoredChannel {
            number,
            peer_addr: peer.to_string(),
            expires_at_ms,
        });
    }
}

async fn flush_batch(
    backend: &Backend,
    node_id: &str,
    realm: &str,
    batch: HashMap<u16, PortBatch>,
    counters: &WriterCounters,
    metrics: &Metrics,
) {
    let n_ports = batch.len() as u64;
    let mut errors = 0u64;
    for (port, pb) in batch {
        if let Err(e) = flush_port(backend, node_id, realm, port, pb, counters).await {
            errors += 1;
            warn!(port, error = ?e, "backend flush failed for port");
        }
    }
    counters.batches.fetch_add(1, Ordering::Relaxed);
    counters.backend_errors.fetch_add(errors, Ordering::Relaxed);

    // Mirror counters into shared Metrics for /metrics.
    sync_metrics(metrics, counters, 0);
    debug!(n_ports, errors, "writer flushed batch");
}

fn sync_metrics(metrics: &Metrics, counters: &WriterCounters, dropped: u64) {
    metrics
        .tarantool_writer_batches
        .store(counters.batches.load(Ordering::Relaxed), Ordering::Relaxed);
    let ops = counters.ops_create.load(Ordering::Relaxed)
        + counters.ops_refresh.load(Ordering::Relaxed)
        + counters.ops_remove.load(Ordering::Relaxed)
        + counters.ops_perm.load(Ordering::Relaxed)
        + counters.ops_chan.load(Ordering::Relaxed);
    metrics.tarantool_writer_ops.store(ops, Ordering::Relaxed);
    metrics.tarantool_writer_coalesced.store(
        counters.coalesced.load(Ordering::Relaxed),
        Ordering::Relaxed,
    );
    metrics.tarantool_writer_errors.store(
        counters.backend_errors.load(Ordering::Relaxed),
        Ordering::Relaxed,
    );
    if dropped > 0 {
        metrics
            .tarantool_writes_dropped
            .store(dropped, Ordering::Relaxed);
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Run the writer task to completion. Returns when the channel is closed
/// (sender dropped) or when `shutdown_rx` flips to `true`.
#[allow(clippy::too_many_arguments)]
pub async fn run_writer(
    backend: Arc<Backend>,
    store: Arc<AllocationStore>,
    realm: String,
    config: WriterConfig,
    metrics: Arc<Metrics>,
    counters: Arc<WriterCounters>,
    mut rx: mpsc::Receiver<WriteOp>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    info!(
        node_id     = %config.node_id,
        batch_max   = config.batch_max_size,
        batch_delay = ?config.batch_max_delay,
        "writer task started"
    );

    let mut batch: HashMap<u16, PortBatch> = HashMap::new();
    let mut deadline: Option<Instant> = None;

    loop {
        // Pick what to wait on. If we have a partial batch, we have a deadline.
        let until = deadline.unwrap_or_else(|| Instant::now() + Duration::from_secs(3600));

        tokio::select! {
            biased;

            // 1) Shutdown — drain whatever is left and exit.
            res = shutdown_rx.changed() => {
                if res.is_err() || *shutdown_rx.borrow() {
                    info!("writer shutting down — flushing partial batch");
                    if !batch.is_empty() {
                        flush_batch(&backend, &config.node_id, &realm,
                                    std::mem::take(&mut batch),
                                    &counters, &metrics).await;
                    }
                    // Also drain anything queued in the channel.
                    while let Ok(op) = rx.try_recv() {
                        if apply(&mut batch, op) {
                            counters.coalesced.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    if !batch.is_empty() {
                        flush_batch(&backend, &config.node_id, &realm,
                                    std::mem::take(&mut batch),
                                    &counters, &metrics).await;
                    }
                    sync_metrics(&metrics, &counters, store.dropped_writes_count());
                    return;
                }
            }

            // 2) New event from the store.
            recv = rx.recv() => {
                match recv {
                    Some(op) => {
                        let coalesced = apply(&mut batch, op);
                        if coalesced { counters.coalesced.fetch_add(1, Ordering::Relaxed); }
                        if deadline.is_none() {
                            deadline = Some(Instant::now() + config.batch_max_delay);
                        }
                        if batch.len() >= config.batch_max_size {
                            flush_batch(&backend, &config.node_id, &realm,
                                        std::mem::take(&mut batch),
                                        &counters, &metrics).await;
                            deadline = None;
                            sync_metrics(&metrics, &counters,
                                          store.dropped_writes_count());
                        }
                    }
                    None => {
                        // Channel closed — store dropped. Flush and exit.
                        info!("writer channel closed by store — flushing");
                        if !batch.is_empty() {
                            flush_batch(&backend, &config.node_id, &realm,
                                        std::mem::take(&mut batch),
                                        &counters, &metrics).await;
                        }
                        sync_metrics(&metrics, &counters, store.dropped_writes_count());
                        return;
                    }
                }
            }

            // 3) Batch deadline elapsed.
            _ = sleep_until(until), if deadline.is_some() => {
                if !batch.is_empty() {
                    flush_batch(&backend, &config.node_id, &realm,
                                std::mem::take(&mut batch),
                                &counters, &metrics).await;
                    sync_metrics(&metrics, &counters, store.dropped_writes_count());
                }
                deadline = None;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use turna_state_backend::{create_backend, BackendConfig};

    fn ipv4(a: u8, b: u8, c: u8, d: u8, port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(a, b, c, d)), port)
    }

    async fn fresh_backend() -> Arc<Backend> {
        Arc::new(create_backend(&BackendConfig::Memory).await.unwrap())
    }

    fn fresh_store() -> Arc<AllocationStore> {
        Arc::new(AllocationStore::new(40000, 41000, 10_000))
    }

    fn spawn_writer(
        backend: Arc<Backend>,
        store: Arc<AllocationStore>,
        batch_max: usize,
        delay_ms: u64,
    ) -> (
        mpsc::Sender<WriteOp>,
        watch::Sender<bool>,
        Arc<WriterCounters>,
        Arc<Metrics>,
        tokio::task::JoinHandle<()>,
    ) {
        let (tx, rx) = mpsc::channel(1024);
        let (sd_tx, sd_rx) = watch::channel(false);
        let counters = Arc::new(WriterCounters::default());
        let metrics = Arc::new(Metrics::new());
        let cfg = WriterConfig {
            channel_capacity: 1024,
            batch_max_size: batch_max,
            batch_max_delay: Duration::from_millis(delay_ms),
            node_id: "test-node".into(),
        };
        let bk_c = backend.clone();
        let st_c = store.clone();
        let ct_c = counters.clone();
        let mt_c = metrics.clone();
        let handle = tokio::spawn(async move {
            run_writer(bk_c, st_c, "test-realm".into(), cfg, mt_c, ct_c, rx, sd_rx).await;
        });
        (tx, sd_tx, counters, metrics, handle)
    }

    /// Single Create flows through to the backend.
    #[tokio::test]
    async fn create_flushes_on_batch_size() {
        let backend = fresh_backend().await;
        let store = fresh_store();
        let (tx, sd, counters, _metrics, handle) =
            spawn_writer(backend.clone(), store.clone(), 1, 60_000);

        tx.send(WriteOp::Create {
            relay_port: 40000,
            client_addr: ipv4(127, 0, 0, 1, 9000),
            relay_addr: ipv4(10, 0, 0, 1, 40000),
            username: "alice".into(),
            allocation_id: "wr-id-1".into(),
            migration_epoch: 0,
            created_at_ms: 1000,
            expires_at_ms: 1_600_000,
        })
        .await
        .unwrap();

        // batch_max=1 → immediate flush. Give it a moment.
        tokio::time::sleep(Duration::from_millis(50)).await;

        let got = backend.get_allocation(40000).await.unwrap();
        assert!(got.is_some(), "allocation should be persisted");
        let alloc = got.unwrap();
        assert_eq!(alloc.user_id, "alice");
        assert_eq!(alloc.expires_at_ms, 1_600_000);
        assert_eq!(alloc.node_id, "test-node");
        assert!(counters.ops_create.load(Ordering::Relaxed) >= 1);

        sd.send(true).unwrap();
        handle.await.unwrap();
    }

    /// Create then Remove in the same batch → backend never sees the alloc.
    #[tokio::test]
    async fn create_then_remove_coalesces_to_nothing() {
        let backend = fresh_backend().await;
        let store = fresh_store();
        // batch_max big, deadline short → both events arrive in same batch.
        let (tx, sd, counters, _metrics, handle) =
            spawn_writer(backend.clone(), store.clone(), 100, 30);

        tx.send(WriteOp::Create {
            relay_port: 40001,
            client_addr: ipv4(127, 0, 0, 1, 9001),
            relay_addr: ipv4(10, 0, 0, 1, 40001),
            username: "bob".into(),
            allocation_id: "wr-id-2".into(),
            migration_epoch: 0,
            created_at_ms: 1000,
            expires_at_ms: 1_600_000,
        })
        .await
        .unwrap();
        tx.send(WriteOp::Remove { relay_port: 40001 })
            .await
            .unwrap();

        // Wait past the deadline so the batch is flushed.
        tokio::time::sleep(Duration::from_millis(120)).await;

        // Remove without prior persisted Create still goes through to the
        // backend (it's idempotent), and we count it. What matters is the
        // record doesn't end up persisted.
        assert!(
            backend.get_allocation(40001).await.unwrap().is_none(),
            "create+remove should leave nothing in backend"
        );

        // Coalescing counter should have incremented at least once.
        assert!(
            counters.coalesced.load(Ordering::Relaxed) >= 1,
            "expected at least one coalesce event"
        );

        sd.send(true).unwrap();
        handle.await.unwrap();
    }

    /// Multiple refreshes for the same port collapse to one final value.
    #[tokio::test]
    async fn refresh_coalesces_to_latest() {
        let backend = fresh_backend().await;
        let store = fresh_store();
        let (tx, sd, _counters, _metrics, handle) =
            spawn_writer(backend.clone(), store.clone(), 100, 30);

        tx.send(WriteOp::Create {
            relay_port: 40002,
            client_addr: ipv4(127, 0, 0, 1, 9002),
            relay_addr: ipv4(10, 0, 0, 1, 40002),
            username: "carol".into(),
            allocation_id: "wr-id-3".into(),
            migration_epoch: 0,
            created_at_ms: 1000,
            expires_at_ms: 1_600_000,
        })
        .await
        .unwrap();
        tx.send(WriteOp::Refresh {
            relay_port: 40002,
            expires_at_ms: 2_000_000,
        })
        .await
        .unwrap();
        tx.send(WriteOp::Refresh {
            relay_port: 40002,
            expires_at_ms: 3_000_000,
        })
        .await
        .unwrap();

        tokio::time::sleep(Duration::from_millis(120)).await;

        let got = backend.get_allocation(40002).await.unwrap().unwrap();
        assert_eq!(
            got.expires_at_ms, 3_000_000,
            "latest Refresh should win the coalesce"
        );

        sd.send(true).unwrap();
        handle.await.unwrap();
    }

    /// Batch hits size limit before deadline → immediate flush.
    #[tokio::test]
    async fn size_limit_triggers_flush() {
        let backend = fresh_backend().await;
        let store = fresh_store();
        let (tx, sd, counters, _metrics, handle) =
            spawn_writer(backend.clone(), store.clone(), 3, 60_000);

        for i in 0..3u16 {
            tx.send(WriteOp::Create {
                relay_port: 40010 + i,
                client_addr: ipv4(127, 0, 0, 1, 9000 + i),
                relay_addr: ipv4(10, 0, 0, 1, 40010 + i),
                username: format!("u{i}"),
                allocation_id: "wr-id-4".into(),
                migration_epoch: 0,
                created_at_ms: 1000,
                expires_at_ms: 1_600_000,
            })
            .await
            .unwrap();
        }

        // Should flush immediately on the 3rd create — give it a beat.
        tokio::time::sleep(Duration::from_millis(50)).await;

        for i in 0..3u16 {
            assert!(
                backend.get_allocation(40010 + i).await.unwrap().is_some(),
                "port {} should be persisted",
                40010 + i
            );
        }
        assert!(counters.batches.load(Ordering::Relaxed) >= 1);

        sd.send(true).unwrap();
        handle.await.unwrap();
    }

    /// Shutdown drains the partial batch.
    #[tokio::test]
    async fn shutdown_flushes_partial_batch() {
        let backend = fresh_backend().await;
        let store = fresh_store();
        // Very large batch + long delay: only shutdown can flush.
        let (tx, sd, _counters, _metrics, handle) =
            spawn_writer(backend.clone(), store.clone(), 10_000, 60_000);

        tx.send(WriteOp::Create {
            relay_port: 40020,
            client_addr: ipv4(127, 0, 0, 1, 9020),
            relay_addr: ipv4(10, 0, 0, 1, 40020),
            username: "dave".into(),
            allocation_id: "wr-id-5".into(),
            migration_epoch: 0,
            created_at_ms: 1000,
            expires_at_ms: 1_600_000,
        })
        .await
        .unwrap();

        // Trigger shutdown before deadline.
        sd.send(true).unwrap();
        handle.await.unwrap();

        assert!(
            backend.get_allocation(40020).await.unwrap().is_some(),
            "shutdown should flush partial batch"
        );
    }

    /// RFC 8016 migration, already-persisted record: a `ReKey` arriving in a
    /// later batch (so the port is `Touched`, not `New`) rewrites the
    /// persisted `client_addr` while leaving the relay binding intact.
    #[tokio::test]
    async fn rekey_persists_new_client_addr_when_already_flushed() {
        let backend = fresh_backend().await;
        let store = fresh_store();
        // batch_max=1 → each op flushes on its own, so the Create is durable
        // *before* the ReKey is processed: the ReKey lands as a Touched port.
        let (tx, sd, _counters, _metrics, handle) =
            spawn_writer(backend.clone(), store.clone(), 1, 60_000);

        let old_client = ipv4(192, 168, 1, 10, 5000); // Wi-Fi
        let new_client = ipv4(10, 20, 30, 40, 7000); // cellular
        let relay = ipv4(10, 0, 0, 1, 40030);

        tx.send(WriteOp::Create {
            relay_port: 40030,
            client_addr: old_client,
            relay_addr: relay,
            username: "mobile".into(),
            allocation_id: "wr-id-6".into(),
            migration_epoch: 0,
            created_at_ms: 1000,
            expires_at_ms: 1_600_000,
        })
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_millis(40)).await;

        // Sanity: persisted with the old address.
        let before = backend.get_allocation(40030).await.unwrap().unwrap();
        assert_eq!(before.client_addr, old_client.to_string());
        assert_eq!(before.relay_addr, relay.to_string());

        // Client migrates → ReKey.
        tx.send(WriteOp::ReKey {
            relay_port: 40030,
            new_client_addr: new_client,
            new_epoch: 1,
        })
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_millis(40)).await;

        let after = backend.get_allocation(40030).await.unwrap().unwrap();
        assert_eq!(
            after.client_addr,
            new_client.to_string(),
            "client_addr should track the migrated 5-tuple"
        );
        assert_eq!(
            after.relay_addr,
            relay.to_string(),
            "relay binding must be unchanged by migration"
        );
        assert_eq!(after.user_id, "mobile");
        assert_eq!(after.migration_epoch, 1, "persisted epoch must track the re-key bump");

        sd.send(true).unwrap();
        handle.await.unwrap();
    }

    /// RFC 8016 migration, in-batch race: `Create` then `ReKey` coalesce in
    /// the same batch — the backend must only ever see the new address.
    #[tokio::test]
    async fn rekey_patches_pending_create_in_same_batch() {
        let backend = fresh_backend().await;
        let store = fresh_store();
        // Large batch + short deadline → Create and ReKey share one batch.
        let (tx, sd, _counters, _metrics, handle) =
            spawn_writer(backend.clone(), store.clone(), 100, 30);

        let old_client = ipv4(192, 168, 1, 11, 5001);
        let new_client = ipv4(10, 20, 30, 41, 7001);
        let relay = ipv4(10, 0, 0, 1, 40031);

        tx.send(WriteOp::Create {
            relay_port: 40031,
            client_addr: old_client,
            relay_addr: relay,
            username: "mobile2".into(),
            allocation_id: "wr-id-7".into(),
            migration_epoch: 0,
            created_at_ms: 1000,
            expires_at_ms: 1_600_000,
        })
        .await
        .unwrap();
        tx.send(WriteOp::ReKey {
            relay_port: 40031,
            new_client_addr: new_client,
            new_epoch: 1,
        })
        .await
        .unwrap();

        tokio::time::sleep(Duration::from_millis(120)).await;

        let after = backend.get_allocation(40031).await.unwrap().unwrap();
        assert_eq!(
            after.client_addr,
            new_client.to_string(),
            "in-batch ReKey must patch the pending Create's address"
        );
        assert_eq!(after.relay_addr, relay.to_string());

        sd.send(true).unwrap();
        handle.await.unwrap();
    }
}
