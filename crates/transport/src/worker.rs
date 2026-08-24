//! Thread-per-core worker with io_uring event loop.
//!
//! Each worker owns: main TURN socket + relay sockets, all in one io_uring.
//! Zero-copy: recv buffer → send without memcpy for ChannelData.
//!
//! # ForwardAction data types
//!
//! `Send` and `SendViaRelay` now carry `Bytes` instead of `Vec<u8>`.
//! `Bytes` implements `Deref<Target=[u8]>` so all `engine.submit_*` calls
//! that took `&[u8]` continue to work unchanged via auto-deref.
//!
//! `ZeroCopyViaRelay` retains `{ offset, len }` — in the io_uring path the
//! buffer is kernel-registered; we copy once from the registered slot into
//! a send buffer, which is the correct behaviour for that path.

#![cfg(all(target_os = "linux", feature = "io-uring"))]

use bytes::Bytes;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{error, info, warn};

use crate::relay_route::{
    classify_owned_command, OwnedSendOutcome, RelayRoutes, RouteDecision, WorkerCommand,
};
use crate::uring::{CompletionEvent, UringEngine};
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant};

// ── Config ────────────────────────────────────────────────────────────────────

pub struct WorkerPoolConfig {
    pub listen_addr: SocketAddr,
    pub num_workers: usize,
    /// IOU-2: max relay sockets per io_uring worker (from `[turn.io_uring]`).
    pub relay_capacity_per_worker: usize,
    pub buffers_per_worker: u16,
    pub external_ip: std::net::IpAddr,
    /// RFC 8016 sharded ownership: shared relay route table (port → owner).
    pub relay_routes: Arc<RelayRoutes>,
    /// Bounded wait for the worker loop so it unparks to drain the cross-worker
    /// command channel even with no ring activity (v1 wakeup).
    pub cmd_poll_timeout: Duration,
    /// Graceful-drain trigger. When flipped to `true` (on SIGTERM / management
    /// drain) every worker stops taking new traffic on its main socket, lets
    /// existing relay flows finish for `drain_grace`, unregisters its routes,
    /// and exits its loop so the pool can be `join`ed instead of abandoned.
    pub shutdown: Arc<AtomicBool>,
    /// Lame-duck window after `shutdown` is observed: how long a worker keeps
    /// servicing already-established relay flows before it tears down.
    pub drain_grace: Duration,
    /// Optional shared per-worker io_uring ring-stats publisher. When `Some`,
    /// each worker publishes its `RingStats` into slot `worker_id` on every
    /// ring-log tick; the node sums the slots for Prometheus. `None` keeps the
    /// log-only behaviour with no publishing.
    pub ring_stats: Option<Arc<crate::uring::RingStatsAggregate>>,
}

impl Default for WorkerPoolConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:3478".parse().unwrap(),
            num_workers: num_cpus(),
            relay_capacity_per_worker: 256,
            buffers_per_worker: 2048,
            external_ip: "127.0.0.1".parse().unwrap(),
            relay_routes: RelayRoutes::new(),
            cmd_poll_timeout: Duration::from_micros(500),
            shutdown: Arc::new(AtomicBool::new(false)),
            drain_grace: Duration::from_secs(5),
            ring_stats: None,
        }
    }
}

// ── PacketHandler ─────────────────────────────────────────────────────────────

pub trait PacketHandler: Send + 'static {
    fn handle_packet(&mut self, data: &[u8], source: SocketAddr) -> ForwardAction;
    fn handle_relay_packet(
        &mut self,
        data: &[u8],
        source: SocketAddr,
        relay_port: u16,
    ) -> ForwardAction;
}

// ── ForwardAction ─────────────────────────────────────────────────────────────

/// What to do after receiving a packet.
///
/// `Send` and `SendViaRelay` use `Bytes` — an Arc-backed slice that is cheap
/// to clone (AtomicAdd) and dereferences to `&[u8]` for send calls.
///
/// `ZeroCopyViaRelay` keeps `{ offset, len }` because this path operates on
/// kernel-registered buffers that cannot be wrapped in `Bytes` without a
/// custom allocator integration.
pub enum ForwardAction {
    None,
    /// Send via main socket. `Bytes` is Arc — no copy into the channel.
    Send {
        data: Bytes,
        target: SocketAddr,
    },
    /// Send via relay socket.
    SendViaRelay {
        data: Bytes,
        target: SocketAddr,
        relay_port: u16,
    },
    /// Zero-copy forward via relay socket (kernel-buffer path).
    ZeroCopyViaRelay {
        offset: usize,
        len: usize,
        target: SocketAddr,
        relay_port: u16,
    },
    /// Create a relay socket on this port.
    CreateRelay {
        port: u16,
        /// RFC 8016: owning allocation id, registered into the route table so
        /// other workers can forward sends to this owner.
        allocation_id: String,
    },
    /// Close a relay socket on this port (allocation released or expired).
    CloseRelay {
        port: u16,
    },
    /// Multiple actions (e.g. CreateRelay + Send).
    Multi(Vec<ForwardAction>),
}

// ── Worker pool ───────────────────────────────────────────────────────────────

pub fn spawn_worker_pool<H, F>(
    config: WorkerPoolConfig,
    handler_factory: F,
) -> Vec<std::thread::JoinHandle<()>>
where
    H: PacketHandler,
    F: Fn(usize) -> H + Send + Sync + 'static,
{
    let factory = Arc::new(handler_factory);
    let mut handles = Vec::with_capacity(config.num_workers);

    for worker_id in 0..config.num_workers {
        let addr = config.listen_addr;
        let bufs = config.buffers_per_worker;
        let factory = factory.clone();
        let routes = config.relay_routes.clone();
        let poll = config.cmd_poll_timeout;
        let shutdown = config.shutdown.clone();
        let drain_grace = config.drain_grace;
        let ring_stats = config.ring_stats.clone();
        let relay_cap = config.relay_capacity_per_worker;
        // Per-worker inbound command channel (cross-worker relay-send forwards).
        let (cmd_tx, cmd_rx) = std::sync::mpsc::channel::<WorkerCommand>();

        let handle = std::thread::Builder::new()
            .name(format!("turna-worker-{worker_id}"))
            .spawn(move || {
                #[cfg(target_os = "linux")]
                pin_to_core(worker_id);
                let handler = factory(worker_id);
                run_worker(
                    worker_id,
                    addr,
                    bufs,
                    handler,
                    routes,
                    cmd_tx,
                    cmd_rx,
                    poll,
                    shutdown,
                    drain_grace,
                    ring_stats,
                    relay_cap,
                );
            })
            .expect("failed to spawn worker thread");

        handles.push(handle);
    }

    info!(workers = config.num_workers, addr = %config.listen_addr, "worker pool started");
    handles
}

// ── Inner worker loop ─────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn run_worker<H: PacketHandler>(
    worker_id: usize,
    addr: SocketAddr,
    buf_count: u16,
    mut handler: H,
    routes: Arc<RelayRoutes>,
    cmd_tx: std::sync::mpsc::Sender<WorkerCommand>,
    cmd_rx: Receiver<WorkerCommand>,
    cmd_poll_timeout: Duration,
    shutdown: Arc<AtomicBool>,
    drain_grace: Duration,
    ring_stats: Option<Arc<crate::uring::RingStatsAggregate>>,
    relay_capacity_per_worker: usize,
) {
    let mut engine = match UringEngine::new(addr, true, buf_count, relay_capacity_per_worker) {
        Ok(e) => e,
        Err(e) => {
            error!(worker_id, %e, "failed to create engine");
            return;
        }
    };

    if let Err(e) = engine.submit_initial_recvs() {
        error!(worker_id, %e, "failed to submit initial recvs");
        return;
    }

    let mut stats = Stats::default();
    // Which 100k-traffic bucket has already been logged, so the periodic line
    // fires once per bucket rather than on an exact modulo hit that a batched
    // counter can step over.
    let mut last_stats_bucket: u64 = 0;

    info!(worker_id, addr = %engine.local_addr(), "worker started");

    // Graceful-drain bookkeeping (Fix 4). `owned_ports` mirrors the relay
    // sockets this worker currently owns (the engine exposes no enumerator, so
    // we track ownership locally from the new/close batches). `drain_deadline`
    // is armed the first time `shutdown` is observed.
    let mut owned_ports: HashSet<u16> = HashSet::new();
    let mut drain_deadline: Option<Instant> = None;
    // Throttle for periodic io_uring ring/CQE utilisation logging.
    let mut last_ring_log = Instant::now();

    loop {
        match engine.submit_and_wait_timeout(cmd_poll_timeout) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => {
                error!(worker_id, %e, "submit_and_wait_timeout failed");
                break;
            }
        }

        if last_ring_log.elapsed() >= Duration::from_secs(30) {
            let rs = engine.ring_stats();
            if let Some(agg) = &ring_stats {
                agg.publish(worker_id, &rs, engine.buffers_available() as u32);
            }
            #[allow(clippy::manual_checked_ops)]
            let avg = if rs.cqe_batches > 0 {
                rs.cqe_drained / rs.cqe_batches
            } else {
                0
            };
            info!(
                worker_id,
                cqe_drained = rs.cqe_drained,
                drain_batches = rs.cqe_batches,
                avg_cqe_per_drain = avg,
                max_cqe_batch = rs.cqe_max_batch,
                sq_push_failed = rs.sq_push_failed,
                sq_len = rs.sq_len,
                sq_capacity = rs.sq_capacity,
                cq_len = rs.cq_len,
                buffers_available = engine.buffers_available(),
                "io_uring ring stats"
            );
            last_ring_log = Instant::now();
        }

        // ── Graceful drain (Fix 4) ────────────────────────────────────────────
        // On the first observed shutdown signal, enter lame-duck: keep
        // servicing in-flight completions and established relay flows, but stop
        // arming new main-socket recvs (no new clients / Allocates). After
        // `drain_grace` — or as soon as this worker owns no relays — tear down:
        // cancel every still-owned relay (the engine drains in-flight ops
        // safely) and drop its route from the shared table so peers stop
        // forwarding to a worker that is going away.
        if shutdown.load(Ordering::Acquire) && drain_deadline.is_none() {
            drain_deadline = Some(Instant::now() + drain_grace);
            info!(
                worker_id,
                grace_ms = drain_grace.as_millis() as u64,
                owned_relays = owned_ports.len(),
                "worker draining: existing flows keep running, new allocations rejected upstream"
            );
        }
        if let Some(deadline) = drain_deadline {
            if Instant::now() >= deadline || owned_ports.is_empty() {
                // Tear down: drop each owned route from the shared table and
                // begin closing its relay socket (the engine cancels in-flight
                // ops and reclaims the block once they drain).
                let closing: Vec<u16> = owned_ports.drain().collect();
                for &port in &closing {
                    if let Some((aid, gen)) =
                        engine.relay_record(port).map(|(a, g)| (a.to_string(), g))
                    {
                        routes.unregister_if(port, &aid, gen);
                    }
                    engine.remove_relay(port);
                }
                // 2.6: bounded final drain. Drive the ring until BOTH every
                // closing relay block is reclaimed AND all in-flight sends
                // (main + relay) have completed, so queued responses are
                // actually transmitted and no registered buffer is freed while
                // the kernel still owns it. Bounded by `drain_grace` to keep
                // shutdown finite. (Inbound recvs still in flight are abandoned
                // to ring teardown — dropping ingress during shutdown is fine.)
                let drain_cap = Instant::now() + drain_grace;
                loop {
                    let relays_reclaimed = closing.iter().all(|p| !engine.has_relay(*p));
                    let sends_drained = engine.send_slots_inflight() == 0;
                    if relays_reclaimed && sends_drained {
                        break;
                    }
                    if Instant::now() >= drain_cap {
                        break;
                    }
                    if engine.submit_and_wait_timeout(cmd_poll_timeout).is_err() {
                        break;
                    }
                    let _ = engine.collect_completions(); // reclaim + send drain
                }
                let _ = engine.flush();
                let sends_left = engine.send_slots_inflight();
                info!(
                    worker_id,
                    relays = closing.len(),
                    fully_reclaimed = closing.iter().all(|p| !engine.has_relay(*p)),
                    sends_inflight_remaining = sends_left,
                    "worker drain complete; exiting loop"
                );
                // Unconditional packet summary at exit. The periodic line is gated on
                // traffic volume, so on a short run spread across many workers it
                // never fires — 960k packets over 32 workers is 30k each, under any
                // sensible threshold. A diagnostic that only appears under load is no
                // help diagnosing a run that produced no load, which is exactly the
                // situation it was added for.
                info!(
                    worker_id,
                    recv = stats.recv,
                    sent = stats.sent,
                    relay_recv = stats.relay_recv,
                    relay_sent = stats.relay_sent,
                    relay_send_failed = stats.relay_send_failed,
                    relay_send_errno = stats.relay_send_errno,
                    zc = stats.zc,
                    errors = stats.errors,
                    "worker packet totals"
                );
                if sends_left > 0 {
                    warn!(
                        worker_id,
                        sends_left,
                        "shutdown drain window elapsed with sends still in \
                         flight; they may be lost on ring teardown"
                    );
                }
                break;
            }
        }

        // Bytes-typed send queues: clones are AtomicAdd, not memcpy.
        let mut main_sends: Vec<(Bytes, SocketAddr)> = Vec::new();
        let mut relay_sends: Vec<(u16, Bytes, SocketAddr)> = Vec::new();
        let mut zc_relay_sends: Vec<ZcRelaySend> = Vec::new();
        let mut resubmit_main: Vec<(u16, u16)> = Vec::new();
        let mut resubmit_relay: Vec<(u16, u16, u16)> = Vec::new();
        let mut new_relays: Vec<(u16, String)> = Vec::new();
        let mut close_relays: Vec<u16> = Vec::new();

        let events = engine.collect_completions();
        for event in events {
            match event {
                CompletionEvent::MainRecv {
                    buf_idx,
                    msghdr_idx,
                    len,
                    source,
                } => {
                    stats.recv += 1;
                    let data = engine.buffer_data(buf_idx, len);
                    let action = handler.handle_packet(data, source);
                    process_action(
                        action,
                        buf_idx,
                        msghdr_idx,
                        true,
                        &mut main_sends,
                        &mut relay_sends,
                        &mut zc_relay_sends,
                        &mut resubmit_main,
                        &mut new_relays,
                        &mut close_relays,
                        &mut stats,
                    );
                }
                CompletionEvent::RelayRecv {
                    relay_port,
                    buf_idx,
                    msghdr_idx,
                    len,
                    source,
                } => {
                    stats.relay_recv += 1;
                    let data = engine.buffer_data(buf_idx, len);
                    let action = handler.handle_relay_packet(data, source, relay_port);
                    process_relay_response(
                        action,
                        buf_idx,
                        msghdr_idx,
                        relay_port,
                        &mut main_sends,
                        &mut resubmit_relay,
                    );
                }
                CompletionEvent::MainSend { result, .. } => {
                    if result >= 0 {
                        stats.sent += 1;
                    } else {
                        stats.errors += 1;
                    }
                }
                CompletionEvent::RelaySend {
                    result, relay_port, ..
                } => {
                    if result >= 0 {
                        stats.relay_sent += 1;
                    } else {
                        stats.errors += 1;
                        stats.relay_send_failed += 1;
                        // Log the first failure per worker with the errno. Every
                        // packet would drown the log, and silence hid the bug — so:
                        // once, loudly, with the number that identifies the cause.
                        if stats.relay_send_errno == 0 {
                            stats.relay_send_errno = -result;
                            warn!(
                                worker_id,
                                relay_port,
                                errno = -result,
                                "relay send FAILED at completion — no relayed traffic will \
                                 reach peers through this socket. This is logged once per \
                                 worker; see relay_send_failed in the periodic stats line."
                            );
                        }
                    }
                }
                CompletionEvent::MainRecvError {
                    msghdr_idx,
                    buf_idx,
                } => {
                    // Re-arm the main recv slot (reuses the buffer) so a
                    // transient error doesn't permanently shrink the recv ring.
                    stats.errors += 1;
                    resubmit_main.push((msghdr_idx, buf_idx));
                }
            }
        }

        // Create new relay sockets and register ownership (RFC 8016). Register
        // first to obtain the generation, then bind the socket stamped with
        // (allocation_id, generation); roll the route back on bind failure.
        for (port, allocation_id) in &new_relays {
            if !engine.has_relay(*port) {
                let generation =
                    routes.register(*port, worker_id, cmd_tx.clone(), allocation_id.clone());
                if let Err(e) = engine.add_relay(*port, allocation_id.clone(), generation) {
                    warn!(worker_id, port, %e, "failed to add relay; rolling back route");
                    routes.unregister_if(*port, allocation_id, generation);
                }
            }
        }

        // Close relays whose allocation was released/expired. The engine marks
        // them draining and reclaims the msghdr block once all in-flight ops
        // complete (in-flight-safe). Done before resubmits so a relay closed in
        // this same batch isn't re-armed.
        for port in &close_relays {
            // Conditional unregister: only drop the route if it still names this
            // allocation/generation (guards a delayed close vs a reused port).
            if let Some((aid, gen)) = engine.relay_record(*port).map(|(a, g)| (a.to_string(), g)) {
                routes.unregister_if(*port, &aid, gen);
            }
            engine.remove_relay(*port);
        }

        // Drain bookkeeping (Fix 4): mirror this batch's ownership changes so
        // the teardown knows which routes to drop. `has_relay` filters out new
        // relays whose bind failed and rolled back.
        for (port, _aid) in &new_relays {
            if engine.has_relay(*port) {
                owned_ports.insert(*port);
            }
        }
        for port in &close_relays {
            owned_ports.remove(port);
        }

        // Submit main sends. The engine now allocates an in-flight-safe send
        // slot internally and releases it on completion. On exhaustion the send
        // is dropped (acceptable for UDP) and counted; the next
        // submit_and_wait frees slots as completions arrive.
        for (data, target) in &main_sends {
            if engine.submit_main_send(data, *target).is_err() {
                stats.errors += 1;
            }
        }

        // Submit relay sends. A relay socket not owned by this worker (post
        // migration reshard) returns NotFound → route the send to its owner.
        for (port, data, target) in relay_sends.drain(..) {
            match engine.submit_relay_send(port, &data, target) {
                Ok(_) => {
                    routes.stats.send_local.fetch_add(1, Ordering::Relaxed);
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    match routes.route_send(worker_id, port, target, data) {
                        RouteDecision::Forward { tx, cmd } => {
                            if tx.send(cmd).is_ok() {
                                routes.stats.send_forwarded.fetch_add(1, Ordering::Relaxed);
                            } else {
                                routes
                                    .stats
                                    .send_forward_failed
                                    .fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        RouteDecision::Miss => {
                            warn!(worker_id, port, "relay route miss — dropping send");
                            stats.errors += 1;
                        }
                        RouteDecision::SelfOwned => {
                            warn!(
                                worker_id,
                                port, "relay route names self but local socket missing (desync)"
                            );
                            stats.errors += 1;
                        }
                    }
                }
                Err(_) => {
                    stats.errors += 1;
                }
            }
        }

        // Drain cross-worker commands: relay sends forwarded to us as the owner.
        // Validate against our local record (anti-stale) and never re-route
        // (anti-loop — SendViaRelayOwned is terminal).
        while let Ok(cmd) = cmd_rx.try_recv() {
            match cmd {
                WorkerCommand::SendViaRelayOwned {
                    allocation_id,
                    generation,
                    relay_port,
                    peer_addr,
                    payload,
                } => {
                    let local = engine
                        .relay_record(relay_port)
                        .map(|(a, g)| (a.to_string(), g));
                    match classify_owned_command(local.as_ref(), &allocation_id, generation) {
                        OwnedSendOutcome::Send => {
                            if engine
                                .submit_relay_send(relay_port, &payload, peer_addr)
                                .is_ok()
                            {
                                routes.stats.send_local.fetch_add(1, Ordering::Relaxed);
                            } else {
                                stats.errors += 1;
                            }
                        }
                        OwnedSendOutcome::StaleAllocation => {
                            routes.stats.send_stale.fetch_add(1, Ordering::Relaxed);
                            warn!(
                                worker_id,
                                relay_port, "forwarded relay send stale — dropping"
                            );
                        }
                        OwnedSendOutcome::MissingSocket => {
                            warn!(
                                worker_id,
                                relay_port, "forwarded relay send for unknown local socket"
                            );
                        }
                    }
                }
            }
        }

        // Relay sends that came from a registered recv buffer: copy the payload
        // out, submit the send, then **re-arm the recv slot with the same buffer**.
        //
        // Re-arming — not `release_buffer` — is what mirrors the `Send` path: the
        // buffer belongs to the slot, and `resubmit_*_recv` hands it back to the
        // kernel for the next packet. Releasing it here and re-arming as well would
        // hand the same buffer to both the free pool and the kernel; doing neither
        // (the previous behaviour) leaked the slot and made the worker deaf after 64
        // relayed packets.
        //
        // NOTE: this still double-copies (buffer → Vec → send_buf); collapsing it
        // requires registered send buffers (tracked in ADR-0002). Until then the
        // name "zero copy" flatters it.
        for zc in &zc_relay_sends {
            let data = engine.buffer_data(zc.buf_idx, zc.offset + zc.len)
                [zc.offset..zc.offset + zc.len]
                .to_vec();
            if engine
                .submit_relay_send(zc.relay_port, &data, zc.target)
                .is_err()
            {
                stats.errors += 1;
            }
            // The payload is copied; the slot can serve the next packet.
            if zc.is_main {
                resubmit_main.push((zc.msghdr_idx, zc.buf_idx));
            } else {
                resubmit_relay.push((zc.relay_port, zc.msghdr_idx, zc.buf_idx));
            }
        }

        // Re-submit recvs. Even while draining we keep the MAIN socket armed:
        // existing clients' Send/ChannelData keep flowing through the grace
        // window, while *new* Allocates are rejected upstream by the processor
        // (508 Server Draining, or 300 Try Alternate when clustered — see
        // PacketProcessor::handle_allocate / maybe_redirect_new_client). So the
        // drain services real traffic instead of going silent.
        for (msghdr_idx, buf_idx) in resubmit_main {
            let _ = engine.resubmit_main_recv(msghdr_idx, buf_idx);
        }
        for (port, msghdr_idx, buf_idx) in resubmit_relay {
            let _ = engine.resubmit_relay_recv(port, msghdr_idx, buf_idx);
        }

        let _ = engine.flush();

        // Gated on total traffic, not on main recv alone: a worker relaying heavily
        // while receiving little would never print, which is the case that needed
        // printing most.
        let traffic = stats.recv + stats.relay_recv + stats.relay_sent;
        if traffic > 0 && traffic / 10_000 != last_stats_bucket {
            last_stats_bucket = traffic / 10_000;
            info!(
                worker_id,
                recv = stats.recv,
                sent = stats.sent,
                relay_recv = stats.relay_recv,
                relay_sent = stats.relay_sent,
                relay_send_failed = stats.relay_send_failed,
                relay_send_errno = stats.relay_send_errno,
                zc = stats.zc,
                errors = stats.errors,
                bufs = engine.buffers_available(),
                "worker packet stats"
            );
        }
    }
}

// ── Action dispatch ───────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn process_action(
    action: ForwardAction,
    buf_idx: u16,
    msghdr_idx: u16,
    is_main: bool,
    main_sends: &mut Vec<(Bytes, SocketAddr)>,
    relay_sends: &mut Vec<(u16, Bytes, SocketAddr)>,
    zc_relay_sends: &mut Vec<ZcRelaySend>,
    resubmit_main: &mut Vec<(u16, u16)>,
    new_relays: &mut Vec<(u16, String)>,
    close_relays: &mut Vec<u16>,
    stats: &mut Stats,
) {
    match action {
        ForwardAction::None => {
            if is_main {
                resubmit_main.push((msghdr_idx, buf_idx));
            }
        }
        ForwardAction::Send { data, target } => {
            main_sends.push((data, target));
            if is_main {
                resubmit_main.push((msghdr_idx, buf_idx));
            }
        }
        ForwardAction::SendViaRelay {
            data,
            target,
            relay_port,
        } => {
            relay_sends.push((relay_port, data, target));
            if is_main {
                resubmit_main.push((msghdr_idx, buf_idx));
            }
        }
        ForwardAction::ZeroCopyViaRelay {
            offset,
            len,
            target,
            relay_port,
        } => {
            stats.zc += 1;
            // The recv slot is carried through and re-armed by the zc loop below,
            // AFTER the payload has been copied out of the buffer.
            //
            // It used to be deliberately not re-armed here, on the grounds that the
            // registered buffer stayed with the kernel until the send completed.
            // That was true of an earlier true-zero-copy send; the loop now copies
            // (`to_vec`) and is done with the buffer immediately, so there is
            // nothing to wait for — and because `msghdr_idx` was not even carried in
            // the batch, the slot could never be re-armed at all. Every relayed
            // packet permanently consumed one recv slot, so each worker went deaf
            // after exactly as many relayed packets as it had slots: 64. Control
            // traffic kept working (it takes the `Send` path, which re-arms), which
            // is why allocation succeeded at 10k/s while media never moved.
            zc_relay_sends.push(ZcRelaySend {
                buf_idx,
                msghdr_idx,
                is_main,
                relay_port,
                offset,
                len,
                target,
            });
        }
        ForwardAction::CreateRelay {
            port,
            allocation_id,
        } => {
            new_relays.push((port, allocation_id));
            if is_main {
                resubmit_main.push((msghdr_idx, buf_idx));
            }
        }
        ForwardAction::CloseRelay { port } => {
            close_relays.push(port);
            if is_main {
                resubmit_main.push((msghdr_idx, buf_idx));
            }
        }
        ForwardAction::Multi(actions) => {
            let mut has_zc = false;
            for a in actions {
                match a {
                    ForwardAction::Send { data, target } => main_sends.push((data, target)),
                    ForwardAction::SendViaRelay {
                        data,
                        target,
                        relay_port,
                    } => relay_sends.push((relay_port, data, target)),
                    ForwardAction::ZeroCopyViaRelay {
                        offset,
                        len,
                        target,
                        relay_port,
                    } => {
                        stats.zc += 1;
                        has_zc = true;
                        zc_relay_sends.push(ZcRelaySend {
                            buf_idx,
                            msghdr_idx,
                            is_main,
                            relay_port,
                            offset,
                            len,
                            target,
                        });
                    }
                    ForwardAction::CreateRelay {
                        port,
                        allocation_id,
                    } => new_relays.push((port, allocation_id)),
                    ForwardAction::CloseRelay { port } => close_relays.push(port),
                    _ => {}
                }
            }
            if is_main && !has_zc {
                resubmit_main.push((msghdr_idx, buf_idx));
            }
        }
    }
}

fn process_relay_response(
    action: ForwardAction,
    buf_idx: u16,
    msghdr_idx: u16,
    relay_port: u16,
    main_sends: &mut Vec<(Bytes, SocketAddr)>,
    resubmit_relay: &mut Vec<(u16, u16, u16)>,
) {
    match action {
        ForwardAction::Send { data, target } => {
            main_sends.push((data, target));
            resubmit_relay.push((relay_port, msghdr_idx, buf_idx));
        }
        ForwardAction::Multi(actions) => {
            for a in actions {
                if let ForwardAction::Send { data, target } = a {
                    main_sends.push((data, target));
                }
            }
            resubmit_relay.push((relay_port, msghdr_idx, buf_idx));
        }
        _ => {
            resubmit_relay.push((relay_port, msghdr_idx, buf_idx));
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// One relayed packet whose payload still lives in a registered recv buffer.
///
/// Carries `msghdr_idx` and `is_main` so the recv slot can be re-armed once the
/// payload has been copied out. The previous tuple omitted both, which is why the
/// slot could never be returned.
struct ZcRelaySend {
    buf_idx: u16,
    msghdr_idx: u16,
    is_main: bool,
    relay_port: u16,
    offset: usize,
    len: usize,
    target: SocketAddr,
}

#[derive(Default)]
struct Stats {
    recv: u64,
    sent: u64,
    relay_recv: u64,
    relay_sent: u64,
    zc: u64,
    errors: u64,
    /// Relay sends that COMPLETED with a negative result.
    ///
    /// Separate from `errors` on purpose. This was folded into `errors`, which is
    /// neither logged per-event nor exported as a metric, so a datapath that
    /// submitted every relay send successfully and then failed every completion was
    /// indistinguishable from one that worked: no warning, no counter, no relayed
    /// bytes. That is how "io_uring does not forward ChannelData" survived a 3-hour
    /// soak reporting PASS on every signal.
    relay_send_failed: u64,
    /// First errno seen on a failed relay send, kept so the log line can name it
    /// once rather than per packet.
    relay_send_errno: i32,
}

#[cfg(target_os = "linux")]
fn pin_to_core(core_id: usize) {
    // `cpu_set_t` is a fixed-size bitmask; calling CPU_SET with an index
    // beyond its capacity is out-of-bounds (UB) and historically truncated
    // silently. Derive the capacity from the type's own size and guard: a
    // core id past the mask means we skip pinning (run unpinned) rather than
    // risk UB. Worker ids are 0..num_workers <= num_cpus, so this only trips
    // when pinning a very high core on a >1024-CPU host.
    let capacity_bits = std::mem::size_of::<libc::cpu_set_t>() * 8;
    if core_id >= capacity_bits {
        warn!(
            core_id,
            capacity_bits, "core id exceeds cpu_set_t capacity; running unpinned"
        );
        return;
    }
    // SAFETY: cpu_set_t is a C POD (all-zeroes valid). `core_id` is proven
    // < capacity_bits, so CPU_SET writes within the mask. sched_setaffinity
    // targets this thread (pid 0) with the cpuset's own byte length.
    unsafe {
        let mut cpuset: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_SET(core_id, &mut cpuset);
        let ret = libc::sched_setaffinity(0, std::mem::size_of_val(&cpuset), &cpuset);
        if ret == 0 {
            info!(core_id, "pinned to core");
        } else {
            warn!(core_id, "pin failed");
        }
    }
}

fn num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}
