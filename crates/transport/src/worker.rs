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

use std::net::SocketAddr;
use std::sync::Arc;
use bytes::Bytes;
use tracing::{info, warn, error};

use crate::uring::{UringEngine, CompletionEvent};

// ── Config ────────────────────────────────────────────────────────────────────

pub struct WorkerPoolConfig {
    pub listen_addr:       SocketAddr,
    pub num_workers:       usize,
    pub buffers_per_worker: u16,
    pub external_ip:       std::net::IpAddr,
}

impl Default for WorkerPoolConfig {
    fn default() -> Self {
        Self {
            listen_addr:        "0.0.0.0:3478".parse().unwrap(),
            num_workers:        num_cpus(),
            buffers_per_worker: 2048,
            external_ip:        "127.0.0.1".parse().unwrap(),
        }
    }
}

// ── PacketHandler ─────────────────────────────────────────────────────────────

pub trait PacketHandler: Send + 'static {
    fn handle_packet(&mut self, data: &[u8], source: SocketAddr) -> ForwardAction;
    fn handle_relay_packet(&mut self, data: &[u8], source: SocketAddr, relay_port: u16) -> ForwardAction;
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
    Send { data: Bytes, target: SocketAddr },
    /// Send via relay socket.
    SendViaRelay { data: Bytes, target: SocketAddr, relay_port: u16 },
    /// Zero-copy forward via relay socket (kernel-buffer path).
    ZeroCopyViaRelay { offset: usize, len: usize, target: SocketAddr, relay_port: u16 },
    /// Create a relay socket on this port.
    CreateRelay { port: u16 },
    /// Multiple actions (e.g. CreateRelay + Send).
    Multi(Vec<ForwardAction>),
}

// ── Worker pool ───────────────────────────────────────────────────────────────

pub fn spawn_worker_pool<H, F>(
    config:          WorkerPoolConfig,
    handler_factory: F,
) -> Vec<std::thread::JoinHandle<()>>
where
    H: PacketHandler,
    F: Fn(usize) -> H + Send + Sync + 'static,
{
    let factory = Arc::new(handler_factory);
    let mut handles = Vec::with_capacity(config.num_workers);

    for worker_id in 0..config.num_workers {
        let addr    = config.listen_addr;
        let bufs    = config.buffers_per_worker;
        let factory = factory.clone();

        let handle = std::thread::Builder::new()
            .name(format!("turna-worker-{worker_id}"))
            .spawn(move || {
                #[cfg(target_os = "linux")]
                pin_to_core(worker_id);
                let handler = factory(worker_id);
                run_worker(worker_id, addr, bufs, handler);
            })
            .expect("failed to spawn worker thread");

        handles.push(handle);
    }

    info!(workers = config.num_workers, addr = %config.listen_addr, "worker pool started");
    handles
}

// ── Inner worker loop ─────────────────────────────────────────────────────────

fn run_worker<H: PacketHandler>(
    worker_id: usize,
    addr:      SocketAddr,
    buf_count: u16,
    mut handler: H,
) {
    let mut engine = match UringEngine::new(addr, true, buf_count) {
        Ok(e)  => e,
        Err(e) => { error!(worker_id, %e, "failed to create engine"); return; }
    };

    if let Err(e) = engine.submit_initial_recvs() {
        error!(worker_id, %e, "failed to submit initial recvs"); return;
    }

    let mut send_slot:       u16 = 0;
    let mut relay_send_slot: u16 = 0;
    let mut stats = Stats::default();

    info!(worker_id, addr = %engine.local_addr(), "worker started");

    loop {
        if let Err(e) = engine.submit_and_wait() {
            if e.kind() == std::io::ErrorKind::Interrupted { continue; }
            error!(worker_id, %e, "submit_and_wait failed"); break;
        }

        // Bytes-typed send queues: clones are AtomicAdd, not memcpy.
        let mut main_sends:     Vec<(Bytes, SocketAddr)>        = Vec::new();
        let mut relay_sends:    Vec<(u16, Bytes, SocketAddr)>   = Vec::new();
        let mut zc_relay_sends: Vec<(u16, u16, usize, usize, SocketAddr)> = Vec::new();
        let mut resubmit_main:  Vec<(u16, u16)>                 = Vec::new();
        let mut resubmit_relay: Vec<(u16, u16, u16)>            = Vec::new();
        let mut new_relays:     Vec<u16>                         = Vec::new();

        let events = engine.collect_completions();
        for event in events {
            match event {
                CompletionEvent::MainRecv { buf_idx, msghdr_idx, len, source } => {
                    stats.recv += 1;
                    let data   = engine.buffer_data(buf_idx, len);
                    let action = handler.handle_packet(data, source);
                    process_action(
                        action, buf_idx, msghdr_idx, true,
                        &mut main_sends, &mut relay_sends, &mut zc_relay_sends,
                        &mut resubmit_main, &mut new_relays, &mut stats,
                    );
                }
                CompletionEvent::RelayRecv { relay_port, buf_idx, msghdr_idx, len, source } => {
                    stats.relay_recv += 1;
                    let data   = engine.buffer_data(buf_idx, len);
                    let action = handler.handle_relay_packet(data, source, relay_port);
                    process_relay_response(
                        action, buf_idx, msghdr_idx, relay_port,
                        &mut main_sends, &mut resubmit_relay,
                    );
                }
                CompletionEvent::MainSend  { result, .. } => {
                    if result >= 0 { stats.sent   += 1; } else { stats.errors += 1; }
                }
                CompletionEvent::RelaySend { result, .. } => {
                    if result >= 0 { stats.relay_sent += 1; } else { stats.errors += 1; }
                }
            }
        }

        // Create new relay sockets.
        for port in &new_relays {
            if !engine.has_relay(*port) {
                if let Err(e) = engine.add_relay(*port) {
                    warn!(worker_id, port, %e, "failed to add relay");
                }
            }
        }

        // Submit main sends. Bytes derefs to &[u8] — no extra copy.
        for (data, target) in &main_sends {
            let slot = send_slot; send_slot = (send_slot + 1) % 64;
            let _ = engine.submit_main_send(&data, *target, slot);
        }

        // Submit relay sends.
        for (port, data, target) in &relay_sends {
            let slot = relay_send_slot; relay_send_slot = (relay_send_slot + 1) % 4;
            let _ = engine.submit_relay_send(*port, &data, *target, slot);
        }

        // Zero-copy relay sends: copy from kernel-registered buffer into send slot.
        // This is the io_uring path — buffer is pinned in kernel memory, cannot be
        // wrapped in Bytes without a custom allocator, so one copy is unavoidable here.
        for (buf_idx, port, offset, len, target) in &zc_relay_sends {
            let data = engine.buffer_data(*buf_idx, offset + len)[*offset..*offset + *len].to_vec();
            let slot = relay_send_slot; relay_send_slot = (relay_send_slot + 1) % 4;
            let _ = engine.submit_relay_send(*port, &data, *target, slot);
            engine.release_buffer(*buf_idx);
        }

        // Re-submit recvs.
        for (msghdr_idx, buf_idx) in resubmit_main {
            let _ = engine.resubmit_main_recv(msghdr_idx, buf_idx);
        }
        for (port, msghdr_idx, buf_idx) in resubmit_relay {
            let _ = engine.resubmit_relay_recv(port, msghdr_idx, buf_idx);
        }

        let _ = engine.flush();

        if stats.recv % 100_000 == 0 && stats.recv > 0 {
            info!(
                worker_id,
                recv = stats.recv, sent = stats.sent,
                relay_recv = stats.relay_recv, relay_sent = stats.relay_sent,
                zc = stats.zc, errors = stats.errors,
                bufs = engine.buffers_available(),
                "stats"
            );
        }
    }
}

// ── Action dispatch ───────────────────────────────────────────────────────────

fn process_action(
    action:         ForwardAction,
    buf_idx:        u16,
    msghdr_idx:     u16,
    is_main:        bool,
    main_sends:     &mut Vec<(Bytes, SocketAddr)>,
    relay_sends:    &mut Vec<(u16, Bytes, SocketAddr)>,
    zc_relay_sends: &mut Vec<(u16, u16, usize, usize, SocketAddr)>,
    resubmit_main:  &mut Vec<(u16, u16)>,
    new_relays:     &mut Vec<u16>,
    stats:          &mut Stats,
) {
    match action {
        ForwardAction::None => {
            if is_main { resubmit_main.push((msghdr_idx, buf_idx)); }
        }
        ForwardAction::Send { data, target } => {
            main_sends.push((data, target));
            if is_main { resubmit_main.push((msghdr_idx, buf_idx)); }
        }
        ForwardAction::SendViaRelay { data, target, relay_port } => {
            relay_sends.push((relay_port, data, target));
            if is_main { resubmit_main.push((msghdr_idx, buf_idx)); }
        }
        ForwardAction::ZeroCopyViaRelay { offset, len, target, relay_port } => {
            stats.zc += 1;
            zc_relay_sends.push((buf_idx, relay_port, offset, len, target));
            // Don't resubmit — buffer is held until the send completes.
        }
        ForwardAction::CreateRelay { port } => {
            new_relays.push(port);
            if is_main { resubmit_main.push((msghdr_idx, buf_idx)); }
        }
        ForwardAction::Multi(actions) => {
            let mut has_zc = false;
            for a in actions {
                match a {
                    ForwardAction::Send { data, target } =>
                        main_sends.push((data, target)),
                    ForwardAction::SendViaRelay { data, target, relay_port } =>
                        relay_sends.push((relay_port, data, target)),
                    ForwardAction::ZeroCopyViaRelay { offset, len, target, relay_port } => {
                        stats.zc += 1;
                        has_zc = true;
                        zc_relay_sends.push((buf_idx, relay_port, offset, len, target));
                    }
                    ForwardAction::CreateRelay { port } =>
                        new_relays.push(port),
                    _ => {}
                }
            }
            if is_main && !has_zc { resubmit_main.push((msghdr_idx, buf_idx)); }
        }
    }
}

fn process_relay_response(
    action:         ForwardAction,
    buf_idx:        u16,
    msghdr_idx:     u16,
    relay_port:     u16,
    main_sends:     &mut Vec<(Bytes, SocketAddr)>,
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

#[derive(Default)]
struct Stats {
    recv: u64, sent: u64,
    relay_recv: u64, relay_sent: u64,
    zc: u64, errors: u64,
}

#[cfg(target_os = "linux")]
fn pin_to_core(core_id: usize) {
    unsafe {
        // NEEDS-REVIEW: cpu_set_t fixed size (1024 CPUs on glibc). If the
        // host has more CPUs and core_id is high, CPU_SET silently bit-
        // truncates. Modern kernels support CPU_ALLOC for dynamic sizing.
        let mut cpuset: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_SET(core_id, &mut cpuset);
        let ret = libc::sched_setaffinity(0, std::mem::size_of_val(&cpuset), &cpuset);
        if ret == 0 { info!(core_id, "pinned to core"); }
        else        { warn!(core_id, "pin failed"); }
    }
}

fn num_cpus() -> usize {
    std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)
}
