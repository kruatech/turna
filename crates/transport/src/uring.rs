//! io_uring-based UDP transport (Linux 5.6+)
//!
//! Supports multiple fds in one ring: main TURN socket + N relay sockets.
//! All recv/send operations share one io_uring instance for max batching.

#![cfg(all(target_os = "linux", feature = "io-uring"))]

use crate::buffer::{BufferRing, MAX_UDP_PACKET};
use io_uring::types::CancelBuilder;
use io_uring::{opcode, types, IoUring};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, RawFd};
use tracing::{info, warn};

const RING_SIZE: u32 = 512;
const RECV_BATCH: u16 = 64;
const RELAY_RECV_BATCH: u16 = 32; // per relay socket

/// Number of pre-allocated main-socket send slots (one `u64` bitmap covers it).
const MAIN_SEND_SLOTS: u16 = 64;
/// Number of send slots reserved per relay socket (one `u32` bitmap covers it).
#[allow(dead_code)] // reserved for io_uring multi-worker relay
const RELAY_SEND_SLOTS: u16 = RELAY_RECV_BATCH; // 32

// ── Slot bitmaps ────────────────────────────────────────────────────────────
//
// A "send slot" owns a `MsgHdrStorage` (msghdr + sockaddr + owned send_buf)
// that the kernel reads asynchronously until the SendMsg completion (CQE)
// arrives. Reusing a slot before its CQE means overwriting memory the kernel
// is still reading — a use-after-free / data race. These bitmaps track which
// slots are free so a slot is never reused while its send is in flight.
//
// Bit `i` set = slot `i` is FREE. Allocation clears the bit; the matching
// completion sets it again (see `collect_completions`).

#[inline]
fn alloc_bit_u64(free: &mut u64) -> Option<u16> {
    if *free == 0 {
        return None;
    }
    let idx = free.trailing_zeros() as u16;
    *free &= !(1u64 << idx);
    Some(idx)
}

#[inline]
fn free_bit_u64(free: &mut u64, idx: u16) {
    *free |= 1u64 << idx;
}

#[inline]
fn alloc_bit_u32(free: &mut u32) -> Option<u16> {
    if *free == 0 {
        return None;
    }
    let idx = free.trailing_zeros() as u16;
    *free &= !(1u32 << idx);
    Some(idx)
}

#[inline]
fn free_bit_u32(free: &mut u32, idx: u16) {
    *free |= 1u32 << idx;
}

// User data encoding:
// Bits 63-56: tag (MAIN_RECV=1, MAIN_SEND=2, RELAY_RECV=3, RELAY_SEND=4)
// Bits 55-32: relay_port (for relay ops)
// Bits 31-16: msghdr_idx
// Bits 15-0:  buf_idx or send_slot
const TAG_MAIN_RECV: u64 = 0x01 << 56;
const TAG_MAIN_SEND: u64 = 0x02 << 56;
const TAG_RELAY_RECV: u64 = 0x03 << 56;
const TAG_RELAY_SEND: u64 = 0x04 << 56;
const TAG_RELAY_CANCEL: u64 = 0x05 << 56;
const TAG_MASK: u64 = 0xFF << 56;

fn encode_user_data(tag: u64, relay_port: u16, msghdr_idx: u16, buf_or_slot: u16) -> u64 {
    tag | ((relay_port as u64) << 32) | ((msghdr_idx as u64) << 16) | (buf_or_slot as u64)
}

fn decode_user_data(ud: u64) -> (u64, u16, u16, u16) {
    let tag = ud & TAG_MASK;
    let relay_port = ((ud >> 32) & 0xFFFF) as u16;
    let msghdr_idx = ((ud >> 16) & 0xFFFF) as u16;
    let buf_or_slot = (ud & 0xFFFF) as u16;
    (tag, relay_port, msghdr_idx, buf_or_slot)
}

/// Pre-allocated msghdr + sockaddr + iovec for io_uring operations.
/// For sends: `send_buf` owns the data so it survives until io_uring completion.
pub struct MsgHdrStorage {
    pub msgvec: libc::iovec,
    pub addr: libc::sockaddr_storage,
    pub addr_len: libc::socklen_t,
    pub msghdr: libc::msghdr,
    /// Owned send buffer — data must live until send completion.
    send_buf: Vec<u8>,
}

impl MsgHdrStorage {
    pub fn new() -> Self {
        Self {
            msgvec: libc::iovec {
                iov_base: std::ptr::null_mut(),
                iov_len: 0,
            },
            addr: unsafe { std::mem::zeroed() },
            addr_len: std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t,
            msghdr: unsafe { std::mem::zeroed() },
            send_buf: Vec::with_capacity(MAX_UDP_PACKET),
        }
    }

    pub fn setup_recv(&mut self, buf_ptr: *mut u8, buf_len: usize) {
        self.msgvec.iov_base = buf_ptr as *mut _;
        self.msgvec.iov_len = buf_len;
        self.addr_len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        self.addr = unsafe { std::mem::zeroed() };
        // SAFETY (self-referential): `msghdr.msg_name` and `msg_iov` are set to
        // point into `self` (the `addr` / `msgvec` fields). This is sound because
        // every `MsgHdrStorage` lives inside the `Box<[MsgHdrStorage]>` owned by
        // `UringEngine` (see USF-003 / SUSPECT #3 fix, documented below): a boxed
        // slice is a fixed-size heap allocation that never reallocates, so these
        // self-pointers stay valid for the lifetime of the engine. The pointers
        // are re-derived from `self` on every call, so they also survive the slot
        // being reused across recv completions.
        self.msghdr.msg_name = &mut self.addr as *mut _ as *mut _;
        self.msghdr.msg_namelen = self.addr_len;
        self.msghdr.msg_iov = &mut self.msgvec;
        self.msghdr.msg_iovlen = 1;
        self.msghdr.msg_control = std::ptr::null_mut();
        self.msghdr.msg_controllen = 0;
        self.msghdr.msg_flags = 0;
    }

    /// Setup send — copies data into owned buffer so it survives until completion.
    pub fn setup_send(&mut self, data: &[u8], target: &SockAddr) {
        self.send_buf.clear();
        self.send_buf.extend_from_slice(data);
        self.msgvec.iov_base = self.send_buf.as_ptr() as *mut _;
        self.msgvec.iov_len = self.send_buf.len();
        unsafe {
            std::ptr::copy_nonoverlapping(
                target.as_ptr() as *const u8,
                &mut self.addr as *mut _ as *mut u8,
                target.len() as usize,
            );
        }
        self.addr_len = target.len();
        self.msghdr.msg_name = &mut self.addr as *mut _ as *mut _;
        self.msghdr.msg_namelen = self.addr_len;
        self.msghdr.msg_iov = &mut self.msgvec;
        self.msghdr.msg_iovlen = 1;
        self.msghdr.msg_control = std::ptr::null_mut();
        self.msghdr.msg_controllen = 0;
        self.msghdr.msg_flags = 0;
    }

    pub fn source_addr(&self) -> Option<SocketAddr> {
        let sa = unsafe { SockAddr::new(self.addr, self.addr_len) };
        sa.as_socket()
    }
}

/// Relay socket state.
struct RelaySocket {
    fd: RawFd,
    /// Held only to keep the relay fd open until the relay is reclaimed; the
    /// Socket is dropped (closing the fd) when the map entry is removed after
    /// the in-flight ops drain. Never read directly.
    #[allow(dead_code)]
    socket: Option<Socket>,
    #[allow(dead_code)]
    port: u16,
    // Dedicated msghdr slots for this relay (recv + send)
    recv_msghdr_base: u16, // block base in relay_msghdrs; returned to free-list on reclaim
    send_msghdr_base: u16,
    /// Free-slot bitmap for this relay's send slots (bit i set = free).
    /// Prevents reuse of a send slot before its SendMsg completion arrives.
    send_free: u32,
    /// In-flight SQEs (recv + send) for this relay. The msghdr block is only
    /// returned to the free-list once this hits 0 — reusing it earlier would
    /// let the kernel write into another relay's reused msghdrs (corruption).
    inflight: u32,
    /// Set by `remove_relay`. Suppresses event emission / resubmits and gates
    /// block reclaim on a full in-flight drain.
    closing: bool,
    /// RFC 8016 sharded ownership: the allocation that owns this relay socket
    /// and the route generation it registered with. Used to validate forwarded
    /// `SendViaRelayOwned` commands — a stale forward (port since reused by a
    /// newer allocation) is dropped rather than sent on the wrong socket.
    allocation_id: String,
    generation: u64,
}

/// Multi-fd io_uring manager: main socket + relay sockets.
///
/// # Self-referential MsgHdrStorage (FIX for SUSPECT #3)
///
/// `MsgHdrStorage` is self-referential: after `setup_recv` / `setup_send`,
/// `msghdr.msg_iov` and `msghdr.msg_name` point into fields of the same
/// struct. This is only sound while the struct does not move.
///
/// Fix: use `Box<[MsgHdrStorage]>` instead of `Vec<MsgHdrStorage>`.
/// `Box<[T]>` is a fixed-size heap allocation that never reallocates —
/// the address of each element is permanently stable for the lifetime of
/// the Box. A `Vec` would silently invalidate self-pointers on any `push`
/// that triggers reallocation.
///
/// The old `Vec::with_capacity(N)` + fill-without-push pattern was safe
/// in practice, but `Box<[T]>` makes the stability invariant a compile-time
/// property rather than a fragile convention.
/// Ring/CQE utilisation snapshot (see `UringEngine::ring_stats`).
#[derive(Debug, Clone, Copy)]
pub struct RingStats {
    pub cqe_drained: u64,
    pub cqe_batches: u64,
    pub cqe_max_batch: u32,
    pub sq_push_failed: u64,
    pub sq_len: u32,
    pub sq_capacity: u32,
    pub cq_len: u32,
}

/// One worker's slot in [`RingStatsAggregate`]. Each io_uring worker owns its
/// own engine and publishes a fresh snapshot here on its periodic ring-log
/// tick; the node sums the slots for `/metrics`. Counters are cumulative
/// per worker; gauges (`sq_len`/`cq_len`/`buffers_available`) are last-sampled.
#[derive(Default)]
pub struct PerWorkerRing {
    pub cqe_drained: std::sync::atomic::AtomicU64,
    pub cqe_batches: std::sync::atomic::AtomicU64,
    pub cqe_max_batch: std::sync::atomic::AtomicU64,
    pub sq_push_failed: std::sync::atomic::AtomicU64,
    pub sq_len: std::sync::atomic::AtomicU64,
    pub sq_capacity: std::sync::atomic::AtomicU64,
    pub cq_len: std::sync::atomic::AtomicU64,
    pub buffers_available: std::sync::atomic::AtomicU64,
}

/// Summed view across all workers, read by the node's Prometheus copy task.
#[derive(Debug, Clone, Copy, Default)]
pub struct RingTotals {
    pub workers: u64,
    pub cqe_drained: u64,
    pub cqe_batches: u64,
    pub cqe_max_batch: u64,
    pub sq_push_failed: u64,
    pub sq_len: u64,
    pub sq_capacity: u64,
    pub cq_len: u64,
    pub buffers_available: u64,
}

/// Shared per-worker ring-stats publisher. Created by the node with one slot
/// per worker, threaded into [`crate::worker::WorkerPoolConfig`], and read back
/// (summed) for Prometheus. Lives in the transport crate so it stays free of a
/// `turna-health` dependency; the node maps [`RingTotals`] into its metrics.
pub struct RingStatsAggregate {
    pub workers: Vec<PerWorkerRing>,
}

impl RingStatsAggregate {
    pub fn new(num_workers: usize) -> Self {
        Self {
            workers: (0..num_workers).map(|_| PerWorkerRing::default()).collect(),
        }
    }

    /// Publish one worker's latest snapshot into its slot (`idx == worker_id`).
    pub fn publish(&self, idx: usize, rs: &RingStats, buffers_available: u32) {
        use std::sync::atomic::Ordering::Relaxed;
        let Some(w) = self.workers.get(idx) else { return };
        w.cqe_drained.store(rs.cqe_drained, Relaxed);
        w.cqe_batches.store(rs.cqe_batches, Relaxed);
        w.cqe_max_batch.store(rs.cqe_max_batch as u64, Relaxed);
        w.sq_push_failed.store(rs.sq_push_failed, Relaxed);
        w.sq_len.store(rs.sq_len as u64, Relaxed);
        w.sq_capacity.store(rs.sq_capacity as u64, Relaxed);
        w.cq_len.store(rs.cq_len as u64, Relaxed);
        w.buffers_available.store(buffers_available as u64, Relaxed);
    }

    /// Sum counters / occupancy across all workers; `cqe_max_batch` is a max.
    pub fn totals(&self) -> RingTotals {
        use std::sync::atomic::Ordering::Relaxed;
        let mut t = RingTotals {
            workers: self.workers.len() as u64,
            ..Default::default()
        };
        for w in &self.workers {
            t.cqe_drained += w.cqe_drained.load(Relaxed);
            t.cqe_batches += w.cqe_batches.load(Relaxed);
            t.cqe_max_batch = t.cqe_max_batch.max(w.cqe_max_batch.load(Relaxed));
            t.sq_push_failed += w.sq_push_failed.load(Relaxed);
            t.sq_len += w.sq_len.load(Relaxed);
            t.sq_capacity += w.sq_capacity.load(Relaxed);
            t.cq_len += w.cq_len.load(Relaxed);
            t.buffers_available += w.buffers_available.load(Relaxed);
        }
        t
    }
}

pub struct UringEngine {
    ring: IoUring,
    // Main socket
    main_fd: RawFd,
    _main_socket: Socket,
    main_addr: SocketAddr,
    // Shared buffers
    buffers: BufferRing,
    /// FIX (SUSPECT #3): Box<[...]> instead of Vec<...> — fixed heap address,
    /// never reallocates, keeps self-referential MsgHdrStorage valid.
    main_recv_msghdrs: Box<[MsgHdrStorage]>,
    main_send_msghdrs: Box<[MsgHdrStorage]>,
    // Relay sockets
    relay_sockets: HashMap<u16, RelaySocket>,
    /// FIX (SUSPECT #3): same as above.
    relay_msghdrs: Box<[MsgHdrStorage]>,
    /// Free-list of 64-slot relay msghdr blocks (32 recv + 32 send each).
    /// A block returns here only once its relay has fully drained.
    relay_free_blocks: Vec<u16>,
    /// Free-slot bitmap for the 64 main-socket send slots (bit i set = free).
    main_send_free: u64,
    // ── Ring/CQE utilisation metrics (single-owner thread; plain counters,
    //    no atomics needed). Snapshotted by the worker for periodic logging. ──
    /// Total CQEs drained across all `collect_completions` calls.
    cqe_drained: u64,
    /// Number of `collect_completions` calls (drain batches).
    cqe_batches: u64,
    /// Largest single drain batch (work events produced in one call).
    cqe_max_batch: u32,
    /// Count of SQE push failures (submission ring full → backpressure signal).
    sq_push_failed: u64,
    /// Last observed submission-queue occupancy / capacity (sampled per drain).
    last_sq_len: u32,
    sq_capacity: u32,
    /// Last observed completion-queue pending count at drain entry.
    last_cq_len: u32,
}

/// Completion event.
pub enum CompletionEvent {
    MainRecv {
        buf_idx: u16,
        msghdr_idx: u16,
        len: usize,
        source: SocketAddr,
    },
    /// A main-socket recv completed with an error (e.g. transient -EAGAIN).
    /// The worker re-arms this exact msghdr/buffer so the recv slot is not
    /// retired and the buffer is not leaked.
    MainRecvError {
        msghdr_idx: u16,
        buf_idx: u16,
    },
    MainSend {
        send_slot: u16,
        result: i32,
    },
    RelayRecv {
        relay_port: u16,
        buf_idx: u16,
        msghdr_idx: u16,
        len: usize,
        source: SocketAddr,
    },
    RelaySend {
        relay_port: u16,
        send_slot: u16,
        result: i32,
    },
}

impl UringEngine {
    pub fn new(addr: SocketAddr, reuse_port: bool, buf_count: u16) -> std::io::Result<Self> {
        let domain = if addr.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };
        let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_reuse_address(true)?;
        if reuse_port {
            socket.set_reuse_port(true)?;
        }
        socket.set_nonblocking(true)?;
        socket.bind(&SockAddr::from(addr))?;
        let main_addr = socket.local_addr()?.as_socket().unwrap();
        let main_fd = socket.as_raw_fd();

        // SQPOLL burns a dedicated kernel poller thread per ring even at idle,
        // so it is opt-in: set TURNA_IOURING_SQPOLL_MS=<idle_ms> to enable.
        // Unset / 0 → plain ring (interrupt-driven), which is the right default
        // for anything but sustained high PPS.
        let sqpoll_idle: u32 = std::env::var("TURNA_IOURING_SQPOLL_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let ring = if sqpoll_idle > 0 {
            IoUring::builder()
                .setup_sqpoll(sqpoll_idle)
                .build(RING_SIZE)
                .or_else(|_| {
                    info!("SQPOLL not available, falling back to interrupt-driven ring");
                    IoUring::new(RING_SIZE)
                })?
        } else {
            IoUring::new(RING_SIZE)?
        };

        let buffers = BufferRing::new(buf_count);

        // FIX (SUSPECT #3): collect into Vec first, then convert to Box<[...]>.
        // Box<[T]> has a fixed heap address — no reallocation possible —
        // which keeps the self-referential pointers in MsgHdrStorage valid.
        let main_recv_msghdrs = (0..RECV_BATCH)
            .map(|_| MsgHdrStorage::new())
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let main_send_msghdrs = (0..MAIN_SEND_SLOTS)
            .map(|_| MsgHdrStorage::new())
            .collect::<Vec<_>>()
            .into_boxed_slice();

        let relay_pool_size = 512;
        let relay_msghdrs = (0..relay_pool_size)
            .map(|_| MsgHdrStorage::new())
            .collect::<Vec<_>>()
            .into_boxed_slice();

        info!(%main_addr, buf_count, "io_uring engine created");

        Ok(Self {
            ring,
            main_fd,
            _main_socket: socket,
            main_addr,
            buffers,
            main_recv_msghdrs,
            main_send_msghdrs,
            relay_sockets: HashMap::new(),
            relay_msghdrs,
            relay_free_blocks: (0..relay_pool_size as u16)
                .step_by(RELAY_RECV_BATCH as usize * 2)
                .collect(),
            // All MAIN_SEND_SLOTS slots start free. MAIN_SEND_SLOTS == 64, so
            // the full u64 is "all free"; if it ever shrinks below 64, mask.
            main_send_free: u64::MAX,
            cqe_drained: 0,
            cqe_batches: 0,
            cqe_max_batch: 0,
            sq_push_failed: 0,
            last_sq_len: 0,
            sq_capacity: 0,
            last_cq_len: 0,
        })
    }

    // === Main socket operations ===

    pub fn submit_initial_recvs(&mut self) -> std::io::Result<()> {
        let batch = RECV_BATCH.min(self.buffers.available() as u16);
        for i in 0..batch {
            let Some(buf_idx) = self.buffers.acquire() else {
                break;
            };
            self.submit_main_recv(i, buf_idx)?;
        }
        self.ring.submit()?;
        info!(batch, "initial main recvs submitted");
        Ok(())
    }

    fn submit_main_recv(&mut self, msghdr_idx: u16, buf_idx: u16) -> std::io::Result<()> {
        let buf = self.buffers.get_mut(buf_idx);
        let msghdr = &mut self.main_recv_msghdrs[msghdr_idx as usize];
        msghdr.setup_recv(buf.as_mut_ptr(), MAX_UDP_PACKET);

        let ud = encode_user_data(TAG_MAIN_RECV, 0, msghdr_idx, buf_idx);
        let entry = opcode::RecvMsg::new(types::Fd(self.main_fd), &mut msghdr.msghdr as *mut _)
            .build()
            .user_data(ud);
        // NEEDS-REVIEW: io_uring submission requires that everything the
        // SQE references (msghdr, iovec, sockaddr, buffer) lives until the
        // kernel completes the operation. The msghdr is held in a Vec slot
        // indexed by `slot`; there is currently no mechanism marking a slot
        // as 'busy until completion'. If a slot index is reused before the
        // CQE arrives, the kernel will write through dangling msghdr.
        unsafe {
            self.ring
                .submission()
                .push(&entry)
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "SQ full"))?;
        }
        Ok(())
    }

    pub fn resubmit_main_recv(&mut self, msghdr_idx: u16, buf_idx: u16) -> std::io::Result<()> {
        self.submit_main_recv(msghdr_idx, buf_idx)
    }

    /// Submit a send on the main socket.
    ///
    /// Acquires a free send slot internally and returns it; the slot is
    /// released when the matching `MainSend` completion arrives (see
    /// `collect_completions`). Returns `WouldBlock` if every send slot is still
    /// in flight — the caller should flush/drain completions and retry rather
    /// than overwriting an in-flight slot (which would be a use-after-free).
    pub fn submit_main_send(&mut self, data: &[u8], target: SocketAddr) -> std::io::Result<u16> {
        let slot = alloc_bit_u64(&mut self.main_send_free).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::WouldBlock, "main send slots exhausted")
        })?;
        let sa = SockAddr::from(target);
        let msghdr = &mut self.main_send_msghdrs[slot as usize];
        msghdr.setup_send(data, &sa);
        let ud = encode_user_data(TAG_MAIN_SEND, 0, 0, slot);
        let entry = opcode::SendMsg::new(types::Fd(self.main_fd), &msghdr.msghdr as *const _)
            .build()
            .user_data(ud);
        let pushed = unsafe { self.ring.submission().push(&entry) };
        if pushed.is_err() {
            self.sq_push_failed += 1;
            // Roll the slot back so a full SQ doesn't leak it forever.
            free_bit_u64(&mut self.main_send_free, slot);
            return Err(std::io::Error::new(std::io::ErrorKind::Other, "SQ full"));
        }
        Ok(slot)
    }

    // === Relay socket operations ===

    /// Create a relay socket and start receiving on it.
    pub fn add_relay(
        &mut self,
        port: u16,
        allocation_id: String,
        generation: u64,
    ) -> std::io::Result<()> {
        let bind_addr: SocketAddr = format!("0.0.0.0:{port}").parse().unwrap();
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_reuse_address(true)?;
        socket.set_nonblocking(true)?;
        socket.bind(&SockAddr::from(bind_addr))?;
        let fd = socket.as_raw_fd();

        // Free-list reclaim: pop a 64-slot block (32 recv + 32 send). On
        // exhaustion, reject the relay cleanly — the worker survives and the
        // client gets a 508 instead of a crash. Blocks return to the list once
        // a relay's in-flight ops fully drain (see remove_relay /
        // collect_completions).
        let Some(recv_base) = self.relay_free_blocks.pop() else {
            warn!(
                port,
                cap = self.relay_msghdrs.len(),
                "io_uring relay msghdr pool exhausted — rejecting relay"
            );
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "io_uring relay msghdr pool exhausted",
            ));
        };
        let send_base = recv_base + RELAY_RECV_BATCH;

        self.relay_sockets.insert(
            port,
            RelaySocket {
                fd,
                socket: Some(socket),
                port,
                recv_msghdr_base: recv_base,
                send_msghdr_base: send_base,
                // RELAY_SEND_SLOTS (32) slots, all free → low 32 bits set.
                send_free: u32::MAX,
                inflight: 0,
                closing: false,
                allocation_id,
                generation,
            },
        );

        // Submit initial recvs on relay socket
        for i in 0..RELAY_RECV_BATCH {
            let Some(buf_idx) = self.buffers.acquire() else {
                break;
            };
            self.submit_relay_recv(port, fd, recv_base + i, buf_idx)?;
        }

        info!(port, "relay socket added to io_uring");
        Ok(())
    }

    fn submit_relay_recv(
        &mut self,
        port: u16,
        fd: RawFd,
        msghdr_idx: u16,
        buf_idx: u16,
    ) -> std::io::Result<()> {
        let buf = self.buffers.get_mut(buf_idx);
        let msghdr = &mut self.relay_msghdrs[msghdr_idx as usize];
        msghdr.setup_recv(buf.as_mut_ptr(), MAX_UDP_PACKET);

        let ud = encode_user_data(TAG_RELAY_RECV, port, msghdr_idx, buf_idx);
        let entry = opcode::RecvMsg::new(types::Fd(fd), &mut msghdr.msghdr as *mut _)
            .build()
            .user_data(ud);
        unsafe {
            self.ring
                .submission()
                .push(&entry)
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "SQ full"))?;
        }
        if let Some(relay) = self.relay_sockets.get_mut(&port) {
            relay.inflight += 1; // recv in flight
        }
        Ok(())
    }

    pub fn resubmit_relay_recv(
        &mut self,
        port: u16,
        msghdr_idx: u16,
        buf_idx: u16,
    ) -> std::io::Result<()> {
        // Only re-arm an open, non-closing relay. If it was reclaimed or is
        // draining, return the recv buffer to the pool instead of leaking it.
        let fd = match self.relay_sockets.get(&port) {
            Some(relay) if !relay.closing => relay.fd,
            _ => {
                self.buffers.release(buf_idx);
                return Ok(());
            }
        };
        self.submit_relay_recv(port, fd, msghdr_idx, buf_idx)
    }

    pub fn submit_relay_send(
        &mut self,
        port: u16,
        data: &[u8],
        target: SocketAddr,
    ) -> std::io::Result<u16> {
        // Phase 1: borrow the relay only long enough to read fd/base and grab a
        // free send slot from its bitmap.
        let (fd, msghdr_idx, slot) = {
            let Some(relay) = self.relay_sockets.get_mut(&port) else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "relay not found",
                ));
            };
            if relay.closing {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "relay closing",
                ));
            }
            let slot = alloc_bit_u32(&mut relay.send_free).ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::WouldBlock, "relay send slots exhausted")
            })?;
            (relay.fd, relay.send_msghdr_base + slot, slot)
        };
        // Phase 2: relay_msghdrs is a different field — no borrow conflict with
        // the relay_sockets map.
        let sa = SockAddr::from(target);
        let msghdr = &mut self.relay_msghdrs[msghdr_idx as usize];
        msghdr.setup_send(data, &sa);
        let ud = encode_user_data(TAG_RELAY_SEND, port, 0, slot);
        let entry = opcode::SendMsg::new(types::Fd(fd), &msghdr.msghdr as *const _)
            .build()
            .user_data(ud);
        let pushed = unsafe { self.ring.submission().push(&entry) };
        if pushed.is_err() {
            self.sq_push_failed += 1;
            if let Some(relay) = self.relay_sockets.get_mut(&port) {
                free_bit_u32(&mut relay.send_free, slot);
            }
            return Err(std::io::Error::new(std::io::ErrorKind::Other, "SQ full"));
        }
        if let Some(relay) = self.relay_sockets.get_mut(&port) {
            relay.inflight += 1; // send in flight
        }
        Ok(slot)
    }

    // === Shared operations ===

    pub fn flush(&mut self) -> std::io::Result<usize> {
        self.ring.submit()
    }
    pub fn submit_and_wait(&mut self) -> std::io::Result<usize> {
        self.ring.submit_and_wait(1)
    }

    /// Bounded wait (RFC 8016 sharded-ownership v1 wakeup). Replaces a bare
    /// `submit_and_wait(1)` so the worker loop unparks within `dur` even with
    /// no ring activity, then drains its cross-worker command channel. Returns
    /// `Ok(0)` on timeout (no completion within `dur`), `Ok(n)` otherwise.
    pub fn submit_and_wait_timeout(&mut self, dur: std::time::Duration) -> std::io::Result<usize> {
        let ts = types::Timespec::new()
            .sec(dur.as_secs())
            .nsec(dur.subsec_nanos());
        let args = types::SubmitArgs::new().timespec(&ts);
        match self.ring.submitter().submit_with_args(1, &args) {
            Ok(n) => Ok(n),
            // ETIME: the wait window elapsed with no completion — expected.
            Err(e) if e.raw_os_error() == Some(libc::ETIME) => Ok(0),
            Err(e) => Err(e),
        }
    }

    /// Collect all completions into a Vec (avoids borrow issues).
    pub fn collect_completions(&mut self) -> Vec<CompletionEvent> {
        let mut events = Vec::new();
        // Sample submission-queue occupancy before draining completions
        // (disjoint-field borrow: `sq` borrows only `self.ring`).
        {
            let sq = self.ring.submission();
            self.last_sq_len = sq.len() as u32;
            self.sq_capacity = sq.capacity() as u32;
        }
        let cq = self.ring.completion();
        self.last_cq_len = cq.len() as u32;
        let drained_before = self.cqe_drained;
        for cqe in cq {
            self.cqe_drained += 1;
            let ud = cqe.user_data();
            let result = cqe.result();
            let (tag, relay_port, msghdr_idx, buf_or_slot) = decode_user_data(ud);

            let event = match tag {
                t if t == TAG_MAIN_RECV => {
                    if result < 0 {
                        // Transient error (commonly -EAGAIN == -11): re-arm the
                        // slot via the worker instead of retiring it + leaking
                        // the buffer. -EAGAIN is too noisy for warn!.
                        if result != -11 {
                            warn!(err = result, "main recv error");
                        }
                        events.push(CompletionEvent::MainRecvError {
                            msghdr_idx,
                            buf_idx: buf_or_slot,
                        });
                        continue;
                    }
                    let source = self.main_recv_msghdrs[msghdr_idx as usize]
                        .source_addr()
                        .unwrap_or_else(|| "0.0.0.0:0".parse().unwrap());
                    CompletionEvent::MainRecv {
                        buf_idx: buf_or_slot,
                        msghdr_idx,
                        len: result as usize,
                        source,
                    }
                }
                t if t == TAG_MAIN_SEND => {
                    // Send completed → the slot's msghdr/buffer are no longer
                    // read by the kernel, so the slot can be reused safely.
                    free_bit_u64(&mut self.main_send_free, buf_or_slot);
                    CompletionEvent::MainSend {
                        send_slot: buf_or_slot,
                        result,
                    }
                }
                t if t == TAG_RELAY_RECV => {
                    // Account for the in-flight recv that just completed.
                    let mut closing = false;
                    let mut reclaim_base: Option<u16> = None;
                    if let Some(relay) = self.relay_sockets.get_mut(&relay_port) {
                        relay.inflight = relay.inflight.saturating_sub(1);
                        if relay.closing {
                            closing = true;
                            if relay.inflight == 0 {
                                reclaim_base = Some(relay.recv_msghdr_base);
                            }
                        }
                    }
                    if closing {
                        // Draining relay: drop the buffer, emit nothing, and
                        // reclaim the block once fully drained.
                        self.buffers.release(buf_or_slot);
                        if let Some(base) = reclaim_base {
                            self.relay_sockets.remove(&relay_port);
                            self.relay_free_blocks.push(base);
                            info!(port = relay_port, "io_uring relay reclaimed (drained)");
                        }
                        continue;
                    }
                    if result < 0 {
                        warn!(relay_port, err = result, "relay recv error");
                        // Recv errored on an open relay: release the buffer
                        // (the worker won't resubmit this slot).
                        self.buffers.release(buf_or_slot);
                        continue;
                    }
                    let source = self.relay_msghdrs[msghdr_idx as usize]
                        .source_addr()
                        .unwrap_or_else(|| "0.0.0.0:0".parse().unwrap());
                    CompletionEvent::RelayRecv {
                        relay_port,
                        buf_idx: buf_or_slot,
                        msghdr_idx,
                        len: result as usize,
                        source,
                    }
                }
                t if t == TAG_RELAY_SEND => {
                    // Release the send slot and account for the in-flight send;
                    // reclaim the block if a closing relay just drained.
                    let mut reclaim_base: Option<u16> = None;
                    if let Some(relay) = self.relay_sockets.get_mut(&relay_port) {
                        free_bit_u32(&mut relay.send_free, buf_or_slot);
                        relay.inflight = relay.inflight.saturating_sub(1); // send drained
                        if relay.closing && relay.inflight == 0 {
                            reclaim_base = Some(relay.recv_msghdr_base);
                        }
                    }
                    if let Some(base) = reclaim_base {
                        self.relay_sockets.remove(&relay_port);
                        self.relay_free_blocks.push(base);
                        info!(port = relay_port, "io_uring relay reclaimed (drained)");
                        continue;
                    }
                    CompletionEvent::RelaySend {
                        relay_port,
                        send_slot: buf_or_slot,
                        result,
                    }
                }
                t if t == TAG_RELAY_CANCEL => continue,
                _ => continue,
            };
            events.push(event);
        }
        // Count a drain "batch" only when we actually pulled >=1 CQE. The
        // worker calls collect_completions every loop iteration (including
        // empty 500us wait-timeout cycles); counting every call inflated
        // cqe_batches far past cqe_drained and broke the HELP ("pulled >=1
        // CQE"). cqe_max_batch now tracks the largest CQE drain in one call.
        let drained_now = self.cqe_drained - drained_before;
        if drained_now > 0 {
            self.cqe_batches += 1;
            if drained_now as u32 > self.cqe_max_batch {
                self.cqe_max_batch = drained_now as u32;
            }
        }
        events
    }

    /// Snapshot of ring/CQE utilisation counters for periodic logging. The
    /// average CQE-per-drain (`cqe_drained / cqe_batches`) indicates batching
    /// efficiency; `sq_push_failed` rising means the submission ring is
    /// saturating (backpressure); `sq_len`/`cq_len` are the last sampled live
    /// occupancies.
    pub fn ring_stats(&self) -> RingStats {
        RingStats {
            cqe_drained: self.cqe_drained,
            cqe_batches: self.cqe_batches,
            cqe_max_batch: self.cqe_max_batch,
            sq_push_failed: self.sq_push_failed,
            sq_len: self.last_sq_len,
            sq_capacity: self.sq_capacity,
            cq_len: self.last_cq_len,
        }
    }

    pub fn buffer_data(&self, idx: u16, len: usize) -> &[u8] {
        &self.buffers.get(idx).as_slice()[..len]
    }

    pub fn release_buffer(&mut self, idx: u16) {
        self.buffers.release(idx);
    }
    pub fn local_addr(&self) -> SocketAddr {
        self.main_addr
    }
    pub fn buffers_available(&self) -> usize {
        self.buffers.available()
    }
    /// Begin closing a relay: mark it draining and drop its `Socket` (closing
    /// the fd, so the kernel completes any in-flight recvs). The msghdr block
    /// is returned to the free-list only once all in-flight ops have drained
    /// (here if already idle, otherwise in `collect_completions`). Reusing the
    /// block before the drain would let late kernel writes corrupt a reused
    /// relay's msghdrs.
    pub fn remove_relay(&mut self, port: u16) {
        // Snapshot fd + drain state; mark closing so no new recvs are armed.
        let (fd, idle, base) = match self.relay_sockets.get_mut(&port) {
            Some(relay) => {
                relay.closing = true;
                (relay.fd, relay.inflight == 0, relay.recv_msghdr_base)
            }
            None => return,
        };
        if idle {
            // No in-flight ops: reclaim now (drops the Socket -> closes fd).
            self.relay_sockets.remove(&port);
            self.relay_free_blocks.push(base);
            info!(port, "io_uring relay reclaimed (idle)");
            return;
        }
        // Closing an fd does NOT drain io_uring ops — the kernel holds its own
        // file reference, so armed RecvMsg SQEs would hang forever waiting for a
        // datagram that never comes. Explicitly cancel every in-flight op on
        // this fd; the recvs complete with -ECANCELED, drive `inflight` to 0,
        // and reclaim fires in collect_completions. The Socket stays alive (fd
        // valid) until reclaim removes the entry and drops it.
        let ud = encode_user_data(TAG_RELAY_CANCEL, port, 0, 0);
        let entry = opcode::AsyncCancel2::new(CancelBuilder::fd(types::Fd(fd)).all())
            .build()
            .user_data(ud);
        if unsafe { self.ring.submission().push(&entry) }.is_err() {
            // SQ full: stay closing (nothing new is armed); a later close/drain
            // pass can re-issue. The block stays reserved until drained.
            warn!(port, "SQ full — relay cancel not submitted, will retry");
        } else {
            info!(port, "io_uring relay closing — cancelling in-flight ops");
        }
    }

    pub fn has_relay(&self, port: u16) -> bool {
        self.relay_sockets.contains_key(&port)
    }

    /// RFC 8016 sharded ownership: the `(allocation_id, generation)` of the
    /// relay socket this worker owns for `port`, if any. The worker compares it
    /// against a forwarded `SendViaRelayOwned` to reject stale commands.
    pub fn relay_record(&self, port: u16) -> Option<(&str, u64)> {
        self.relay_sockets
            .get(&port)
            .map(|r| (r.allocation_id.as_str(), r.generation))
    }
}
