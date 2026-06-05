//! io_uring-based UDP transport (Linux 5.6+)
//!
//! Supports multiple fds in one ring: main TURN socket + N relay sockets.
//! All recv/send operations share one io_uring instance for max batching.

#![cfg(all(target_os = "linux", feature = "io-uring"))]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, RawFd};
use io_uring::{IoUring, opcode, types};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use crate::buffer::{BufferRing, MAX_UDP_PACKET};
use tracing::{info, warn};

const RING_SIZE: u32 = 512;
const RECV_BATCH: u16 = 64;
const RELAY_RECV_BATCH: u16 = 32; // per relay socket

// User data encoding:
// Bits 63-56: tag (MAIN_RECV=1, MAIN_SEND=2, RELAY_RECV=3, RELAY_SEND=4)
// Bits 55-32: relay_port (for relay ops)
// Bits 31-16: msghdr_idx
// Bits 15-0:  buf_idx or send_slot
const TAG_MAIN_RECV: u64  = 0x01 << 56;
const TAG_MAIN_SEND: u64  = 0x02 << 56;
const TAG_RELAY_RECV: u64 = 0x03 << 56;
const TAG_RELAY_SEND: u64 = 0x04 << 56;
const TAG_MASK: u64       = 0xFF << 56;

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
            msgvec: libc::iovec { iov_base: std::ptr::null_mut(), iov_len: 0 },
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
        // SUSPECT: MsgHdrStorage is self-referential — msghdr.msg_name
        // and msg_iov point into the same struct. Sound only as long as
        // the storage is not moved. Currently held in Vec<MsgHdrStorage>
        // inside UringEngine; the Vec is sized once with `with_capacity`
        // in `new()` and never grows, so addresses are stable. Any future
        // `push` to those Vecs would silently break this.
        // Fix: Box<MsgHdrStorage> for stable address, or explicit Pin.
        // See docs/unsafe-audit.md §SUSPECT #3.
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
    _socket: Socket,
    port: u16,
    // Dedicated msghdr slots for this relay (recv + send)
    recv_msghdr_base: u16, // starting index in relay_msghdrs
    send_msghdr_base: u16,
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
    relay_msghdr_next: u16,
}

/// Completion event.
pub enum CompletionEvent {
    MainRecv { buf_idx: u16, msghdr_idx: u16, len: usize, source: SocketAddr },
    MainSend { send_slot: u16, result: i32 },
    RelayRecv { relay_port: u16, buf_idx: u16, msghdr_idx: u16, len: usize, source: SocketAddr },
    RelaySend { relay_port: u16, send_slot: u16, result: i32 },
}

impl UringEngine {
    pub fn new(addr: SocketAddr, reuse_port: bool, buf_count: u16) -> std::io::Result<Self> {
        let domain = if addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
        let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_reuse_address(true)?;
        if reuse_port { socket.set_reuse_port(true)?; }
        socket.set_nonblocking(true)?;
        socket.bind(&SockAddr::from(addr))?;
        let main_addr = socket.local_addr()?.as_socket().unwrap();
        let main_fd = socket.as_raw_fd();

        let ring = IoUring::builder()
            .setup_sqpoll(2000)
            .build(RING_SIZE)
            .or_else(|_| {
                info!("SQPOLL not available, falling back");
                IoUring::new(RING_SIZE)
            })?;

        let buffers = BufferRing::new(buf_count);

        // FIX (SUSPECT #3): collect into Vec first, then convert to Box<[...]>.
        // Box<[T]> has a fixed heap address — no reallocation possible —
        // which keeps the self-referential pointers in MsgHdrStorage valid.
        let main_recv_msghdrs = (0..RECV_BATCH)
            .map(|_| MsgHdrStorage::new())
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let main_send_msghdrs = (0..64)
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
            relay_msghdr_next: 0,
        })
    }

    // === Main socket operations ===

    pub fn submit_initial_recvs(&mut self) -> std::io::Result<()> {
        let batch = RECV_BATCH.min(self.buffers.available() as u16);
        for i in 0..batch {
            let Some(buf_idx) = self.buffers.acquire() else { break };
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
            .build().user_data(ud);
        // NEEDS-REVIEW: io_uring submission requires that everything the
        // SQE references (msghdr, iovec, sockaddr, buffer) lives until the
        // kernel completes the operation. The msghdr is held in a Vec slot
        // indexed by `slot`; there is currently no mechanism marking a slot
        // as 'busy until completion'. If a slot index is reused before the
        // CQE arrives, the kernel will write through dangling msghdr.
        unsafe { self.ring.submission().push(&entry)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "SQ full"))?; }
        Ok(())
    }

    pub fn resubmit_main_recv(&mut self, msghdr_idx: u16, buf_idx: u16) -> std::io::Result<()> {
        self.submit_main_recv(msghdr_idx, buf_idx)
    }

    pub fn submit_main_send(&mut self, data: &[u8], target: SocketAddr, slot: u16) -> std::io::Result<()> {
        let sa = SockAddr::from(target);
        let msghdr = &mut self.main_send_msghdrs[slot as usize];
        msghdr.setup_send(data, &sa);
        let ud = encode_user_data(TAG_MAIN_SEND, 0, 0, slot);
        let entry = opcode::SendMsg::new(types::Fd(self.main_fd), &msghdr.msghdr as *const _)
            .build().user_data(ud);
        unsafe { self.ring.submission().push(&entry)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "SQ full"))?; }
        Ok(())
    }

    // === Relay socket operations ===

    /// Create a relay socket and start receiving on it.
    pub fn add_relay(&mut self, port: u16) -> std::io::Result<()> {
        let bind_addr: SocketAddr = format!("0.0.0.0:{port}").parse().unwrap();
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_reuse_address(true)?;
        socket.set_nonblocking(true)?;
        socket.bind(&SockAddr::from(bind_addr))?;
        let fd = socket.as_raw_fd();

        let recv_base = self.relay_msghdr_next;
        let send_base = recv_base + RELAY_RECV_BATCH;
        self.relay_msghdr_next = send_base + RELAY_RECV_BATCH;

        self.relay_sockets.insert(port, RelaySocket {
            fd,
            _socket: socket,
            port,
            recv_msghdr_base: recv_base,
            send_msghdr_base: send_base,
        });

        // Submit initial recvs on relay socket
        for i in 0..RELAY_RECV_BATCH {
            let Some(buf_idx) = self.buffers.acquire() else { break };
            self.submit_relay_recv(port, fd, recv_base + i, buf_idx)?;
        }

        info!(port, "relay socket added to io_uring");
        Ok(())
    }

    fn submit_relay_recv(&mut self, port: u16, fd: RawFd, msghdr_idx: u16, buf_idx: u16) -> std::io::Result<()> {
        let buf = self.buffers.get_mut(buf_idx);
        let msghdr = &mut self.relay_msghdrs[msghdr_idx as usize];
        msghdr.setup_recv(buf.as_mut_ptr(), MAX_UDP_PACKET);

        let ud = encode_user_data(TAG_RELAY_RECV, port, msghdr_idx, buf_idx);
        let entry = opcode::RecvMsg::new(types::Fd(fd), &mut msghdr.msghdr as *mut _)
            .build().user_data(ud);
        unsafe { self.ring.submission().push(&entry)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "SQ full"))?; }
        Ok(())
    }

    pub fn resubmit_relay_recv(&mut self, port: u16, msghdr_idx: u16, buf_idx: u16) -> std::io::Result<()> {
        if let Some(relay) = self.relay_sockets.get(&port) {
            let fd = relay.fd;
            self.submit_relay_recv(port, fd, msghdr_idx, buf_idx)
        } else {
            Ok(())
        }
    }

    pub fn submit_relay_send(&mut self, port: u16, data: &[u8], target: SocketAddr, slot: u16) -> std::io::Result<()> {
        let Some(relay) = self.relay_sockets.get(&port) else {
            return Err(std::io::Error::new(std::io::ErrorKind::NotFound, "relay not found"));
        };
        let fd = relay.fd;
        let msghdr_idx = relay.send_msghdr_base + slot;
        let sa = SockAddr::from(target);
        let msghdr = &mut self.relay_msghdrs[msghdr_idx as usize];
        msghdr.setup_send(data, &sa);

        let ud = encode_user_data(TAG_RELAY_SEND, port, 0, slot);
        let entry = opcode::SendMsg::new(types::Fd(fd), &msghdr.msghdr as *const _)
            .build().user_data(ud);
        unsafe { self.ring.submission().push(&entry)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "SQ full"))?; }
        Ok(())
    }

    // === Shared operations ===

    pub fn flush(&mut self) -> std::io::Result<usize> { self.ring.submit() }
    pub fn submit_and_wait(&mut self) -> std::io::Result<usize> { self.ring.submit_and_wait(1) }

    /// Collect all completions into a Vec (avoids borrow issues).
    pub fn collect_completions(&mut self) -> Vec<CompletionEvent> {
        let mut events = Vec::new();
        let cq = self.ring.completion();
        for cqe in cq {
            let ud = cqe.user_data();
            let result = cqe.result();
            let (tag, relay_port, msghdr_idx, buf_or_slot) = decode_user_data(ud);

            let event = match tag {
                t if t == TAG_MAIN_RECV => {
                    if result < 0 { warn!(err = result, "main recv error"); continue; }
                    let source = self.main_recv_msghdrs[msghdr_idx as usize]
                        .source_addr().unwrap_or_else(|| "0.0.0.0:0".parse().unwrap());
                    CompletionEvent::MainRecv { buf_idx: buf_or_slot, msghdr_idx, len: result as usize, source }
                }
                t if t == TAG_MAIN_SEND => {
                    CompletionEvent::MainSend { send_slot: buf_or_slot, result }
                }
                t if t == TAG_RELAY_RECV => {
                    if result < 0 { warn!(relay_port, err = result, "relay recv error"); continue; }
                    let source = self.relay_msghdrs[msghdr_idx as usize]
                        .source_addr().unwrap_or_else(|| "0.0.0.0:0".parse().unwrap());
                    CompletionEvent::RelayRecv { relay_port, buf_idx: buf_or_slot, msghdr_idx, len: result as usize, source }
                }
                t if t == TAG_RELAY_SEND => {
                    CompletionEvent::RelaySend { relay_port, send_slot: buf_or_slot, result }
                }
                _ => continue,
            };
            events.push(event);
        }
        events
    }

    pub fn buffer_data(&self, idx: u16, len: usize) -> &[u8] {
        &self.buffers.get(idx).as_slice()[..len]
    }

    pub fn release_buffer(&mut self, idx: u16) { self.buffers.release(idx); }
    pub fn local_addr(&self) -> SocketAddr { self.main_addr }
    pub fn buffers_available(&self) -> usize { self.buffers.available() }
    pub fn has_relay(&self, port: u16) -> bool { self.relay_sockets.contains_key(&port) }
}