//! AF_XDP Transport — zero-copy UDP via kernel bypass.
//!
//! AF_XDP provides a raw socket that shares a memory region (UMEM) between
//! kernel and userspace. Packets are received/sent without copying through
//! the kernel network stack.
//!
//! Architecture:
//!   UMEM (shared memory)
//!     ├── Fill Ring     (userspace → kernel: "here are empty buffers")
//!     ├── Completion Ring (kernel → userspace: "these sends completed")
//!     ├── RX Ring       (kernel → userspace: "received packets here")
//!     └── TX Ring       (userspace → kernel: "send these packets")
//!
//! Requires: Linux 5.4+, CAP_NET_RAW or root.
//! Enable: `--features af-xdp`

#![cfg(target_os = "linux")]

use std::net::SocketAddr;
use std::os::fd::RawFd;

use thiserror::Error;
use tracing::{info, warn};

#[derive(Debug, Error)]
pub enum AfXdpError {
    #[error("socket creation: {0}")]
    Socket(std::io::Error),
    #[error("UMEM allocation: {0}")]
    Umem(String),
    #[error("bind: {0}")]
    Bind(String),
    #[error("ring setup: {0}")]
    Ring(String),
    #[error("xdp program: {0}")]
    Xdp(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, AfXdpError>;

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct AfXdpConfig {
    /// Interface name (e.g., "eth0").
    pub interface: String,
    /// Queue ID to bind to.
    pub queue_id: u32,
    /// Number of frames in UMEM.
    pub frame_count: u32,
    /// Size of each frame.
    pub frame_size: u32,
    /// Fill ring size (power of 2).
    pub fill_ring_size: u32,
    /// Completion ring size.
    pub comp_ring_size: u32,
    /// RX ring size.
    pub rx_ring_size: u32,
    /// TX ring size.
    pub tx_ring_size: u32,
    /// Use zero-copy mode (requires driver support).
    pub zero_copy: bool,
    /// Use NEED_WAKEUP flag for efficiency.
    pub need_wakeup: bool,
}

impl Default for AfXdpConfig {
    fn default() -> Self {
        Self {
            interface: "eth0".into(),
            queue_id: 0,
            frame_count: 4096,
            frame_size: 2048,
            fill_ring_size: 2048,
            comp_ring_size: 2048,
            rx_ring_size: 2048,
            tx_ring_size: 2048,
            zero_copy: false,
            need_wakeup: true,
        }
    }
}

// ---------------------------------------------------------------------------
// UMEM — shared memory region
// ---------------------------------------------------------------------------

/// UMEM: shared memory between kernel and userspace.
#[allow(dead_code)] // legacy hand-rolled datapath; the xsk module is the live one
pub struct Umem {
    /// mmap'd memory region.
    area: *mut u8,
    /// Total size.
    size: usize,
    /// Frame size.
    frame_size: u32,
    /// Number of frames.
    frame_count: u32,
    /// Free frame indices.
    free_frames: Vec<u64>,
}

// SAFETY: (Send) `Umem` exclusively owns its mmap region (`area`); moving the
// value to another thread transfers that sole ownership, and `Drop` munmaps on
// whichever thread holds it. No shared state crosses the move, so `Send` is sound.
unsafe impl Send for Umem {}
// SAFETY: (USF-003, Sync) `&Umem` hands out `&[u8]` (via `frame_slice`) over an
// mmap region into which the kernel performs RX DMA. Sharing `&Umem` across
// threads is sound ONLY under the AF_XDP frame-ownership protocol, which callers
// MUST uphold:
//
//   1. Frame ownership is exclusive and ring-mediated. A frame is kernel-owned
//      while its descriptor sits in the FILL ring; it transfers to userspace
//      ownership only once its descriptor has been dequeued from the RX ring
//      (an acquire load paired with the kernel's release store on the ring head).
//   2. `frame_slice(addr, ..)` MUST only be called for an `addr` whose RX
//      descriptor has already been dequeued, and BEFORE that frame's address is
//      handed back to the kernel via the FILL ring. Within that window no kernel
//      write to the frame can occur, so the `&[u8]` read does not race.
//   3. A given frame address is never concurrently aliased: at most one thread
//      holds the post-dequeue / pre-refill window for it at a time.
//
// These obligations are NOT enforced by the type system — they are a reviewed
// invariant of the RX-ring driver loop. If the loop is ever restructured to read
// a frame before its RX dequeue, or to refill before dropping the slice, this
// `impl` becomes unsound and must be revisited (or replaced by a dequeue-proving
// typestate). NOTE: `Umem` is currently owned by value inside a single socket and
// is not shared as `&Umem` across threads; if that remains true, this `Sync` impl
// can simply be removed instead of relied upon.
unsafe impl Sync for Umem {}

impl Umem {
    pub fn new(frame_count: u32, frame_size: u32) -> Result<Self> {
        // FIX (USF-008): `frame_count * frame_size` can overflow `usize` for
        // large or untrusted configs. An overflowed (wrapped) `size` would be
        // smaller than the real geometry, so every later `frame_slice` bounds
        // check would validate against a too-small region — re-introducing the
        // OOB that USF-002/#2 closed. Reject overflow and degenerate geometry
        // up front, before the mmap.
        if frame_count == 0 || frame_size == 0 {
            return Err(AfXdpError::Umem(format!(
                "invalid UMEM geometry: frame_count={frame_count}, frame_size={frame_size} \
                 (both must be non-zero)"
            )));
        }
        let size = (frame_count as usize)
            .checked_mul(frame_size as usize)
            .ok_or_else(|| {
                AfXdpError::Umem(format!(
                    "UMEM size overflow: frame_count={frame_count} * frame_size={frame_size} \
                     exceeds usize::MAX"
                ))
            })?;

        // SAFETY: null addr lets the kernel pick the mapping; len/prot/flags
        // form a valid request and the result is checked vs MAP_FAILED below.
        let area = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_POPULATE,
                -1,
                0,
            )
        };

        if area == libc::MAP_FAILED {
            return Err(AfXdpError::Umem(format!(
                "mmap failed: {}",
                std::io::Error::last_os_error()
            )));
        }

        // Pre-populate free frame list
        let free_frames: Vec<u64> = (0..frame_count)
            .map(|i| (i as u64) * (frame_size as u64))
            .collect();

        info!(
            frames = frame_count,
            frame_size,
            total_mib = size / (1024 * 1024),
            "UMEM allocated"
        );

        Ok(Self {
            area: area as *mut u8,
            size,
            frame_size,
            frame_count,
            free_frames,
        })
    }

    /// Get a free frame address. Returns None if exhausted.
    pub fn alloc_frame(&mut self) -> Option<u64> {
        self.free_frames.pop()
    }

    /// Return a frame to the free pool.
    pub fn free_frame(&mut self, addr: u64) {
        self.free_frames.push(addr);
    }

    /// Get pointer to frame data.
    pub fn frame_ptr(&self, addr: u64) -> *mut u8 {
        // SAFETY: `addr` is an in-bounds frame offset (< self.size); the
        // resulting pointer stays within this Umem's mapped region.
        unsafe { self.area.add(addr as usize) }
    }

    /// Get slice of frame data.
    ///
    /// FIX (SUSPECT #2): bounds-checked before pointer arithmetic.
    /// `addr` comes from the RX ring (kernel-supplied). A driver bug or
    /// malformed descriptor could produce an out-of-range value; without
    /// this check, that is an OOB read of the mmap region (UB + potential
    /// info-leak). The branch is essentially free at recv rate.
    pub fn frame_slice(&self, addr: u64, len: usize) -> &[u8] {
        let end = addr
            .checked_add(len as u64)
            .expect("af_xdp: frame_slice address overflow");
        assert!(
            end <= self.size as u64,
            "af_xdp: frame_slice OOB: addr={addr} len={len} umem_size={}",
            self.size
        );
        // SAFETY: bounds checked above; area is valid for `self.size` bytes.
        unsafe { std::slice::from_raw_parts(self.area.add(addr as usize), len) }
    }

    /// Get mutable slice of frame data.
    ///
    /// FIX (SUSPECT #2, write side): same bounds check as `frame_slice`.
    pub fn frame_slice_mut(&mut self, addr: u64, len: usize) -> &mut [u8] {
        let end = addr
            .checked_add(len as u64)
            .expect("af_xdp: frame_slice_mut address overflow");
        assert!(
            end <= self.size as u64,
            "af_xdp: frame_slice_mut OOB: addr={addr} len={len} umem_size={}",
            self.size
        );
        // SAFETY: bounds checked above; exclusive access via &mut self.
        unsafe { std::slice::from_raw_parts_mut(self.area.add(addr as usize), len) }
    }

    pub fn as_ptr(&self) -> *mut u8 {
        self.area
    }

    pub fn total_size(&self) -> usize {
        self.size
    }

    pub fn available_frames(&self) -> usize {
        self.free_frames.len()
    }
}

impl Drop for Umem {
    fn drop(&mut self) {
        // SAFETY: `area`/`size` are exactly the region mmap returned in `new`;
        // Drop runs once, so the region is unmapped exactly once.
        unsafe {
            libc::munmap(self.area as *mut libc::c_void, self.size);
        }
    }
}

// ---------------------------------------------------------------------------
// AF_XDP Socket
// ---------------------------------------------------------------------------

/// AF_XDP socket handle.
#[allow(dead_code)] // legacy hand-rolled datapath; the xsk module is the live one
pub struct AfXdpSocket {
    fd: RawFd,
    config: AfXdpConfig,
    umem: Umem,
    ifindex: u32,
}

impl AfXdpSocket {
    /// Create and bind AF_XDP socket.
    pub fn create(config: AfXdpConfig) -> Result<Self> {
        let ifindex = get_ifindex(&config.interface)?;
        let umem = Umem::new(config.frame_count, config.frame_size)?;

        // Create AF_XDP socket
        // SAFETY: libc::socket takes scalar args only; the returned fd is
        // checked (< 0) before use.
        let fd = unsafe { libc::socket(libc::AF_XDP, libc::SOCK_RAW | libc::SOCK_CLOEXEC, 0) };
        if fd < 0 {
            return Err(AfXdpError::Socket(std::io::Error::last_os_error()));
        }

        // Register UMEM with socket
        let umem_reg = XdpUmemReg {
            addr: umem.as_ptr() as u64,
            len: umem.total_size() as u64,
            chunk_size: config.frame_size,
            headroom: 0,
            flags: 0,
        };

        // SAFETY: `fd` is the open AF_XDP socket; `umem_reg` is a valid
        // initialized struct living for the call, with matching optlen.
        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_XDP,
                XDP_UMEM_REG,
                &umem_reg as *const _ as *const libc::c_void,
                std::mem::size_of::<XdpUmemReg>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            // SAFETY: `fd` is the open socket; closed once on this error path,
            // not used afterwards.
            unsafe { libc::close(fd) };
            return Err(AfXdpError::Umem(format!(
                "UMEM register: {}",
                std::io::Error::last_os_error()
            )));
        }

        // Set ring sizes
        set_ring_size(fd, XDP_UMEM_FILL_RING, config.fill_ring_size)?;
        set_ring_size(fd, XDP_UMEM_COMPLETION_RING, config.comp_ring_size)?;
        set_ring_size(fd, XDP_RX_RING, config.rx_ring_size)?;
        set_ring_size(fd, XDP_TX_RING, config.tx_ring_size)?;

        // Bind to interface + queue
        let mut sxdp = XdpSocketAddr {
            family: libc::AF_XDP as u16,
            flags: if config.zero_copy {
                XDP_ZEROCOPY
            } else {
                XDP_COPY
            },
            ifindex,
            queue_id: config.queue_id,
            shared_umem_fd: 0,
        };

        if config.need_wakeup {
            sxdp.flags |= XDP_USE_NEED_WAKEUP;
        }

        // SAFETY: `fd` is the open socket; `sxdp` is a valid initialized
        // sockaddr living for the call, with matching addrlen.
        let ret = unsafe {
            libc::bind(
                fd,
                &sxdp as *const _ as *const libc::sockaddr,
                std::mem::size_of::<XdpSocketAddr>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            // SAFETY: `fd` is the open socket; closed once on the bind-failure path.
            unsafe { libc::close(fd) };
            // Try copy mode if zero-copy failed
            if config.zero_copy {
                warn!("zero-copy bind failed, try copy mode");
            }
            return Err(AfXdpError::Bind(format!("bind: {err}")));
        }

        info!(
            interface = %config.interface,
            queue = config.queue_id,
            mode = if config.zero_copy { "zero-copy" } else { "copy" },
            frames = config.frame_count,
            "AF_XDP socket bound"
        );

        Ok(Self {
            fd,
            config,
            umem,
            ifindex,
        })
    }

    pub fn fd(&self) -> RawFd {
        self.fd
    }

    pub fn umem(&self) -> &Umem {
        &self.umem
    }

    pub fn umem_mut(&mut self) -> &mut Umem {
        &mut self.umem
    }

    /// Poll for readiness (RX or TX completion).
    pub fn poll(&self, timeout_ms: i32) -> Result<PollResult> {
        let mut pfd = libc::pollfd {
            fd: self.fd,
            events: libc::POLLIN | libc::POLLOUT,
            revents: 0,
        };
        // SAFETY: `pfd` is a valid initialized pollfd; nfds=1 matches the
        // single-element array passed by pointer.
        let ret = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
        if ret < 0 {
            return Err(AfXdpError::Io(std::io::Error::last_os_error()));
        }
        Ok(PollResult {
            readable: pfd.revents & libc::POLLIN != 0,
            writable: pfd.revents & libc::POLLOUT != 0,
        })
    }

    /// Wake up kernel if NEED_WAKEUP is set.
    pub fn wakeup_tx(&self) -> Result<()> {
        // SAFETY: `self.fd` is the open socket; a null/zero-length sendto is
        // the documented AF_XDP TX wakeup poke, no buffer is read.
        let ret = unsafe {
            libc::sendto(
                self.fd,
                std::ptr::null(),
                0,
                libc::MSG_DONTWAIT,
                std::ptr::null(),
                0,
            )
        };
        // EAGAIN/ENOBUFS are expected
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EAGAIN) && err.raw_os_error() != Some(libc::ENOBUFS)
            {
                return Err(AfXdpError::Io(err));
            }
        }
        Ok(())
    }
}

impl Drop for AfXdpSocket {
    fn drop(&mut self) {
        // SAFETY: `self.fd` is owned by this struct, closed once in Drop and
        // not used afterwards.
        unsafe { libc::close(self.fd) };
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PollResult {
    pub readable: bool,
    pub writable: bool,
}

/// A received frame from AF_XDP.
pub struct ReceivedFrame {
    /// TURN payload (after stripping ETH+IP+UDP headers).
    pub data: Vec<u8>,
    /// Source address (parsed from IP+UDP headers).
    pub source: SocketAddr,
    /// Destination address (parsed from IP+UDP headers). Used to demux the main
    /// TURN socket vs an allocation's relay port on the AF_XDP datapath.
    pub dst: SocketAddr,
    /// Frame address in UMEM (for returning to free pool).
    pub frame_addr: u64,
}

// ---------------------------------------------------------------------------
// Kernel structs / constants
// ---------------------------------------------------------------------------

const SOL_XDP: i32 = 283;
const XDP_UMEM_REG: i32 = 1;
const XDP_UMEM_FILL_RING: i32 = 2;
const XDP_UMEM_COMPLETION_RING: i32 = 3;
const XDP_RX_RING: i32 = 4;
const XDP_TX_RING: i32 = 5;
const XDP_COPY: u16 = 1 << 1;
const XDP_ZEROCOPY: u16 = 1 << 2;
const XDP_USE_NEED_WAKEUP: u16 = 1 << 3;

#[repr(C)]
struct XdpUmemReg {
    addr: u64,
    len: u64,
    chunk_size: u32,
    headroom: u32,
    flags: u32,
}

#[repr(C)]
struct XdpSocketAddr {
    family: u16,
    flags: u16,
    ifindex: u32,
    queue_id: u32,
    shared_umem_fd: u32,
}

fn get_ifindex(name: &str) -> Result<u32> {
    let cname = std::ffi::CString::new(name)
        .map_err(|_| AfXdpError::Bind(format!("invalid interface name: {name}")))?;
    // SAFETY: `cname` is a valid NUL-terminated CString that outlives the call.
    let idx = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    if idx == 0 {
        Err(AfXdpError::Bind(format!("interface not found: {name}")))
    } else {
        Ok(idx)
    }
}

fn set_ring_size(fd: RawFd, opt: i32, size: u32) -> Result<()> {
    // SAFETY: `fd` is the caller's open socket; `size` is a u32 living for the
    // call, optlen = size_of::<u32>().
    let ret = unsafe {
        libc::setsockopt(
            fd,
            SOL_XDP,
            opt,
            &size as *const _ as *const libc::c_void,
            std::mem::size_of::<u32>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        Err(AfXdpError::Ring(format!(
            "setsockopt({opt}): {}",
            std::io::Error::last_os_error()
        )))
    } else {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Pure L2–L4 stack (no kernel/ring involvement — unit-testable).
//
// AF_XDP delivers and accepts *full Ethernet frames*, so the datapath must
// parse inbound ETH/IP/UDP itself and build the headers for outbound frames.
// This module is Phase 2 of docs/design/af-xdp-datapath.md. IPv4 only for now
// (IPv6 is a TODO). MAC resolution for TX is the caller's responsibility (the
// kernel neighbour table); these functions take the MACs as inputs and are
// completely free of any socket/ring state, so they are directly unit-testable.
// ---------------------------------------------------------------------------
pub mod frame {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

    pub const ETH_HDR_LEN: usize = 14;
    pub const ETHERTYPE_IPV4: u16 = 0x0800;
    pub const ETHERTYPE_ARP: u16 = 0x0806;
    pub const ETHERTYPE_IPV6: u16 = 0x86DD;
    pub const IPPROTO_ICMPV6: u8 = 58;
    pub const IPPROTO_UDP: u8 = 17;

    /// A parsed inbound IPv4/UDP datagram. `payload_offset`/`payload_len` index
    /// into the *original frame* so the caller can slice the UMEM frame without
    /// copying.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ParsedUdpV4 {
        pub src: SocketAddrV4,
        pub dst: SocketAddrV4,
        pub payload_offset: usize,
        pub payload_len: usize,
    }

    /// Parse an Ethernet+IPv4+UDP frame. Returns `None` for non-IPv4, non-UDP,
    /// fragmented, or truncated frames. RX checksums are not re-validated (the
    /// NIC already did); this only locates the payload + endpoints.
    pub fn parse_eth_ipv4_udp(frame: &[u8]) -> Option<ParsedUdpV4> {
        if frame.len() < ETH_HDR_LEN + 20 + 8 {
            return None;
        }
        if u16::from_be_bytes([frame[12], frame[13]]) != ETHERTYPE_IPV4 {
            return None;
        }
        let ip = &frame[ETH_HDR_LEN..];
        let version = ip[0] >> 4;
        let ihl = (ip[0] & 0x0f) as usize * 4;
        if version != 4 || ihl < 20 || ip.len() < ihl + 8 {
            return None;
        }
        if ip[9] != IPPROTO_UDP {
            return None;
        }
        // Drop fragments (MF set or non-zero fragment offset).
        if u16::from_be_bytes([ip[6], ip[7]]) & 0x3fff != 0 {
            return None;
        }
        let src_ip = Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]);
        let dst_ip = Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]);
        let udp = &ip[ihl..];
        let src_port = u16::from_be_bytes([udp[0], udp[1]]);
        let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
        let udp_len = u16::from_be_bytes([udp[4], udp[5]]) as usize;
        if udp_len < 8 || udp.len() < udp_len {
            return None;
        }
        let payload_len = udp_len - 8;
        let payload_offset = ETH_HDR_LEN + ihl + 8;
        if frame.len() < payload_offset + payload_len {
            return None;
        }
        Some(ParsedUdpV4 {
            src: SocketAddrV4::new(src_ip, src_port),
            dst: SocketAddrV4::new(dst_ip, dst_port),
            payload_offset,
            payload_len,
        })
    }

    /// Build an Ethernet+IPv4+UDP frame carrying `payload` from `src` to `dst`
    /// using the given MACs. Computes the IPv4 header checksum and the UDP
    /// checksum (with pseudo-header). TTL 64, DF set, no IP options.
    pub fn build_eth_ipv4_udp(
        src_mac: [u8; 6],
        dst_mac: [u8; 6],
        src: SocketAddrV4,
        dst: SocketAddrV4,
        payload: &[u8],
    ) -> Vec<u8> {
        let udp_len = 8 + payload.len();
        let total_len = 20 + udp_len;
        let mut f = Vec::with_capacity(ETH_HDR_LEN + total_len);
        // Ethernet
        f.extend_from_slice(&dst_mac);
        f.extend_from_slice(&src_mac);
        f.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        // IPv4 header (checksum patched below)
        let ip = f.len();
        f.push(0x45); // version 4, IHL 5
        f.push(0x00); // DSCP/ECN
        f.extend_from_slice(&(total_len as u16).to_be_bytes());
        f.extend_from_slice(&0u16.to_be_bytes()); // identification
        f.extend_from_slice(&0x4000u16.to_be_bytes()); // flags=DF, fragment=0
        f.push(64); // TTL
        f.push(IPPROTO_UDP);
        f.extend_from_slice(&0u16.to_be_bytes()); // header checksum placeholder
        f.extend_from_slice(&src.ip().octets());
        f.extend_from_slice(&dst.ip().octets());
        let ipsum = ones_complement(&f[ip..ip + 20]);
        f[ip + 10..ip + 12].copy_from_slice(&ipsum.to_be_bytes());
        // UDP header (checksum patched below) + payload
        let udp = f.len();
        f.extend_from_slice(&src.port().to_be_bytes());
        f.extend_from_slice(&dst.port().to_be_bytes());
        f.extend_from_slice(&(udp_len as u16).to_be_bytes());
        f.extend_from_slice(&0u16.to_be_bytes()); // checksum placeholder
        f.extend_from_slice(payload);
        let mut udpsum = udp_checksum_v4(src.ip(), dst.ip(), &f[udp..]);
        // RFC 768: a computed checksum of 0 is transmitted as 0xFFFF.
        if udpsum == 0 {
            udpsum = 0xFFFF;
        }
        f[udp + 6..udp + 8].copy_from_slice(&udpsum.to_be_bytes());
        f
    }

    /// 16-bit one's-complement checksum over a byte slice (RFC 1071).
    pub fn ones_complement(data: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        let mut i = 0;
        while i + 1 < data.len() {
            sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
            i += 2;
        }
        if i < data.len() {
            sum += (data[i] as u32) << 8;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    /// UDP checksum over the IPv4 pseudo-header + UDP header + payload. `udp`
    /// must be the UDP header (checksum field zeroed) followed by the payload.
    pub fn udp_checksum_v4(src: &Ipv4Addr, dst: &Ipv4Addr, udp: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        let (s, d) = (src.octets(), dst.octets());
        for pair in [[s[0], s[1]], [s[2], s[3]], [d[0], d[1]], [d[2], d[3]]] {
            sum += u16::from_be_bytes(pair) as u32;
        }
        sum += IPPROTO_UDP as u32;
        sum += udp.len() as u32;
        let mut i = 0;
        while i + 1 < udp.len() {
            sum += u16::from_be_bytes([udp[i], udp[i + 1]]) as u32;
            i += 2;
        }
        if i < udp.len() {
            sum += (udp[i] as u32) << 8;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    /// Build an Ethernet+IPv6+UDP frame for `payload` from `src` to `dst`.
    /// IPv6 has no header checksum; the UDP checksum is mandatory and uses the
    /// IPv6 pseudo-header. Hop limit 64, no extension headers, flow label 0.
    pub fn build_eth_ipv6_udp(
        src_mac: [u8; 6],
        dst_mac: [u8; 6],
        src: SocketAddrV6,
        dst: SocketAddrV6,
        payload: &[u8],
    ) -> Vec<u8> {
        let udp_len = 8 + payload.len();
        let mut f = Vec::with_capacity(ETH_HDR_LEN + 40 + udp_len);
        f.extend_from_slice(&dst_mac);
        f.extend_from_slice(&src_mac);
        f.extend_from_slice(&ETHERTYPE_IPV6.to_be_bytes());
        f.push(0x60); // version 6, traffic-class high nibble 0
        f.push(0x00); // traffic-class low + flow-label high
        f.extend_from_slice(&0u16.to_be_bytes()); // flow label low 16
        f.extend_from_slice(&(udp_len as u16).to_be_bytes()); // payload length
        f.push(IPPROTO_UDP); // next header
        f.push(64); // hop limit
        f.extend_from_slice(&src.ip().octets());
        f.extend_from_slice(&dst.ip().octets());
        let udp = f.len();
        f.extend_from_slice(&src.port().to_be_bytes());
        f.extend_from_slice(&dst.port().to_be_bytes());
        f.extend_from_slice(&(udp_len as u16).to_be_bytes());
        f.extend_from_slice(&0u16.to_be_bytes()); // checksum placeholder
        f.extend_from_slice(payload);
        let mut udpsum = udp_checksum_v6(src.ip(), dst.ip(), &f[udp..]);
        // RFC 8200: a computed checksum of 0 is sent as 0xFFFF (a zero UDP
        // checksum is not permitted over IPv6).
        if udpsum == 0 {
            udpsum = 0xFFFF;
        }
        f[udp + 6..udp + 8].copy_from_slice(&udpsum.to_be_bytes());
        f
    }

    /// UDP checksum over the IPv6 pseudo-header + UDP header + payload. `udp`
    /// must be the UDP header (checksum field zeroed) followed by the payload.
    pub fn udp_checksum_v6(src: &Ipv6Addr, dst: &Ipv6Addr, udp: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        for addr in [src.octets(), dst.octets()] {
            let mut i = 0;
            while i < 16 {
                sum += u16::from_be_bytes([addr[i], addr[i + 1]]) as u32;
                i += 2;
            }
        }
        let len = udp.len() as u32;
        sum += (len >> 16) & 0xffff;
        sum += len & 0xffff;
        sum += IPPROTO_UDP as u32;
        let mut i = 0;
        while i + 1 < udp.len() {
            sum += u16::from_be_bytes([udp[i], udp[i + 1]]) as u32;
            i += 2;
        }
        if i < udp.len() {
            sum += (udp[i] as u32) << 8;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    /// A parsed inbound IPv6/UDP datagram (offsets index into the original frame).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ParsedUdpV6 {
        pub src: SocketAddrV6,
        pub dst: SocketAddrV6,
        pub payload_offset: usize,
        pub payload_len: usize,
    }

    /// Parse an Ethernet+IPv6+UDP frame. Returns `None` for non-IPv6, anything
    /// with an IPv6 extension header (Phase 2 handles only a bare UDP next
    /// header), non-UDP, or truncated frames.
    pub fn parse_eth_ipv6_udp(frame: &[u8]) -> Option<ParsedUdpV6> {
        if frame.len() < ETH_HDR_LEN + 40 + 8 {
            return None;
        }
        if u16::from_be_bytes([frame[12], frame[13]]) != ETHERTYPE_IPV6 {
            return None;
        }
        let ip = &frame[ETH_HDR_LEN..];
        if ip[0] >> 4 != 6 {
            return None;
        }
        if ip[6] != IPPROTO_UDP {
            return None;
        }
        let mut s = [0u8; 16];
        s.copy_from_slice(&ip[8..24]);
        let mut d = [0u8; 16];
        d.copy_from_slice(&ip[24..40]);
        let udp = &ip[40..];
        let src_port = u16::from_be_bytes([udp[0], udp[1]]);
        let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
        let udp_len = u16::from_be_bytes([udp[4], udp[5]]) as usize;
        if udp_len < 8 {
            return None;
        }
        let payload_offset = ETH_HDR_LEN + 40 + 8;
        let avail = frame.len().saturating_sub(payload_offset);
        let payload_len = (udp_len - 8).min(avail);
        Some(ParsedUdpV6 {
            src: SocketAddrV6::new(Ipv6Addr::from(s), src_port, 0, 0),
            dst: SocketAddrV6::new(Ipv6Addr::from(d), dst_port, 0, 0),
            payload_offset,
            payload_len,
        })
    }

    /// ICMPv6 checksum over the IPv6 pseudo-header + ICMPv6 message. `msg` must
    /// be the ICMPv6 message with its checksum field zeroed.
    pub fn icmpv6_checksum(src: &Ipv6Addr, dst: &Ipv6Addr, msg: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        for addr in [src.octets(), dst.octets()] {
            let mut i = 0;
            while i < 16 {
                sum += u16::from_be_bytes([addr[i], addr[i + 1]]) as u32;
                i += 2;
            }
        }
        let len = msg.len() as u32;
        sum += (len >> 16) & 0xffff;
        sum += len & 0xffff;
        sum += IPPROTO_ICMPV6 as u32;
        let mut i = 0;
        while i + 1 < msg.len() {
            sum += u16::from_be_bytes([msg[i], msg[i + 1]]) as u32;
            i += 2;
        }
        if i < msg.len() {
            sum += (msg[i] as u32) << 8;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    /// Parse an Ethernet+IPv6+ICMPv6 Neighbour Solicitation (type 135). Returns
    /// `(target, source_ip)` — the solicited address and the soliciting node's
    /// IPv6 source. `None` for anything that is not a bare-header NS.
    pub fn parse_icmpv6_ns(frame: &[u8]) -> Option<(Ipv6Addr, Ipv6Addr)> {
        if frame.len() < ETH_HDR_LEN + 40 + 24 {
            return None;
        }
        if u16::from_be_bytes([frame[12], frame[13]]) != ETHERTYPE_IPV6 {
            return None;
        }
        let ip = &frame[ETH_HDR_LEN..];
        if ip[0] >> 4 != 6 || ip[6] != IPPROTO_ICMPV6 {
            return None;
        }
        let icmp = &ip[40..];
        if icmp[0] != 135 || icmp[1] != 0 {
            return None;
        }
        let mut s = [0u8; 16];
        s.copy_from_slice(&ip[8..24]);
        let mut t = [0u8; 16];
        t.copy_from_slice(&icmp[8..24]);
        Some((Ipv6Addr::from(t), Ipv6Addr::from(s)))
    }

    /// Build an Ethernet+IPv6+ICMPv6 Neighbour Advertisement advertising
    /// `our_ip` (link-layer `src_mac`) to `dst_ip`/`dst_mac`. Solicited+Override
    /// flags; hop limit 255 (mandatory for NDP).
    pub fn build_eth_ipv6_na(
        src_mac: [u8; 6],
        dst_mac: [u8; 6],
        our_ip: Ipv6Addr,
        dst_ip: Ipv6Addr,
    ) -> Vec<u8> {
        let mut icmp = Vec::with_capacity(32);
        icmp.push(136); // type = Neighbour Advertisement
        icmp.push(0); // code
        icmp.extend_from_slice(&0u16.to_be_bytes()); // checksum placeholder
        icmp.push(0x60); // flags: Solicited | Override (host, not router)
        icmp.extend_from_slice(&[0u8; 3]); // reserved
        icmp.extend_from_slice(&our_ip.octets()); // target = advertised address
        icmp.push(2); // option: Target Link-Layer Address
        icmp.push(1); // length in 8-octet units
        icmp.extend_from_slice(&src_mac);
        let sum = icmpv6_checksum(&our_ip, &dst_ip, &icmp);
        icmp[2..4].copy_from_slice(&sum.to_be_bytes());

        let mut f = Vec::with_capacity(ETH_HDR_LEN + 40 + icmp.len());
        f.extend_from_slice(&dst_mac);
        f.extend_from_slice(&src_mac);
        f.extend_from_slice(&ETHERTYPE_IPV6.to_be_bytes());
        f.push(0x60); // version 6
        f.push(0x00);
        f.extend_from_slice(&0u16.to_be_bytes()); // flow label
        f.extend_from_slice(&(icmp.len() as u16).to_be_bytes()); // payload length
        f.push(IPPROTO_ICMPV6); // next header
        f.push(255); // hop limit — NDP requires 255
        f.extend_from_slice(&our_ip.octets());
        f.extend_from_slice(&dst_ip.octets());
        f.extend_from_slice(&icmp);
        f
    }

    #[cfg(test)]
    mod frame_tests {
        use super::*;

        #[test]
        fn build_then_parse_roundtrips() {
            let src = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 10), 50000);
            let dst = SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 5), 3478);
            let payload = b"STUN-ish payload bytes";
            let f = build_eth_ipv4_udp([1, 2, 3, 4, 5, 6], [6, 5, 4, 3, 2, 1], src, dst, payload);
            let p = parse_eth_ipv4_udp(&f).expect("must parse");
            assert_eq!(p.src, src);
            assert_eq!(p.dst, dst);
            assert_eq!(
                &f[p.payload_offset..p.payload_offset + p.payload_len],
                payload
            );
        }

        #[test]
        fn checksums_are_valid() {
            // A frame we build must have a self-consistent IPv4 header checksum
            // (ones-complement over the 20-byte header sums to 0) and a valid
            // UDP checksum (ones-complement over pseudo-header+UDP sums to 0).
            let src = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 1234);
            let dst = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 5678);
            let f = build_eth_ipv4_udp([0; 6], [0; 6], src, dst, b"abc");
            let ip = &f[ETH_HDR_LEN..ETH_HDR_LEN + 20];
            assert_eq!(ones_complement(ip), 0, "IPv4 header checksum invalid");
            let udp = &f[ETH_HDR_LEN + 20..];
            // Verify by recomputing over the as-sent UDP (checksum field intact):
            // the verifier sum (pseudo-header + udp incl. checksum) must be 0.
            assert_eq!(
                udp_checksum_v4(src.ip(), dst.ip(), udp),
                0,
                "UDP checksum invalid"
            );
        }

        #[test]
        fn rejects_non_udp_and_truncated() {
            assert!(parse_eth_ipv4_udp(&[0u8; 10]).is_none()); // too short
            let mut f = build_eth_ipv4_udp(
                [0; 6],
                [0; 6],
                SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1),
                SocketAddrV4::new(Ipv4Addr::LOCALHOST, 2),
                b"x",
            );
            f[ETH_HDR_LEN + 9] = 6; // protocol TCP, not UDP
            assert!(parse_eth_ipv4_udp(&f).is_none());
        }

        #[test]
        fn build_then_parse_v6_roundtrips() {
            let src = SocketAddrV6::new("2001:db8::10".parse().unwrap(), 50000, 0, 0);
            let dst = SocketAddrV6::new("2001:db8::5".parse().unwrap(), 3478, 0, 0);
            let payload = b"STUN-ish payload bytes";
            let f = build_eth_ipv6_udp([1, 2, 3, 4, 5, 6], [6, 5, 4, 3, 2, 1], src, dst, payload);
            let p = parse_eth_ipv6_udp(&f).expect("must parse");
            assert_eq!(p.src, src);
            assert_eq!(p.dst, dst);
            assert_eq!(
                &f[p.payload_offset..p.payload_offset + p.payload_len],
                payload
            );
        }

        #[test]
        fn v6_udp_checksum_valid() {
            let src = SocketAddrV6::new("fe80::1".parse().unwrap(), 1234, 0, 0);
            let dst = SocketAddrV6::new("fe80::2".parse().unwrap(), 5678, 0, 0);
            let f = build_eth_ipv6_udp([0; 6], [0; 6], src, dst, b"abc");
            let udp = &f[ETH_HDR_LEN + 40..];
            assert_eq!(
                udp_checksum_v6(src.ip(), dst.ip(), udp),
                0,
                "v6 UDP checksum invalid"
            );
        }

        #[test]
        fn v6_rejects_non_udp_and_truncated() {
            assert!(parse_eth_ipv6_udp(&[0u8; 20]).is_none());
            let mut f = build_eth_ipv6_udp(
                [0; 6],
                [0; 6],
                SocketAddrV6::new(Ipv6Addr::LOCALHOST, 1, 0, 0),
                SocketAddrV6::new(Ipv6Addr::LOCALHOST, 2, 0, 0),
                b"x",
            );
            f[ETH_HDR_LEN + 6] = 6; // next header TCP, not UDP
            assert!(parse_eth_ipv6_udp(&f).is_none());
        }

        #[test]
        fn icmpv6_na_parse_ns_and_checksum() {
            let our: Ipv6Addr = "2001:db8::1".parse().unwrap();
            let peer: Ipv6Addr = "2001:db8::2".parse().unwrap();
            let our_mac = [0x52, 0x54, 0, 0, 0, 0x01];
            let peer_mac = [0x52, 0x54, 0, 0, 0, 0x02];
            let mut icmp = vec![135u8, 0, 0, 0, 0, 0, 0, 0];
            icmp.extend_from_slice(&our.octets());
            icmp.extend_from_slice(&[1, 1]);
            icmp.extend_from_slice(&peer_mac);
            let sum = icmpv6_checksum(&peer, &our, &icmp);
            icmp[2..4].copy_from_slice(&sum.to_be_bytes());
            let mut ns = Vec::new();
            ns.extend_from_slice(&our_mac);
            ns.extend_from_slice(&peer_mac);
            ns.extend_from_slice(&ETHERTYPE_IPV6.to_be_bytes());
            ns.extend_from_slice(&[0x60, 0x00]);
            ns.extend_from_slice(&0u16.to_be_bytes());
            ns.extend_from_slice(&(icmp.len() as u16).to_be_bytes());
            ns.push(IPPROTO_ICMPV6);
            ns.push(255);
            ns.extend_from_slice(&peer.octets());
            ns.extend_from_slice(&our.octets());
            ns.extend_from_slice(&icmp);

            let (target, src) = parse_icmpv6_ns(&ns).expect("must parse NS");
            assert_eq!(target, our);
            assert_eq!(src, peer);

            let na = build_eth_ipv6_na(our_mac, peer_mac, our, peer);
            let na_icmp = &na[ETH_HDR_LEN + 40..];
            assert_eq!(na_icmp[0], 136);
            assert_eq!(na[ETH_HDR_LEN + 7], 255);
            assert_eq!(
                icmpv6_checksum(&our, &peer, na_icmp),
                0,
                "NA checksum invalid"
            );
        }

        #[test]
        fn parse_icmpv6_ns_rejects_non_ns() {
            let src = SocketAddrV6::new("2001:db8::1".parse().unwrap(), 1, 0, 0);
            let dst = SocketAddrV6::new("2001:db8::2".parse().unwrap(), 2, 0, 0);
            let f = build_eth_ipv6_udp([0; 6], [0; 6], src, dst, b"hello");
            assert!(parse_icmpv6_ns(&f).is_none());
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn umem_alloc_free() {
        let mut umem = Umem::new(16, 2048).unwrap();
        assert_eq!(umem.available_frames(), 16);

        let addr = umem.alloc_frame().unwrap();
        assert_eq!(umem.available_frames(), 15);

        umem.free_frame(addr);
        assert_eq!(umem.available_frames(), 16);
    }

    #[test]
    fn umem_write_read() {
        let mut umem = Umem::new(4, 2048).unwrap();
        let addr = umem.alloc_frame().unwrap();
        let slice = umem.frame_slice_mut(addr, 5);
        slice.copy_from_slice(b"hello");
        let read = umem.frame_slice(addr, 5);
        assert_eq!(read, b"hello");
    }

    #[test]
    fn config_defaults() {
        let c = AfXdpConfig::default();
        assert_eq!(c.frame_count, 4096);
        assert_eq!(c.frame_size, 2048);
    }
}

// ---------------------------------------------------------------------------
// xsk-rs ring datapath (AF_XDP Phase 1)
// ---------------------------------------------------------------------------

/// xsk-rs-backed AF_XDP datapath. Rather than hand-rolling the four rings and
/// their memory ordering, this delegates UMEM + socket + ring management to
/// `xsk-rs` and keeps only the turna-specific L2-L4 (de)framing, reusing
/// [`frame`]. This is the datapath the `af-xdp` feature should use in
/// production; the hand-rolled `Umem`/`AfXdpSocket` above remain as the raw
/// libc reference.
///
/// NOTE (draft): written against the xsk-rs 0.6 API. `Umem::new` / `Socket::new`
/// return shapes and the queue methods (`fill`, `poll_and_consume`,
/// `produce_and_wakeup`, `consume`) plus UMEM access (`umem.data` /
/// `umem.data_mut`, `FrameDesc` len/addr accessors) are version-sensitive —
/// verify with `cargo build --features af-xdp` on Linux with a bound NIC queue.
/// All unsafe UMEM access is isolated to this module.
pub mod xsk {
    use super::{frame, AfXdpConfig, AfXdpError, ReceivedFrame, Result};
    use std::net::SocketAddr;
    use std::num::NonZeroU32;

    use std::os::fd::AsRawFd;
    use xsk_rs::{
        config::{
            BindFlags, Interface, LibxdpFlags, SocketConfig, SocketConfigBuilder, UmemConfig,
        },
        CompQueue, FillQueue, FrameDesc, RxQueue, Socket, TxQueue, Umem,
    };

    /// 1.1: load/attach the embedded selective XDP program and manage its maps
    /// (`xsks_map`, `ports`). All libxdp/libbpf FFI is isolated here; the handle
    /// detaches the program and frees the object on Drop (graceful unload).
    mod loader {
        use super::{AfXdpError, Result};
        use libxdp_sys::{
            bpf_map__fd, bpf_map_delete_elem, bpf_map_update_elem, bpf_object, bpf_object__close,
            bpf_object__find_map_by_name, bpf_object__open_mem, xdp_program, xdp_program__attach,
            xdp_program__close, xdp_program__detach, xdp_program__from_bpf_obj, BPF_ANY,
        };
        use std::os::raw::{c_char, c_int, c_uint};

        // enum xdp_attach_mode (libxdp.h): NATIVE=1 (DRV), SKB=2 (generic).
        const XDP_MODE_NATIVE: c_uint = 1;
        const XDP_MODE_SKB: c_uint = 2;

        /// Embedded BPF object, compiled from `src/bpf/xdp_turn.c` by build.rs.
        static XDP_OBJ: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/xdp_turn.o"));

        pub struct XdpProgram {
            obj: *mut bpf_object,
            prog: *mut xdp_program,
            ifindex: c_int,
            mode: c_uint,
            ports_fd: c_int,
        }

        impl XdpProgram {
            /// Open + attach the program to `ifindex` (DRV if `native`, else SKB),
            /// point `xsks_map[queue_id]` at `xsk_fd`, and seed `ports` with
            /// `listen_port`. libxdp loads the object during attach, so map fds
            /// are only valid afterwards.
            pub fn load(
                ifindex: u32,
                xsk_fd: i32,
                queue_id: u32,
                listen_port: u16,
                native: bool,
            ) -> Result<Self> {
                let mode = if native {
                    XDP_MODE_NATIVE
                } else {
                    XDP_MODE_SKB
                };
                // SAFETY: FFI into libxdp/libbpf. Every returned pointer is
                // null-checked; on any failure we unwind the partial state
                // (detach/close) before returning. The owned handles live in
                // `XdpProgram` and are released in `Drop`.
                unsafe {
                    let obj = bpf_object__open_mem(
                        XDP_OBJ.as_ptr() as *const _,
                        XDP_OBJ.len(),
                        std::ptr::null(),
                    );
                    if obj.is_null() {
                        return Err(AfXdpError::Xdp("bpf_object__open_mem failed".into()));
                    }
                    // Pass a null section name: the object has a single SEC("xdp")
                    // program, which libxdp auto-selects. (If your libxdp build
                    // requires an explicit name, pass b"xdp\0".)
                    let prog = xdp_program__from_bpf_obj(obj, std::ptr::null::<c_char>());
                    if prog.is_null() {
                        bpf_object__close(obj);
                        return Err(AfXdpError::Xdp("xdp_program__from_bpf_obj failed".into()));
                    }
                    let rc = xdp_program__attach(prog, ifindex as c_int, mode, 0);
                    if rc != 0 {
                        xdp_program__close(prog);
                        bpf_object__close(obj);
                        return Err(AfXdpError::Xdp(format!(
                            "xdp_program__attach failed (rc={rc}, mode={mode}); try \
                             zero_copy=false (SKB mode) or verify driver XDP support"
                        )));
                    }
                    let xsks = bpf_object__find_map_by_name(obj, c"xsks_map".as_ptr());
                    let ports = bpf_object__find_map_by_name(obj, c"ports".as_ptr());
                    if xsks.is_null() || ports.is_null() {
                        xdp_program__detach(prog, ifindex as c_int, mode, 0);
                        xdp_program__close(prog);
                        bpf_object__close(obj);
                        return Err(AfXdpError::Xdp("xsks_map/ports map not found".into()));
                    }
                    let xsks_fd = bpf_map__fd(xsks);
                    let ports_fd = bpf_map__fd(ports);
                    let k = queue_id;
                    let rc = bpf_map_update_elem(
                        xsks_fd,
                        &k as *const u32 as *const _,
                        &xsk_fd as *const i32 as *const _,
                        BPF_ANY as u64,
                    );
                    if rc != 0 {
                        xdp_program__detach(prog, ifindex as c_int, mode, 0);
                        xdp_program__close(prog);
                        bpf_object__close(obj);
                        return Err(AfXdpError::Xdp(format!("xskmap update failed (rc={rc})")));
                    }
                    let me = Self {
                        obj,
                        prog,
                        ifindex: ifindex as c_int,
                        mode,
                        ports_fd,
                    };
                    me.set_port(listen_port, true)?;
                    Ok(me)
                }
            }

            /// Add (`add=true`) or remove a UDP destination port from the `ports`
            /// map (host byte order key, matching the XDP program's ntohs).
            pub fn set_port(&self, port: u16, add: bool) -> Result<()> {
                // SAFETY: `ports_fd` is a live bpf map fd owned by `self`.
                let rc = unsafe {
                    if add {
                        let one: u8 = 1;
                        bpf_map_update_elem(
                            self.ports_fd,
                            &port as *const u16 as *const _,
                            &one as *const u8 as *const _,
                            BPF_ANY as u64,
                        )
                    } else {
                        bpf_map_delete_elem(self.ports_fd, &port as *const u16 as *const _)
                    }
                };
                // Deletes can legitimately fail with -ENOENT (already gone); only
                // surface add failures.
                if add && rc != 0 {
                    return Err(AfXdpError::Xdp(format!(
                        "ports map update failed (rc={rc})"
                    )));
                }
                Ok(())
            }
        }

        impl Drop for XdpProgram {
            fn drop(&mut self) {
                // SAFETY: detach + close the program/object we own, restoring the
                // interface to its prior (no-turna-XDP) state — task 1.1 graceful
                // unload.
                unsafe {
                    xdp_program__detach(self.prog, self.ifindex, self.mode, 0);
                    xdp_program__close(self.prog);
                    bpf_object__close(self.obj);
                }
            }
        }

        // SAFETY: the raw libxdp/libbpf handles are owned solely by this struct
        // and only touched from the single datapath thread; they are never
        // aliased or shared, so moving the handle across threads is sound.
        unsafe impl Send for XdpProgram {}
    }

    /// One AF_XDP socket bound to a single NIC queue, with its UMEM and rings.
    pub struct XskDatapath {
        umem: Umem,
        rx: RxQueue,
        tx: TxQueue,
        fill: FillQueue,
        comp: CompQueue,
        /// Descriptors not currently owned by a kernel ring — available for TX.
        free_frames: Vec<FrameDesc>,
        /// Pre-allocated buffer the completion ring overwrites with the
        /// descriptors of finished TX frames (see `reclaim_completions`).
        comp_scratch: Vec<FrameDesc>,
        local_addr: SocketAddr,
        src_mac: [u8; 6],
        // TX needs the next-hop (gateway) MAC. Phase 1: configured/placeholder;
        // real neighbor resolution (ARP / netlink NEIGH) is a follow-up.
        dst_mac: [u8; 6],
        /// Count of ARP replies this datapath has sent for its own IP.
        arp_replies: u64,
        /// Count of IPv6 Neighbour Advertisements sent for our own IP.
        ndp_replies: u64,
        /// Cumulative descriptors submitted to the TX ring.
        tx_produced: u64,
        /// Cumulative completions reaped from the completion ring.
        comp_consumed: u64,
        /// Optional Phase-2 neighbor resolution: (cache, resolve-request sender, TTL).
        neighbor: Option<(
            crate::neighbor::NeighborCache,
            tokio::sync::mpsc::Sender<std::net::IpAddr>,
            std::time::Duration,
        )>,
        /// 1.1: the selective XDP program attached to the NIC for this datapath.
        /// Detached/unloaded when this datapath drops. `None` is never the case
        /// after a successful `bind`, but kept optional for clarity.
        xdp_prog: Option<loader::XdpProgram>,
    }

    /// Parse "aa:bb:cc:dd:ee:ff" into 6 octets.
    fn parse_mac_str(s: &str) -> Option<[u8; 6]> {
        let parts: Vec<&str> = s.trim().split(':').collect();
        if parts.len() != 6 {
            return None;
        }
        let mut m = [0u8; 6];
        for (i, p) in parts.iter().enumerate() {
            m[i] = u8::from_str_radix(p, 16).ok()?;
        }
        Some(m)
    }

    /// Read the interface's own MAC from sysfs (`/sys/class/net/<iface>/address`).
    fn read_iface_mac(iface: &str) -> Option<[u8; 6]> {
        let s = std::fs::read_to_string(format!("/sys/class/net/{iface}/address")).ok()?;
        parse_mac_str(&s)
    }

    /// Default-route gateway IPv4 for `iface` from `/proc/net/route` (the field
    /// is a little-endian hex of the address in memory; swap to get dotted IP).
    fn default_gateway_ip(iface: &str) -> Option<std::net::Ipv4Addr> {
        let txt = std::fs::read_to_string("/proc/net/route").ok()?;
        for line in txt.lines().skip(1) {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 3 || f[0] != iface || f[1] != "00000000" {
                continue;
            }
            let v = u32::from_str_radix(f[2], 16).ok()?;
            return Some(std::net::Ipv4Addr::from(v.swap_bytes()));
        }
        None
    }

    /// Look up an IPv4's MAC in the kernel ARP cache (`/proc/net/arp`).
    fn arp_mac_for_ip(ip: std::net::Ipv4Addr) -> Option<[u8; 6]> {
        let txt = std::fs::read_to_string("/proc/net/arp").ok()?;
        let target = ip.to_string();
        for line in txt.lines().skip(1) {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() >= 4 && f[0] == target {
                return parse_mac_str(f[3]);
            }
        }
        None
    }

    /// Resolve the source MAC: keep the configured value if non-zero, else read
    /// the interface MAC from sysfs.
    fn resolve_src_mac(iface: &str, configured: [u8; 6]) -> [u8; 6] {
        if configured != [0u8; 6] {
            return configured;
        }
        match read_iface_mac(iface) {
            Some(m) => {
                tracing::info!(iface, mac = ?m, "AF_XDP: resolved source MAC from sysfs");
                m
            }
            None => {
                tracing::warn!(
                    iface,
                    "AF_XDP: could not read source MAC; using zero placeholder"
                );
                configured
            }
        }
    }

    /// Resolve the next-hop (TX destination) MAC: keep the configured value if
    /// non-zero, else resolve the default gateway's MAC from the ARP cache.
    ///
    /// First-cut neighbor resolution: this uses the *default-route gateway* MAC
    /// for all TX, which is correct for an internet-facing relay. Per-destination
    /// resolution (on-link peers, multiple routes) and live ARP refresh are a
    /// follow-up (netlink NEIGH); for now an empty ARP cache yields the zero
    /// placeholder and a warning. The gateway must already be in the ARP cache
    /// (ping it once at startup if needed).
    fn resolve_dst_mac(iface: &str, configured: [u8; 6]) -> [u8; 6] {
        if configured != [0u8; 6] {
            return configured;
        }
        let resolved = default_gateway_ip(iface).and_then(arp_mac_for_ip);
        match resolved {
            Some(m) => {
                tracing::info!(iface, mac = ?m, "AF_XDP: resolved gateway (next-hop) MAC from ARP cache");
                m
            }
            None => {
                tracing::warn!(
                    iface,
                    "AF_XDP: could not resolve gateway MAC (no default route or empty ARP cache); \
                     using zero placeholder — set [turn.af_xdp].dst_mac or warm the ARP cache"
                );
                configured
            }
        }
    }

    impl XskDatapath {
        /// Create the UMEM and bind an AF_XDP socket to `cfg.interface` queue
        /// `cfg.queue_id`. `src_mac`/`dst_mac` frame the L2 headers for TX.
        pub fn bind(
            cfg: &AfXdpConfig,
            local_addr: SocketAddr,
            src_mac: [u8; 6],
            dst_mac: [u8; 6],
        ) -> Result<Self> {
            // Phase-1 neighbor resolution: fill empty MACs from sysfs (src) and
            // the default-gateway ARP entry (dst). Configured non-zero values win.
            let src_mac = resolve_src_mac(&cfg.interface, src_mac);
            let dst_mac = resolve_dst_mac(&cfg.interface, dst_mac);

            let frame_count = NonZeroU32::new(cfg.frame_count)
                .ok_or_else(|| AfXdpError::Umem("frame_count must be > 0".into()))?;

            // xsk-rs 0.6 gates frame/queue sizes behind FrameSize/QueueSize newtypes
            // whose constructors are version-sensitive. For first-light use library
            // defaults (frame 4096, rings 2048) and honour only frame_count.
            let umem_config = UmemConfig::default();

            // (Umem, Vec<FrameDesc>): one descriptor per frame in the UMEM.
            let (umem, mut frames) = Umem::new(umem_config, frame_count, false)
                .map_err(|e| AfXdpError::Umem(format!("umem: {e}")))?;

            // 1.1: inhibit libxdp's default redirect-all program — we attach our
            // own selective filter below. Bind flags honour cfg.zero_copy
            // (zero-copy vs copy) and cfg.need_wakeup.
            let mut bind_flags = if cfg.zero_copy {
                BindFlags::XDP_ZEROCOPY
            } else {
                BindFlags::XDP_COPY
            };
            if cfg.need_wakeup {
                bind_flags |= BindFlags::XDP_USE_NEED_WAKEUP;
            }
            let mut scb = SocketConfigBuilder::new();
            scb.libxdp_flags(LibxdpFlags::XSK_LIBXDP_FLAGS_INHIBIT_PROG_LOAD)
                .bind_flags(bind_flags);
            let socket_config: SocketConfig = scb.build();

            let iface =
                Interface::new(std::ffi::CString::new(cfg.interface.clone()).map_err(|e| {
                    AfXdpError::Socket(std::io::Error::other(format!("interface name: {e}")))
                })?);
            // The first socket on a UMEM owns the (fill, comp) pair.
            // SAFETY: `umem`/`iface` outlive the socket and `queue_id` is valid
            // for the device, satisfying xsk-rs Socket::new requirements.
            let (tx, rx, fill_comp) =
                unsafe { Socket::new(socket_config, &umem, &iface, cfg.queue_id) }.map_err(
                    |e| AfXdpError::Socket(std::io::Error::other(format!("xsk socket: {e}"))),
                )?;
            let (mut fill, comp) = fill_comp
                .ok_or_else(|| AfXdpError::Umem("no fill/comp queue for first socket".into()))?;

            // Reserve a small buffer of descriptor slots for the completion
            // ring to write finished TX frames into (it overwrites these). The
            // reserved frames themselves are effectively donated to the scratch
            // and not used as RX/TX frames — a few wasted frames, fine here.
            let scratch_n = frames.len().min(64);
            let comp_scratch: Vec<FrameDesc> = frames.drain(..scratch_n).collect();

            // Split remaining descriptors: half seed the fill ring (kernel RX
            // targets), the rest stay free for TX. Simple even split for the draft.
            let split = frames.len() / 2;
            let for_rx: Vec<FrameDesc> = frames.drain(..split).collect();
            // SAFETY: these descriptors point at frames we own and are not in
            // any other ring; handing them to the fill ring transfers them to
            // the kernel for RX DMA.
            unsafe {
                fill.produce(&for_rx);
            }

            // 1.1: attach the selective XDP program and wire its xskmap to this
            // socket's queue. Must follow socket creation (we need the xsk fd).
            let xsk_fd = rx.fd().as_raw_fd();
            let ifname = std::ffi::CString::new(cfg.interface.clone())
                .map_err(|e| AfXdpError::Xdp(format!("interface name: {e}")))?;
            // SAFETY: `ifname` is a valid NUL-terminated C string for the call.
            let ifindex = unsafe { libc::if_nametoindex(ifname.as_ptr()) };
            if ifindex == 0 {
                return Err(AfXdpError::Xdp(format!(
                    "if_nametoindex('{}') failed (no such interface?)",
                    cfg.interface
                )));
            }
            let xdp_prog = loader::XdpProgram::load(
                ifindex,
                xsk_fd,
                cfg.queue_id,
                local_addr.port(),
                cfg.zero_copy,
            )?;
            tracing::info!(
                iface = %cfg.interface,
                queue = cfg.queue_id,
                mode = if cfg.zero_copy { "drv" } else { "skb" },
                main_port = local_addr.port(),
                "AF_XDP: selective XDP filter attached (xsks_map + ports)"
            );

            Ok(Self {
                umem,
                rx,
                tx,
                fill,
                comp,
                free_frames: frames,
                comp_scratch,
                local_addr,
                src_mac,
                dst_mac,
                arp_replies: 0,
                ndp_replies: 0,
                tx_produced: 0,
                comp_consumed: 0,
                neighbor: None,
                xdp_prog: Some(xdp_prog),
            })
        }

        pub fn local_addr(&self) -> SocketAddr {
            self.local_addr
        }

        /// 1.1: register an allocation relay port so the XDP filter redirects its
        /// ingress into the xsk. Called when a relay port is registered.
        pub fn add_relay_port(&self, port: u16) {
            if let Some(p) = &self.xdp_prog {
                if let Err(e) = p.set_port(port, true) {
                    tracing::warn!(port, %e, "AF_XDP: failed to add relay port to XDP filter");
                }
            }
        }

        /// 1.1: drop a relay port from the XDP filter (allocation released).
        pub fn del_relay_port(&self, port: u16) {
            if let Some(p) = &self.xdp_prog {
                let _ = p.set_port(port, false);
            }
        }

        /// Free UMEM frames available for RX/TX (gauge source for
        /// turna_afxdp_umem_free_frames).
        pub fn free_frames(&self) -> usize {
            self.free_frames.len()
        }

        /// ARP replies sent for our own IP (counter source).
        pub fn arp_replies(&self) -> u64 {
            self.arp_replies
        }

        /// Count of IPv6 Neighbour Advertisements sent for our own IP.
        pub fn ndp_replies(&self) -> u64 {
            self.ndp_replies
        }

        /// True if the next-hop (TX dst) MAC is resolved (non-zero).
        pub fn neighbor_resolved(&self) -> bool {
            self.dst_mac != [0u8; 6]
        }

        /// Frames submitted to TX but whose completions are not yet reaped
        /// (TX in-flight / backpressure depth).
        pub fn tx_inflight(&self) -> u64 {
            self.tx_produced.saturating_sub(self.comp_consumed)
        }

        /// Attach Phase-2 neighbor resolution. Send paths then resolve the
        /// target MAC from `cache` (queuing an async resolve on a miss) rather
        /// than always using the static next-hop `dst_mac`.
        pub fn attach_neighbor(
            &mut self,
            cache: crate::neighbor::NeighborCache,
            req_tx: tokio::sync::mpsc::Sender<std::net::IpAddr>,
            ttl: std::time::Duration,
        ) {
            self.neighbor = Some((cache, req_tx, ttl));
        }

        /// Destination MAC for `dst`: cache hit -> that MAC; miss -> queue an
        /// async resolve and fall back to the static `dst_mac` this time.
        fn resolve_dst(&self, dst: std::net::IpAddr) -> [u8; 6] {
            if let Some((cache, req_tx, ttl)) = &self.neighbor {
                if let Some(mac) = cache.get(dst, *ttl) {
                    return mac;
                }
                // Stale or missing: trigger async (re)resolution. Prefer a
                // last-known (stale) MAC over the static fallback so a TTL
                // refresh doesn't drop packets; the resolver updates it soon.
                // B6: bounded queue — drop the resolve hint if it's full. A miss
                // just falls back to the static dst_mac this time; the resolver
                // catches up on the next packet, so dropping here is harmless.
                let _ = req_tx.try_send(dst);
                if let Some(stale) = cache.get_stale(dst) {
                    return stale;
                }
            }
            self.dst_mac
        }

        /// Number of resolved neighbor entries currently cached (0 if neighbor
        /// resolution is not attached).
        pub fn neighbor_cache_entries(&self) -> u64 {
            self.neighbor
                .as_ref()
                .map(|(c, _, _)| c.len() as u64)
                .unwrap_or(0)
        }

        /// Drain up to `max` received frames: poll RX, parse ETH+IPv4+UDP, emit
        /// the TURN payloads, then return the descriptors to the fill ring.
        pub fn recv_batch(&mut self, max: usize) -> Vec<ReceivedFrame> {
            let want = self.free_frames.len().min(max);
            if want == 0 {
                return Vec::new();
            }
            let mut rx_descs: Vec<FrameDesc> = self.free_frames.drain(..want).collect();

            // Non-blocking poll (timeout 0). Returns how many descs were filled.
            // SAFETY: `rx_descs` is a valid mutable buffer; the RX queue is owned
            // solely by this datapath, no aliasing.
            let n = unsafe { self.rx.poll_and_consume(&mut rx_descs, 0) }.unwrap_or(0);

            let mut out = Vec::with_capacity(n);
            let mut arp_reqs: Vec<Vec<u8>> = Vec::new();
            let mut ndp_reqs: Vec<Vec<u8>> = Vec::new();
            for desc in rx_descs.iter().take(n) {
                // SAFETY: the kernel has completed RX DMA into this frame; we
                // read it immutably and copy out the payload.
                let data = unsafe { self.umem.data(desc) };
                let bytes = data.contents();
                if let Some(p) = frame::parse_eth_ipv4_udp(bytes) {
                    out.push(ReceivedFrame {
                        data: bytes[p.payload_offset..p.payload_offset + p.payload_len].to_vec(),
                        source: SocketAddr::V4(p.src),
                        dst: SocketAddr::V4(p.dst),
                        frame_addr: desc.addr() as u64,
                    });
                } else if let Some(p6) = frame::parse_eth_ipv6_udp(bytes) {
                    out.push(ReceivedFrame {
                        data: bytes[p6.payload_offset..p6.payload_offset + p6.payload_len].to_vec(),
                        source: SocketAddr::V6(p6.src),
                        dst: SocketAddr::V6(p6.dst),
                        frame_addr: desc.addr() as u64,
                    });
                } else if bytes.len() >= frame::ETH_HDR_LEN
                    && u16::from_be_bytes([bytes[12], bytes[13]]) == frame::ETHERTYPE_ARP
                {
                    // ARP can't be answered while the RX borrow is live — collect
                    // and reply after the descriptors are recycled below.
                    arp_reqs.push(bytes.to_vec());
                } else if frame::parse_icmpv6_ns(bytes).is_some() {
                    // IPv6 Neighbour Solicitation — deferred like ARP.
                    ndp_reqs.push(bytes.to_vec());
                }
            }

            // Recycle consumed descriptors back to the kernel for more RX; any
            // we didn't use return to the free pool.
            // SAFETY: as in `bind` — these frames are ours and ring-free.
            unsafe {
                self.fill.produce(&rx_descs[..n]);
            }
            self.free_frames.extend(rx_descs.drain(n..));

            // The XDP redirect funnels ALL ingress (including ARP) into the xsk,
            // bypassing the kernel's ARP responder — so we answer ARP for our own
            // IP here, otherwise clients/peers can't resolve us without a static
            // neighbor entry.
            for req in &arp_reqs {
                if self.maybe_arp_reply(req) {
                    self.arp_replies += 1;
                }
            }
            for req in &ndp_reqs {
                if self.maybe_ndp_reply(req) {
                    self.ndp_replies += 1;
                }
            }
            out
        }

        /// Build an ETH+IPv4+UDP frame for `data` → `target` and submit it on
        /// the TX ring. IPv4-only in Phase 1.
        pub fn send_to(&mut self, data: &[u8], target: SocketAddr) -> Result<()> {
            // Reclaim completed TX frames so the free pool can refill.
            self.reclaim_completions();

            let mut desc = self
                .free_frames
                .pop()
                .ok_or_else(|| AfXdpError::Umem("no free TX frame".into()))?;

            let dst_mac = self.resolve_dst(target.ip());
            // Single-stack: frame in the datapath's listen address family.
            let pkt = match (self.local_addr, target) {
                (SocketAddr::V4(src), SocketAddr::V4(dst)) => {
                    frame::build_eth_ipv4_udp(self.src_mac, dst_mac, src, dst, data)
                }
                (SocketAddr::V6(src), SocketAddr::V6(dst)) => {
                    frame::build_eth_ipv6_udp(self.src_mac, dst_mac, src, dst, data)
                }
                _ => {
                    self.free_frames.push(desc);
                    return Err(AfXdpError::Umem(
                        "address-family mismatch: datapath is single-stack to its listen family"
                            .into(),
                    ));
                }
            };
            // Write via the Data cursor: copies the packet AND updates the
            // descriptor length (xsk-rs 0.6 has no FrameDesc::set_len).
            {
                use std::io::Write;
                let write_res =
                    // SAFETY: `desc` was popped from the free pool — we own it
                    // exclusively and no kernel access is in flight for it.
                    unsafe { self.umem.data_mut(&mut desc).cursor().write_all(&pkt) };
                if let Err(e) = write_res {
                    self.free_frames.push(desc);
                    return Err(AfXdpError::Umem(format!(
                        "frame write ({} bytes): {e}",
                        pkt.len()
                    )));
                }
            }

            let batch = [desc];
            // SAFETY: descriptors in `batch` reference frames we own (popped from
            // the free pool) and not in any ring.
            let produced = unsafe { self.tx.produce_and_wakeup(&batch) }.map_err(|e| {
                AfXdpError::Socket(std::io::Error::other(format!("tx produce: {e}")))
            })?;
            self.tx_produced += produced as u64;
            Ok(())
        }

        /// Like [`send_to`] but with an explicit UDP source port. Used to emit
        /// client→peer relay frames from the allocation's relay port instead of
        /// the main TURN port (the source IP stays `local_addr`'s).
        pub fn send_to_from(
            &mut self,
            src_port: u16,
            data: &[u8],
            target: SocketAddr,
        ) -> Result<()> {
            self.reclaim_completions();

            let mut desc = self
                .free_frames
                .pop()
                .ok_or_else(|| AfXdpError::Umem("no free TX frame".into()))?;

            let dst_mac = self.resolve_dst(target.ip());
            // Single-stack: frame in the datapath's listen family, overriding
            // the UDP source port with the allocation's relay port.
            let pkt = match (self.local_addr, target) {
                (SocketAddr::V4(mut src), SocketAddr::V4(dst)) => {
                    src.set_port(src_port);
                    frame::build_eth_ipv4_udp(self.src_mac, dst_mac, src, dst, data)
                }
                (SocketAddr::V6(mut src), SocketAddr::V6(dst)) => {
                    src.set_port(src_port);
                    frame::build_eth_ipv6_udp(self.src_mac, dst_mac, src, dst, data)
                }
                _ => {
                    self.free_frames.push(desc);
                    return Err(AfXdpError::Umem(
                        "address-family mismatch: datapath is single-stack to its listen family"
                            .into(),
                    ));
                }
            };
            {
                use std::io::Write;
                let write_res =
                    // SAFETY: `desc` was popped from the free pool — we own the frame
                    // exclusively, no kernel access in flight.
                    unsafe { self.umem.data_mut(&mut desc).cursor().write_all(&pkt) };
                if let Err(e) = write_res {
                    self.free_frames.push(desc);
                    return Err(AfXdpError::Umem(format!(
                        "frame write ({} bytes): {e}",
                        pkt.len()
                    )));
                }
            }

            let batch = [desc];
            // SAFETY: descriptors in `batch` reference frames we own (popped from
            // the free pool) and not in any ring.
            let produced = unsafe { self.tx.produce_and_wakeup(&batch) }.map_err(|e| {
                AfXdpError::Socket(std::io::Error::other(format!("tx produce: {e}")))
            })?;
            self.tx_produced += produced as u64;
            Ok(())
        }

        /// Answer an ARP request for our own IP. The XDP redirect funnels ARP
        /// into the xsk (bypassing the kernel's responder), so without this
        /// clients/peers can't resolve us without a static neighbor entry.
        /// Returns true if a reply was sent. No-op for non-ARP / non-request /
        /// other-target frames and when bound to a wildcard address (0.0.0.0).
        /// Resolving *peer* MACs (us as ARP requester) is still a follow-up; the
        /// configured `dst_mac` covers the same-subnet next hop.
        fn maybe_arp_reply(&mut self, req: &[u8]) -> bool {
            // ETH(14) + ARP(28) = 42 bytes minimum.
            if req.len() < 42 || u16::from_be_bytes([req[12], req[13]]) != frame::ETHERTYPE_ARP {
                return false;
            }
            let arp = &req[14..];
            // htype=1, ptype=0x0800, hlen=6, plen=4, op=1 (request).
            if arp[0..2] != [0x00, 0x01]
                || arp[2..4] != [0x08, 0x00]
                || arp[4] != 6
                || arp[5] != 4
                || arp[6..8] != [0x00, 0x01]
            {
                return false;
            }
            let our_ip = match self.local_addr {
                SocketAddr::V4(v4) => v4.ip().octets(),
                SocketAddr::V6(_) => return false,
            };
            let target_ip = [arp[24], arp[25], arp[26], arp[27]];
            if our_ip == [0, 0, 0, 0] || target_ip != our_ip {
                return false;
            }
            let sender_mac = [arp[8], arp[9], arp[10], arp[11], arp[12], arp[13]];
            let sender_ip = [arp[14], arp[15], arp[16], arp[17]];

            // 42-byte ARP reply.
            let mut pkt = Vec::with_capacity(42);
            pkt.extend_from_slice(&sender_mac); // eth dst = requester
            pkt.extend_from_slice(&self.src_mac); // eth src = us
            pkt.extend_from_slice(&frame::ETHERTYPE_ARP.to_be_bytes());
            pkt.extend_from_slice(&[0x00, 0x01, 0x08, 0x00, 6, 4, 0x00, 0x02]); // hdr + op=reply
            pkt.extend_from_slice(&self.src_mac); // sender mac = us
            pkt.extend_from_slice(&our_ip); // sender ip = us
            pkt.extend_from_slice(&sender_mac); // target mac = requester
            pkt.extend_from_slice(&sender_ip); // target ip = requester
            pkt.resize(60, 0); // pad to minimum Ethernet frame (sans FCS)

            self.reclaim_completions();
            let mut desc = match self.free_frames.pop() {
                Some(d) => d,
                None => return false,
            };
            {
                use std::io::Write;
                // SAFETY: `desc` was popped from the free pool — we own the frame
                // exclusively, no kernel access in flight.
                if unsafe { self.umem.data_mut(&mut desc).cursor().write_all(&pkt) }.is_err() {
                    self.free_frames.push(desc);
                    return false;
                }
            }
            let batch = [desc];
            // SAFETY: descriptors in `batch` reference frames we own (popped from
            // the free pool) and not in any ring.
            match unsafe { self.tx.produce_and_wakeup(&batch) } {
                Ok(produced) => self.tx_produced += produced as u64,
                Err(_) => return false,
            }
            true
        }

        /// Answer an ICMPv6 Neighbour Solicitation for our own IPv6 address
        /// with a Neighbour Advertisement. The XDP redirect steals NDP off the
        /// queue (as with ARP), so without this peers can't resolve us over
        /// IPv6. Only fires when bound to V6; ignores DAD (unspecified src).
        fn maybe_ndp_reply(&mut self, req: &[u8]) -> bool {
            let our_v6 = match self.local_addr {
                SocketAddr::V6(v6) => *v6.ip(),
                SocketAddr::V4(_) => return false,
            };
            let (target, src_ip) = match frame::parse_icmpv6_ns(req) {
                Some(t) => t,
                None => return false,
            };
            if target != our_v6 || src_ip.is_unspecified() || req.len() < 12 {
                return false;
            }
            // Unicast reply to the solicitor: eth dst = the NS's eth source.
            let mut dst_mac = [0u8; 6];
            dst_mac.copy_from_slice(&req[6..12]);
            let pkt = frame::build_eth_ipv6_na(self.src_mac, dst_mac, our_v6, src_ip);

            self.reclaim_completions();
            let mut desc = match self.free_frames.pop() {
                Some(d) => d,
                None => return false,
            };
            {
                use std::io::Write;
                // SAFETY: `desc` was popped from the free pool — we own the
                // frame exclusively, no kernel access in flight.
                if unsafe { self.umem.data_mut(&mut desc).cursor().write_all(&pkt) }.is_err() {
                    self.free_frames.push(desc);
                    return false;
                }
            }
            let batch = [desc];
            // SAFETY: descriptors in `batch` reference frames we own (popped
            // from the free pool) and not in any ring.
            match unsafe { self.tx.produce_and_wakeup(&batch) } {
                Ok(produced) => self.tx_produced += produced as u64,
                Err(_) => return false,
            }
            true
        }

        /// Move completed TX descriptors from the completion ring back to free.
        fn reclaim_completions(&mut self) {
            if self.comp_scratch.is_empty() {
                return;
            }
            // SAFETY: consuming the completion ring transfers ownership of the
            // listed descriptors back to us; xsk-rs overwrites `comp_scratch`
            // with the finished frames' descriptors and returns the count.
            let c = unsafe { self.comp.consume(&mut self.comp_scratch) };
            self.comp_consumed += c as u64;
            for i in 0..c {
                // FrameDesc is Copy in xsk-rs 0.6 — verify; else `.clone()`.
                self.free_frames.push(self.comp_scratch[i]);
            }
        }
    }
}
