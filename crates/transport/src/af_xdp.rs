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
use std::sync::Arc;
use std::os::fd::{AsRawFd, RawFd};

use thiserror::Error;
use tracing::{debug, info, warn};

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

unsafe impl Send for Umem {}
// NEEDS-REVIEW: Sync via &Umem.frame_slice returns &[u8] over an
// mmap region that the kernel concurrently writes (RX DMA). Under
// the Rust memory model this is data race / UB. AF_XDP semantics
// are 'kernel writes before the descriptor is dequeued from RX
// ring; userspace reads only after dequeue' — but nothing in this
// type enforces that. Consider removing Sync or wrapping access in
// a typestate that proves dequeue-before-read.
unsafe impl Sync for Umem {}

impl Umem {
    pub fn new(frame_count: u32, frame_size: u32) -> Result<Self> {
        let size = (frame_count as usize) * (frame_size as usize);

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
        unsafe {
            libc::munmap(self.area as *mut libc::c_void, self.size);
        }
    }
}

// ---------------------------------------------------------------------------
// AF_XDP Socket
// ---------------------------------------------------------------------------

/// AF_XDP socket handle.
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
        let fd = unsafe {
            libc::socket(
                libc::AF_XDP,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                0,
            )
        };
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

        let ret = unsafe {
            libc::bind(
                fd,
                &sxdp as *const _ as *const libc::sockaddr,
                std::mem::size_of::<XdpSocketAddr>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            let err = std::io::Error::last_os_error();
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
            if err.raw_os_error() != Some(libc::EAGAIN)
                && err.raw_os_error() != Some(libc::ENOBUFS)
            {
                return Err(AfXdpError::Io(err));
            }
        }
        Ok(())
    }
}

impl Drop for AfXdpSocket {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PollResult {
    pub readable: bool,
    pub writable: bool,
}

// ---------------------------------------------------------------------------
// AF_XDP Transport (implements Transport trait pattern)
// ---------------------------------------------------------------------------

/// AF_XDP transport wrapper compatible with turna-transport architecture.
///
/// Provides the same recv_from / send_to interface as TokioTransport.
/// Designed for thread-per-core model: one AfXdpTransport per worker.
pub struct AfXdpTransport {
    socket: AfXdpSocket,
    local_addr: SocketAddr,
}

impl AfXdpTransport {
    pub fn bind(config: AfXdpConfig, listen_addr: SocketAddr) -> Result<Self> {
        let socket = AfXdpSocket::create(config)?;
        Ok(Self {
            socket,
            local_addr: listen_addr,
        })
    }

    /// Receive batch of packets (non-blocking).
    ///
    /// Returns Vec of (frame_addr, length, source_addr).
    /// Caller must parse Ethernet+IP+UDP to extract source_addr.
    pub fn recv_batch(&mut self, max: usize) -> Vec<ReceivedFrame> {
        // In production: drain RX ring, parse each frame
        // Each frame contains: ETH | IP | UDP | TURN payload
        // We strip headers and return TURN payload + source addr
        Vec::new() // placeholder
    }

    /// Send a packet.
    pub fn send_to(&mut self, data: &[u8], target: SocketAddr) -> Result<()> {
        // In production: alloc frame from UMEM, build ETH+IP+UDP headers,
        // copy payload, submit to TX ring
        Ok(()) // placeholder
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn available_frames(&self) -> usize {
        self.socket.umem().available_frames()
    }
}

/// A received frame from AF_XDP.
pub struct ReceivedFrame {
    /// TURN payload (after stripping ETH+IP+UDP headers).
    pub data: Vec<u8>,
    /// Source address (parsed from IP+UDP headers).
    pub source: SocketAddr,
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
    let idx = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    if idx == 0 {
        Err(AfXdpError::Bind(format!("interface not found: {name}")))
    } else {
        Ok(idx)
    }
}

fn set_ring_size(fd: RawFd, opt: i32, size: u32) -> Result<()> {
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
