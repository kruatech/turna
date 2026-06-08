//! SQE Batching — группировка отправок для снижения syscall overhead
//!
//! - Linux: sendmmsg(2) — до 64 пакетов за один syscall
//! - macOS/other: single send fallback
//! - Адаптивный режим: батчинг включается только при PPS > threshold

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use tracing::{debug, trace};

#[cfg(target_os = "linux")]
use std::os::unix::io::RawFd;

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct BatchConfig {
    /// Max packets per batch.
    pub max_batch_size: usize,
    /// Max time to wait for batch to fill.
    pub max_delay: Duration,
    /// Min PPS to enable batching. Below this — send immediately.
    pub adaptive_threshold_pps: u64,
    /// Window for PPS calculation.
    pub adaptive_window: Duration,
}

impl Default for BatchConfig {
    fn default() -> Self {
        Self {
            max_batch_size: 64,
            max_delay: Duration::from_micros(100),
            adaptive_threshold_pps: 100_000,
            adaptive_window: Duration::from_secs(1),
        }
    }
}

// ---------------------------------------------------------------------------
// Pending Packet
// ---------------------------------------------------------------------------

pub struct PendingPacket {
    pub data: Vec<u8>,
    pub dest: SocketAddr,
}

// ---------------------------------------------------------------------------
// sendmmsg (Linux only)
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
pub fn sendmmsg_batch(fd: RawFd, packets: &[PendingPacket]) -> std::io::Result<usize> {
    if packets.is_empty() {
        return Ok(0);
    }

    let count = packets.len().min(libc::UIO_MAXIOV as usize);

    let mut iovecs: Vec<libc::iovec> = Vec::with_capacity(count);
    let mut addrs: Vec<libc::sockaddr_storage> = Vec::with_capacity(count);
    let mut addr_lens: Vec<libc::socklen_t> = Vec::with_capacity(count);

    #[repr(C)]
    struct MmsgHdr {
        msg_hdr: libc::msghdr,
        msg_len: libc::c_uint,
    }

    let mut msgs: Vec<MmsgHdr> = Vec::with_capacity(count);

    for pkt in packets.iter().take(count) {
        iovecs.push(libc::iovec {
            iov_base: pkt.data.as_ptr() as *mut libc::c_void,
            iov_len: pkt.data.len(),
        });

        let (addr, len) = sockaddr_to_raw(&pkt.dest);
        addrs.push(addr);
        addr_lens.push(len);

        msgs.push(MmsgHdr {
            msg_hdr: libc::msghdr {
                msg_name: std::ptr::null_mut(),
                msg_namelen: 0,
                msg_iov: std::ptr::null_mut(),
                msg_iovlen: 1,
                msg_control: std::ptr::null_mut(),
                msg_controllen: 0,
                msg_flags: 0,
            },
            msg_len: 0,
        });
    }

    // FIX (SUSPECT #5): was `&mut iovecs[i] as *mut _` inside a loop.
    // That creates a temporary `&mut` reference in each iteration, which
    // by Rust's stacked-borrow rules "invalidates" the raw pointer stored
    // in the previous iteration's `msg_hdr.msg_iov`. After the loop all
    // those pointers are passed simultaneously to sendmmsg — UB.
    //
    // Fix: obtain ONE raw pointer to the start of each Vec via `as_mut_ptr()`
    // (a single mutable borrow that ends immediately) and then compute
    // element offsets via `.add(i)`. No intermediate `&mut` is created,
    // so stacked borrows are not violated.
    //
    // SAFETY: i < count ≤ iovecs.len() = addrs.len() = msgs.len(),
    // so all .add(i) calls are in-bounds.
    unsafe {
        let iovecs_ptr = iovecs.as_mut_ptr();
        let addrs_ptr = addrs.as_mut_ptr();
        for i in 0..count {
            msgs[i].msg_hdr.msg_iov = iovecs_ptr.add(i);
            msgs[i].msg_hdr.msg_name = addrs_ptr.add(i) as *mut libc::c_void;
            msgs[i].msg_hdr.msg_namelen = addr_lens[i];
        }
    }
    let sent = unsafe {
        libc::syscall(
            libc::SYS_sendmmsg,
            fd,
            msgs.as_mut_ptr(),
            count as libc::c_uint,
            0 as libc::c_int,
        )
    };

    if sent < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(sent as usize)
    }
}

#[cfg(target_os = "linux")]
fn sockaddr_to_raw(addr: &SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    match addr {
        SocketAddr::V4(v4) => {
            let sin: &mut libc::sockaddr_in =
                unsafe { &mut *(&mut storage as *mut _ as *mut libc::sockaddr_in) };
            sin.sin_family = libc::AF_INET as libc::sa_family_t;
            sin.sin_port = v4.port().to_be();
            sin.sin_addr.s_addr = u32::from_ne_bytes(v4.ip().octets());
            (
                storage,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        }
        SocketAddr::V6(v6) => {
            let sin6: &mut libc::sockaddr_in6 =
                unsafe { &mut *(&mut storage as *mut _ as *mut libc::sockaddr_in6) };
            sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            sin6.sin6_port = v6.port().to_be();
            sin6.sin6_addr.s6_addr = v6.ip().octets();
            sin6.sin6_flowinfo = v6.flowinfo();
            sin6.sin6_scope_id = v6.scope_id();
            (
                storage,
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            )
        }
    }
}

// ---------------------------------------------------------------------------
// Adaptive Batcher
// ---------------------------------------------------------------------------

pub struct SqeBatcher {
    config: BatchConfig,
    pending_count: usize,
    batch_start: Option<Instant>,
    packets_in_window: u64,
    window_start: Instant,
    batching_enabled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BatchAction {
    SendImmediately,
    Wait,
    FlushNow,
}

impl SqeBatcher {
    pub fn new(config: BatchConfig) -> Self {
        Self {
            config,
            pending_count: 0,
            batch_start: None,
            packets_in_window: 0,
            window_start: Instant::now(),
            batching_enabled: false,
        }
    }

    pub fn on_packet(&mut self) -> BatchAction {
        self.packets_in_window += 1;
        self.update_adaptive();

        if !self.batching_enabled {
            return BatchAction::SendImmediately;
        }

        if self.batch_start.is_none() {
            self.batch_start = Some(Instant::now());
        }

        self.pending_count += 1;

        if self.pending_count >= self.config.max_batch_size {
            self.reset_batch();
            return BatchAction::FlushNow;
        }

        BatchAction::Wait
    }

    pub fn check_timeout(&mut self) -> bool {
        if let Some(start) = self.batch_start {
            if start.elapsed() >= self.config.max_delay && self.pending_count > 0 {
                self.reset_batch();
                return true;
            }
        }
        false
    }

    pub fn pending(&self) -> usize {
        self.pending_count
    }
    pub fn is_enabled(&self) -> bool {
        self.batching_enabled
    }

    pub fn current_pps(&self) -> u64 {
        let elapsed = self.window_start.elapsed().as_secs_f64();
        if elapsed > 0.0 {
            (self.packets_in_window as f64 / elapsed) as u64
        } else {
            0
        }
    }

    fn reset_batch(&mut self) {
        trace!(size = self.pending_count, "batch flushed");
        self.pending_count = 0;
        self.batch_start = None;
    }

    fn update_adaptive(&mut self) {
        if self.window_start.elapsed() >= self.config.adaptive_window {
            let pps = self.current_pps();
            let was = self.batching_enabled;
            self.batching_enabled = pps >= self.config.adaptive_threshold_pps;
            if self.batching_enabled != was {
                debug!(
                    pps,
                    enabled = self.batching_enabled,
                    "adaptive batching toggled"
                );
            }
            self.packets_in_window = 0;
            self.window_start = Instant::now();
        }
    }
}

#[derive(Debug, Clone)]
pub struct BatchStats {
    pub batching_enabled: bool,
    pub current_pps: u64,
    pub queued: usize,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adaptive_off_at_low_pps() {
        let mut b = SqeBatcher::new(BatchConfig {
            adaptive_threshold_pps: 100_000,
            ..Default::default()
        });
        assert_eq!(b.on_packet(), BatchAction::SendImmediately);
        assert!(!b.is_enabled());
    }

    #[test]
    fn flush_at_max_batch() {
        let mut b = SqeBatcher::new(BatchConfig {
            max_batch_size: 3,
            ..Default::default()
        });
        b.batching_enabled = true;
        assert_eq!(b.on_packet(), BatchAction::Wait);
        assert_eq!(b.on_packet(), BatchAction::Wait);
        assert_eq!(b.on_packet(), BatchAction::FlushNow);
        assert_eq!(b.pending(), 0);
    }

    #[test]
    fn timeout_check() {
        let mut b = SqeBatcher::new(BatchConfig {
            max_delay: Duration::from_millis(1),
            ..Default::default()
        });
        b.batching_enabled = true;
        b.on_packet();
        assert!(!b.check_timeout());
        std::thread::sleep(Duration::from_millis(5));
        assert!(b.check_timeout());
        assert_eq!(b.pending(), 0);
    }

    #[test]
    fn default_config() {
        let c = BatchConfig::default();
        assert_eq!(c.max_batch_size, 64);
        assert_eq!(c.adaptive_threshold_pps, 100_000);
    }
}
