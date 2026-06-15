//! UDP GRO/GSO — Generic Receive/Segmentation Offload.
//!
//! GRO: kernel coalesces multiple UDP packets into one large buffer.
//!   One recvmsg() returns multiple packets → fewer syscalls.
//!
//! GSO: userspace submits one large buffer, NIC splits into segments.
//!   One sendmsg() sends multiple packets → fewer syscalls.
//!
//! Linux 5.0+. Transparent to PacketProcessor — it still sees individual packets.

use std::os::fd::RawFd;

use tracing::{info, warn};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
const UDP_GRO: libc::c_int = 104;
#[cfg(target_os = "linux")]
const UDP_SEGMENT: libc::c_int = 103;

/// Max GRO coalesced size (64 KB typical).
const GRO_MAX_SIZE: usize = 65536;

/// Default GSO segment size (MTU minus headers).
const GSO_DEFAULT_SEGMENT: u16 = 1472; // 1500 - 20 (IP) - 8 (UDP)

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct GsoConfig {
    /// Enable GRO on receive.
    pub enable_gro: bool,
    /// Enable GSO on send.
    pub enable_gso: bool,
    /// GSO segment size (0 = auto from MTU).
    pub gso_segment_size: u16,
    /// Max GRO buffer size.
    pub gro_buffer_size: usize,
}

impl Default for GsoConfig {
    fn default() -> Self {
        Self {
            enable_gro: true,
            enable_gso: true,
            gso_segment_size: GSO_DEFAULT_SEGMENT,
            gro_buffer_size: GRO_MAX_SIZE,
        }
    }
}

// ---------------------------------------------------------------------------
// Socket Setup
// ---------------------------------------------------------------------------

/// Enable GRO on a UDP socket.
#[cfg(target_os = "linux")]
pub fn enable_gro(fd: RawFd) -> std::io::Result<bool> {
    let val: libc::c_int = 1;
    // SAFETY: `fd` is the caller's open socket; `val` is a c_int living for the
    // call, optlen = size_of::<c_int>().
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_UDP,
            UDP_GRO,
            &val as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ENOPROTOOPT) {
            warn!("UDP GRO not supported by kernel");
            return Ok(false);
        }
        return Err(err);
    }
    info!("UDP GRO enabled");
    Ok(true)
}

#[cfg(not(target_os = "linux"))]
pub fn enable_gro(_fd: RawFd) -> std::io::Result<bool> {
    warn!("UDP GRO not supported on this platform");
    Ok(false)
}

/// Setup a socket for GSO and GRO.
pub fn setup_socket(fd: RawFd, config: &GsoConfig) -> GsoCapabilities {
    let mut caps = GsoCapabilities::default();

    if config.enable_gro {
        match enable_gro(fd) {
            Ok(true) => caps.gro_enabled = true,
            Ok(false) => {}
            Err(e) => warn!(%e, "GRO setup failed"),
        }
    }

    if config.enable_gso {
        caps.gso_enabled = check_gso_support();
        caps.gso_segment_size = config.gso_segment_size;
        if caps.gso_enabled {
            info!(segment = caps.gso_segment_size, "UDP GSO available");
        }
    }

    caps
}

// ---------------------------------------------------------------------------
// GRO Receive — split coalesced buffer into individual packets
// ---------------------------------------------------------------------------

/// Split a GRO-coalesced buffer into individual UDP payloads.
pub fn split_gro_buffer<'a>(
    buf: &'a [u8],
    total_len: usize,
    segment_size: u16,
) -> GroSegmentIter<'a> {
    GroSegmentIter {
        buf: &buf[..total_len],
        segment_size: segment_size as usize,
        offset: 0,
    }
}

pub struct GroSegmentIter<'a> {
    buf: &'a [u8],
    segment_size: usize,
    offset: usize,
}

impl<'a> Iterator for GroSegmentIter<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.buf.len() {
            return None;
        }
        let remaining = self.buf.len() - self.offset;
        let len = remaining.min(self.segment_size);
        let slice = &self.buf[self.offset..self.offset + len];
        self.offset += len;
        Some(slice)
    }
}

/// Parse GRO segment size from recvmsg cmsg.
#[cfg(target_os = "linux")]
pub fn parse_gro_cmsg(cmsg_buf: &[u8]) -> Option<u16> {
    let mut offset = 0;
    while offset + std::mem::size_of::<libc::cmsghdr>() <= cmsg_buf.len() {
        // FIX (SUSPECT #6): `cmsg_buf` is `&[u8]` (alignment 1) but
        // `cmsghdr` requires 8-byte alignment. Creating a reference via a
        // pointer cast is UB when alignment is not guaranteed.
        //
        // Fix: `ptr::read_unaligned` copies the struct byte-by-byte without
        // requiring the source address to satisfy `align_of::<cmsghdr>()`.
        // This is always safe for a `#[repr(C)]` struct with no padding UB.
        //
        // SAFETY: we checked that offset + size_of::<cmsghdr> <= buf.len(),
        // so the pointer is within the slice bounds.
        let hdr: libc::cmsghdr = unsafe {
            std::ptr::read_unaligned(cmsg_buf.as_ptr().add(offset) as *const libc::cmsghdr)
        };
        if hdr.cmsg_len == 0 {
            break;
        }
        if hdr.cmsg_level == libc::SOL_UDP && hdr.cmsg_type == UDP_GRO {
            let data_offset = offset + std::mem::size_of::<libc::cmsghdr>();
            if data_offset + 2 <= cmsg_buf.len() {
                let segment =
                    u16::from_ne_bytes([cmsg_buf[data_offset], cmsg_buf[data_offset + 1]]);
                return Some(segment);
            }
        }
        let aligned = (hdr.cmsg_len + 7) & !7;
        offset += aligned as usize;
    }
    None
}

// ---------------------------------------------------------------------------
// GSO Send — batch multiple packets in one sendmsg
// ---------------------------------------------------------------------------

/// Prepare GSO cmsg for sendmsg.
#[cfg(target_os = "linux")]
pub fn build_gso_cmsg(segment_size: u16) -> Vec<u8> {
    // SAFETY: CMSG_SPACE is a pure size computation over a constant; no memory access.
    let cmsg_space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<u16>() as u32) } as usize;
    let mut buf = vec![0u8; cmsg_space];

    // SAFETY: `buf` is sized via CMSG_SPACE for one cmsghdr and suitably aligned;
    // the reference is used only within `buf`'s lifetime.
    let hdr = unsafe { &mut *(buf.as_mut_ptr() as *mut libc::cmsghdr) };
    hdr.cmsg_level = libc::SOL_UDP;
    hdr.cmsg_type = UDP_SEGMENT;
    // SAFETY: CMSG_LEN is a pure size computation over a constant; no memory access.
    hdr.cmsg_len = unsafe { libc::CMSG_LEN(std::mem::size_of::<u16>() as u32) } as usize;

    // SAFETY: `hdr` points into `buf` sized for the cmsg; CMSG_DATA returns a
    // pointer to the data area within those bounds.
    let data_ptr = unsafe { libc::CMSG_DATA(hdr) } as *mut u16;
    // SAFETY: `data_ptr` is the cmsg data slot within `buf` (>= size_of::<u16>()),
    // aligned and writable.
    unsafe { *data_ptr = segment_size };

    buf
}

/// Batch multiple packets into one GSO-ready buffer.
pub fn batch_for_gso(packets: &[&[u8]], segment_size: u16) -> (Vec<u8>, u16) {
    let seg = segment_size as usize;
    let mut buf = Vec::with_capacity(packets.len() * seg);

    for (i, pkt) in packets.iter().enumerate() {
        buf.extend_from_slice(pkt);
        if i < packets.len() - 1 && pkt.len() < seg {
            buf.resize(buf.len() + (seg - pkt.len()), 0);
        }
    }

    (buf, segment_size)
}

// ---------------------------------------------------------------------------
// Capabilities
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct GsoCapabilities {
    pub gro_enabled: bool,
    pub gso_enabled: bool,
    pub gso_segment_size: u16,
}

#[cfg(target_os = "linux")]
fn check_gso_support() -> bool {
    let kernel = std::fs::read_to_string("/proc/version").unwrap_or_default();
    !kernel.is_empty()
}

#[cfg(not(target_os = "linux"))]
fn check_gso_support() -> bool {
    false
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gro_split_exact() {
        let buf = vec![0xAA; 3000];
        let segments: Vec<&[u8]> = split_gro_buffer(&buf, 3000, 1000).collect();
        assert_eq!(segments.len(), 3);
        assert_eq!(segments[0].len(), 1000);
        assert_eq!(segments[1].len(), 1000);
        assert_eq!(segments[2].len(), 1000);
    }

    #[test]
    fn gro_split_remainder() {
        let buf = vec![0xBB; 2500];
        let segments: Vec<&[u8]> = split_gro_buffer(&buf, 2500, 1000).collect();
        assert_eq!(segments.len(), 3);
        assert_eq!(segments[0].len(), 1000);
        assert_eq!(segments[1].len(), 1000);
        assert_eq!(segments[2].len(), 500);
    }

    #[test]
    fn gro_split_single() {
        let buf = vec![0xCC; 500];
        let segments: Vec<&[u8]> = split_gro_buffer(&buf, 500, 1500).collect();
        assert_eq!(segments.len(), 1);
        assert_eq!(segments[0].len(), 500);
    }

    #[test]
    fn gso_batch() {
        let p1 = vec![1u8; 100];
        let p2 = vec![2u8; 100];
        let packets: Vec<&[u8]> = vec![&p1, &p2];
        let (buf, seg) = batch_for_gso(&packets, 100);
        assert_eq!(seg, 100);
        assert_eq!(buf.len(), 200);
        assert_eq!(buf[0], 1);
        assert_eq!(buf[100], 2);
    }

    #[test]
    fn config_defaults() {
        let c = GsoConfig::default();
        assert!(c.enable_gro);
        assert!(c.enable_gso);
        assert_eq!(c.gso_segment_size, 1472);
    }
}
