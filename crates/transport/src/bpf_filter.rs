//! BPF socket filter — in-kernel rejection of non-TURN packets.
//!
//! Attached via `SO_ATTACH_FILTER` to the UDP socket, the classic-BPF
//! program below runs in the kernel before data is copied to userspace
//! and accepts a datagram only if it is shaped like one of:
//!
//!   * **STUN**: length ≥ 20 and the 4 bytes at offset 4 equal the STUN
//!     magic cookie `0x2112A442`;
//!   * **ChannelData**: length ≥ 4 and the first 2 bytes (the channel
//!     number) are in `0x4000..=0x7FFE`.
//!
//! Everything else — random UDP garbage, too-short or over-`max_size`
//! datagrams — is dropped in the kernel. Channel-shaped garbage (first
//! two bytes happen to land in the channel range) still passes BPF and
//! is rejected in userspace at channel lookup; BPF only does the cheap
//! shape check.
//!
//! `SO_ATTACH_FILTER` on a `SOCK_DGRAM` UDP socket runs the program over
//! the packet from the **UDP header** (8 bytes), so the STUN/ChannelData
//! message starts at offset 8; build_stun_filter shifts offsets by UDP_HDR. On macOS this is a
//! no-op. The filter can be disabled at runtime with
//! `TURNA_BPF_FILTER=0` if a particular kernel misbehaves.

#[cfg(not(target_os = "linux"))]
use tracing::warn;

use std::io;
use std::os::unix::io::RawFd;

// ---------------------------------------------------------------------------
// BPF program (pure data — compiled on Linux for the real attach, and in
// test builds on any OS so the simulator tests below can validate it).
// ---------------------------------------------------------------------------

#[cfg(any(target_os = "linux", test))]
pub(crate) mod prog {
    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    pub struct BpfInsn {
        pub code: u16,
        pub jt: u8,
        pub jf: u8,
        pub k: u32,
    }

    // Classic-BPF opcode bits (see <linux/filter.h>).
    pub const BPF_LD: u16 = 0x00;
    pub const BPF_W: u16 = 0x00;
    pub const BPF_H: u16 = 0x08;
    pub const BPF_ABS: u16 = 0x20;
    pub const BPF_LEN: u16 = 0x80;
    pub const BPF_JMP: u16 = 0x05;
    pub const BPF_JEQ: u16 = 0x10;
    pub const BPF_JGE: u16 = 0x30;
    pub const BPF_JGT: u16 = 0x20;
    pub const BPF_RET: u16 = 0x06;
    pub const BPF_K: u16 = 0x00;

    pub const STUN_MAGIC_COOKIE: u32 = 0x2112A442;
    pub const CHANNEL_MIN: u32 = 0x4000;
    pub const CHANNEL_MAX: u32 = 0x7FFE; // 0x7FFF is reserved
    pub const ACCEPT: u32 = 65535;
    pub const DROP: u32 = 0;

    #[inline]
    fn insn(code: u16, jt: u8, jf: u8, k: u32) -> BpfInsn {
        BpfInsn { code, jt, jf, k }
    }

    /// Build the STUN + ChannelData accept filter.
    ///
    /// Layout (indices matter — jt/jf are relative instruction offsets):
    /// ```text
    ///  0  A = len
    ///  1  if A <  4        -> DROP(11)
    ///  2  if A >  max_size -> DROP(11)
    ///  3  A = u16[0]                       (channel candidate)
    ///  4  if A <  0x4000   -> STUN(6)
    ///  5  if A >  0x7FFE   -> STUN(6) else ACCEPT(10)   (ChannelData)
    ///  6  A = len                          (reload after the u16 load)
    ///  7  if A <  20       -> DROP(11)
    ///  8  A = u32[4]                        (magic candidate)
    ///  9  if A == MAGIC    -> ACCEPT(10) else DROP(11)
    /// 10  RET ACCEPT
    /// 11  RET DROP
    /// ```
    pub fn build_stun_filter(max_size: u32) -> Vec<BpfInsn> {
        // SOCK_DGRAM UDP: the kernel runs SO_ATTACH_FILTER over the packet
        // starting at the UDP HEADER, so the message begins at offset
        // UDP_HDR. All message-relative offsets + BPF_LEN thresholds are
        // shifted by it. (Verified empirically against the live kernel.)
        const UDP_HDR: u32 = 8;
        vec![
            insn(BPF_LD | BPF_W | BPF_LEN, 0, 0, 0),            // 0
            insn(BPF_JMP | BPF_JGE | BPF_K, 0, 9, UDP_HDR + 4), // 1  A>=4 ? : DROP
            insn(BPF_JMP | BPF_JGT | BPF_K, 8, 0, max_size + UDP_HDR), // 2  A>max ? DROP :
            insn(BPF_LD | BPF_H | BPF_ABS, 0, 0, UDP_HDR),      // 3  A=u16[0]
            insn(BPF_JMP | BPF_JGE | BPF_K, 0, 1, CHANNEL_MIN), // 4 A>=0x4000 ? : STUN
            insn(BPF_JMP | BPF_JGT | BPF_K, 0, 4, CHANNEL_MAX), // 5 A>0x7FFE ? STUN : ACCEPT
            insn(BPF_LD | BPF_W | BPF_LEN, 0, 0, 0),            // 6  A=len
            insn(BPF_JMP | BPF_JGE | BPF_K, 0, 3, UDP_HDR + 20), // 7  A>=20 ? : DROP
            insn(BPF_LD | BPF_W | BPF_ABS, 0, 0, UDP_HDR + 4),  // 8  A=u32[4]
            insn(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, STUN_MAGIC_COOKIE), // 9 ==MAGIC ? ACCEPT : DROP
            insn(BPF_RET | BPF_K, 0, 0, ACCEPT),                // 10
            insn(BPF_RET | BPF_K, 0, 0, DROP),                  // 11
        ]
    }

    /// Reference interpreter for the subset of classic BPF this module
    /// emits. Used by the unit tests to validate the program on any OS
    /// (the real kernel runs the identical instruction array on Linux).
    /// Returns the RET value (ACCEPT or DROP).
    #[cfg(test)]
    pub fn simulate(prog: &[BpfInsn], pkt: &[u8]) -> u32 {
        let mut a: u32 = 0;
        let mut pc: usize = 0;
        let len = pkt.len() as u32;
        for _ in 0..10_000 {
            let i = prog[pc];
            match i.code & 0x07 {
                BPF_LD => {
                    if i.code & BPF_LEN != 0 {
                        a = len;
                    } else if i.code & BPF_ABS != 0 {
                        let sz = if i.code & BPF_H != 0 { 2usize } else { 4usize };
                        let k = i.k as usize;
                        if k + sz > pkt.len() {
                            return DROP; // out-of-bounds load aborts → drop
                        }
                        a = pkt[k..k + sz]
                            .iter()
                            .fold(0u32, |acc, &b| (acc << 8) | b as u32);
                    }
                    pc += 1;
                }
                BPF_JMP => {
                    let cond = match i.code & 0xf0 {
                        BPF_JGE => a >= i.k,
                        BPF_JGT => a > i.k,
                        BPF_JEQ => a == i.k,
                        _ => panic!("unsupported jmp"),
                    };
                    pc += 1 + if cond { i.jt as usize } else { i.jf as usize };
                }
                BPF_RET => return i.k,
                _ => panic!("unsupported class"),
            }
        }
        panic!("BPF program did not terminate");
    }
}

// ---------------------------------------------------------------------------
// Kernel attach/detach (Linux only)
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod sys {
    use super::prog::BpfInsn;
    use super::*;
    use tracing::info;

    #[repr(C)]
    pub struct BpfProg {
        pub len: u16,
        pub filter: *const BpfInsn,
    }

    pub fn attach_filter(fd: RawFd, filter: &[BpfInsn]) -> io::Result<()> {
        let prog = BpfProg {
            len: filter.len() as u16,
            filter: filter.as_ptr(),
        };
        // SAFETY: `fd` is the caller's open socket; `prog` is a valid initialized
        // sock_fprog living for the call, with matching optlen.
        let result = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_ATTACH_FILTER,
                &prog as *const _ as *const libc::c_void,
                std::mem::size_of::<BpfProg>() as libc::socklen_t,
            )
        };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        info!(fd, instructions = filter.len(), "BPF filter attached");
        Ok(())
    }

    pub fn detach(fd: RawFd) -> io::Result<()> {
        let optval: libc::c_int = 0;
        // SAFETY: `fd` is the caller's open socket; `optval` is a c_int living for
        // the call, with matching optlen.
        let result = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_DETACH_FILTER,
                &optval as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Public API (cross-platform)
// ---------------------------------------------------------------------------

/// Attach the STUN/ChannelData BPF filter to a UDP socket.
#[cfg(target_os = "linux")]
pub fn attach_stun_filter(fd: RawFd, max_packet_size: u32) -> io::Result<()> {
    let filter = prog::build_stun_filter(max_packet_size);
    sys::attach_filter(fd, &filter)
}

#[cfg(not(target_os = "linux"))]
pub fn attach_stun_filter(_fd: RawFd, _max_packet_size: u32) -> io::Result<()> {
    warn!("BPF socket filter not supported on this platform");
    Ok(())
}

/// Detach the BPF filter from a socket.
#[cfg(target_os = "linux")]
pub fn detach_filter(fd: RawFd) -> io::Result<()> {
    sys::detach(fd)
}

#[cfg(not(target_os = "linux"))]
pub fn detach_filter(_fd: RawFd) -> io::Result<()> {
    Ok(())
}

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct FilterStats {
    pub packets_received: u64,
    pub packets_dropped: u64,
    pub drop_rate: f64,
}

#[cfg(target_os = "linux")]
pub fn read_udp_drop_stats() -> FilterStats {
    let content = std::fs::read_to_string("/proc/net/snmp").unwrap_or_default();
    let mut recv = 0u64;
    let mut errors = 0u64;
    let lines: Vec<&str> = content.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        if line.starts_with("Udp:") && i + 1 < lines.len() {
            let vals: Vec<&str> = lines[i + 1].split_whitespace().collect();
            if vals.len() >= 4 {
                recv = vals[1].parse().unwrap_or(0);
                errors = vals[3].parse().unwrap_or(0);
            }
            break;
        }
    }
    FilterStats {
        packets_received: recv,
        packets_dropped: errors,
        drop_rate: if recv > 0 {
            errors as f64 / recv as f64
        } else {
            0.0
        },
    }
}

#[cfg(not(target_os = "linux"))]
pub fn read_udp_drop_stats() -> FilterStats {
    FilterStats {
        packets_received: 0,
        packets_dropped: 0,
        drop_rate: 0.0,
    }
}

// ---------------------------------------------------------------------------
// Tests (the simulator tests run on every OS, including macOS)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use prog::{build_stun_filter, simulate, ACCEPT, DROP, STUN_MAGIC_COOKIE};

    fn stun(len: usize) -> Vec<u8> {
        // prepend an 8-byte dummy UDP header (kernel feeds filter from there)
        let mut p = vec![0u8; 8 + len.max(8)];
        p[8] = 0x00;
        p[9] = 0x01; // Binding request
        p[12..16].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        p
    }
    fn channel(ch: u16, len: usize) -> Vec<u8> {
        let mut p = vec![0u8; 8 + len.max(4)];
        p[8..10].copy_from_slice(&ch.to_be_bytes());
        let body = (len.max(4) - 4) as u16;
        p[10..12].copy_from_slice(&body.to_be_bytes());
        p
    }

    #[test]
    fn accepts_valid_stun() {
        let f = build_stun_filter(65535);
        assert_eq!(simulate(&f, &stun(20)), ACCEPT);
        assert_eq!(simulate(&f, &stun(60)), ACCEPT);
    }

    #[test]
    fn accepts_channel_data_in_range() {
        let f = build_stun_filter(65535);
        assert_eq!(simulate(&f, &channel(0x4000, 8)), ACCEPT);
        assert_eq!(simulate(&f, &channel(0x7FFE, 64)), ACCEPT);
    }

    #[test]
    fn drops_non_stun_non_channel() {
        let f = build_stun_filter(65535);
        // STUN-shaped but wrong magic: corrupt the cookie at message offset 4,
        // i.e. packet offset 12 (after the 8-byte UDP header)
        let mut bad = stun(20);
        bad[12] = 0xDE;
        assert_eq!(simulate(&f, &bad), DROP);
        // reserved channel 0x7FFF and below-range 0x3FFF
        assert_eq!(simulate(&f, &channel(0x7FFF, 8)), DROP);
        assert_eq!(simulate(&f, &channel(0x3FFF, 8)), DROP);
    }

    #[test]
    fn drops_short_and_oversize() {
        let f = build_stun_filter(1500);
        assert_eq!(simulate(&f, &[0x00, 0x01, 0x02]), DROP); // < 4
        assert_eq!(simulate(&f, &stun(19)), DROP); // STUN < 20
        assert_eq!(simulate(&f, &vec![0u8; 2000]), DROP); // > max_size
    }

    #[test]
    fn drops_typical_random_garbage() {
        // Garbage whose first byte is outside the channel range and which
        // has no magic cookie must be dropped. (Channel-shaped garbage,
        // ~25% of random traffic, intentionally passes BPF and is dropped
        // later in userspace at channel lookup.)
        let f = build_stun_filter(65535);
        let garbage: Vec<u8> = (0..200u32)
            .map(|i| (i.wrapping_mul(31) & 0x3F) as u8)
            .collect();
        // first byte forced < 0x40 ⇒ not channel-shaped, no magic ⇒ DROP
        assert_eq!(simulate(&f, &garbage), DROP);
    }

    // Structural assertions kept from the original tests — now they pass
    // because the filter really does encode these constants.
    #[test]
    fn filter_encodes_magic_and_channel_bounds() {
        let f = build_stun_filter(65535);
        assert!(f.iter().any(|i| i.k == 0x2112A442), "magic cookie present");
        assert!(
            f.iter().any(|i| i.k == 0x4000),
            "channel lower bound present"
        );
    }

    #[test]
    fn stats_no_panic() {
        let _ = read_udp_drop_stats();
    }

    #[test]
    fn attach_detach_no_panic_on_invalid_fd() {
        let _ = attach_stun_filter(-1, 65535);
        let _ = detach_filter(-1);
    }
}
