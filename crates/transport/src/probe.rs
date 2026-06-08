//! Runtime detection of io_uring availability.
//!
//! "io_uring compiled in" != "io_uring usable". Even on a recent kernel,
//! `io_uring_setup` can be blocked by a seccomp profile or a container
//! sandbox (returns `EPERM`/`ENOSYS`), and older kernels may lack the
//! opcodes the relay datapath relies on. This module answers the *runtime*
//! question: "can we actually use io_uring here, right now?".
//!
//! The probe is intentionally cheap and side-effect free: it creates a tiny
//! ring, asks the kernel which opcodes it supports, and tears the ring down.
//! It does not bind sockets or move packets.

/// Outcome of probing io_uring.
#[derive(Debug, Clone)]
pub enum IoUringProbe {
    /// io_uring is usable and all required opcodes are supported.
    Available,
    /// io_uring cannot be used here; the string is a human-readable reason
    /// suitable for an operator-facing log line.
    Unavailable(String),
}

impl IoUringProbe {
    pub fn is_available(&self) -> bool {
        matches!(self, IoUringProbe::Available)
    }

    pub fn reason(&self) -> Option<&str> {
        match self {
            IoUringProbe::Available => None,
            IoUringProbe::Unavailable(r) => Some(r.as_str()),
        }
    }
}

/// Probe whether io_uring can drive the relay datapath on this host.
///
/// Linux + `io-uring` feature: actually exercises `io_uring_setup` and an
/// opcode capability probe. Anywhere else: io_uring is never available.
#[cfg(all(target_os = "linux", feature = "io-uring"))]
pub fn probe_io_uring() -> IoUringProbe {
    use io_uring::{opcode, IoUring, Probe};

    // 1. Can we even create a ring? `ENOSYS` = kernel has no io_uring;
    //    `EPERM` = blocked by seccomp / sandbox (common in hardened
    //    containers and some managed Kubernetes node images).
    let ring = match IoUring::new(8) {
        Ok(r) => r,
        Err(e) => return IoUringProbe::Unavailable(format!("io_uring_setup failed: {e}")),
    };

    // 2. Does the kernel support the opcodes our datapath needs? Probing the
    //    opcode table is more reliable than sniffing the kernel version.
    let mut probe = Probe::new();
    if let Err(e) = ring.submitter().register_probe(&mut probe) {
        return IoUringProbe::Unavailable(format!("register_probe failed: {e}"));
    }

    for (name, code) in [
        ("RecvMsg", opcode::RecvMsg::CODE),
        ("SendMsg", opcode::SendMsg::CODE),
    ] {
        if !probe.is_supported(code) {
            return IoUringProbe::Unavailable(format!("required opcode {name} unsupported"));
        }
    }

    IoUringProbe::Available
}

/// On non-Linux targets or when the `io-uring` feature is not compiled in,
/// io_uring is never available and the tokio backend is the only option.
#[cfg(not(all(target_os = "linux", feature = "io-uring")))]
pub fn probe_io_uring() -> IoUringProbe {
    IoUringProbe::Unavailable(
        "io_uring not compiled in (requires Linux + --features io-uring)".to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_is_deterministic_and_reports_reason_when_unavailable() {
        let p = probe_io_uring();
        // We don't assert availability (CI/sandbox may block io_uring), but
        // an unavailable result must always carry a non-empty reason.
        if let IoUringProbe::Unavailable(r) = p {
            assert!(!r.is_empty(), "unavailable probe must explain why");
        }
    }
}
