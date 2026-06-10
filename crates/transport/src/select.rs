//! Transport backend selection: configuration preference + runtime probe.
//!
//! In `Auto` mode, io_uring is used when the runtime probe reports it usable,
//! otherwise the tokio (epoll + recvmmsg/sendmmsg) backend is used. The
//! preference can be forced either way via config.

use crate::probe::{probe_io_uring, IoUringProbe};

/// Backend preference as requested by configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportPreference {
    /// Use io_uring if available at runtime, otherwise tokio. (default)
    Auto,
    /// Force io_uring; fail fast if it is not usable/ready.
    IoUring,
    /// Force the tokio backend (epoll + recvmmsg/sendmmsg).
    Tokio,
    /// Force the AF_XDP ring datapath (Linux + `--features af-xdp`; needs
    /// CAP_NET_RAW and a bound NIC queue). Opt-in only — never auto-selected.
    AfXdp,
}

/// The backend actually selected after applying preference + probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportBackend {
    Tokio,
    IoUring,
    AfXdp,
}

/// AF_XDP availability probe. Unlike io_uring (which can be auto-selected),
/// AF_XDP is opt-in: this only reports whether the build/platform *could* run
/// it; the real readiness check (privileges, driver, NIC queue) happens at
/// `XskDatapath::bind`.
#[derive(Debug, Clone)]
pub enum AfXdpProbe {
    Available,
    Unavailable(String),
}

impl AfXdpProbe {
    pub fn is_available(&self) -> bool {
        matches!(self, AfXdpProbe::Available)
    }
}

/// Report whether AF_XDP could run here (Linux + `af-xdp` feature compiled in).
pub fn probe_af_xdp() -> AfXdpProbe {
    #[cfg(all(target_os = "linux", feature = "af-xdp"))]
    {
        AfXdpProbe::Available
    }
    #[cfg(not(all(target_os = "linux", feature = "af-xdp")))]
    {
        AfXdpProbe::Unavailable("built without the `af-xdp` feature or not on Linux".to_string())
    }
}

/// Selection result, carrying a log-friendly reason for the choice.
#[derive(Debug, Clone)]
pub struct TransportDecision {
    pub backend: TransportBackend,
    pub reason: String,
}

/// Resolve the transport backend from a preference and a runtime probe.
///
/// - `Auto`: io_uring when the probe reports it usable, otherwise tokio.
/// - `IoUring`: io_uring if usable; otherwise an `Err` (no silent downgrade —
///   an explicit opt-in should be told io_uring is unavailable here).
/// - `Tokio`: always tokio.
///
/// Note: io_uring selection routes traffic onto the thread-per-core io_uring
/// datapath. It is sound (send-slot lifecycle is tracked) but currently runs a
/// single worker and has no graceful drain — see the io_uring wiring in
/// `services/node`.
pub fn resolve(pref: TransportPreference) -> Result<TransportDecision, String> {
    let probe = probe_io_uring();

    match pref {
        TransportPreference::Tokio => Ok(TransportDecision {
            backend: TransportBackend::Tokio,
            reason: "tokio: explicitly requested via config".to_string(),
        }),

        TransportPreference::Auto => match &probe {
            IoUringProbe::Available => Ok(TransportDecision {
                backend: TransportBackend::IoUring,
                reason: "io_uring: available and selected (auto)".to_string(),
            }),
            IoUringProbe::Unavailable(r) => Ok(TransportDecision {
                backend: TransportBackend::Tokio,
                reason: format!("tokio: io_uring unavailable ({r})"),
            }),
        },

        TransportPreference::IoUring => match &probe {
            IoUringProbe::Available => Ok(TransportDecision {
                backend: TransportBackend::IoUring,
                reason: "io_uring: explicitly requested and available".to_string(),
            }),
            IoUringProbe::Unavailable(r) => Err(format!(
                "transport=io_uring was requested, but io_uring is unavailable on this \
                 host ({r})"
            )),
        },

        // AF_XDP is opt-in only (never reached via Auto). Fail fast if the build
        // or platform can't run it — no silent downgrade.
        TransportPreference::AfXdp => match probe_af_xdp() {
            AfXdpProbe::Available => Ok(TransportDecision {
                backend: TransportBackend::AfXdp,
                reason: "af_xdp: explicitly requested and available".to_string(),
            }),
            AfXdpProbe::Unavailable(r) => Err(format!(
                "transport=af_xdp was requested, but AF_XDP is unavailable here ({r})"
            )),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokio_is_always_selectable() {
        let d = resolve(TransportPreference::Tokio).expect("tokio must resolve");
        assert_eq!(d.backend, TransportBackend::Tokio);
    }

    #[test]
    fn auto_falls_back_to_tokio_when_io_uring_unavailable() {
        // On hosts without io_uring (e.g. macOS, or no `io-uring` feature),
        // Auto must resolve to tokio. Where io_uring IS available this would
        // instead select io_uring; we don't assert that here since it is
        // environment-dependent.
        let d = resolve(TransportPreference::Auto).expect("auto must resolve");
        if probe_io_uring().is_available() {
            assert_eq!(d.backend, TransportBackend::IoUring);
        } else {
            assert_eq!(d.backend, TransportBackend::Tokio);
        }
        assert!(!d.reason.is_empty());
    }

    #[test]
    fn forced_io_uring_errors_when_unavailable() {
        // Forcing io_uring where it is unavailable is an error, never a silent
        // downgrade. Where io_uring is available it resolves to the io_uring
        // backend instead.
        let r = resolve(TransportPreference::IoUring);
        if probe_io_uring().is_available() {
            assert_eq!(r.unwrap().backend, TransportBackend::IoUring);
        } else {
            assert!(r.is_err());
        }
    }

    #[test]
    fn forced_af_xdp_matches_probe() {
        // AF_XDP is opt-in: forcing it resolves to the AfXdp backend when the
        // build/platform supports it, otherwise it's a hard error (no downgrade).
        let r = resolve(TransportPreference::AfXdp);
        if probe_af_xdp().is_available() {
            assert_eq!(r.unwrap().backend, TransportBackend::AfXdp);
        } else {
            assert!(r.is_err());
        }
    }
}
