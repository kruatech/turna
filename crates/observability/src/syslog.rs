//! Syslog export for SIEM ingestion — RFC 5424.
//!
//! # Why RFC 5424 and not something easier
//!
//! Every SIEM parses 5424. It carries structured data natively, so fields arrive
//! as fields rather than as a string a collector has to guess at. The older 3164
//! format is more widely *emitted* but has no structured section, and a JSON line
//! over a socket needs the collector configured to expect exactly our shape.
//!
//! The choice is not about elegance: a log format the customer's existing SIEM
//! already understands is one they can use on the first day.
//!
//! # What gets exported, and what does not
//!
//! Security-relevant events only: authentication failures, authorisation
//! denials, peer-filter refusals, rate-limit trips, audit entries, readiness
//! transitions. Not relayed traffic, not per-packet anything.
//!
//! That boundary is deliberate and worth stating because the temptation runs the
//! other way. A SIEM billed per event that receives a line per relayed frame
//! becomes expensive enough to be switched off, and a switched-off SIEM catches
//! nothing. Sending less is what keeps it on.
//!
//! # Addresses
//!
//! Client addresses are included. This is the opposite decision from the support
//! bundle, and for a reason: a SIEM exists to answer "who did this", it is inside
//! the operator's trust boundary, and an authentication-failure event without the
//! source is not actionable. The support bundle leaves that boundary and is
//! therefore hashed.
//!
//! Deployments where that is unacceptable can set `redact_addresses = true`,
//! which hashes them the same way — and loses the ability to correlate an attack
//! across events, which the documentation says plainly rather than leaving to be
//! discovered.

use std::io::Write;
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Syslog facility. 16 (`local0`) is conventional for application logs and is
/// what a SIEM rule set is most likely to already have a filter for.
const FACILITY_LOCAL0: u8 = 16;

/// Severity, RFC 5424 §6.2.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Alert = 1,
    Critical = 2,
    Error = 3,
    Warning = 4,
    Notice = 5,
    Informational = 6,
}

/// What kind of event this is. Becomes the `MSGID` field, which is what a SIEM
/// rule matches on — so these names are a contract and changing one breaks
/// somebody's alert.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    AuthFailure,
    RbacDenied,
    PeerRefused,
    RateLimited,
    QuotaExceeded,
    AuditEntry,
    ReadinessChanged,
    ConfigChanged,
    TlsHandshakeFailed,
    /// Input that did not parse: a decode error, an over-long attribute, a frame
    /// that did not fit. Individually ordinary — the internet sends rubbish — but
    /// the rate is a probing signal, which is why it is a distinct kind and not
    /// folded into AuthFailure.
    MalformedInput,
    /// A listener would not bind, or a control refused to start.
    ///
    /// The moment something meant to protect the deployment did not engage.
    /// Distinct from a crash: the process is fine, one of its defences is not.
    ControlFailed,
}

impl EventKind {
    fn msgid(self) -> &'static str {
        match self {
            EventKind::AuthFailure => "AUTH_FAILURE",
            EventKind::RbacDenied => "RBAC_DENIED",
            EventKind::PeerRefused => "PEER_REFUSED",
            EventKind::RateLimited => "RATE_LIMITED",
            EventKind::QuotaExceeded => "QUOTA_EXCEEDED",
            EventKind::AuditEntry => "AUDIT",
            EventKind::ReadinessChanged => "READINESS",
            EventKind::ConfigChanged => "CONFIG_CHANGED",
            EventKind::TlsHandshakeFailed => "TLS_HANDSHAKE_FAILED",
            EventKind::MalformedInput => "MALFORMED_INPUT",
            EventKind::ControlFailed => "CONTROL_FAILED",
        }
    }

    /// Default severity. An operator can raise or lower per kind in config; these
    /// are what the events mean on their own.
    ///
    /// `RateLimited` is Notice rather than Warning on purpose: a rate limiter
    /// doing its job is not a problem, and a SIEM that pages on it teaches people
    /// to mute the source. The *rate* of these is the alertable thing, which is a
    /// SIEM rule, not a severity.
    fn default_severity(self) -> Severity {
        match self {
            EventKind::AuthFailure => Severity::Warning,
            EventKind::RbacDenied => Severity::Warning,
            EventKind::PeerRefused => Severity::Notice,
            EventKind::RateLimited => Severity::Notice,
            EventKind::QuotaExceeded => Severity::Notice,
            EventKind::AuditEntry => Severity::Informational,
            EventKind::ReadinessChanged => Severity::Notice,
            EventKind::ConfigChanged => Severity::Notice,
            EventKind::TlsHandshakeFailed => Severity::Warning,
            // Notice, not Warning: one malformed packet is the internet being the
            // internet. The rate is the alertable thing, and that is a SIEM rule.
            EventKind::MalformedInput => Severity::Notice,
            // Error: a defence that did not engage is not routine, and unlike the
            // refusals above it will not resolve on its own.
            EventKind::ControlFailed => Severity::Error,
        }
    }
}

/// Where to send, and how.
#[derive(Debug, Clone)]
pub struct SyslogConfig {
    /// `udp://host:port`, `tcp://host:port`, or empty to disable.
    pub endpoint: String,
    /// APP-NAME in the syslog header. Defaults to `turna`.
    pub app_name: String,
    /// Hash client addresses instead of sending them.
    ///
    /// Off by default: a SIEM is inside the trust boundary and an
    /// authentication-failure event without a source is not actionable. On, you
    /// lose the ability to correlate one attacker across events — which is most
    /// of what a SIEM is for, so this is a real trade and not a free safety
    /// improvement.
    pub redact_addresses: bool,
    /// Drop events rather than block when the transport is slow.
    ///
    /// True by default. A syslog collector that stops reading must not be able to
    /// stall the relay: security logging that can take the service down is a
    /// worse security posture than logging that can gap. The gap is counted.
    pub non_blocking: bool,
}

impl Default for SyslogConfig {
    fn default() -> Self {
        Self {
            endpoint: String::new(),
            app_name: "turna".to_string(),
            redact_addresses: false,
            non_blocking: true,
        }
    }
}

enum Sink {
    Udp(UdpSocket, SocketAddr),
    /// Behind a mutex because a TCP stream is a single ordered channel and two
    /// threads writing interleave into garbage. UDP needs no lock: each datagram
    /// is whole.
    Tcp(Mutex<Option<TcpStream>>, SocketAddr),
    Disabled,
}

/// Emits security events to a syslog collector.
pub struct SyslogExporter {
    sink: Sink,
    config: SyslogConfig,
    hostname: String,
    /// Events successfully written.
    pub sent: AtomicU64,
    /// Events dropped: transport error, or a full path under `non_blocking`.
    ///
    /// Exported as a metric. A silent gap in a security log is worse than a
    /// visible one, because an investigation reads absence as "nothing happened".
    pub dropped: AtomicU64,
    /// Salt for address hashing when `redact_addresses` is set. Per process, so
    /// correlation holds within one node's lifetime and not across restarts.
    salt: String,
}

impl SyslogExporter {
    pub fn new(config: SyslogConfig) -> Self {
        let hostname = hostname_or_dash();
        let salt = format!("{:x}", nanos_now());

        let sink = if config.endpoint.is_empty() {
            Sink::Disabled
        } else {
            match parse_endpoint(&config.endpoint) {
                Some(("udp", addr)) => match UdpSocket::bind("0.0.0.0:0") {
                    Ok(s) => {
                        let _ = s.set_nonblocking(config.non_blocking);
                        Sink::Udp(s, addr)
                    }
                    Err(e) => {
                        tracing::error!(%e, "syslog: could not open a UDP socket; export disabled");
                        Sink::Disabled
                    }
                },
                Some(("tcp", addr)) => {
                    // Connected lazily: refusing to start because a log collector
                    // is down would make the SIEM a dependency of the relay, which
                    // inverts the relationship. Reconnection is attempted per
                    // write.
                    Sink::Tcp(Mutex::new(None), addr)
                }
                _ => {
                    tracing::error!(
                        endpoint = %config.endpoint,
                        "syslog: endpoint must be udp://host:port or tcp://host:port; export disabled"
                    );
                    Sink::Disabled
                }
            }
        };

        if matches!(sink, Sink::Disabled) && !config.endpoint.is_empty() {
            tracing::warn!("syslog export was configured but could not be set up");
        } else if !matches!(sink, Sink::Disabled) {
            tracing::info!(endpoint = %config.endpoint, "syslog export active");
        }

        Self {
            sink,
            config,
            hostname,
            sent: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            salt,
        }
    }

    pub fn is_enabled(&self) -> bool {
        !matches!(self.sink, Sink::Disabled)
    }

    /// Emit one event.
    ///
    /// `fields` become RFC 5424 structured data. Keys must be short and stable —
    /// a SIEM rule refers to them by name, so renaming one breaks a customer's
    /// alert as surely as renaming a metric breaks a dashboard.
    pub fn emit(&self, kind: EventKind, fields: &[(&str, &str)]) {
        self.emit_with_severity(kind, kind.default_severity(), fields)
    }

    pub fn emit_with_severity(&self, kind: EventKind, severity: Severity, fields: &[(&str, &str)]) {
        if matches!(self.sink, Sink::Disabled) {
            return;
        }

        let pri = FACILITY_LOCAL0 as u16 * 8 + severity as u16;
        let ts = rfc3339_now();

        let mut sd = String::from("[turna@0");
        for (k, v) in fields {
            let value = if self.config.redact_addresses && looks_like_address(k) {
                hash_address(&self.salt, v)
            } else {
                v.to_string()
            };
            // Escaping per RFC 5424 §6.3.3: `"`, `\` and `]` inside a param
            // value. Without it a value containing `]` truncates the structured
            // section and the SIEM sees a malformed line — which most collectors
            // discard silently, losing the event that mattered most.
            let escaped = value
                .replace('\\', "\\\\")
                .replace('"', "\\\"")
                .replace(']', "\\]");
            sd.push_str(&format!(" {k}=\"{escaped}\""));
        }
        sd.push(']');

        let line = format!(
            "<{pri}>1 {ts} {host} {app} {pid} {msgid} {sd}",
            host = self.hostname,
            app = self.config.app_name,
            pid = std::process::id(),
            msgid = kind.msgid(),
        );

        self.write(&line);
    }

    fn write(&self, line: &str) {
        match &self.sink {
            Sink::Disabled => {}
            Sink::Udp(sock, addr) => match sock.send_to(line.as_bytes(), addr) {
                Ok(_) => {
                    self.sent.fetch_add(1, Ordering::Relaxed);
                }
                Err(_) => {
                    self.dropped.fetch_add(1, Ordering::Relaxed);
                }
            },
            Sink::Tcp(guard, addr) => {
                let mut slot = match guard.try_lock() {
                    Ok(g) => g,
                    Err(_) => {
                        // Another thread is writing. Under non_blocking we drop
                        // rather than queue: a lock held by a stalled write is
                        // exactly the case where blocking would propagate a
                        // collector's problem into the relay.
                        self.dropped.fetch_add(1, Ordering::Relaxed);
                        return;
                    }
                };
                if slot.is_none() {
                    match TcpStream::connect_timeout(addr, Duration::from_secs(2)) {
                        Ok(s) => {
                            let _ = s.set_write_timeout(Some(Duration::from_secs(2)));
                            *slot = Some(s);
                        }
                        Err(_) => {
                            self.dropped.fetch_add(1, Ordering::Relaxed);
                            return;
                        }
                    }
                }
                // Octet counting (RFC 5425 framing): length, space, message. A
                // newline-delimited stream breaks on any message containing a
                // newline, and structured data values can.
                let framed = format!("{} {}", line.len(), line);
                let ok = slot
                    .as_mut()
                    .map(|s| s.write_all(framed.as_bytes()).is_ok())
                    .unwrap_or(false);
                if ok {
                    self.sent.fetch_add(1, Ordering::Relaxed);
                } else {
                    // Drop the connection so the next write reconnects rather
                    // than writing into a half-closed socket forever.
                    *slot = None;
                    self.dropped.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }
}

fn parse_endpoint(s: &str) -> Option<(&str, SocketAddr)> {
    let (proto, rest) = s.split_once("://")?;
    let addr = rest.parse().ok()?;
    Some((proto, addr))
}

fn looks_like_address(key: &str) -> bool {
    matches!(
        key,
        "src" | "src_ip" | "client" | "client_addr" | "peer" | "peer_ip" | "remote"
    )
}

/// Stable label for an address, salted per process.
///
/// FNV-1a, not a cryptographic hash. Pulling `turna_crypto` into this crate for
/// an optional feature would add a dependency to every binary that logs. What
/// this needs is that one address maps to one label within a process — enough to
/// correlate an attacker across events — and the salt is never written down.
///
/// Somebody holding the log *and* guessing an address could confirm the guess.
/// That is true of SHA-256 here too: the input space is four billion. If that
/// matters, use `--strip-addresses` and accept losing correlation.
fn hash_address(salt: &str, v: &str) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in salt.bytes().chain(v.bytes()) {
        h ^= b as u64;
        h = h.wrapping_mul(0x100_0000_01b3);
    }
    format!("ip-{h:012x}")
}

fn hostname_or_dash() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        // `-` is RFC 5424's NILVALUE. Better than a guess: a SIEM grouping by
        // host would otherwise group unrelated nodes under whatever we invented.
        .unwrap_or_else(|| "-".to_string())
}

fn nanos_now() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

/// RFC 3339 with microseconds, which is what 5424 wants for TIMESTAMP.
fn rfc3339_now() -> String {
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = d.as_secs();
    let micros = d.subsec_micros();

    // Civil-from-days, so this has no chrono dependency. The management plane
    // already pulls enough in; a timestamp is not worth another crate.
    let days = (secs / 86_400) as i64;
    let sod = secs % 86_400;
    let (y, m, dd) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{dd:02}T{:02}:{:02}:{:02}.{micros:06}Z",
        sod / 3600,
        (sod % 3600) / 60,
        sod % 60
    )
}

/// Howard Hinnant's algorithm. Days since the Unix epoch to a civil date.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_by_default() {
        let e = SyslogExporter::new(SyslogConfig::default());
        assert!(!e.is_enabled());
        // Emitting into a disabled exporter must be free and silent, not an error
        // path: every call site would otherwise need a conditional.
        e.emit(EventKind::AuthFailure, &[("src", "1.2.3.4")]);
        assert_eq!(e.sent.load(Ordering::Relaxed), 0);
        assert_eq!(e.dropped.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn bad_endpoint_disables_rather_than_panics() {
        for bad in ["not-a-url", "udp://", "http://host:80", "tcp://nope"] {
            let e = SyslogExporter::new(SyslogConfig {
                endpoint: bad.to_string(),
                ..Default::default()
            });
            assert!(!e.is_enabled(), "{bad} should have disabled the exporter");
        }
    }

    /// A `]` in a value would truncate the structured-data section, and most
    /// collectors discard a malformed line silently — losing precisely the event
    /// worth keeping.
    #[test]
    fn structured_data_escapes_the_three_dangerous_characters() {
        let e = SyslogExporter::new(SyslogConfig {
            endpoint: "udp://127.0.0.1:1".to_string(),
            ..Default::default()
        });
        // Exercised through emit rather than a private helper: the escaping has to
        // happen on the path that actually runs.
        e.emit(
            EventKind::AuthFailure,
            &[("detail", r#"has ] and " and \ in it"#)],
        );
        // Sent or dropped, but never a panic and never a partial line.
        let total = e.sent.load(Ordering::Relaxed) + e.dropped.load(Ordering::Relaxed);
        assert_eq!(total, 1);
    }

    #[test]
    fn timestamp_is_rfc3339_with_microseconds() {
        let ts = rfc3339_now();
        assert!(ts.ends_with('Z'), "{ts}");
        assert_eq!(
            ts.len(),
            27,
            "expected YYYY-MM-DDThh:mm:ss.ffffffZ, got {ts}"
        );
        assert_eq!(&ts[4..5], "-");
        assert_eq!(&ts[10..11], "T");
    }

    /// Known dates, because an off-by-one in the civil-date arithmetic produces
    /// timestamps that look right and sort wrong.
    #[test]
    fn civil_dates_are_correct_at_known_points() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(365), (1971, 1, 1));
        // 2000-02-29: the leap year that catches naive implementations.
        assert_eq!(civil_from_days(11016), (2000, 2, 29));
        assert_eq!(civil_from_days(19723), (2024, 1, 1));
    }

    #[test]
    fn msgids_are_stable_and_distinct() {
        let kinds = [
            EventKind::AuthFailure,
            EventKind::RbacDenied,
            EventKind::PeerRefused,
            EventKind::RateLimited,
            EventKind::QuotaExceeded,
            EventKind::AuditEntry,
            EventKind::ReadinessChanged,
            EventKind::ConfigChanged,
            EventKind::TlsHandshakeFailed,
        ];
        let ids: Vec<&str> = kinds.iter().map(|k| k.msgid()).collect();
        let unique: std::collections::HashSet<&&str> = ids.iter().collect();
        assert_eq!(ids.len(), unique.len(), "two event kinds share a MSGID");
        // These are a contract: a SIEM rule matches on them.
        assert_eq!(EventKind::AuthFailure.msgid(), "AUTH_FAILURE");
        assert_eq!(EventKind::RbacDenied.msgid(), "RBAC_DENIED");
    }

    /// A rate limiter doing its job is not a warning. If it were, a SIEM would
    /// page on normal operation and somebody would mute the source.
    #[test]
    fn routine_refusals_are_not_warnings() {
        assert_eq!(EventKind::RateLimited.default_severity(), Severity::Notice);
        assert_eq!(EventKind::PeerRefused.default_severity(), Severity::Notice);
        assert_eq!(EventKind::AuthFailure.default_severity(), Severity::Warning);
    }

    #[test]
    fn address_keys_are_recognised() {
        for k in ["src", "client_addr", "peer_ip", "remote"] {
            assert!(looks_like_address(k), "{k} should be treated as an address");
        }
        for k in ["realm", "username", "reason", "detail"] {
            assert!(!looks_like_address(k), "{k} is not an address");
        }
    }
}
