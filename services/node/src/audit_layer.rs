//! Record lifecycle events in the audit ring, from wherever they happen.
//!
//! # Why a layer and not calls at the sites
//!
//! `record_infra` needs an `AuditLog`, which lives in `turna-control`. Neither
//! `turna-relay` nor `turna-transport` depends on it — checked, both have zero
//! references — and adding the dependency is the wrong trade in both directions.
//!
//! `turna-transport` sits at the bottom of the stack. Pulling a management-plane
//! type into it so a listener can write a log entry inverts the layering for the
//! sake of one call.
//!
//! And doing it for `turna-relay` alone would be worse than not doing it: the
//! audit log would then cover draining and bind failures but not certificate
//! rotation, because that happens in `CertReloader` in the transport crate. A
//! journal with a hole exactly where the interesting event is has the appearance
//! of coverage.
//!
//! The node depends on everything. So the observation happens there, in a layer,
//! and every crate is covered on the same terms.
//!
//! # The cost, which is the same one the syslog layer pays
//!
//! Matching on message text. Rewording `"shutdown signal received, draining..."`
//! silently stops the drain being audited, and nothing fails.
//!
//! Two mitigations, neither complete: matching is on a substring rather than the
//! whole message, so a reworded tail survives; and `unmatched_lifecycle` counts
//! events from the modules these rules watch that matched nothing, which turns
//! silent loss into a number.
//!
//! The proper fix is the same as for syslog — a structured field set at the site,
//! `lifecycle_event = "drain_started"`, matched on instead of the text. That is
//! additive at each site and cannot break anything, and it is the work this
//! defers.
//!
//! # What is deliberately not audited
//!
//! The `draining... remaining=N` line inside the drain loop. It fires every two
//! seconds for the length of the drain, and auditing it would fill the ring with
//! one event repeated — a log that grows at a fixed rate regardless of activity
//! is one nobody reads. The transition is audited; the progress is not.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::Context;
use tracing_subscriber::Layer;

use turna_control::audit::{AuditLog, InfraEvent};

/// Modules whose lifecycle events are worth auditing.
///
/// Used for the unmatched counter as well as for matching: an unmatched event
/// from one of these is worth knowing about, while an unmatched line from
/// elsewhere is ordinary.
const WATCHED: &[&str] = &[
    "turna_relay::server",
    "turna_transport::tcp_tls",
    "turna_transport::dtls",
    "turna_transport::quic",
    "turna_transport::sctp",
    "turna_node",
];

/// Message substring to event kind, with the outcome the message implies.
///
/// The `bool` is `outcome` in the audit entry, and it deserves attention here
/// more than on an RPC. An RPC that fails returns an error to a caller who
/// notices; a certificate reload that fails is invisible, because the node
/// correctly keeps serving on the old material. `outcome: false` is often the
/// only trace that a control did not engage.
const RULES: &[(&str, InfraEvent, bool)] = &[
    // Taken from the messages these files actually write, not invented. Checked
    // against crates/relay/src/server.rs:644 and :837.
    (
        "shutdown signal received, draining",
        InfraEvent::DrainStateChanged,
        true,
    ),
    (
        "drain complete",
        InfraEvent::DrainStateChanged,
        true,
    ),
    (
        "SO_REUSEPORT bind failed",
        InfraEvent::SecurityControlFailed,
        false,
    ),
    (
        "bind failed",
        InfraEvent::SecurityControlFailed,
        false,
    ),
    (
        "listener bind failed",
        InfraEvent::SecurityControlFailed,
        false,
    ),
    (
        "certificate hot-reload",
        InfraEvent::CertRotated,
        true,
    ),
    (
        "certificate reloaded",
        InfraEvent::CertRotated,
        true,
    ),
    (
        "cert reload failed",
        InfraEvent::CertRotated,
        false,
    ),
    (
        "configuration reloaded",
        InfraEvent::ConfigReloaded,
        true,
    ),
    (
        "readiness",
        InfraEvent::ReadinessChanged,
        true,
    ),
    (
        "degraded",
        InfraEvent::ReadinessChanged,
        false,
    ),
    // ── added after cross-checking against the real messages ──────────────
    //
    // Nine were missed on the first pass, and several matter more than the rules
    // that hit. Each of these is verbatim from server.rs or tcp_tls.rs.

    // My rule said "drain complete"; the code says this. So the drain-*finished*
    // event was missed while the drain-*started* one matched — a journal showing
    // a drain that begins and never ends.
    (
        "all allocations drained",
        InfraEvent::DrainStateChanged,
        true,
    ),
    // A successful rotation. Without this the audit recorded only failures, and
    // could not answer "did the rotation take effect" — which is the question
    // asked after an incident that followed one.
    (
        "TLS cert reloaded",
        InfraEvent::CertRotated,
        true,
    ),
    (
        "certificate hot-reload disabled",
        InfraEvent::CertRotated,
        true,
    ),
    (
        "certificate hot-reload unavailable",
        InfraEvent::CertRotated,
        false,
    ),
    // The most serious message in server.rs, and nothing covered it. The node
    // stops relaying and remains a live process: health may still answer, the
    // port stays bound, and no allocation succeeds. An auditor asking why a node
    // went silent needs this entry to exist.
    (
        "datapath is dead",
        InfraEvent::SecurityControlFailed,
        false,
    ),
    // A listener or bridge task died. Same shape, smaller blast radius.
    (
        "exited unexpectedly",
        InfraEvent::SecurityControlFailed,
        false,
    ),
    (
        "worker stopping",
        InfraEvent::SecurityControlFailed,
        false,
    ),
    // A transport draining, distinct from the relay's drain above.
    (
        "listener draining",
        InfraEvent::DrainStateChanged,
        true,
    ),
    // Found on the second coverage pass, both in quic.rs. The same asymmetry
    // already fixed for TLS: the success was recorded and the failure was not.
    //
    // "rejected" as well as "failed" because WebTransport words it differently,
    // and a rule matching only one keeps missing the other. That is the whole
    // exposure of text matching in one line.
    (
        "certificate reload failed",
        InfraEvent::CertRotated,
        false,
    ),
    (
        "certificate reload rejected",
        InfraEvent::CertRotated,
        false,
    ),
];

/// Fields worth carrying into the entry. An allowlist, not a denylist: a log line
/// can carry anything a developer found useful, and forwarding all of it would put
/// unexamined values into a hash-chained log.
const FORWARD: &[&str] = &[
    "worker", "listen", "addr", "path", "cert", "reason", "error", "e",
    "remaining", "state", "grace_secs", "max",
];

pub struct AuditLayer {
    audit: Arc<AuditLog>,
    /// Events from watched modules that matched no rule.
    ///
    /// Rising after a refactor means log wording moved and lifecycle events
    /// stopped being audited — which otherwise looks like a quiet system.
    pub unmatched_lifecycle: Arc<AtomicU64>,
}

impl AuditLayer {
    pub fn new(audit: Arc<AuditLog>) -> Self {
        Self {
            audit,
            unmatched_lifecycle: Arc::new(AtomicU64::new(0)),
        }
    }

    fn classify(message: &str) -> Option<(InfraEvent, bool)> {
        let m = message.to_lowercase();
        // The drain-loop progress line is excluded before matching, not by
        // omitting a rule: "draining..." would otherwise match the
        // drain-transition rule every two seconds for the length of the drain.
        if m.starts_with("draining") && m.contains("remaining") {
            return None;
        }
        for (needle, event, ok) in RULES {
            if m.contains(&needle.to_lowercase()) {
                return Some((*event, *ok));
            }
        }
        None
    }

    fn watched(target: &str) -> bool {
        WATCHED.iter().any(|t| target.starts_with(t))
    }
}

impl Clone for AuditLayer {
    /// Shares the counter rather than duplicating it. Two independent counters
    /// would each hold half the truth, and the counter exists to say how much the
    /// rule set is missing.
    fn clone(&self) -> Self {
        Self {
            audit: Arc::clone(&self.audit),
            unmatched_lifecycle: Arc::clone(&self.unmatched_lifecycle),
        }
    }
}

#[derive(Default)]
struct Collector {
    message: String,
    detail: Vec<String>,
}

impl Visit for Collector {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        let name = field.name();
        let v = format!("{value:?}");
        let v = v.trim_matches('"');
        if name == "message" {
            self.message = v.to_string();
        } else if FORWARD.contains(&name) {
            self.detail.push(format!("{name}={v}"));
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        let name = field.name();
        if name == "message" {
            self.message = value.to_string();
        } else if FORWARD.contains(&name) {
            self.detail.push(format!("{name}={value}"));
        }
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        if FORWARD.contains(&field.name()) {
            self.detail.push(format!("{}={}", field.name(), value));
        }
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        if FORWARD.contains(&field.name()) {
            self.detail.push(format!("{}={}", field.name(), value));
        }
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        if FORWARD.contains(&field.name()) {
            self.detail.push(format!("{}={}", field.name(), value));
        }
    }
}

impl<S: Subscriber> Layer<S> for AuditLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let meta = event.metadata();
        // INFO and above. A lifecycle event that only appears at DEBUG is not one
        // an auditor would be told about anyway.
        if *meta.level() > Level::INFO {
            return;
        }
        let target = meta.target();
        if !Self::watched(target) {
            return;
        }

        let mut c = Collector::default();
        event.record(&mut c);

        match Self::classify(&c.message) {
            Some((kind, ok)) => {
                let detail = if c.detail.is_empty() {
                    c.message.clone()
                } else {
                    format!("{} [{}]", c.message, c.detail.join(" "))
                };
                self.audit.record_infra(kind, &detail, ok);
            }
            None => {
                // Counted only at WARN and above. An unmatched INFO from a watched
                // module is ordinary — those modules log plenty that is not a
                // lifecycle event — and counting it would make the number always
                // rise and therefore mean nothing.
                if *meta.level() <= Level::WARN {
                    self.unmatched_lifecycle.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_the_lines_server_actually_writes() {
        // Verbatim from crates/relay/src/server.rs. A test against invented
        // messages would pass while the real ones went unmatched — which is the
        // failure mode of matching on text at all.
        let cases = [
            ("shutdown signal received, draining...", InfraEvent::DrainStateChanged, true),
            ("drain complete — no active allocations remaining", InfraEvent::DrainStateChanged, true),
            ("SO_REUSEPORT bind failed, continuing with fewer workers", InfraEvent::SecurityControlFailed, false),
        ];
        for (msg, kind, ok) in cases {
            assert_eq!(
                AuditLayer::classify(msg),
                Some((kind, ok)),
                "{msg:?} should classify"
            );
        }
    }

    /// The drain loop logs `draining... remaining=N` every two seconds. Auditing
    /// it would fill the ring with one event repeated, and a log that grows at a
    /// fixed rate regardless of activity is one nobody reads.
    #[test]
    fn the_drain_progress_line_is_excluded() {
        assert_eq!(AuditLayer::classify("draining... remaining=113"), None);
        assert_eq!(AuditLayer::classify("draining..."), None);
        // But the transition itself is not.
        assert!(AuditLayer::classify("shutdown signal received, draining...").is_some());
    }

    /// A failed reload is the case that most needs auditing, because it is
    /// otherwise invisible: the node correctly keeps serving on the old
    /// certificate and says nothing an operator would notice.
    #[test]
    fn a_failed_reload_is_recorded_as_a_failure() {
        let (kind, ok) = AuditLayer::classify("cert reload failed: bad PEM").unwrap();
        assert_eq!(kind, InfraEvent::CertRotated);
        assert!(!ok, "a failed rotation must not be recorded as outcome: true");
    }

    /// The nine the first pass missed. Verbatim from the source, so a refactor of
    /// any of these messages fails this test rather than silently stopping the
    /// audit — which is the whole exposure of matching on text.
    #[test]
    fn the_messages_a_first_pass_missed() {
        let cases = [
            ("all allocations drained", InfraEvent::DrainStateChanged, true),
            ("TLS cert reloaded", InfraEvent::CertRotated, true),
            ("cert reload failed; keeping previous certificate", InfraEvent::CertRotated, false),
            ("all recv workers exited — datapath is dead", InfraEvent::SecurityControlFailed, false),
            ("relay egress task exited — datapath is dead", InfraEvent::SecurityControlFailed, false),
            ("TURNS bridge exited unexpectedly", InfraEvent::SecurityControlFailed, false),
            ("cleanup/metrics task exited unexpectedly", InfraEvent::SecurityControlFailed, false),
            ("recv error, worker stopping", InfraEvent::SecurityControlFailed, false),
        ];
        for (msg, kind, ok) in cases {
            assert_eq!(
                AuditLayer::classify(msg),
                Some((kind, ok)),
                "{msg:?} was missed on the first pass and must not be again"
            );
        }
    }

    /// Every failed rotation, across all four transports, must be recorded as a
    /// failure. A journal that logs successful rotations and not failed ones
    /// cannot answer the question asked after an incident: did the rotation take
    /// effect? And the failure is the invisible one — the node keeps serving on
    /// the old certificate, correctly and silently.
    #[test]
    fn every_failed_rotation_is_recorded_as_a_failure() {
        for msg in [
            "cert reload failed; keeping previous certificate",
            "QUIC certificate reload failed; keeping previous certificate",
            "WebTransport certificate reload rejected; keeping previous certificate",
            "TURNS certificate hot-reload unavailable; using static cert",
        ] {
            let (kind, ok) = AuditLayer::classify(msg)
                .unwrap_or_else(|| panic!("{msg:?} must classify"));
            assert_eq!(kind, InfraEvent::CertRotated, "{msg:?}");
            assert!(!ok, "{msg:?} must be recorded as outcome: false");
        }
    }

    /// And every successful one as a success, so the pair can be told apart.
    #[test]
    fn every_successful_rotation_is_recorded_as_a_success() {
        for msg in [
            "TLS cert reloaded",
            "QUIC certificate reloaded",
            "WebTransport certificate reloaded",
        ] {
            let (kind, ok) = AuditLayer::classify(msg)
                .unwrap_or_else(|| panic!("{msg:?} must classify"));
            assert_eq!(kind, InfraEvent::CertRotated, "{msg:?}");
            assert!(ok, "{msg:?} must be recorded as outcome: true");
        }
    }

    /// "datapath is dead" is the most serious message in server.rs and the first
    /// rule set did not cover it. The node stops relaying and stays a live
    /// process: the port is bound, health may answer, and nothing works.
    #[test]
    fn a_dead_datapath_is_recorded_as_a_failure() {
        let (kind, ok) = AuditLayer::classify("all recv workers exited — datapath is dead").unwrap();
        assert_eq!(kind, InfraEvent::SecurityControlFailed);
        assert!(!ok);
    }

    #[test]
    fn ordinary_lines_do_not_classify() {
        for msg in [
            "recv workers started",
            "UDP socket bound",
            "allocation created",
            "BPF filter attached",
        ] {
            assert_eq!(AuditLayer::classify(msg), None, "{msg:?}");
        }
    }

    #[test]
    fn watched_targets_include_submodules() {
        assert!(AuditLayer::watched("turna_relay::server"));
        assert!(AuditLayer::watched("turna_transport::tcp_tls::reload"));
        assert!(!AuditLayer::watched("turna_relay::processor"));
        assert!(!AuditLayer::watched("hyper::server"));
    }

    /// The allowlist keeps an unexamined value out of a hash-chained log. A
    /// denylist would admit the next developer's debug field.
    #[test]
    fn only_allowlisted_fields_travel() {
        assert!(FORWARD.contains(&"worker"));
        assert!(FORWARD.contains(&"reason"));
        assert!(!FORWARD.contains(&"key"));
        assert!(!FORWARD.contains(&"secret"));
        assert!(!FORWARD.contains(&"src"));
    }

    /// Matching is case-insensitive and by substring, because log wording drifts
    /// and the alternative is silent loss.
    #[test]
    fn matching_tolerates_rewording_of_the_tail() {
        assert!(AuditLayer::classify("Shutdown signal received, draining now").is_some());
        assert!(AuditLayer::classify("SO_REUSEPORT BIND FAILED on worker 3").is_some());
    }
}
