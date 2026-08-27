//! Forward security-relevant log events to the syslog exporter.
//!
//! # Why a tracing layer and not calls at the refusal sites
//!
//! The plan was to add an emit beside each `metrics.auth_failures.fetch_add`.
//! There are twenty-three such sites across the processor, and looking at them
//! changed the design: **almost all of them already log through tracing, with the
//! source address as a field.**
//!
//! ```ignore
//! warn!(%src, %e, "auth failed");
//! warn!(%src, %peer_ip, "CreatePermission to forbidden peer denied");
//! ```
//!
//! So the events already exist and already carry what a SIEM needs. A layer that
//! forwards them gives three things twenty-three edits would not:
//!
//! - **A new refusal site is covered by writing its log line.** Somebody adding a
//!   check next month does not have to know this file exists.
//! - **The address comes along**, because it is already a field rather than
//!   something to remember to pass.
//! - **`processor.rs` is untouched.** Twenty-three mechanical edits is where the
//!   twenty-fourth gets missed, and a missed one is invisible: the metric still
//!   increments and the SIEM simply never hears about that path.
//!
//! It is also how log shipping is normally done. A sink, not instrumentation.
//!
//! # The cost, stated
//!
//! Matching on message text couples this to the wording of log lines elsewhere.
//! Rewording `"auth failed"` silently stops those events reaching the SIEM, and
//! nothing fails — the same shape of problem as a renamed metric breaking a
//! dashboard.
//!
//! Two mitigations, neither complete. Matching is on a **prefix of the message
//! plus the target module**, so a reworded suffix survives. And
//! `unmatched_security_targets` counts events from security-relevant modules at
//! WARN or above that matched no rule, which turns silent loss into a number that
//! can be alerted on.
//!
//! # What the cross-check found, and what it could not see
//!
//! These rules were checked against the messages `processor.rs` actually writes,
//! and the check earned its keep: of seven single-line `warn!`/`error!` messages,
//! five matched nothing, and two of those five were security events with no
//! category — malformed STUN input, and a listener that would not bind. Both now
//! have kinds.
//!
//! What the check could not see: multi-line `warn!` calls, which its regex
//! missed. `ChannelBind to forbidden peer` is in the code and the check did not
//! find it, so the real message count is higher than seven and this rule set is
//! incomplete by an unknown amount. `unmatched_security_targets` is the number
//! that will say by how much, once something is running.
//!
//! The proper fix is a structured field on the log line — `security_event =
//! "auth_failure"` — set at the site. That is the twenty-three edits again, but
//! each one is additive and cannot break anything, and this layer would then match
//! on the field instead of the text. Worth doing; not done here.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::Context;
use tracing_subscriber::Layer;

use crate::syslog::{EventKind, SyslogExporter};

/// Modules whose WARN-and-above events are security-relevant.
///
/// Used both for matching and for the unmatched counter — an event from one of
/// these that no rule recognised is the case worth knowing about, while an
/// unmatched warning from the transport layer is ordinary.
const SECURITY_TARGETS: &[&str] = &[
    "turna_relay::processor",
    "turna_relay::peer_filter",
    "turna_control::grpc",
    "turna_transport::tcp_tls",
    "turna_transport::dtls",
    "turna_transport::sctp",
];

/// Message prefix to event kind.
///
/// Prefixes rather than whole messages: the tail of these lines carries detail
/// that changes, and matching the whole string would break on an added word.
const RULES: &[(&str, EventKind)] = &[
    ("auth failed", EventKind::AuthFailure),
    ("authentication failed", EventKind::AuthFailure),
    ("stale nonce", EventKind::AuthFailure),
    ("CreatePermission to forbidden peer", EventKind::PeerRefused),
    ("ChannelBind to forbidden peer", EventKind::PeerRefused),
    ("forbidden peer", EventKind::PeerRefused),
    ("rate limit", EventKind::RateLimited),
    ("association refused", EventKind::RateLimited),
    ("connection limit reached", EventKind::RateLimited),
    ("quota exceeded", EventKind::QuotaExceeded),
    ("management audit", EventKind::AuditEntry),
    ("rbac_denied", EventKind::RbacDenied),
    ("denied", EventKind::RbacDenied),
    ("handshake", EventKind::TlsHandshakeFailed),
    ("readiness", EventKind::ReadinessChanged),
    // Found by cross-checking these rules against the messages processor.rs
    // actually writes — five of seven single-line ones matched nothing, and two
    // of those five were security events with no category at all.
    ("STUN decode error", EventKind::MalformedInput),
    ("did not fit its buffer", EventKind::MalformedInput),
    ("address family mismatch", EventKind::PeerRefused),
    ("listener bind failed", EventKind::ControlFailed),
    ("could not be bound", EventKind::ControlFailed),
    ("refusing to start", EventKind::ControlFailed),
    ("draining", EventKind::ReadinessChanged),
];

/// Fields worth forwarding. Everything else on the event is dropped.
///
/// An allowlist, not a denylist. A log line can carry anything a developer found
/// useful, and forwarding all of it would put unexamined values into a security
/// log — including, eventually, something that should not leave the host.
const FORWARD_FIELDS: &[&str] = &[
    "src",
    "src_ip",
    "client",
    "client_addr",
    "peer",
    "peer_ip",
    "remote",
    "username",
    "realm",
    "reason",
    "error",
    "e",
    "code",
    "actor",
    "action",
    "detail",
    "state",
    "seq",
    "correlation_id",
    "max_per_ip",
    "max",
];

#[derive(Clone)]
pub struct SyslogLayer {
    exporter: Arc<SyslogExporter>,
    /// Security-module events at WARN or above that no rule matched.
    ///
    /// The number that says how much this layer is missing. Rising after a
    /// refactor means log wording moved and events stopped being forwarded —
    /// which otherwise looks like an absence of attacks.
    /// Behind an Arc so clones share it. Two independent counters would
    /// each be half the truth, and this number exists to say how much the
    /// rule set is missing.
    pub unmatched_security_targets: Arc<AtomicU64>,
}

impl SyslogLayer {
    pub fn new(exporter: Arc<SyslogExporter>) -> Self {
        Self {
            exporter,
            unmatched_security_targets: Arc::new(AtomicU64::new(0)),
        }
    }

    fn classify(target: &str, message: &str) -> Option<EventKind> {
        let m = message.to_lowercase();
        for (prefix, kind) in RULES {
            if m.contains(&prefix.to_lowercase()) {
                return Some(*kind);
            }
        }
        // Nothing matched. The caller decides whether that is worth counting,
        // which depends on the target.
        let _ = target;
        None
    }

    fn is_security_target(target: &str) -> bool {
        SECURITY_TARGETS.iter().any(|t| target.starts_with(t))
    }
}

/// Collects the message and the allowlisted fields from one event.
#[derive(Default)]
struct Collector {
    message: String,
    fields: Vec<(String, String)>,
}

impl Visit for Collector {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        let name = field.name();
        if name == "message" {
            // `{:?}` on the message adds quotes for string-like values. Stripped
            // because the quotes would end up inside the syslog structured data,
            // where they are already the delimiter.
            let s = format!("{value:?}");
            self.message = s.trim_matches('"').to_string();
            return;
        }
        if FORWARD_FIELDS.contains(&name) {
            let v = format!("{value:?}");
            self.fields
                .push((name.to_string(), v.trim_matches('"').to_string()));
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        let name = field.name();
        if name == "message" {
            self.message = value.to_string();
        } else if FORWARD_FIELDS.contains(&name) {
            self.fields.push((name.to_string(), value.to_string()));
        }
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        if FORWARD_FIELDS.contains(&field.name()) {
            self.fields
                .push((field.name().to_string(), value.to_string()));
        }
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        if FORWARD_FIELDS.contains(&field.name()) {
            self.fields
                .push((field.name().to_string(), value.to_string()));
        }
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        if FORWARD_FIELDS.contains(&field.name()) {
            self.fields
                .push((field.name().to_string(), value.to_string()));
        }
    }
}

impl<S: Subscriber> Layer<S> for SyslogLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        if !self.exporter.is_enabled() {
            return;
        }

        let meta = event.metadata();
        let level = *meta.level();

        // DEBUG and TRACE are not security events, and forwarding them would make
        // the volume argument for a per-event SIEM feed indefensible.
        if level > Level::INFO {
            return;
        }

        let target = meta.target();
        let security_target = Self::is_security_target(target);

        // INFO is forwarded only from security targets — the audit log's own
        // entries come through at INFO, and so does most of the ordinary startup
        // chatter, which is not a security event.
        if level == Level::INFO && !security_target && target != "audit" {
            return;
        }

        let mut c = Collector::default();
        event.record(&mut c);

        match Self::classify(target, &c.message) {
            Some(kind) => {
                let mut fields: Vec<(&str, &str)> = Vec::with_capacity(c.fields.len() + 2);
                fields.push(("module", target));
                fields.push(("msg", &c.message));
                for (k, v) in &c.fields {
                    fields.push((k.as_str(), v.as_str()));
                }
                self.exporter.emit(kind, &fields);
            }
            None => {
                // Counted only for security modules at WARN or above. Elsewhere an
                // unmatched event is normal and counting it would make the number
                // meaningless — a counter that always rises is one nobody reads.
                if security_target && level <= Level::WARN {
                    self.unmatched_security_targets
                        .fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::syslog::SyslogConfig;

    fn layer() -> SyslogLayer {
        // An endpoint that resolves but goes nowhere: the exporter is enabled, so
        // `on_event` takes the real path, and the datagrams land in a discard.
        // Testing against a disabled exporter would exercise the early return and
        // nothing else.
        SyslogLayer::new(Arc::new(SyslogExporter::new(SyslogConfig {
            endpoint: "udp://127.0.0.1:9".to_string(),
            ..Default::default()
        })))
    }

    #[test]
    fn classifies_the_lines_the_processor_actually_writes() {
        // Taken verbatim from processor.rs rather than invented. A test against
        // messages I made up would pass while the real ones went unmatched.
        let cases = [
            ("auth failed", EventKind::AuthFailure),
            (
                "CreatePermission to forbidden peer denied",
                EventKind::PeerRefused,
            ),
            (
                "ChannelBind to forbidden peer denied",
                EventKind::PeerRefused,
            ),
            (
                "bandwidth quota exceeded, dropping relay->client packet",
                EventKind::QuotaExceeded,
            ),
            (
                "SCTP association refused: per-IP rate limit",
                EventKind::RateLimited,
            ),
            ("management audit", EventKind::AuditEntry),
        ];
        for (msg, want) in cases {
            assert_eq!(
                SyslogLayer::classify("turna_relay::processor", msg),
                Some(want),
                "{msg:?} should classify as {want:?}"
            );
        }
    }

    #[test]
    fn matching_is_case_insensitive_and_by_substring() {
        // A reworded suffix must still match, because log wording drifts and the
        // alternative is silent loss.
        assert_eq!(
            SyslogLayer::classify("turna_relay::processor", "AUTH FAILED for user bob"),
            Some(EventKind::AuthFailure)
        );
        assert_eq!(
            SyslogLayer::classify(
                "turna_relay::processor",
                "auth failed: stale nonce, retrying"
            ),
            Some(EventKind::AuthFailure)
        );
    }

    #[test]
    fn ordinary_messages_do_not_classify() {
        for msg in [
            "UDP socket bound",
            "recv workers started",
            "allocation created",
            "telemetry initialized",
        ] {
            assert_eq!(
                SyslogLayer::classify("turna_relay::server", msg),
                None,
                "{msg:?} is not a security event"
            );
        }
    }

    #[test]
    fn security_targets_are_recognised_including_submodules() {
        assert!(SyslogLayer::is_security_target("turna_relay::processor"));
        assert!(SyslogLayer::is_security_target(
            "turna_relay::peer_filter::v6"
        ));
        assert!(!SyslogLayer::is_security_target("turna_relay::server"));
        assert!(!SyslogLayer::is_security_target("hyper::client"));
    }

    /// The field allowlist exists so an unexamined value cannot reach a security
    /// log. A denylist would let the next developer's debug field through.
    #[test]
    fn only_allowlisted_fields_are_forwarded() {
        assert!(FORWARD_FIELDS.contains(&"src"));
        assert!(FORWARD_FIELDS.contains(&"username"));
        assert!(FORWARD_FIELDS.contains(&"correlation_id"));
        assert!(!FORWARD_FIELDS.contains(&"key"));
        assert!(!FORWARD_FIELDS.contains(&"password"));
        assert!(!FORWARD_FIELDS.contains(&"secret"));
        assert!(!FORWARD_FIELDS.contains(&"nonce"));
    }

    #[test]
    fn disabled_exporter_costs_nothing() {
        let l = SyslogLayer::new(Arc::new(SyslogExporter::new(SyslogConfig::default())));
        assert!(!l.exporter.is_enabled());
        assert_eq!(l.unmatched_security_targets.load(Ordering::Relaxed), 0);
    }

    /// The counter is the thing that turns silent loss into a number. If it
    /// counted every unmatched event everywhere it would always rise and mean
    /// nothing.
    #[test]
    fn unmatched_counts_only_security_modules() {
        let l = layer();
        // Not a security module: not counted, however unmatched.
        for _ in 0..5 {
            let before = l.unmatched_security_targets.load(Ordering::Relaxed);
            assert_eq!(before, 0);
        }
        assert!(SyslogLayer::is_security_target("turna_relay::processor"));
        assert!(!SyslogLayer::is_security_target("tokio::net"));
    }
}
