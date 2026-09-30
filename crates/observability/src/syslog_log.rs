//! Forward ALL log lines (at a configured level) to syslog.
//!
//! # How this differs from `syslog_layer`
//!
//! `syslog_layer` sends a curated set of *security events* to a SIEM, classified
//! into stable MSGIDs, with an allowlist of fields. This module is the other
//! thing operators ask for: "put the log in syslog", so that journald, rsyslog or
//! a remote collector holds the same lines stdout carries. It is off unless
//! `[turn.observability.log_syslog] endpoint` is set, and it does not change what
//! the security exporter sends — its lines carry MSGID `LOG`, which no security
//! rule matches.
//!
//! # Redaction
//!
//! The line text is rendered by [`crate::fmt_redact::render_fields`], the same
//! formatter the stdout layer uses. So `log_allocation_addresses = false` hashes
//! client addresses here exactly as it does on stdout, and credential-named
//! fields are replaced here as everywhere. A second visitor written for this sink
//! would be a second place for that to go wrong.
//!
//! # Never on the caller's thread
//!
//! The security exporter writes synchronously from the thread that logged, which
//! is tolerable for a handful of refusals per second. The full log is not a
//! handful: at DEBUG it is a line per request. So the layer only formats and
//! `try_send`s into a bounded queue; one background thread owns the socket. A
//! full queue drops the line and counts it (`turna_log_syslog_dropped_total`).
//! A TCP collector that stops reading, or a `connect` that takes two seconds to
//! time out, then stalls that thread and nothing else.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, SyncSender, TrySendError};
use std::sync::Arc;

use tracing::{Event, Subscriber};
use tracing_subscriber::layer::Context;
use tracing_subscriber::Layer;

use crate::syslog::{Severity, SyslogConfig, SyslogExporter};

/// Where to send the full log.
#[derive(Debug, Clone)]
pub struct SyslogLogConfig {
    /// `unix:///dev/log`, `udp://host:514` or `tcp://host:601`.
    pub endpoint: String,
    /// APP-NAME / TAG.
    pub app_name: String,
    /// Lines buffered between the logging threads and the sender. Beyond this
    /// they are dropped and counted.
    pub queue_capacity: usize,
}

struct Line {
    severity: Severity,
    module: String,
    text: String,
}

/// Shared counters: the layer counts queue drops, the sender thread counts
/// what the exporter reports.
#[derive(Default)]
pub struct SyslogLogStats {
    pub sent: AtomicU64,
    pub dropped: AtomicU64,
}

#[derive(Clone)]
pub struct SyslogLogLayer {
    tx: SyncSender<Line>,
    stats: Arc<SyslogLogStats>,
}

impl SyslogLogLayer {
    /// Open the sink and start the sender thread.
    ///
    /// Fails when the endpoint does not parse or the socket cannot be opened —
    /// the exporter would otherwise disable itself quietly, and a configured sink
    /// that silently sends nothing is the failure this project keeps finding.
    pub fn spawn(cfg: &SyslogLogConfig) -> std::io::Result<Self> {
        let exporter = SyslogExporter::new(SyslogConfig {
            endpoint: cfg.endpoint.clone(),
            app_name: cfg.app_name.clone(),
            // Address redaction for this sink is the stdout switch, applied when
            // the line is rendered; the exporter's own switch is for the
            // structured fields of security events and stays off here so an
            // address is not hashed twice into a different label.
            redact_addresses: false,
            non_blocking: true,
        });
        if !exporter.is_enabled() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "log_syslog endpoint {:?} could not be set up \
                     (expected unix:///path, udp://host:port or tcp://host:port)",
                    cfg.endpoint
                ),
            ));
        }
        let (tx, rx) = sync_channel::<Line>(cfg.queue_capacity.max(1));
        let stats = Arc::new(SyslogLogStats::default());
        let thread_stats = stats.clone();
        std::thread::Builder::new()
            .name("turna-syslog-log".into())
            .spawn(move || {
                // Ends when every sender is gone, i.e. never in a running node.
                for line in rx {
                    exporter.emit_log(line.severity, &line.module, &line.text);
                    // The exporter's counters are cumulative; mirror them rather
                    // than diffing, so the two can never disagree.
                    thread_stats
                        .sent
                        .store(exporter.sent.load(Ordering::Relaxed), Ordering::Relaxed);
                    TRANSPORT_DROPPED
                        .store(exporter.dropped.load(Ordering::Relaxed), Ordering::Relaxed);
                }
            })?;
        Ok(Self { tx, stats })
    }

    pub fn stats(&self) -> &Arc<SyslogLogStats> {
        &self.stats
    }
}

/// Transport-level drops reported by the exporter on the sender thread. Kept
/// apart from the queue drops the layer counts, and summed in [`stats`], so
/// neither writer overwrites the other's count.
static TRANSPORT_DROPPED: AtomicU64 = AtomicU64::new(0);

static ACTIVE: std::sync::OnceLock<Arc<SyslogLogStats>> = std::sync::OnceLock::new();

/// Record the installed layer's counters. Called by telemetry only once the
/// subscriber carrying the layer is installed, so `stats()` returning `Some`
/// means lines are really going to syslog.
pub(crate) fn set_active(stats: Arc<SyslogLogStats>) {
    let _ = ACTIVE.set(stats);
}

/// `(sent, dropped)` for the full-log syslog sink, or `None` when it is not
/// configured. `dropped` is queue overflow plus transport errors.
pub fn stats() -> Option<(u64, u64)> {
    ACTIVE.get().map(|s| {
        (
            s.sent.load(Ordering::Relaxed),
            s.dropped.load(Ordering::Relaxed) + TRANSPORT_DROPPED.load(Ordering::Relaxed),
        )
    })
}

impl<S: Subscriber> Layer<S> for SyslogLogLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let meta = event.metadata();
        let line = Line {
            severity: Severity::from_level(meta.level()),
            module: meta.target().to_string(),
            text: crate::fmt_redact::render_fields(event),
        };
        match self.tx.try_send(line) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                self.stats.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing_subscriber::layer::SubscriberExt;

    #[test]
    fn a_bad_endpoint_is_an_error_not_a_silent_sink() {
        for bad in ["", "http://x:1", "udp://nope", "unix://relative"] {
            let r = SyslogLogLayer::spawn(&SyslogLogConfig {
                endpoint: bad.into(),
                app_name: "turna".into(),
                queue_capacity: 4,
            });
            assert!(r.is_err(), "{bad:?} must be refused");
        }
    }

    /// End to end over a real socket: lines arrive, formatted, with the level
    /// filter applied and credential fields redacted by the shared formatter.
    #[test]
    fn lines_reach_a_udp_collector_redacted_and_filtered() {
        let collector = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        collector
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let layer = SyslogLogLayer::spawn(&SyslogLogConfig {
            endpoint: format!("udp://{}", collector.local_addr().unwrap()),
            app_name: "turna-test".into(),
            queue_capacity: 64,
        })
        .unwrap();
        let stats = layer.stats().clone();
        let subscriber = tracing_subscriber::registry()
            .with(layer.with_filter(tracing::level_filters::LevelFilter::INFO));
        tracing::subscriber::with_default(subscriber, || {
            tracing::debug!("below the level, must not arrive");
            tracing::warn!(password = "hunter2", user = "alice", "hello syslog");
        });
        let mut buf = [0u8; 2048];
        let n = collector.recv(&mut buf).unwrap();
        let got = std::str::from_utf8(&buf[..n]).unwrap();
        // local0 (16) * 8 + warning (4) = 132.
        assert!(got.starts_with("<132>1 "), "{got}");
        assert!(got.contains(" turna-test "), "{got}");
        assert!(got.contains(" LOG [turna@0 module=\""), "{got}");
        assert!(got.contains("hello syslog"), "{got}");
        assert!(got.contains("user=alice"), "{got}");
        assert!(got.contains("password=[redacted]"), "{got}");
        assert!(!got.contains("hunter2"), "{got}");
        // Only one datagram: the DEBUG line was filtered out.
        collector
            .set_read_timeout(Some(std::time::Duration::from_millis(300)))
            .unwrap();
        assert!(
            collector.recv(&mut buf).is_err(),
            "DEBUG line leaked through"
        );
        assert_eq!(stats.dropped.load(Ordering::Relaxed), 0);
    }

    #[cfg(unix)]
    #[test]
    fn local_socket_gets_the_rfc3164_shape() {
        let dir = std::env::temp_dir().join(format!("turna-devlog-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("log");
        let collector = std::os::unix::net::UnixDatagram::bind(&path).unwrap();
        collector
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let layer = SyslogLogLayer::spawn(&SyslogLogConfig {
            endpoint: format!("unix://{}", path.display()),
            app_name: "turna".into(),
            queue_capacity: 8,
        })
        .unwrap();
        let subscriber = tracing_subscriber::registry().with(layer);
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!("local line");
        });
        let mut buf = [0u8; 1024];
        let n = collector.recv(&mut buf).unwrap();
        let got = std::str::from_utf8(&buf[..n]).unwrap();
        // local0 * 8 + informational (6) = 134, then `Mmm dd hh:mm:ss turna[pid]: `.
        assert!(got.starts_with("<134>"), "{got}");
        assert!(
            got.contains(&format!(" turna[{}]: LOG ", std::process::id())),
            "{got}"
        );
        assert!(got.ends_with("local line"), "{got}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
