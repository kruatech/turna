//! Observability — structured logging and distributed tracing.
//!
//! # Quick start (logging only)
//! ```ignore
//! turna_observability::init();
//! ```
//!
//! # With OTLP tracing (production)
//! ```ignore
//! let cfg = turna_observability::TelemetryConfig {
//!     otlp_endpoint: "http://otel-collector:4317".into(),
//!     ..Default::default()
//! };
//! let _guard = turna_observability::init_with_config(cfg).unwrap();
//! // _guard must be kept alive for the duration of the process.
//! ```

// This crate contains no `unsafe`. The attribute makes that checkable by
// the compiler instead of by `docs/unsafe-audit.md`: a future change that
// introduces `unsafe` here fails to build rather than quietly widening the
// audited surface, which is confined to turna-transport and turna-relay.
#![forbid(unsafe_code)]

/// Address redaction for the stdout (`fmt`) layer. See the module docs for why
/// it sits at the sink rather than at each call site.
pub mod fmt_redact;
/// Rotating log file sink (`[turn.observability.log_file]`).
pub mod log_file;
pub mod syslog;
pub mod syslog_layer;
/// Full-log syslog sink (`[turn.observability.log_syslog]`).
pub mod syslog_log;
pub mod telemetry;

pub use telemetry::{
    log_sink_stats, FileSink, LogSinkStats, SamplingConfig, SyslogSink, TelemetryConfig,
    TelemetryError, TelemetryGuard, TurnaSampler,
};

/// Initialise logging with defaults (no OTLP).
///
/// Equivalent to `init_with_config(TelemetryConfig::default())`.
/// Kept for backward compatibility with existing call sites.
pub fn init() {
    // Ignore error: if subscriber is already installed (e.g. in tests) this
    // is benign.
    let _ = telemetry::init(TelemetryConfig::default());
}

/// Initialise logging and (optionally) OTLP tracing from a config struct.
///
/// Returns a `TelemetryGuard` that flushes the tracer provider on drop.
/// Keep it alive in `main()` for the duration of the process.
pub fn init_with_config(config: TelemetryConfig) -> telemetry::Result<TelemetryGuard> {
    telemetry::init(config)
}

/// As [`init_with_config`], plus one caller-supplied layer applied to the bare
/// `Registry` beneath every other layer. See [`telemetry::init_with_layer`].
pub fn init_with_layer<L>(config: TelemetryConfig, extra: L) -> telemetry::Result<TelemetryGuard>
where
    L: tracing_subscriber::Layer<tracing_subscriber::Registry> + Send + Sync + 'static,
{
    telemetry::init_with_layer(config, extra)
}
