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

pub mod telemetry;

pub use telemetry::{
    SamplingConfig, TelemetryConfig, TelemetryError, TelemetryGuard, TurnaSampler,
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
