//! OpenTelemetry интеграция
//!
//! - TurnaSampler: 1% base + 100% ошибок + 100% Allocate/Refresh + rate limit
//! - OTLP export (gRPC) в Jaeger/Tempo/Grafana Cloud
//! - TURN-специфичные histogram buckets
//!
//! # Cargo.toml additions required in crates/observability/Cargo.toml:
//!
//! ```toml
//! thiserror.workspace = true
//! opentelemetry          = "0.32"
//! opentelemetry_sdk      = "0.32"
//! opentelemetry-otlp     = { version = "0.32", features = ["grpc-tonic"] }
//! tracing-opentelemetry  = "0.33"
//! hostname               = "0.3"
//! ```

use std::sync::Arc;
use std::time::Duration;

use opentelemetry::trace::TraceId;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry::KeyValue;
use opentelemetry_sdk::trace::{Sampler, SamplingDecision, SamplingResult, ShouldSample};
use thiserror::Error;
use tracing::info;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Error)]
pub enum TelemetryError {
    #[error("tracer init: {0}")]
    Tracer(String),
    #[error("metrics init: {0}")]
    Metrics(String),
}

pub type Result<T> = std::result::Result<T, TelemetryError>;

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct TelemetryConfig {
    pub service_name: String,
    pub service_version: String,
    pub instance_id: String,
    /// OTLP gRPC endpoint, e.g. "http://localhost:4317".
    /// Empty string → tracing disabled (only logs).
    pub otlp_endpoint: String,
    pub sampling: SamplingConfig,
    pub prometheus_addr: String,
    pub log_filter: String,
    pub json_logs: bool,
}

#[derive(Debug, Clone)]
pub struct SamplingConfig {
    pub base_ratio: f64,
    pub always_sample_errors: bool,
    pub latency_threshold_us: u64,
    pub always_sample_methods: Vec<String>,
    pub max_spans_per_second: u32,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            service_name: "turna".into(),
            service_version: env!("CARGO_PKG_VERSION").into(),
            instance_id: hostname::get()
                .ok()
                .and_then(|h| h.into_string().ok())
                .unwrap_or_else(|| "unknown".into()),
            otlp_endpoint: String::new(),
            sampling: SamplingConfig::default(),
            prometheus_addr: "0.0.0.0:9090".into(),
            log_filter: "info,turna=debug".into(),
            json_logs: false,
        }
    }
}

impl Default for SamplingConfig {
    fn default() -> Self {
        Self {
            base_ratio: 0.01,
            always_sample_errors: true,
            latency_threshold_us: 10_000,
            always_sample_methods: vec!["Allocate".into(), "Refresh".into()],
            max_spans_per_second: 1000,
        }
    }
}

// ---------------------------------------------------------------------------
// TurnaSampler
// ---------------------------------------------------------------------------

// FIX: added #[derive(Debug)] — required because TurnaSampler derives Debug
#[derive(Debug)]
struct TokenBucket {
    max: u32,
    tokens: std::sync::atomic::AtomicU32,
    last_refill: std::sync::Mutex<std::time::Instant>,
}

impl TokenBucket {
    fn new(max: u32) -> Self {
        Self {
            max,
            tokens: std::sync::atomic::AtomicU32::new(max),
            last_refill: std::sync::Mutex::new(std::time::Instant::now()),
        }
    }

    fn try_acquire(&self) -> bool {
        {
            let mut t = self.last_refill.lock().unwrap();
            if t.elapsed() >= Duration::from_secs(1) {
                self.tokens
                    .store(self.max, std::sync::atomic::Ordering::Relaxed);
                *t = std::time::Instant::now();
            }
        }
        loop {
            let c = self.tokens.load(std::sync::atomic::Ordering::Relaxed);
            if c == 0 {
                return false;
            }
            if self
                .tokens
                .compare_exchange_weak(
                    c,
                    c - 1,
                    std::sync::atomic::Ordering::Relaxed,
                    std::sync::atomic::Ordering::Relaxed,
                )
                .is_ok()
            {
                return true;
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct TurnaSampler {
    config: SamplingConfig,
    inner: Sampler,
    limiter: Arc<TokenBucket>,
}

impl TurnaSampler {
    pub fn new(config: SamplingConfig) -> Self {
        let inner = Sampler::TraceIdRatioBased(config.base_ratio);
        let limiter = Arc::new(TokenBucket::new(config.max_spans_per_second));
        Self {
            config,
            inner,
            limiter,
        }
    }
}

impl ShouldSample for TurnaSampler {
    fn should_sample(
        &self,
        parent: Option<&opentelemetry::Context>,
        trace_id: TraceId,
        name: &str,
        kind: &opentelemetry::trace::SpanKind,
        attrs: &[KeyValue],
        links: &[opentelemetry::trace::Link],
    ) -> SamplingResult {
        if !self.limiter.try_acquire() {
            return SamplingResult {
                decision: SamplingDecision::Drop,
                attributes: vec![],
                trace_state: Default::default(),
            };
        }
        if self.config.always_sample_errors && attrs.iter().any(|kv| kv.key.as_str() == "error") {
            return SamplingResult {
                decision: SamplingDecision::RecordAndSample,
                attributes: vec![KeyValue::new("sampling.reason", "error")],
                trace_state: Default::default(),
            };
        }
        if self
            .config
            .always_sample_methods
            .iter()
            .any(|m| name.contains(m.as_str()))
        {
            return SamplingResult {
                decision: SamplingDecision::RecordAndSample,
                attributes: vec![KeyValue::new("sampling.reason", "critical")],
                trace_state: Default::default(),
            };
        }
        self.inner
            .should_sample(parent, trace_id, name, kind, attrs, links)
    }
}

// ---------------------------------------------------------------------------
// Histogram Buckets
// ---------------------------------------------------------------------------

pub mod buckets {
    pub const PROCESSING_LATENCY: &[f64] = &[
        0.000_005, 0.000_010, 0.000_025, 0.000_050, 0.000_100, 0.000_250, 0.000_500, 0.001, 0.005,
        0.010, 0.050, 0.100,
    ];
    pub const PACKET_SIZE: &[f64] = &[
        64.0, 128.0, 256.0, 512.0, 1024.0, 1280.0, 1500.0, 4096.0, 8192.0, 65535.0,
    ];
    pub const ALLOCATION_LIFETIME: &[f64] = &[
        10.0, 30.0, 60.0, 120.0, 300.0, 600.0, 1800.0, 3600.0, 7200.0,
    ];
}

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------

pub struct TelemetryGuard {
    provider: Option<opentelemetry_sdk::trace::SdkTracerProvider>,
}

impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        // opentelemetry 0.32: no global shutdown fn — flush via the provider.
        if let Some(provider) = self.provider.take() {
            let _ = provider.shutdown();
        }
        info!("telemetry shutdown");
    }
}

/// Initialise structured logging and (optionally) OTLP tracing.
///
/// # Layer order
///
/// OTel layer must be applied to the bare `Registry` — before EnvFilter —
/// because `OpenTelemetryLayer<S, T>` is implemented for `Layer<S>` where
/// S must be the subscriber type at the point of application.  Applying
/// EnvFilter first changes S from `Registry` to `Layered<EnvFilter, Registry>`,
/// which no longer satisfies the trait bound.
pub fn init(config: TelemetryConfig) -> Result<TelemetryGuard> {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&config.log_filter));

    // Build OTel layer first (needs bare Registry as subscriber type).
    // Wrap in Option so we can choose whether to include it.
    let otlp_enabled = !config.otlp_endpoint.is_empty();
    let mut guard_provider: Option<opentelemetry_sdk::trace::SdkTracerProvider> = None;

    // FIX: apply layers in correct order — OTel → filter → fmt.
    // This ensures the OTel layer sees Registry as its subscriber type.
    macro_rules! try_init_with_fmt {
        ($base:expr) => {
            if config.json_logs {
                $base
                    .with(tracing_subscriber::fmt::layer().json())
                    .try_init()
                    .map_err(|e| TelemetryError::Tracer(e.to_string()))
            } else {
                $base
                    .with(tracing_subscriber::fmt::layer())
                    .try_init()
                    .map_err(|e| TelemetryError::Tracer(e.to_string()))
            }
        };
    }

    if otlp_enabled {
        let (otel_layer, provider) = build_otel_layer(&config)?;
        guard_provider = Some(provider);
        // Registry → OTel → EnvFilter → fmt
        let base = tracing_subscriber::registry().with(otel_layer).with(filter);
        try_init_with_fmt!(base)?;
    } else {
        info!("OTLP endpoint not configured — distributed tracing disabled");
        // Registry → EnvFilter → fmt
        let base = tracing_subscriber::registry().with(filter);
        try_init_with_fmt!(base)?;
    }

    info!(
        service  = %config.service_name,
        version  = %config.service_version,
        instance = %config.instance_id,
        otlp     = %config.otlp_endpoint,
        sampling = config.sampling.base_ratio,
        "telemetry initialized"
    );

    Ok(TelemetryGuard {
        provider: guard_provider,
    })
}

/// Build a `tracing_opentelemetry` layer backed by an OTLP gRPC exporter.
///
/// Returns a layer typed for `tracing_subscriber::Registry` — must be
/// applied BEFORE any other layers in the subscriber chain.
fn build_otel_layer(
    config: &TelemetryConfig,
) -> Result<(
    impl tracing_subscriber::Layer<tracing_subscriber::Registry> + Send + Sync + 'static,
    opentelemetry_sdk::trace::SdkTracerProvider,
)> {
    use opentelemetry_otlp::WithExportConfig;

    let resource = opentelemetry_sdk::Resource::builder()
        .with_service_name(config.service_name.clone())
        .with_attributes([
            KeyValue::new("service.version", config.service_version.clone()),
            KeyValue::new("service.instance.id", config.instance_id.clone()),
            KeyValue::new(
                "deployment.environment",
                std::env::var("DEPLOYMENT_ENV").unwrap_or_else(|_| "production".into()),
            ),
        ])
        .build();

    let sampler = TurnaSampler::new(config.sampling.clone());

    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(&config.otlp_endpoint)
        .build()
        .map_err(|e| TelemetryError::Tracer(format!("OTLP exporter: {e}")))?;

    // opentelemetry_sdk 0.32: sampler/resource go on the provider builder
    // (trace::Config was removed) and the batch exporter takes no runtime arg.
    let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
        .with_sampler(opentelemetry_sdk::trace::Sampler::ParentBased(Box::new(
            sampler,
        )))
        .with_resource(resource)
        .with_batch_exporter(exporter)
        .build();

    let tracer = provider.tracer(config.service_name.clone());
    // Clone for the global provider; keep the original for the guard to
    // shut down on drop.
    opentelemetry::global::set_tracer_provider(provider.clone());

    info!(endpoint = %config.otlp_endpoint, "OTLP tracer provider installed");

    Ok((tracing_opentelemetry::layer().with_tracer(tracer), provider))
}

/// Span macro для обработки STUN-запроса.
#[macro_export]
macro_rules! stun_span {
    ($method:expr, $class:expr, $client:expr) => {
        tracing::info_span!(
            "stun_request",
            stun.method = $method,
            stun.class  = $class,
            client      = %$client,
            otel.kind   = "server"
        )
    };
}

/// Span macro для relay (ChannelData).
#[macro_export]
macro_rules! relay_span {
    ($channel:expr, $dir:expr) => {
        tracing::trace_span!("channel_relay", ch = $channel, dir = $dir)
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limiter_blocks_after_max() {
        let tb = TokenBucket::new(3);
        assert!(tb.try_acquire());
        assert!(tb.try_acquire());
        assert!(tb.try_acquire());
        assert!(!tb.try_acquire());
    }

    #[test]
    fn buckets_sorted() {
        assert!(buckets::PROCESSING_LATENCY.windows(2).all(|w| w[0] < w[1]));
        assert!(buckets::PACKET_SIZE.windows(2).all(|w| w[0] < w[1]));
        assert!(buckets::ALLOCATION_LIFETIME.windows(2).all(|w| w[0] < w[1]));
    }

    #[test]
    fn turna_sampler_always_samples_errors() {
        let sampler = TurnaSampler::new(SamplingConfig {
            base_ratio: 0.0,
            always_sample_errors: true,
            always_sample_methods: vec![],
            ..Default::default()
        });
        let attrs = vec![KeyValue::new("error", true)];
        let result = sampler.should_sample(
            None,
            TraceId::from_bytes([1u8; 16]),
            "some_span",
            &opentelemetry::trace::SpanKind::Server,
            &attrs,
            &[],
        );
        assert_eq!(result.decision, SamplingDecision::RecordAndSample);
    }

    #[test]
    fn turna_sampler_always_samples_allocate() {
        let sampler = TurnaSampler::new(SamplingConfig {
            base_ratio: 0.0,
            always_sample_errors: false,
            always_sample_methods: vec!["Allocate".into()],
            ..Default::default()
        });
        let result = sampler.should_sample(
            None,
            TraceId::from_bytes([2u8; 16]),
            "turn.Allocate",
            &opentelemetry::trace::SpanKind::Server,
            &[],
            &[],
        );
        assert_eq!(result.decision, SamplingDecision::RecordAndSample);
    }
}
