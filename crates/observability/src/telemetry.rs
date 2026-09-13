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
    /// Syslog collector for security events. `udp://host:514` or `tcp://host:601`.
    /// Empty disables export.
    ///
    /// Duplicated from the node's config rather than shared: this crate does not
    /// depend on `turna-config`, and adding that dependency to make one string
    /// travel would invert the direction the crates point in.
    pub syslog_endpoint: String,
    /// Hash client addresses before sending them to the collector.
    pub syslog_redact_addresses: bool,
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
            syslog_endpoint: String::new(),
            syslog_redact_addresses: false,
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
/// Installs no extra layer; see [`init_with_layer`] for the layer order and for
/// the one hook a caller gets into the chain.
pub fn init(config: TelemetryConfig) -> Result<TelemetryGuard> {
    init_with_layer(config, tracing_subscriber::layer::Identity::new())
}

/// Same as [`init`], plus one caller-supplied layer applied to the bare
/// `Registry` underneath everything else.
///
/// This exists because a layer can only be installed while the subscriber is
/// being built, and a caller may not yet have what the layer writes to. The node
/// installs its audit layer here and hands it the audit log later: the layer is
/// in the chain from the first event, and drops events until it is armed.
///
/// `extra` sits below `EnvFilter`, so it observes events regardless of
/// `RUST_LOG`. That is deliberate for an audit journal — a log-level setting
/// should not be able to empty it — and means the layer must do its own
/// filtering, which `AuditLayer` does by target and level.
pub fn init_with_layer<L>(config: TelemetryConfig, extra: L) -> Result<TelemetryGuard>
where
    L: tracing_subscriber::Layer<tracing_subscriber::Registry> + Send + Sync + 'static,
{
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&config.log_filter));

    let otlp_enabled = !config.otlp_endpoint.is_empty();
    let mut guard_provider: Option<opentelemetry_sdk::trace::SdkTracerProvider> = None;

    // Layer order: Registry -> extra -> [OTel] -> EnvFilter -> syslog -> fmt.
    //
    // `OpenTelemetryLayer<S, T>` is a `Layer<S>` where S is the subscriber type
    // AT THE POINT OF APPLICATION, so it cannot go after EnvFilter (S would be
    // `Layered<EnvFilter, _>`). It used to have to be first for the same reason;
    // `build_otel_layer` is now generic over S, so `extra` can sit under it and
    // OTel still gets a type it accepts.
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

    // The security-event layer, added to whichever branch runs below.
    //
    // Constructed from the same config the node uses for the exporter, so there is
    // one endpoint rather than two that can disagree. Disabled when the endpoint
    // is empty, and a disabled layer returns from `on_event` immediately.
    let syslog_layer = {
        let exporter = std::sync::Arc::new(crate::syslog::SyslogExporter::new(
            crate::syslog::SyslogConfig {
                endpoint: config.syslog_endpoint.clone(),
                app_name: config.service_name.clone(),
                redact_addresses: config.syslog_redact_addresses,
                non_blocking: true,
            },
        ));
        crate::syslog_layer::SyslogLayer::new(exporter)
    };

    if otlp_enabled {
        let (otel_layer, provider) = build_otel_layer::<
            tracing_subscriber::layer::Layered<L, tracing_subscriber::Registry>,
        >(&config)?;
        guard_provider = Some(provider);
        // Registry → extra → OTel → EnvFilter → fmt
        let base = tracing_subscriber::registry()
            .with(extra)
            .with(otel_layer)
            .with(filter)
            .with(syslog_layer.clone());
        try_init_with_fmt!(base)?;
    } else {
        // No log here: the subscriber is installed on the next line, and anything
        // emitted before it exists is discarded. This message used to live here
        // and had therefore never appeared in a log — found when an air-gap check
        // looked for it and a correctly-behaving node failed the check. It now
        // goes out below, with the other startup line.
        //
        // Registry → extra → EnvFilter → fmt
        let base = tracing_subscriber::registry()
            .with(extra)
            .with(filter)
            .with(syslog_layer.clone());
        try_init_with_fmt!(base)?;
    }

    if !otlp_enabled {
        // Stated explicitly rather than left to be inferred from the empty
        // `otlp=` field below. An operator verifying that a deployment sends
        // nothing outward should find a sentence saying so, not an absence.
        info!("distributed tracing disabled (no OTLP endpoint configured)");
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
/// Generic over the subscriber it will be applied to. It used to return a layer
/// pinned to the bare `Registry`, which forced OTel to be the FIRST layer in the
/// chain and left no room for a caller-supplied one underneath it. `S` is
/// inferred from the application site instead, so `init_with_layer` can put the
/// caller's layer on the registry first and still satisfy
/// `OpenTelemetryLayer<S, T>`.
fn build_otel_layer<S>(
    config: &TelemetryConfig,
) -> Result<(
    impl tracing_subscriber::Layer<S> + Send + Sync + 'static,
    opentelemetry_sdk::trace::SdkTracerProvider,
)>
where
    // `Send + Sync + 'static` are not decoration: `OpenTelemetryLayer<S, T>`
    // stores a `PhantomData<S>`, so the auto traits on the returned layer are
    // only satisfied when S carries them too. `Layered<L, Registry>` does,
    // because `Registry` does and `init_with_layer` already requires it of `L`.
    S: tracing::Subscriber
        + for<'span> tracing_subscriber::registry::LookupSpan<'span>
        + Send
        + Sync
        + 'static,
{
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
