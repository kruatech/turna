//! Unified configuration for all Turna services.
//!
//! Single root config with sections:
//!   [turn], [sfu], [signaling], [cluster], [health], [management], [recording]
//!
//! Features:
//! - ENV variable substitution: `shared_secret = "${TURNA_SHARED_SECRET}"`
//! - File secrets: `shared_secret = "file:///run/secrets/turna_secret"`
//! - Validation at startup (port conflicts, required fields)
//! - **Strict schema** (`deny_unknown_fields`): typos and stale layout fail
//!   loudly instead of silently falling back to defaults.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{info, warn};

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("file not found: {0}")]
    FileNotFound(String),
    #[error("parse error: {0}")]
    ParseError(String),
    #[error("validation: {0}")]
    Validation(String),
    #[error("env var not set: {0}")]
    EnvVarNotSet(String),
    #[error("secret file not readable: {0}")]
    SecretFileError(String),
}

pub type Result<T> = std::result::Result<T, ConfigError>;

// ---------------------------------------------------------------------------
// Root Config
// ---------------------------------------------------------------------------

/// Root configuration — loaded from TOML, ENV-substituted, validated.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TurnaConfig {
    /// Production-mode flag.
    ///
    /// When `true`, validation refuses dangerous defaults (placeholder
    /// `shared_secret`, missing TLS in cluster mode, etc). When `false`
    /// (the default), the server emits warnings but still starts —
    /// convenient for development and self-hosted first-run.
    ///
    /// Can also be set via the `TURNA_PRODUCTION=true` environment variable
    /// without touching the config file. Either source enables production
    /// mode; the file value wins ties.
    #[serde(default)]
    pub production: bool,

    #[serde(default)]
    pub turn: TurnConfig,
    #[serde(default)]
    pub sfu: SfuConfig,
    #[serde(default)]
    pub signaling: SignalingConfig,
    #[serde(default)]
    pub cluster: ClusterConfig,
    #[serde(default)]
    pub health: HealthConfig,
    #[serde(default)]
    pub management: ManagementConfig,
    #[serde(default)]
    pub recording: RecordingConfig,
    /// TLS configuration for the gRPC management API (read by
    /// `turna-control-plane`). Optional; absent or `tls_mode = "disabled"`
    /// means plaintext.
    #[serde(default)]
    pub grpc: GrpcConfigSection,

    /// TURNS — TURN over TLS-over-TCP (RFC 5766/8656), typically port 5349.
    /// Disabled by default; enable for clients on UDP-blocked networks.
    #[serde(default)]
    pub tls: TlsConfig,

    /// Multi-tenancy (P1). Empty = single-tenant (use `[turn]` realm/auth).
    /// Each tenant is matched by its `realm` and gets an isolated relay-port
    /// pool plus its own credentials and limits.
    #[serde(default)]
    pub tenants: Vec<TenantConfig>,
}

impl TurnaConfig {
    /// Load from TOML file with ENV substitution.
    pub fn load(path: &str) -> Result<Self> {
        let content =
            std::fs::read_to_string(path).map_err(|_| ConfigError::FileNotFound(path.into()))?;
        let expanded = expand_env_vars(&content)?;
        let config: TurnaConfig =
            toml::from_str(&expanded).map_err(|e| ConfigError::ParseError(e.to_string()))?;
        config.validate()?;
        info!(path, "config loaded and validated");
        Ok(config)
    }

    /// Load from string (for testing).
    pub fn from_str(toml_str: &str) -> Result<Self> {
        let expanded = expand_env_vars(toml_str)?;
        let config: TurnaConfig =
            toml::from_str(&expanded).map_err(|e| ConfigError::ParseError(e.to_string()))?;
        config.validate()?;
        Ok(config)
    }

    /// Validate configuration. Called automatically on load.
    pub fn validate(&self) -> Result<()> {
        let mut errors = Vec::new();
        let mut ports = HashSet::new();
        let prod = self.is_production();

        // Check port conflicts
        let all_ports = [
            ("turn", self.turn.listen),
            ("signaling", self.signaling.listen),
            ("health", self.health.listen),
            ("management", self.management.listen),
        ];
        for (name, addr) in &all_ports {
            if !ports.insert(addr.port()) {
                errors.push(format!(
                    "{name} port {} conflicts with another service",
                    addr.port()
                ));
            }
        }

        // TURN validation
        if self.turn.auth.shared_secret.is_empty() {
            errors.push("turn.auth.shared_secret is empty".into());
        }
        // Refuse to start with the placeholder secret in production.
        // In dev mode we only warn — the server still runs, which is the
        // first-time experience for self-hosted users running `cargo run`
        // before they've copied the example config.
        if self.turn.auth.shared_secret == DEFAULT_SHARED_SECRET {
            if prod {
                errors.push(
                    "turn.auth.shared_secret is the public placeholder default; \
                     generate one with `openssl rand -hex 32` and set \
                     TURNA_SHARED_SECRET or edit turn.toml"
                        .into(),
                );
            } else {
                warn!(
                    "turn.auth.shared_secret is the placeholder default — \
                     set production=true and generate a real secret \
                     before deploying"
                );
            }
        }
        if self.turn.relay.min_port >= self.turn.relay.max_port {
            errors.push(format!(
                "turn.relay.min_port ({}) >= max_port ({})",
                self.turn.relay.min_port, self.turn.relay.max_port
            ));
        }
        if self.turn.external_ip.is_empty() {
            if prod {
                errors.push(
                    "turn.external_ip must be set in production \
                             (NAT traversal cannot work without it)"
                        .into(),
                );
            } else {
                warn!("turn.external_ip is empty — NAT traversal may not work");
            }
        }

        // Signaling validation
        if self.signaling.turn_shared_secret.is_empty() {
            errors.push("signaling.turn_shared_secret is empty".into());
        }
        if self.signaling.turn_shared_secret == DEFAULT_SHARED_SECRET && prod {
            errors.push(
                "signaling.turn_shared_secret is the placeholder default; \
                 set TURNA_SHARED_SECRET or edit turn.toml"
                    .into(),
            );
        }

        // Cluster / persistence validation (PR1).
        if let Err(persistence_errs) = self.cluster.persistence.validate() {
            errors.extend(persistence_errs);
        }
        if let Err(cluster_errs) = self.cluster.validate_redirect_mode(&self.turn) {
            errors.extend(cluster_errs);
        }

        // gRPC TLS validation (PR6).
        // We feed the production flag through so prod can demand TLS unless
        // the management listener is bound to loopback.
        errors.extend(self.grpc.validate(prod, self.management.listen));

        // Multi-tenancy validation (P1): unique ids/realms, sane and disjoint
        // relay-port ranges (disjointness is the whole point — isolation),
        // and authenticatable credentials.
        if !self.tenants.is_empty() {
            let mut seen_ids = HashSet::new();
            let mut seen_realms = HashSet::new();
            let mut ranges: Vec<(String, u16, u16)> = Vec::new();
            for t in &self.tenants {
                if t.id.trim().is_empty() {
                    errors.push("a tenant has an empty id".into());
                } else if !seen_ids.insert(t.id.clone()) {
                    errors.push(format!("duplicate tenant id '{}'", t.id));
                }
                if t.realm.trim().is_empty() {
                    errors.push(format!("tenant '{}' has an empty realm", t.id));
                } else if !seen_realms.insert(t.realm.clone()) {
                    errors.push(format!("duplicate tenant realm '{}'", t.realm));
                }
                let [lo, hi] = t.relay_port_range;
                if lo >= hi {
                    errors.push(format!(
                        "tenant '{}' relay_port_range [{lo}, {hi}] is empty or inverted",
                        t.id
                    ));
                }
                if t.shared_secret.is_empty() && t.static_users.is_empty() {
                    errors.push(format!(
                        "tenant '{}' has neither shared_secret nor static_users — \
                         no client could authenticate",
                        t.id
                    ));
                }
                for (oid, olo, ohi) in &ranges {
                    if lo <= *ohi && *olo <= hi {
                        errors.push(format!(
                            "tenant '{}' port range [{lo}, {hi}] overlaps tenant '{}' \
                             [{olo}, {ohi}] — port isolation requires disjoint ranges",
                            t.id, oid
                        ));
                    }
                }
                ranges.push((t.id.clone(), lo, hi));
            }
        }

        if !errors.is_empty() {
            return Err(ConfigError::Validation(errors.join("; ")));
        }

        Ok(())
    }

    /// Returns true if production mode is active.
    ///
    /// Sources, in order of precedence:
    /// 1. `production = true` in the config file (highest).
    /// 2. `TURNA_PRODUCTION=true|1|yes` environment variable.
    /// 3. Default: `false`.
    ///
    /// We deliberately accept multiple "truthy" spellings on the env side
    /// — the typical deploy script writes `TURNA_PRODUCTION=1` or
    /// `TURNA_PRODUCTION=true` without consulting docs. Anything that
    /// isn't truthy is treated as false.
    pub fn is_production(&self) -> bool {
        if self.production {
            return true;
        }
        match std::env::var("TURNA_PRODUCTION") {
            Ok(v) => {
                let v = v.trim().to_ascii_lowercase();
                matches!(v.as_str(), "1" | "true" | "yes" | "on")
            }
            Err(_) => false,
        }
    }
}

/// Placeholder secret used by `AuthConfig::default()` and the example
/// `turn.toml`. Anything matching this string is rejected in production.
/// Centralised so the validator and the default impl stay in sync.
pub const DEFAULT_SHARED_SECRET: &str = "change-me-in-production";

impl Default for TurnaConfig {
    fn default() -> Self {
        Self {
            production: false,
            turn: TurnConfig::default(),
            sfu: SfuConfig::default(),
            signaling: SignalingConfig::default(),
            cluster: ClusterConfig::default(),
            health: HealthConfig::default(),
            management: ManagementConfig::default(),
            recording: RecordingConfig::default(),
            grpc: GrpcConfigSection::default(),
            tls: TlsConfig::default(),
            tenants: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Section configs
//
// Each section uses `#[serde(default, deny_unknown_fields)]` so that:
//   - missing fields fall back to that section's `Default` impl
//     (so existing partial-TOML tests keep working);
//   - unknown / mistyped fields are rejected at parse time.
// ---------------------------------------------------------------------------

/// Which network transport backend drives the TURN datapath.
///
/// Maps to `turna_transport::TransportPreference` in the node binary. The
/// actual backend is chosen at startup by a runtime io_uring probe (see
/// `turna-transport::select`); this only expresses the operator's preference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TransportSelection {
    /// Use io_uring when available at runtime, otherwise tokio. (default)
    #[default]
    Auto,
    /// Force io_uring (Linux + `--features io-uring`); fails fast if not ready.
    IoUring,
    /// Force the tokio backend (epoll + recvmmsg/sendmmsg).
    Tokio,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TurnConfig {
    pub listen: SocketAddr,
    pub external_ip: String,
    pub realm: String,
    /// Transport backend preference (`auto` | `io_uring` | `tokio`).
    pub transport: TransportSelection,
    pub auth: AuthConfig,
    pub relay: RelayConfig,
    pub observability: ObservabilityConfig,
}

impl Default for TurnConfig {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0:3478".parse().unwrap(),
            external_ip: String::new(),
            realm: "turna".into(),
            transport: TransportSelection::default(),
            auth: AuthConfig::default(),
            relay: RelayConfig::default(),
            observability: ObservabilityConfig::default(),
        }
    }
}

impl TurnConfig {
    pub fn load(path: &str) -> Result<Self> {
        let config = TurnaConfig::load(path)?;
        Ok(config.turn)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuthConfig {
    pub shared_secret: String,
    pub token_ttl: u64,
    pub static_users: Vec<StaticUser>,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            shared_secret: DEFAULT_SHARED_SECRET.into(),
            token_ttl: 86400,
            static_users: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaticUser {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RelayConfig {
    pub min_port: u16,
    pub max_port: u16,
    pub max_allocations: usize,
    /// Per-user bandwidth + allocation count limits. Defaults are
    /// "no bandwidth limit, 100 allocations per username".
    pub quota: QuotaConfig,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            min_port: 49152,
            max_port: 65535,
            max_allocations: 10000,
            quota: QuotaConfig::default(),
        }
    }
}

/// Per-user quota knobs surfaced into `BandwidthQuota` at startup.
///
/// `0` means "unlimited" in both fields — matches the in-code defaults
/// of `turna-session::BandwidthQuota`. Production deployments should
/// set non-zero values to make abuse uneconomic.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct QuotaConfig {
    /// Max bytes/second relayed per allocation. 0 = unlimited.
    pub max_bytes_per_sec: u64,
    /// Max simultaneous allocations per username. 0 = unlimited.
    pub max_per_user: usize,
}

impl Default for QuotaConfig {
    fn default() -> Self {
        Self {
            max_bytes_per_sec: 0, // unlimited — matches session default
            max_per_user: 100,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SfuConfig {
    pub listen: SocketAddr,
    pub max_rooms: usize,
    pub max_participants_per_room: usize,
}

impl Default for SfuConfig {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0:4000".parse().unwrap(),
            max_rooms: 1000,
            max_participants_per_room: 50,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SignalingConfig {
    pub listen: SocketAddr,
    pub turn_url: String,
    pub turn_shared_secret: String,
    pub max_rooms: usize,
}

impl Default for SignalingConfig {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0:9001".parse().unwrap(),
            turn_url: "turn:127.0.0.1:3478".into(),
            turn_shared_secret: DEFAULT_SHARED_SECRET.into(),
            max_rooms: 1000,
        }
    }
}

impl SignalingConfig {
    pub fn load(path: &str) -> Result<Self> {
        let config = TurnaConfig::load(path)?;
        Ok(config.signaling)
    }
}

// ── Observability ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ObservabilityConfig {
    /// OTLP gRPC endpoint.  Set to empty string to disable tracing.
    /// Example: "http://otel-collector:4317"
    pub otlp_endpoint: String,
    /// Base sampling ratio (0.0–1.0).  Errors and Allocate/Refresh are
    /// always sampled regardless of this value (see TurnaSampler).
    pub trace_sample_rate: f64,
    /// Emit logs as JSON instead of human-readable text.
    pub json_logs: bool,
    /// Maximum number of spans per second (rate limiter in TurnaSampler).
    pub max_spans_per_second: u32,
}

impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self {
            otlp_endpoint: String::new(), // disabled by default
            trace_sample_rate: 0.01,      // 1%
            json_logs: false,
            max_spans_per_second: 1000,
        }
    }
}

/// Failure-detection timing for the heartbeat / failover loop.
///
/// Defaults favour fast detection (~5s) while `suspicion_ticks` debounces a
/// single missed heartbeat so it cannot trigger a false failover. Widen the
/// window / interval on jittery WAN links; tighten on a reliable LAN.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FailureDetectionConfig {
    /// How often this node publishes its heartbeat.
    pub heartbeat_interval_secs: u64,
    /// A peer is "stale" if its last heartbeat is older than this.
    pub live_window_secs: u64,
    /// How often the failover task scans for dead peers.
    pub sweep_interval_secs: u64,
    /// Consecutive sweeps a peer must stay stale before it is declared dead and
    /// its allocations are claimed. `1` = claim on the first stale sweep.
    pub suspicion_ticks: u32,
}

impl Default for FailureDetectionConfig {
    fn default() -> Self {
        Self {
            heartbeat_interval_secs: 1,
            live_window_secs: 3,
            sweep_interval_secs: 1,
            suspicion_ticks: 2,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ClusterConfig {
    pub node_id: String,
    /// Enables gossip discovery and TURN 300 redirects for new clients.
    pub cluster_mode: bool,
    /// Legacy UDP gossip port kept for existing configs. Prefer `gossip_bind`.
    pub gossip_port: u16,
    /// Legacy seed list kept for existing configs. Prefer `gossip_seeds`.
    pub seeds: Vec<String>,
    pub gossip_bind: SocketAddr,
    pub gossip_seeds: Vec<String>,
    pub gossip_interval_secs: u64,
    pub gossip_timeout_secs: u64,
    /// Externally reachable TURN address advertised in ALTERNATE-SERVER.
    /// `0.0.0.0:0` means derive it at startup from `turn.external_ip` and
    /// `turn.listen.port()`.
    pub turn_announce_addr: SocketAddr,
    /// Cluster identity. Nodes only merge with peers sharing this name; a stray
    /// staging node can't join a prod ring. Default `"turna"`.
    pub cluster_name: String,
    /// Address peers should use to reach this node's gossip endpoint.
    /// `0.0.0.0:0` means "infer from packet source"; set explicitly behind
    /// NAT / in Kubernetes (the NATS `cluster.advertise` analogue).
    pub gossip_advertise_addr: SocketAddr,
    /// Shared secret for gossip HMAC authentication. Empty = unauthenticated
    /// (logs a warning). Set it so only trusted hosts can change the ring.
    pub cluster_secret: String,
    /// Lame-duck window: on shutdown the node announces it is leaving and keeps
    /// redirecting new clients away for this many seconds before exiting, so a
    /// rolling deploy doesn't drop new sessions. Existing sessions are never
    /// interrupted. `0` = exit immediately.
    pub drain_grace_secs: u64,
    pub backend: BackendConfigSection,
    /// Allocation persistence (PR1 scaffolding — task #3).
    ///
    /// Default `mode = "disabled"` preserves pre-PR1 behaviour exactly:
    /// no writer task is spawned, no `WriteOp` events are emitted.
    /// See `docs/design/allocation-store-persistence.md`.
    pub persistence: PersistenceConfig,
    /// Heartbeat / failover timing (detection speed vs. false-failover margin).
    pub failure_detection: FailureDetectionConfig,
}

impl Default for ClusterConfig {
    fn default() -> Self {
        Self {
            node_id: "node-1".into(),
            cluster_mode: false,
            gossip_port: 7946,
            seeds: Vec::new(),
            gossip_bind: "0.0.0.0:7946".parse().unwrap(),
            gossip_seeds: Vec::new(),
            gossip_interval_secs: 2,
            gossip_timeout_secs: 30,
            turn_announce_addr: "0.0.0.0:0".parse().unwrap(),
            cluster_name: "turna".into(),
            gossip_advertise_addr: "0.0.0.0:0".parse().unwrap(),
            cluster_secret: String::new(),
            drain_grace_secs: 5,
            backend: BackendConfigSection::default(),
            persistence: PersistenceConfig::default(),
            failure_detection: FailureDetectionConfig::default(),
        }
    }
}

impl ClusterConfig {
    pub fn effective_gossip_bind(&self) -> SocketAddr {
        let default_bind: SocketAddr = "0.0.0.0:7946".parse().unwrap();
        if self.gossip_bind == default_bind && self.gossip_port != default_bind.port() {
            SocketAddr::new(self.gossip_bind.ip(), self.gossip_port)
        } else {
            self.gossip_bind
        }
    }

    pub fn effective_gossip_seeds(&self) -> Vec<String> {
        if self.gossip_seeds.is_empty() {
            self.seeds.clone()
        } else {
            self.gossip_seeds.clone()
        }
    }

    fn validate_redirect_mode(&self, turn: &TurnConfig) -> std::result::Result<(), Vec<String>> {
        let mut errors = Vec::new();
        if self.cluster_mode {
            if self.node_id.trim().is_empty() {
                errors.push("cluster.node_id must be non-empty when cluster_mode = true".into());
            }
            if self.cluster_name.trim().is_empty() {
                errors.push("cluster.cluster_name must be non-empty when cluster_mode = true".into());
            }
            if self.gossip_interval_secs == 0 {
                errors.push("cluster.gossip_interval_secs must be > 0".into());
            }
            if self.gossip_timeout_secs == 0 {
                errors.push("cluster.gossip_timeout_secs must be > 0".into());
            }
            if self.turn_announce_addr.ip().is_unspecified() && turn.external_ip.is_empty() {
                errors.push(
                    "cluster.turn_announce_addr is unspecified and turn.external_ip is empty"
                        .into(),
                );
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BackendConfigSection {
    pub r#type: String,
    pub uri: String,
    /// Tarantool authentication. Empty string = anonymous guest user
    /// (acceptable only for local dev against a permissive Tarantool).
    /// Production: set via `${TURNA_BACKEND_USER}` and route the password
    /// through `${TURNA_BACKEND_PASSWORD}` or `file:///run/secrets/...`.
    pub user: String,
    pub password: String,
    /// Number of parallel TCP connections to maintain per node.
    /// `0` means "use the library default" (currently 8).
    pub pool_size: usize,
}

impl Default for BackendConfigSection {
    fn default() -> Self {
        Self {
            r#type: "memory".into(),
            uri: String::new(),
            user: String::new(),
            password: String::new(),
            pool_size: 0, // 0 → backend picks its DEFAULT_POOL_SIZE
        }
    }
}

/// Allocation-store persistence settings.
///
/// In PR1 only `mode = "disabled"` (default) and `mode = "scaffold"`
/// are accepted. The latter spawns a no-op writer task that drains
/// and counts events — useful to verify the channel works end-to-end
/// before PR2 plugs in a real `Backend`.
///
/// Future modes (PR2+): `"write_behind"`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PersistenceConfig {
    /// `"disabled"` | `"scaffold"` (PR1) | `"write_behind"` (PR2+).
    pub mode: String,
    /// Max events queued before the writer is considered overloaded.
    /// On overflow, events are dropped and a counter is incremented.
    pub channel_capacity: usize,
    /// Writer flushes a batch when this many events are queued.
    pub batch_max_size: usize,
    /// …or when this many milliseconds have elapsed since the first
    /// event in the current batch, whichever comes first.
    pub batch_max_delay_ms: u64,
}

impl Default for PersistenceConfig {
    fn default() -> Self {
        Self {
            mode: "disabled".into(),
            channel_capacity: 65_536,
            batch_max_size: 256,
            batch_max_delay_ms: 100,
        }
    }
}

impl PersistenceConfig {
    pub fn is_enabled(&self) -> bool {
        !matches!(self.mode.as_str(), "disabled" | "")
    }

    /// Returns Err with a list of validation issues, if any.
    pub(crate) fn validate(&self) -> std::result::Result<(), Vec<String>> {
        let mut errors = Vec::new();
        match self.mode.as_str() {
            "disabled" | "scaffold" | "write_behind" | "" => {}
            other => errors.push(format!(
                "cluster.persistence.mode = {other:?} — must be one of \
                 \"disabled\", \"scaffold\", \"write_behind\""
            )),
        }
        if self.channel_capacity == 0 {
            errors.push("cluster.persistence.channel_capacity must be > 0".into());
        }
        if self.batch_max_size == 0 {
            errors.push("cluster.persistence.batch_max_size must be > 0".into());
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HealthConfig {
    pub listen: SocketAddr,
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0:8080".parse().unwrap(),
        }
    }
}

/// TURNS — TURN over TLS-over-TCP (RFC 5766/8656).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TlsConfig {
    /// Enable the TURNS listener.
    pub enabled: bool,
    /// Listen address (default `0.0.0.0:5349`, the IANA TURNS port).
    pub listen: SocketAddr,
    /// PEM certificate chain.
    pub cert_path: PathBuf,
    /// PEM private key (PKCS#8 / PKCS#1 / SEC1).
    pub key_path: PathBuf,
    /// Max framed STUN/ChannelData message size, bytes.
    pub max_frame_size: usize,
    /// TLS handshake timeout, seconds.
    pub handshake_timeout_secs: u64,
    /// Per-connection idle read timeout, seconds.
    pub read_timeout_secs: u64,
    /// Max concurrent TURNS connections.
    pub max_connections: usize,
    /// Advertise ALPN (`stun.turn`).
    pub enable_alpn: bool,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: "0.0.0.0:5349".parse().unwrap(),
            cert_path: PathBuf::from("/etc/turna/tls/cert.pem"),
            key_path: PathBuf::from("/etc/turna/tls/key.pem"),
            max_frame_size: 64 * 1024,
            handshake_timeout_secs: 5,
            read_timeout_secs: 300,
            max_connections: 10_000,
            enable_alpn: true,
        }
    }
}

/// One tenant in a multi-tenant deployment. Matched by `realm`; isolated relay
/// port pool, own credentials, own limits. No `Default` — every field that
/// isn't `#[serde(default)]` must be set explicitly per tenant.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantConfig {
    /// Stable identifier (metrics label, logs). Must be unique.
    pub id: String,
    /// TURN realm clients authenticate against. Must be unique across tenants.
    pub realm: String,
    /// Isolated relay UDP port range `[min, max]` for this tenant — clients of
    /// one tenant cannot exhaust another tenant's ports.
    pub relay_port_range: [u16; 2],
    /// coturn-style time-limited credentials secret. Empty → use `static_users`.
    #[serde(default)]
    pub shared_secret: String,
    /// Static long-term users for this tenant.
    #[serde(default)]
    pub static_users: Vec<StaticUser>,
    /// Max simultaneous allocations for this tenant. 0 = unlimited.
    #[serde(default)]
    pub max_allocations: usize,
    /// Per-tenant bandwidth / per-user limits.
    #[serde(default)]
    pub quota: QuotaConfig,
    /// Optional dedicated listener. `None` (default) = share the main `[turn]`
    /// listener and match the tenant by request REALM. `Some(addr)` reserves a
    /// per-tenant listener (stronger isolation; future option-A wiring).
    #[serde(default)]
    pub listen: Option<SocketAddr>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ManagementConfig {
    pub listen: SocketAddr,
    pub enabled: bool,
}

impl Default for ManagementConfig {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:9090".parse().unwrap(),
            enabled: false,
        }
    }
}

/// TLS configuration for the gRPC management API.
///
/// Read by `turna-control-plane` to decide whether to:
/// - serve plaintext (`tls_mode = "disabled"`, default — safe only on
///   `127.0.0.1`),
/// - serve TLS where the server presents a certificate to clients
///   (`tls_mode = "tls"`),
/// - require mutual TLS where both server and client present certificates
///   signed by the configured CA (`tls_mode = "mtls"`, recommended for
///   any remote access).
///
/// All three fields hold **filesystem paths** to PEM files. PEM contents
/// must never be passed via environment variables — only paths. The
/// usual `${VAR}` and `file:///` substitution rules apply to the paths
/// themselves.
///
/// In production (`production = true` or `TURNA_PRODUCTION=true`), the
/// validator rejects `tls_mode = "disabled"` unless `management.listen`
/// is bound to `127.0.0.1` / `::1`, and rejects missing paths when a
/// non-disabled mode is selected.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GrpcConfigSection {
    /// One of: `"disabled"` (default), `"tls"`, `"mtls"`.
    pub tls_mode: String,
    /// Path to PEM with the server certificate. Required when
    /// `tls_mode != "disabled"`.
    pub tls_cert: String,
    /// Path to PEM with the server private key. Required when
    /// `tls_mode != "disabled"`.
    pub tls_key: String,
    /// Path to PEM with the CA used to verify client certificates.
    /// Required when `tls_mode = "mtls"`. Ignored otherwise.
    pub tls_ca: String,
}

impl Default for GrpcConfigSection {
    fn default() -> Self {
        Self {
            tls_mode: "disabled".into(),
            tls_cert: String::new(),
            tls_key: String::new(),
            tls_ca: String::new(),
        }
    }
}

impl GrpcConfigSection {
    /// Returns the canonical mode string, lowercased and trimmed.
    /// Anything other than `"tls"` / `"mtls"` is reported as
    /// `"disabled"`. The validator separately rejects unrecognised
    /// values to make typos loud — this method exists so call sites
    /// don't have to do the same normalisation in three places.
    pub fn normalised_mode(&self) -> &str {
        match self.tls_mode.trim().to_ascii_lowercase().as_str() {
            "tls" => "tls",
            "mtls" => "mtls",
            _ => "disabled",
        }
    }

    /// True when TLS (or mTLS) is requested.
    pub fn is_enabled(&self) -> bool {
        matches!(self.normalised_mode(), "tls" | "mtls")
    }

    /// True when mTLS (client-cert verification) is requested.
    pub fn requires_client_ca(&self) -> bool {
        self.normalised_mode() == "mtls"
    }

    /// Internal validator — gathers errors and is called from
    /// `TurnaConfig::validate`. Splits into a separate method so the
    /// production gate can be applied at the call site.
    fn validate(&self, prod: bool, management_listen: SocketAddr) -> Vec<String> {
        let mut errs = Vec::new();
        match self.tls_mode.trim().to_ascii_lowercase().as_str() {
            "" | "disabled" => {
                if prod && !management_listen.ip().is_loopback() {
                    errs.push(format!(
                        "grpc.tls_mode is \"disabled\" but management.listen \
                         ({management_listen}) is not loopback — refusing in production. \
                         Set tls_mode = \"tls\" or \"mtls\", or bind management.listen \
                         to 127.0.0.1 / ::1."
                    ));
                }
            }
            "tls" => {
                if self.tls_cert.is_empty() {
                    errs.push("grpc.tls_mode = \"tls\" but grpc.tls_cert is empty".into());
                }
                if self.tls_key.is_empty() {
                    errs.push("grpc.tls_mode = \"tls\" but grpc.tls_key is empty".into());
                }
            }
            "mtls" => {
                if self.tls_cert.is_empty() {
                    errs.push("grpc.tls_mode = \"mtls\" but grpc.tls_cert is empty".into());
                }
                if self.tls_key.is_empty() {
                    errs.push("grpc.tls_mode = \"mtls\" but grpc.tls_key is empty".into());
                }
                if self.tls_ca.is_empty() {
                    errs.push(
                        "grpc.tls_mode = \"mtls\" but grpc.tls_ca is empty \
                         (CA file is required to verify client certificates)"
                            .into(),
                    );
                }
            }
            other => {
                errs.push(format!(
                    "grpc.tls_mode = {other:?} is invalid; use \"disabled\", \"tls\", or \"mtls\""
                ));
            }
        }
        errs
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RecordingConfig {
    pub output_dir: String,
    pub enabled: bool,
    pub max_duration_secs: u64,
}

impl Default for RecordingConfig {
    fn default() -> Self {
        Self {
            output_dir: "/var/lib/turna/recordings".into(),
            enabled: false,
            max_duration_secs: 7200,
        }
    }
}

// ---------------------------------------------------------------------------
// ENV variable expansion
// ---------------------------------------------------------------------------

/// Expand `${VAR_NAME}` and `file:///path` in config string.
///
/// - `${VAR}` → reads from environment variable
/// - `file:///path` → reads file content (trimmed)
/// - `${VAR:-default}` → uses default if VAR not set
fn expand_env_vars(input: &str) -> Result<String> {
    // Drop full-line TOML comments first: substitution must not run over
    // `${VAR}` or `file:///path` tokens inside `# ...` lines. End-of-line
    // comments aren't stripped — keep configs simple.
    let stripped: String = input
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    let mut result = stripped;

    // Expand ${VAR} and ${VAR:-default}
    while let Some(start) = result.find("${") {
        let end = result[start..]
            .find('}')
            .ok_or_else(|| ConfigError::ParseError("unclosed ${".into()))?
            + start;
        let expr = &result[start + 2..end];

        let value = if let Some(sep) = expr.find(":-") {
            let var_name = &expr[..sep];
            let default = &expr[sep + 2..];
            std::env::var(var_name).unwrap_or_else(|_| default.to_string())
        } else {
            std::env::var(expr).map_err(|_| ConfigError::EnvVarNotSet(expr.into()))?
        };

        result = format!("{}{}{}", &result[..start], value, &result[end + 1..]);
    }

    // Expand file:///path references
    let mut expanded = String::new();
    for line in result.lines() {
        if let Some(pos) = line.find("file:///") {
            // Extract the file path from the value
            let before = &line[..pos];
            let path_start = pos + 7; // "file://" length
            let path_end = line[path_start..]
                .find('"')
                .map(|i| path_start + i)
                .unwrap_or(line.len());
            let file_path = line[path_start..path_end].trim();

            let content = std::fs::read_to_string(file_path)
                .map_err(|_| ConfigError::SecretFileError(file_path.into()))?;
            expanded.push_str(before);
            expanded.push_str(content.trim());
            if path_end < line.len() {
                expanded.push_str(&line[path_end..]);
            }
        } else {
            expanded.push_str(line);
        }
        expanded.push('\n');
    }

    Ok(expanded)
}

// ---------------------------------------------------------------------------
// Example config
// ---------------------------------------------------------------------------

/// Generate example config TOML.
pub fn example_config() -> String {
    r#"# Turna Configuration

[turn]
listen = "0.0.0.0:3478"
external_ip = "203.0.113.1"
realm = "turna"

[turn.auth]
# Substitution: ${VAR:-default} = env var with fallback; file:/// = secret from disk
shared_secret = "${TURNA_SHARED_SECRET:-dev-secret-change-me}"
token_ttl = 86400

[turn.relay]
min_port = 49152
max_port = 65535
max_allocations = 10000

[sfu]
listen = "0.0.0.0:4000"
max_rooms = 1000
max_participants_per_room = 50

[signaling]
listen = "0.0.0.0:9001"
turn_url = "turn:203.0.113.1:3478"
turn_shared_secret = "${TURNA_SHARED_SECRET:-dev-secret-change-me}"

[cluster]
node_id = "node-1"
gossip_port = 7946
seeds = []

[cluster.backend]
type = "memory"  # or "tarantool"
# uri = "127.0.0.1:3301"

[health]
listen = "0.0.0.0:8080"

[management]
listen = "127.0.0.1:9090"
enabled = true

[recording]
output_dir = "/var/lib/turna/recordings"
enabled = false
max_duration_secs = 7200
"#
    .into()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::sync::{Mutex, OnceLock};

    fn production_env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
    }

    fn restore_turna_production(value: Option<OsString>) {
        if let Some(value) = value {
            std::env::set_var("TURNA_PRODUCTION", value);
        } else {
            std::env::remove_var("TURNA_PRODUCTION");
        }
    }

    #[test]
    fn default_config_valid() {
        let _guard = production_env_lock();
        let saved_turna_production = std::env::var_os("TURNA_PRODUCTION");
        std::env::remove_var("TURNA_PRODUCTION");

        let config = TurnaConfig::default();
        let result = config.validate();

        restore_turna_production(saved_turna_production);
        result.unwrap();
    }

    #[test]
    fn parse_minimal_toml() {
        let toml = r#"
[turn]
listen = "0.0.0.0:3478"
external_ip = "127.0.0.1"

[turn.auth]
shared_secret = "test-secret"

[signaling]
listen = "0.0.0.0:9001"
turn_shared_secret = "test-secret"
"#;
        let config = TurnaConfig::from_str(toml).unwrap();
        assert_eq!(config.turn.listen.port(), 3478);
        assert_eq!(config.turn.auth.shared_secret, "test-secret");
    }

    #[test]
    fn port_conflict_detected() {
        let toml = r#"
[turn]
listen = "0.0.0.0:3478"
[turn.auth]
shared_secret = "s"
[signaling]
listen = "0.0.0.0:3478"
turn_shared_secret = "s"
"#;
        let err = TurnaConfig::from_str(toml).unwrap_err();
        assert!(err.to_string().contains("conflicts"));
    }

    #[test]
    fn empty_secret_rejected() {
        let toml = r#"
[turn.auth]
shared_secret = ""
[signaling]
turn_shared_secret = "s"
"#;
        let err = TurnaConfig::from_str(toml).unwrap_err();
        assert!(err.to_string().contains("shared_secret"));
    }

    #[test]
    fn env_var_expansion() {
        std::env::set_var("TURNA_TEST_SECRET", "expanded-value");
        let input = r#"shared_secret = "${TURNA_TEST_SECRET}""#;
        let expanded = expand_env_vars(input).unwrap();
        assert!(expanded.contains("expanded-value"));
        std::env::remove_var("TURNA_TEST_SECRET");
    }

    #[test]
    fn env_var_default() {
        let input = r#"shared_secret = "${TURNA_NONEXISTENT:-fallback}""#;
        let expanded = expand_env_vars(input).unwrap();
        assert!(expanded.contains("fallback"));
    }

    #[test]
    fn relay_port_range_validated() {
        let toml = r#"
[turn.auth]
shared_secret = "s"
[turn.relay]
min_port = 60000
max_port = 50000
[signaling]
turn_shared_secret = "s"
"#;
        let err = TurnaConfig::from_str(toml).unwrap_err();
        assert!(err.to_string().contains("min_port"));
    }

    #[test]
    fn example_config_parseable() {
        // Set env var that example config references
        std::env::set_var("TURNA_SHARED_SECRET", "test");
        let config = TurnaConfig::from_str(&example_config()).unwrap();
        assert_eq!(config.turn.listen.port(), 3478);
        std::env::remove_var("TURNA_SHARED_SECRET");
    }

    #[test]
    fn expand_env_vars_skips_comment_lines() {
        // Regression: bare ${VAR} / file:/// inside TOML comments must
        // not trigger env reads or file I/O. This caused two cycles of
        // false-positive errors when sanitising example_config() docs.
        let input = "# ${UNSET_VAR} and file:///nope/path\nkey = \"v\"";
        let expanded =
            expand_env_vars(input).expect("env/file refs inside comments must not error");
        assert!(
            expanded.contains("key = \"v\""),
            "non-comment content lost: {expanded:?}"
        );
    }

    // ── deny_unknown_fields regression tests ─────────────────────────────

    #[test]
    fn unknown_top_level_section_rejected() {
        let toml = r#"
[turn.auth]
shared_secret = "s"
[signaling]
turn_shared_secret = "s"
[unknown_section]
foo = "bar"
"#;
        let err =
            TurnaConfig::from_str(toml).expect_err("unknown top-level section must be rejected");
        let msg = err.to_string().to_lowercase();
        assert!(
            msg.contains("unknown") || msg.contains("unknown_section") || msg.contains("parse"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn unknown_nested_field_rejected() {
        let toml = r#"
[turn.auth]
shared_secret = "s"
typo_field = "x"
[signaling]
turn_shared_secret = "s"
"#;
        let err =
            TurnaConfig::from_str(toml).expect_err("unknown field in [turn.auth] must be rejected");
        let msg = err.to_string().to_lowercase();
        assert!(
            msg.contains("unknown") || msg.contains("typo_field") || msg.contains("parse"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn old_flat_auth_layout_rejected() {
        // This is exactly the bug we just hunted down: a flat [auth] section
        // at the root instead of [turn.auth]. Before deny_unknown_fields it
        // was silently dropped; now it must fail loudly.
        let toml = r#"
listen = "0.0.0.0:3478"
realm = "turna"

[auth]
shared_secret = "turna-secret"

[signaling]
turn_shared_secret = "s"
"#;
        let err = TurnaConfig::from_str(toml).expect_err("flat [auth] section must be rejected");
        let msg = err.to_string().to_lowercase();
        assert!(
            msg.contains("unknown")
                || msg.contains("auth")
                || msg.contains("listen")
                || msg.contains("parse"),
            "unexpected error: {err}"
        );
    }

    // ── production-mode validation ───────────────────────────────────────
    //
    // These tests manipulate `TURNA_PRODUCTION` which is global to the process.
    // Cargo runs tests in parallel by default; if two tests touch the same
    // env var concurrently they race. We sidestep that by funnelling every
    // TURNA_PRODUCTION assertion through ONE test function that drives the
    // env var sequentially. The downside is less granular failure messages;
    // the upside is no flaky CI and no extra dev-dependency on `serial_test`.

    fn dev_config_with_default_secret() -> &'static str {
        r#"
production = false

[turn]
external_ip = "1.2.3.4"

[turn.auth]
shared_secret = "change-me-in-production"

[signaling]
turn_shared_secret = "ok-for-signaling"
"#
    }

    fn prod_config_with_default_secret() -> &'static str {
        r#"
production = true

[turn]
external_ip = "1.2.3.4"

[turn.auth]
shared_secret = "change-me-in-production"

[signaling]
turn_shared_secret = "ok-for-signaling"
"#
    }

    fn prod_config_no_external_ip() -> &'static str {
        r#"
production = true

[turn]
external_ip = ""

[turn.auth]
shared_secret = "a-real-secret-12345"

[signaling]
turn_shared_secret = "another-one"
"#
    }

    fn prod_config_clean() -> &'static str {
        r#"
production = true

[turn]
external_ip = "1.2.3.4"

[turn.auth]
shared_secret = "deadbeef-this-is-a-real-secret-honest"

[signaling]
turn_shared_secret = "another-not-placeholder"
"#
    }

    #[test]
    fn production_mode_validation_scenarios() {
        let _guard = production_env_lock();
        let saved_turna_production = std::env::var_os("TURNA_PRODUCTION");

        // Scenario 1: dev mode tolerates default secret (just warns).
        std::env::remove_var("TURNA_PRODUCTION");
        let cfg = TurnaConfig::from_str(dev_config_with_default_secret())
            .expect("dev mode tolerates default secret");
        assert!(!cfg.is_production(), "scenario 1: production must be false");

        // Scenario 2: prod mode rejects placeholder secret loudly.
        let err = TurnaConfig::from_str(prod_config_with_default_secret())
            .expect_err("scenario 2: production rejects placeholder secret");
        let msg = err.to_string().to_lowercase();
        assert!(
            msg.contains("placeholder") || msg.contains("shared_secret"),
            "scenario 2: expected placeholder error, got: {err}"
        );

        // Scenario 3: env var can promote a dev-style file to production.
        std::env::set_var("TURNA_PRODUCTION", "true");
        let err = TurnaConfig::from_str(dev_config_with_default_secret())
            .expect_err("scenario 3: env override must enable strict validation");
        let msg = err.to_string().to_lowercase();
        assert!(
            msg.contains("placeholder") || msg.contains("shared_secret"),
            "scenario 3: expected placeholder error, got: {err}"
        );

        // Scenario 4: falsy values for TURNA_PRODUCTION leave us in dev mode.
        for val in ["", "0", "false", "no", "off", "anything-else"] {
            std::env::set_var("TURNA_PRODUCTION", val);
            let cfg = TurnaConfig::from_str(dev_config_with_default_secret())
                .unwrap_or_else(|e| panic!("scenario 4 val={val:?}: {e}"));
            assert!(
                !cfg.is_production(),
                "scenario 4: TURNA_PRODUCTION={val:?} must NOT enable prod"
            );
        }

        // Scenario 5: external_ip required in production.
        std::env::remove_var("TURNA_PRODUCTION");
        let err = TurnaConfig::from_str(prod_config_no_external_ip())
            .expect_err("scenario 5: production requires external_ip");
        let msg = err.to_string().to_lowercase();
        assert!(
            msg.contains("external_ip"),
            "scenario 5: expected external_ip error, got: {err}"
        );

        // Scenario 6: real secrets in prod mode → all good.
        let cfg = TurnaConfig::from_str(prod_config_clean())
            .expect("scenario 6: clean prod config must validate");
        assert!(cfg.is_production());

        // Restore the caller's environment instead of leaking test state.
        restore_turna_production(saved_turna_production);
    }
}
