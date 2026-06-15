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
use std::net::{IpAddr, SocketAddr};
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
#[derive(Default)]
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
    #[allow(clippy::should_implement_trait)]
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
        } else if self.turn.external_ip.parse::<IpAddr>().is_err() {
            errors.push(format!(
                "turn.external_ip must be a valid IPv4 or IPv6 address, got {:?}",
                self.turn.external_ip
            ));
        }

        // Connection Migration (RFC 8016). A random per-process ticket secret
        // is fine for dev but breaks across restarts and across cluster nodes,
        // so production must pin a stable secret when mobility is enabled.
        if self.turn.migration.enabled {
            if self.turn.migration.ticket_secret.is_empty() {
                // A random per-process ticket secret is only acceptable for a
                // single, non-production node: every restart invalidates
                // outstanding mobility tickets. With clustering enabled it is
                // worse than that — each node derives an *independent* random
                // key, so a ticket minted by node A is not valid on node B and
                // cross-node migration (the advertised feature) silently fails
                // with only a warning. So an empty secret is a hard error
                // whenever clustering is on, regardless of the production flag,
                // and also in production for the single-node restart reason.
                if prod || self.cluster.cluster_mode {
                    let reason = if self.cluster.cluster_mode {
                        "in a cluster (each node would derive an independent \
                         random key, so mobility tickets are not valid across \
                         nodes and cross-node migration silently fails)"
                    } else {
                        "in production (a random per-process key would \
                         invalidate every mobility ticket on restart)"
                    };
                    errors.push(format!(
                        "turn.migration.ticket_secret is empty while migration is \
                         enabled {reason}; generate one with `openssl rand -hex 32` \
                         and set the SAME value on every node"
                    ));
                } else {
                    warn!(
                        "turn.migration.ticket_secret is empty — using a random \
                         per-process key; mobility tickets will not survive a \
                         restart. Set a stable secret (identical on every node) \
                         before deploying or enabling cluster_mode."
                    );
                }
            }
            if self.turn.migration.ticket_ttl_secs == 0 {
                errors.push("turn.migration.ticket_ttl_secs must be > 0".into());
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

        // Peer-filter policy validation (M1): known profile + parseable CIDRs.
        errors.extend(self.turn.peer_filter.validate());

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
///
/// The default is `tokio` -- the safest, most predictable backend on every
/// platform. `io_uring` and `af_xdp` are explicit opt-ins; `auto` is a
/// convenience/dev/benchmark mode that may pick io_uring when the runtime
/// probe reports it usable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TransportSelection {
    /// Use io_uring when available at runtime, otherwise tokio. Convenience /
    /// dev / benchmark mode -- opt in explicitly; it is not the default.
    Auto,
    /// Force io_uring (Linux + `--features io-uring`); fails fast if not ready.
    IoUring,
    /// Force the tokio backend (epoll + recvmmsg/sendmmsg). Safest default.
    #[default]
    Tokio,
    /// Force the AF_XDP ring datapath (Linux + `--features af-xdp`; needs
    /// CAP_NET_RAW and a bound NIC queue). Opt-in only — never auto-selected.
    AfXdp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TurnConfig {
    pub listen: SocketAddr,
    pub external_ip: String,
    pub realm: String,
    /// Transport backend preference. Default `tokio` (safest); `io_uring`,
    /// `af_xdp` and `auto` are explicit opt-ins.
    pub transport: TransportSelection,
    pub auth: AuthConfig,
    pub relay: RelayConfig,
    pub observability: ObservabilityConfig,
    /// RFC 8016 Connection Migration (mobility).
    pub migration: MigrationConfig,
    /// QUIC / WebTransport listener (browsers on UDP-blocked or high-loss
    /// networks). Disabled by default. Requires the node binary built with the
    /// `quic` (raw QUIC) and/or `web-transport` (browser H3) features.
    #[serde(default)]
    pub quic: QuicConfigSection,
    /// io_uring datapath tuning (used only when `transport = "io_uring"`).
    #[serde(default)]
    pub io_uring: IoUringSection,
    /// AF_XDP ring-datapath parameters (used only when `transport = "af_xdp"`).
    /// Requires a Linux build with `--features af-xdp`, CAP_NET_RAW, and a NIC
    /// queue dedicated via an XDP program.
    #[serde(default)]
    pub af_xdp: AfXdpSection,
    /// TURN over DTLS (RFC 7350): encrypted UDP transport. Disabled by default.
    /// Requires the node binary built with `--features dtls`.
    #[serde(default)]
    pub dtls: DtlsSection,
    /// Peer-address filtering policy (M1). Defaults to `internet-facing`
    /// (denies RFC 1918 / ULA peers). Set `profile = "lan"` to allow private
    /// relaying. See `docs/security/peer-filter.md`.
    #[serde(default)]
    pub peer_filter: PeerFilterConfig,
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
            migration: MigrationConfig::default(),
            quic: QuicConfigSection::default(),
            io_uring: IoUringSection::default(),
            af_xdp: AfXdpSection::default(),
            dtls: DtlsSection::default(),
            peer_filter: PeerFilterConfig::default(),
        }
    }
}

impl TurnConfig {
    pub fn load(path: &str) -> Result<Self> {
        let config = TurnaConfig::load(path)?;
        Ok(config.turn)
    }
}

/// Peer-address filter policy (M1). Lives under `[turn.peer_filter]`.
///
/// Closes the SSRF-into-private-network vector: the `internet-facing` profile
/// (default) denies RFC 1918 / ULA relay peers. Operators that legitimately
/// relay to a LAN opt in with `profile = "lan"`. `allowed_peer_ranges` /
/// `denied_peer_ranges` refine the decision (allow wins over deny); neither
/// can re-enable the always-denied special-use ranges (loopback, link-local
/// incl. cloud metadata, multicast, broadcast, 0.0.0.0/8).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PeerFilterConfig {
    /// `"internet-facing"` (default; denies RFC 1918 / ULA) or `"lan"`
    /// (allows private relaying). `"trusted"` is an alias for `"lan"`.
    pub profile: String,
    /// Permit relaying to loopback peers (dev/test only). Also honoured via
    /// `TURNA_ALLOW_LOOPBACK_PEERS=1` for backward compatibility.
    pub allow_loopback_peers: bool,
    /// Extra CIDR ranges to deny on top of the profile (e.g. `"100.64.0.0/10"`).
    pub denied_peer_ranges: Vec<String>,
    /// CIDR ranges to allow even if the profile/deny list would block them
    /// (e.g. allow one internal subnet on an internet-facing node).
    pub allowed_peer_ranges: Vec<String>,
}

impl Default for PeerFilterConfig {
    fn default() -> Self {
        Self {
            // Secure by default: deny private peers unless the operator opts in.
            profile: "internet-facing".into(),
            allow_loopback_peers: false,
            denied_peer_ranges: Vec::new(),
            allowed_peer_ranges: Vec::new(),
        }
    }
}

impl PeerFilterConfig {
    /// Returns a list of validation issues (empty == valid).
    pub(crate) fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();
        match self.profile.trim().to_ascii_lowercase().as_str() {
            "internet-facing" | "lan" | "trusted" => {}
            other => errors.push(format!(
                "turn.peer_filter.profile = {other:?} is invalid; \
                 use \"internet-facing\" or \"lan\""
            )),
        }
        for (label, ranges) in [
            ("denied_peer_ranges", &self.denied_peer_ranges),
            ("allowed_peer_ranges", &self.allowed_peer_ranges),
        ] {
            for r in ranges {
                if let Err(why) = validate_cidr(r) {
                    errors.push(format!("turn.peer_filter.{label}: {why}"));
                }
            }
        }
        errors
    }
}

/// Lightweight CIDR syntax check (the relay does the authoritative parse).
fn validate_cidr(s: &str) -> std::result::Result<(), String> {
    let Some((ip_str, pfx_str)) = s.trim().split_once('/') else {
        return Err(format!("{s:?} is not in <ip>/<prefix> form"));
    };
    let ip: std::net::IpAddr = ip_str
        .trim()
        .parse()
        .map_err(|_| format!("{ip_str:?} is not a valid IP address"))?;
    let prefix: u8 = pfx_str
        .trim()
        .parse()
        .map_err(|_| format!("{pfx_str:?} is not a valid prefix length"))?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    if prefix > max {
        return Err(format!("prefix /{prefix} exceeds /{max} for {s:?}"));
    }
    Ok(())
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

/// RFC 8016 "Mobility with TURN" (Connection Migration).
///
/// Opt-in (`enabled = false` by default). When enabled, the server hands a
/// client a server-signed MOBILITY-TICKET in the Allocate success response —
/// but only if the client opted in by including a (zero-length)
/// MOBILITY-TICKET in its Allocate request. So clients that do not ask for
/// mobility are unaffected even when the feature is on.
///
/// The ticket is an opaque HMAC-SHA256 token over `allocation_id:epoch:issued`.
/// On a network change the client presents the ticket in a Refresh from its
/// new address; the server re-keys the allocation to the new 5-tuple while
/// keeping the same relay address (the peer-facing media path is undisturbed).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MigrationConfig {
    pub enabled: bool,
    /// HMAC key used to sign and verify mobility tickets. Subject to the usual
    /// `${VAR}` / `file:///` substitution. Empty means "generate a random
    /// per-process key at startup" — fine for a single node where tickets only
    /// need to outlive a network blip, but such tickets do NOT survive a
    /// restart and are NOT valid on another node. Production deployments that
    /// enable mobility must set a stable secret (validated below).
    pub ticket_secret: String,
    /// Ticket lifetime in seconds. A migration must complete within this
    /// window. RFC 8016 leaves this to the server; 300s mirrors the default
    /// permission lifetime.
    pub ticket_ttl_secs: u64,
}

impl Default for MigrationConfig {
    fn default() -> Self {
        Self {
            // Opt-in. Connection Migration changes allocation-identity
            // semantics (an allocation can move between 5-tuples), so it is
            // off unless an operator turns it on — at which point a stable
            // ticket secret is required in production (see `validate`).
            enabled: false,
            ticket_secret: String::new(),
            ticket_ttl_secs: 300,
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
                errors
                    .push("cluster.cluster_name must be non-empty when cluster_mode = true".into());
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

/// QUIC / WebTransport listener. Reuses the same PEM cert/key material as the
/// TURNS (`[tls]`) listener by default.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct QuicConfigSection {
    /// Enable the QUIC/WebTransport listener.
    pub enabled: bool,
    /// Negotiate WebTransport-over-HTTP/3 (browser handshake). When `false`,
    /// only the raw-QUIC datapath runs. Requires the `web-transport` feature.
    pub web_transport: bool,
    /// Listen address (default `0.0.0.0:5350`).
    pub listen: SocketAddr,
    /// PEM certificate chain.
    pub cert_path: PathBuf,
    /// PEM private key.
    pub key_path: PathBuf,
    /// Max concurrent bidirectional streams per connection.
    pub max_bi_streams: u64,
    /// Max concurrent unidirectional streams per connection.
    pub max_uni_streams: u64,
    /// Enable QUIC datagrams (RFC 9221) for low-latency media.
    pub enable_datagrams: bool,
    /// Max datagram size, bytes.
    pub max_datagram_size: usize,
    /// Connection idle timeout, seconds.
    pub idle_timeout_secs: u64,
    /// Keep-alive interval, seconds.
    pub keep_alive_secs: u64,
    /// ALPN protocols for the raw-QUIC path (WebTransport forces `h3`).
    pub alpn: Vec<String>,
}

impl Default for QuicConfigSection {
    fn default() -> Self {
        Self {
            enabled: false,
            web_transport: true,
            listen: "0.0.0.0:5350".parse().unwrap(),
            cert_path: PathBuf::from("/etc/turna/tls/cert.pem"),
            key_path: PathBuf::from("/etc/turna/tls/key.pem"),
            max_bi_streams: 256,
            max_uni_streams: 256,
            enable_datagrams: true,
            max_datagram_size: 1200,
            idle_timeout_secs: 30,
            keep_alive_secs: 10,
            alpn: vec!["stun.turn".to_string()],
        }
    }
}

/// io_uring datapath tuning (used only when `transport = "io_uring"` and the
/// node is built with `--features io-uring`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct IoUringSection {
    /// Max relay sockets (allocations) one io_uring worker services
    /// concurrently. Each consumes a fixed msghdr block; the 16-bit msghdr
    /// index packed into the CQE user_data caps this at 1024 per worker.
    pub relay_socket_capacity_per_worker: usize,
}

impl Default for IoUringSection {
    fn default() -> Self {
        Self {
            relay_socket_capacity_per_worker: 256,
        }
    }
}

/// AF_XDP ring-datapath parameters. Mirrors the transport-layer `AfXdpConfig`;
/// kept in the config crate so it stays free of a `turna-transport` dependency.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AfXdpSection {
    /// NIC interface name (e.g. "eth0").
    pub interface: String,
    /// NIC queue id to bind the AF_XDP socket to.
    pub queue_id: u32,
    /// UMEM frame count.
    pub frame_count: u32,
    /// UMEM frame size, bytes.
    pub frame_size: u32,
    /// Fill ring size (power of two).
    pub fill_ring_size: u32,
    /// Completion ring size.
    pub comp_ring_size: u32,
    /// RX ring size.
    pub rx_ring_size: u32,
    /// TX ring size.
    pub tx_ring_size: u32,
    /// Zero-copy mode (requires driver support).
    pub zero_copy: bool,
    /// Use the NEED_WAKEUP flag.
    pub need_wakeup: bool,
    /// Source MAC for TX frames, e.g. "aa:bb:cc:dd:ee:ff". Empty → 00:..:00
    /// placeholder until neighbor resolution lands.
    pub src_mac: String,
    /// Next-hop (gateway) MAC for TX frames. Empty → placeholder (ARP/netlink
    /// neighbor resolution is a follow-up).
    pub dst_mac: String,
}

impl Default for AfXdpSection {
    fn default() -> Self {
        Self {
            interface: "eth0".into(),
            queue_id: 0,
            frame_count: 4096,
            frame_size: 2048,
            fill_ring_size: 2048,
            comp_ring_size: 2048,
            rx_ring_size: 2048,
            tx_ring_size: 2048,
            zero_copy: false,
            need_wakeup: true,
            src_mac: String::new(),
            dst_mac: String::new(),
        }
    }
}

/// TURN over DTLS (RFC 7350) listener. Shares the same PEM material as TURNS
/// by default; DTLS-over-UDP and TURNS (TLS-over-TCP) coexist on port 5349.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DtlsSection {
    /// Enable the DTLS listener.
    pub enabled: bool,
    /// Listen address (default `0.0.0.0:5349`, the IANA TURNS/DTLS port).
    pub listen: SocketAddr,
    /// PEM certificate chain.
    pub cert_path: PathBuf,
    /// PEM private key.
    pub key_path: PathBuf,
    /// Max concurrent DTLS sessions.
    pub max_sessions: usize,
    /// Per-session idle timeout, seconds.
    pub idle_timeout_secs: u64,
    /// Application record MTU (caps outbound TURN responses to avoid IP
    /// fragmentation). Default 1200, matching the QUIC datagram default.
    pub mtu: usize,
    /// DTL-3: bounded per-session outbound (egress) queue capacity. When full,
    /// the newest datagram is dropped (turna_dtls_outbound_dropped_total)
    /// rather than blocking the relay return path. Default 1024.
    pub outbound_queue_capacity: usize,
    /// DTL-9: max concurrent DTLS sessions from one source IP (anti
    /// slot-exhaustion). 0 = unlimited.
    pub max_sessions_per_ip: usize,
}

impl Default for DtlsSection {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: "0.0.0.0:5349".parse().unwrap(),
            cert_path: PathBuf::from("/etc/turna/tls/cert.pem"),
            key_path: PathBuf::from("/etc/turna/tls/key.pem"),
            max_sessions: 10_000,
            idle_timeout_secs: 300,
            mtu: 1200,
            outbound_queue_capacity: 1024,
            max_sessions_per_ip: 0,
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
                // M4: server-only TLS encrypts the channel but does NOT
                // authenticate the *client*. Anyone who can reach the port and
                // speak TLS can invoke admin RPCs (shutdown, add_user,
                // update_config, delete_allocation, …). In production a
                // non-loopback management listener must therefore use mutual
                // TLS — server-only TLS is acceptable only behind a trusted
                // perimeter (loopback / private network you already control).
                if prod && !management_listen.ip().is_loopback() {
                    errs.push(format!(
                        "grpc.tls_mode = \"tls\" (server-only) but management.listen \
                         ({management_listen}) is not loopback — refusing in production: \
                         it does not authenticate clients. Set tls_mode = \"mtls\", or bind \
                         management.listen to 127.0.0.1 / ::1."
                    ));
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
    fn migration_defaults_to_opt_in() {
        let m = MigrationConfig::default();
        assert!(!m.enabled, "mobility is opt-in (off by default)");
        assert!(m.ticket_secret.is_empty());
        assert_eq!(m.ticket_ttl_secs, 300);
    }

    #[test]
    fn quic_section_defaults_and_parse() {
        // Off by default; when present, fields parse and unknown keys are
        // rejected (deny_unknown_fields). Lives under [turn.quic].
        let q = QuicConfigSection::default();
        assert!(!q.enabled, "QUIC is opt-in");
        assert!(q.web_transport, "WebTransport on when QUIC is enabled");
        assert_eq!(q.listen.port(), 5350);
        assert!(q.enable_datagrams);

        let toml = r#"
            [turn]
            listen = "0.0.0.0:3478"

            [turn.quic]
            enabled = true
            web_transport = true
            listen = "0.0.0.0:5350"
            cert_path = "/etc/turna/tls/cert.pem"
            key_path = "/etc/turna/tls/key.pem"
            enable_datagrams = false
        "#;
        let cfg: TurnaConfig = toml::from_str(toml).expect("quic section parses");
        assert!(cfg.turn.quic.enabled);
        assert!(!cfg.turn.quic.enable_datagrams, "explicit override applied");
        // Untouched fields fall back to defaults.
        assert_eq!(cfg.turn.quic.max_bi_streams, 256);
    }

    #[test]
    fn default_transport_is_tokio() {
        // 2.2: tokio is the safe default; io_uring/af_xdp/auto are opt-ins.
        assert!(matches!(
            TransportSelection::default(),
            TransportSelection::Tokio
        ));
        assert!(matches!(
            TurnConfig::default().transport,
            TransportSelection::Tokio
        ));

        // A [turn] section that omits `transport` resolves to tokio, not auto.
        let toml = r#"
            [turn]
            listen = "0.0.0.0:3478"
        "#;
        let cfg: TurnaConfig = toml::from_str(toml).expect("minimal turn section parses");
        assert!(matches!(cfg.turn.transport, TransportSelection::Tokio));
    }

    #[test]
    fn io_uring_section_parses_and_defaults() {
        assert_eq!(
            IoUringSection::default().relay_socket_capacity_per_worker,
            256
        );
        let toml = r#"
            [turn]
            listen = "0.0.0.0:3478"
            transport = "io_uring"

            [turn.io_uring]
            relay_socket_capacity_per_worker = 512
        "#;
        let cfg: TurnaConfig = toml::from_str(toml).expect("io_uring section parses");
        assert_eq!(cfg.turn.io_uring.relay_socket_capacity_per_worker, 512);
    }

    #[test]
    fn af_xdp_section_and_transport_selection_parse() {
        let q = AfXdpSection::default();
        assert_eq!(q.queue_id, 0);
        assert_eq!(q.frame_count, 4096);

        let toml = r#"
            [turn]
            listen = "0.0.0.0:3478"
            transport = "af_xdp"

            [turn.af_xdp]
            interface = "enp1s0"
            queue_id = 3
            zero_copy = true
            dst_mac = "aa:bb:cc:dd:ee:ff"
        "#;
        let cfg: TurnaConfig = toml::from_str(toml).expect("af_xdp section parses");
        assert!(matches!(cfg.turn.transport, TransportSelection::AfXdp));
        assert_eq!(cfg.turn.af_xdp.interface, "enp1s0");
        assert_eq!(cfg.turn.af_xdp.queue_id, 3);
        assert!(cfg.turn.af_xdp.zero_copy);
        assert_eq!(cfg.turn.af_xdp.dst_mac, "aa:bb:cc:dd:ee:ff");
        // Untouched ring sizes keep defaults.
        assert_eq!(cfg.turn.af_xdp.rx_ring_size, 2048);
    }

    #[test]
    fn dtls_section_defaults_and_parse() {
        let d = DtlsSection::default();
        assert!(!d.enabled, "DTLS is opt-in");
        assert_eq!(d.listen.port(), 5349);
        assert_eq!(d.mtu, 1200);

        let toml = r#"
            [turn]
            listen = "0.0.0.0:3478"

            [turn.dtls]
            enabled = true
            listen = "0.0.0.0:5349"
            cert_path = "/etc/turna/tls/cert.pem"
            key_path = "/etc/turna/tls/key.pem"
            mtu = 1100
        "#;
        let cfg: TurnaConfig = toml::from_str(toml).expect("dtls section parses");
        assert!(cfg.turn.dtls.enabled);
        assert_eq!(cfg.turn.dtls.mtu, 1100);
        assert_eq!(cfg.turn.dtls.max_sessions, 10_000);
    }

    #[test]
    fn migration_empty_ticket_secret_in_cluster_is_hard_error() {
        // Cross-node migration needs the SAME ticket_secret on every node.
        // An empty secret under cluster_mode must fail validation even outside
        // production (otherwise each node picks an independent random key and
        // migration silently breaks).
        let _guard = production_env_lock();
        let saved = std::env::var_os("TURNA_PRODUCTION");
        std::env::remove_var("TURNA_PRODUCTION");

        let mut cfg = TurnaConfig::default();
        // External IP so the cluster redirect check doesn't add an unrelated
        // error; we want the ticket_secret error to be the one under test.
        cfg.turn.external_ip = "203.0.113.1".into();
        cfg.turn.migration.enabled = true;
        cfg.turn.migration.ticket_secret.clear();
        cfg.cluster.cluster_mode = true;

        let result = cfg.validate();
        restore_turna_production(saved);

        let msg = result
            .expect_err("empty ticket_secret + cluster_mode must fail validation")
            .to_string();
        assert!(
            msg.contains("ticket_secret"),
            "validation error should call out ticket_secret, got: {msg}"
        );
    }

    #[test]
    fn migration_empty_ticket_secret_single_node_is_warn_only() {
        // A single, non-production node may run with a random per-process key
        // (it only loses tickets across a restart) — that path stays a warning,
        // not a hard error, to keep the first-run experience friendly.
        let _guard = production_env_lock();
        let saved = std::env::var_os("TURNA_PRODUCTION");
        std::env::remove_var("TURNA_PRODUCTION");

        let mut cfg = TurnaConfig::default();
        cfg.turn.migration.enabled = true;
        cfg.turn.migration.ticket_secret.clear();
        // cluster_mode left at its default (false) → single node.

        let result = cfg.validate();
        restore_turna_production(saved);

        result.expect("single-node empty ticket_secret must validate (warn only)");
    }

    #[test]
    fn migration_section_parses() {
        let toml = r#"
[turn]
listen = "0.0.0.0:3478"
external_ip = "127.0.0.1"

[turn.auth]
shared_secret = "s"

[turn.migration]
enabled = true
ticket_secret = "deadbeef"
ticket_ttl_secs = 120

[signaling]
listen = "0.0.0.0:9001"
turn_shared_secret = "s"
"#;
        let config = TurnaConfig::from_str(toml).unwrap();
        assert!(config.turn.migration.enabled);
        assert_eq!(config.turn.migration.ticket_secret, "deadbeef");
        assert_eq!(config.turn.migration.ticket_ttl_secs, 120);
    }

    #[test]
    fn migration_ticket_secret_honours_env_substitution() {
        // The same ${VAR:-default} expansion that covers auth secrets must
        // apply to the migration ticket secret.
        let toml = r#"
[turn]
external_ip = "127.0.0.1"
[turn.auth]
shared_secret = "s"
[turn.migration]
ticket_secret = "${TURNA_NONEXISTENT_MT_SECRET:-fallback-mt}"
[signaling]
turn_shared_secret = "s"
"#;
        let config = TurnaConfig::from_str(toml).unwrap();
        assert_eq!(config.turn.migration.ticket_secret, "fallback-mt");
    }

    #[test]
    fn migration_zero_ttl_rejected() {
        // `from_str` runs `validate()`, and ttl=0 is rejected in any mode,
        // so the load itself must fail. No env lock needed.
        let toml = r#"
[turn]
external_ip = "127.0.0.1"
[turn.auth]
shared_secret = "s"
[turn.migration]
enabled = true
ticket_secret = "x"
ticket_ttl_secs = 0
[signaling]
turn_shared_secret = "s"
"#;
        assert!(
            TurnaConfig::from_str(toml).is_err(),
            "ticket_ttl_secs = 0 must be rejected"
        );
    }

    #[test]
    fn migration_unknown_key_rejected() {
        // deny_unknown_fields discipline must extend to the new section.
        let toml = r#"
[turn.migration]
enbaled = true
"#;
        assert!(TurnaConfig::from_str(toml).is_err());
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

    fn prod_config_invalid_external_ip() -> &'static str {
        r#"
production = true

[turn]
external_ip = "not-an-ip"

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

        // Scenario 6: external_ip must be parseable, not merely non-empty.
        let err = TurnaConfig::from_str(prod_config_invalid_external_ip())
            .expect_err("scenario 6: invalid external_ip must be rejected");
        let msg = err.to_string().to_lowercase();
        assert!(
            msg.contains("external_ip") && (msg.contains("valid") || msg.contains("ip")),
            "scenario 6: expected invalid external_ip error, got: {err}"
        );

        // Scenario 7: real secrets in prod mode → all good.
        let cfg = TurnaConfig::from_str(prod_config_clean())
            .expect("scenario 7: clean prod config must validate");
        assert!(cfg.is_production());

        // Restore the caller's environment instead of leaking test state.
        restore_turna_production(saved_turna_production);
    }
}
