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
        // Capacity: each allocation consumes at least one relay port, so a cap
        // above the usable range is physically unreachable — hard error. A cap
        // above half the range is only a *worst-case* EVEN-PORT concern
        // (RFC 8656 §7.2 can reserve the next-higher port), so it is a warning,
        // not a failure — real traffic mixes rarely hit 2 ports per allocation.
        if self.turn.relay.min_port < self.turn.relay.max_port {
            let usable = (self.turn.relay.max_port - self.turn.relay.min_port) as usize + 1;
            if self.turn.relay.max_allocations > usable {
                errors.push(format!(
                    "turn.relay.max_allocations ({}) exceeds usable relay ports ({}) \
                     for range [{}, {}] — a cap above the port count is unreachable",
                    self.turn.relay.max_allocations,
                    usable,
                    self.turn.relay.min_port,
                    self.turn.relay.max_port
                ));
            } else if self.turn.relay.max_allocations > usable / 2 {
                warn!(
                    "turn.relay.max_allocations ({}) exceeds half the usable relay \
                     ports ({}/2 = {}); under worst-case EVEN-PORT reservations the \
                     range may exhaust before the cap is reached",
                    self.turn.relay.max_allocations,
                    usable,
                    usable / 2
                );
            }
        }
        // B2: an unlimited per-allocation bandwidth cap in production is a DoS
        // amplifier — a single authenticated client can relay without bound.
        // Require an explicit opt-in to run that way.
        if prod
            && self.turn.relay.quota.max_bytes_per_sec_per_allocation == 0
            && !self.turn.relay.quota.allow_unlimited_bandwidth
        {
            errors.push(
                "turn.relay.quota.max_bytes_per_sec_per_allocation is 0 (unlimited) in production; \
                 set a per-allocation byte/sec cap, or explicitly set \
                 turn.relay.quota.allow_unlimited_bandwidth = true to accept the risk"
                    .into(),
            );
        }
        // The demux-only DTLS knobs do nothing on the stock listener path. Set
        // without `demux = true` they read as protection that is not there, which
        // is worse than an explicit error at startup.
        if self.turn.dtls.enabled && !self.turn.dtls.demux {
            if self.turn.dtls.max_handshakes_per_sec_per_ip != 0 {
                errors.push(
                    "turn.dtls.max_handshakes_per_sec_per_ip requires turn.dtls.demux = true \
                     (on the stock listener the handshake runs below accept(), so the limit \
                     cannot be enforced)"
                        .into(),
                );
            }
            if self.turn.dtls.cert_reload_secs != 0 {
                errors.push(
                    "turn.dtls.cert_reload_secs requires turn.dtls.demux = true (the stock \
                     listener fixes its certificate at bind time and can only warn that the \
                     files changed; set demux = true or plan a restart on rotation)"
                        .into(),
                );
            }
        }
        // RFC 6156: external_ip6 must be a real IPv6 literal if set — a v4 literal
        // here would advertise a v4 address for a v6-family allocation, which is
        // exactly the mismatch the 443 check exists to prevent.
        if !self.turn.external_ip6.is_empty() {
            match self.turn.external_ip6.parse::<std::net::IpAddr>() {
                Ok(std::net::IpAddr::V6(_)) => {}
                Ok(std::net::IpAddr::V4(_)) => errors.push(
                    "turn.external_ip6 must be an IPv6 address (it is the address \
                     advertised for IPv6-family allocations)"
                        .into(),
                ),
                Err(_) => errors.push(
                    "turn.external_ip6 is not a valid IP address; leave it empty to \
                     keep IPv4-only relaying"
                        .into(),
                ),
            }
        }
        // require_client_cert with no CA would demand a certificate nothing can
        // validate, refusing every client — fail at startup, not at first connect.
        if self.tls.enabled && self.tls.require_client_cert && self.tls.client_ca.is_empty() {
            errors.push(
                "tls.require_client_cert = true requires tls.client_ca (a CA bundle to \
                 validate client certificates against)"
                    .into(),
            );
        }
        // Strict ALPN with nothing advertised refuses every client (no protocol
        // can be negotiated), so the combination is a config error rather than a
        // runtime surprise.
        if self.tls.enabled && self.tls.alpn_required && !self.tls.enable_alpn {
            errors.push(
                "tls.alpn_required = true requires tls.enable_alpn = true (nothing \
                 would be advertised, so every client would be refused)"
                    .into(),
            );
        }
        // Experimental transports are not production-ready: RFC 6062 TCP relay is
        // partial/experimental, and TURN-over-SCTP is experimental. Refuse to
        // enable either under `production` so an unfinished datapath is never
        // shipped as if it were supported.
        if prod && self.turn.tcp_relay.enabled {
            errors.push(
                "turn.tcp_relay.enabled = true in production, but RFC 6062 TCP relay is experimental/partial and not supported in production"
                    .into(),
            );
        }
        if prod && self.turn.sctp.enabled {
            errors.push(
                "turn.sctp.enabled = true in production, but TURN-over-SCTP is experimental and not supported in production"
                    .into(),
            );
        }
        // RFC 7635 OAuth is experimental: refuse in production, and when enabled
        // require a server_name plus at least one valid AES keyring entry.
        if self.turn.auth.oauth.enabled {
            if prod {
                errors.push(
                    "turn.auth.oauth.enabled = true in production, but RFC 7635 OAuth \
                     is experimental and not supported in production"
                        .into(),
                );
            }
            if self.turn.auth.oauth.server_name.is_empty() {
                errors.push(
                    "turn.auth.oauth.enabled but turn.auth.oauth.server_name is empty                      (it is the AEAD associated-data binding tokens to this server)"
                        .into(),
                );
            }
            if self.turn.auth.oauth.as_rs_keys.is_empty() && self.turn.auth.oauth.keys.is_empty() {
                errors.push(
                    "turn.auth.oauth.enabled but no AS-RS keys configured (need at least \
                     one of turn.auth.oauth.as_rs_keys or turn.auth.oauth.keys)"
                        .into(),
                );
            }
            for (i, k) in self.turn.auth.oauth.as_rs_keys.iter().enumerate() {
                let hex_ok = k.len().is_multiple_of(2) && k.bytes().all(|b| b.is_ascii_hexdigit());
                if !hex_ok || !matches!(k.len() / 2, 16 | 32) {
                    errors.push(format!(
                        "turn.auth.oauth.as_rs_keys[{i}] must be hex encoding a 16- or 32-byte \
                         AES key (got {} hex chars)",
                        k.len()
                    ));
                }
            }
            // RFC 7635 kid-tagged keys: same hex/length rule, plus a non-empty,
            // unique kid so USERNAME-based key selection is unambiguous.
            let mut seen_kids = std::collections::HashSet::new();
            for (i, entry) in self.turn.auth.oauth.keys.iter().enumerate() {
                if entry.kid.is_empty() {
                    errors.push(format!("turn.auth.oauth.keys[{i}].kid must not be empty"));
                } else if !seen_kids.insert(entry.kid.as_str()) {
                    errors.push(format!(
                        "turn.auth.oauth.keys[{i}].kid '{}' is duplicated",
                        entry.kid
                    ));
                }
                let k = &entry.key;
                let hex_ok = k.len().is_multiple_of(2) && k.bytes().all(|b| b.is_ascii_hexdigit());
                if !hex_ok || !matches!(k.len() / 2, 16 | 32) {
                    errors.push(format!(
                        "turn.auth.oauth.keys[{i}].key must be hex encoding a 16- or 32-byte \
                         AES key (got {} hex chars)",
                        k.len()
                    ));
                }
            }
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
        if let Err(command_log_errs) = self.cluster.command_log.validate() {
            errors.extend(command_log_errs);
        }
        if let Err(cluster_errs) = self.cluster.validate_redirect_mode(&self.turn) {
            errors.extend(cluster_errs);
        }

        // P0 #10: the state backend must be explicit and valid. A typo must
        // never silently downgrade the deployment to a process-local
        // in-memory store, and clustering cannot run on such a store.
        {
            let backend_type = self.cluster.backend.r#type.trim();
            match backend_type {
                // "" defaults to memory (BackendConfigSection::default).
                "" | "memory" | "tarantool" => {}
                other => errors.push(format!(
                    "cluster.backend.type = {other:?} is not a known backend; \
                     use \"memory\" (single-node) or \"tarantool\" (cluster)"
                )),
            }
            let is_memory = matches!(backend_type, "" | "memory");
            // Clustering fundamentally cannot share a process-local store —
            // refuse regardless of the production flag (same rationale as the
            // cluster_secret requirement above).
            if self.cluster.cluster_mode && is_memory {
                errors.push(
                    "cluster.cluster_mode = true requires a shared state backend; \
                     set cluster.backend.type = \"tarantool\" (the in-memory backend \
                     is process-local and cannot be shared across nodes)"
                        .into(),
                );
            }
            // Write-behind persistence to a process-local store provides no
            // durability or cross-node sharing; refuse it in production.
            if prod && self.cluster.persistence.mode == "write_behind" && is_memory {
                errors.push(
                    "cluster.persistence.mode = \"write_behind\" with an in-memory backend \
                     provides no durable persistence in production; set \
                     cluster.backend.type = \"tarantool\""
                        .into(),
                );
            }
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
                // Capacity per tenant: cap must fit the tenant's isolated range
                // (0 = unlimited → skip). Hard error above range size; EVEN-PORT
                // worst-case (> half) is a warning, mirroring the base check.
                if lo < hi && t.max_allocations > 0 {
                    let usable = (hi - lo) as usize + 1;
                    if t.max_allocations > usable {
                        errors.push(format!(
                            "tenant '{}' max_allocations ({}) exceeds usable ports \
                             ({}) in its relay range [{lo}, {hi}]",
                            t.id, t.max_allocations, usable
                        ));
                    } else if t.max_allocations > usable / 2 {
                        warn!(
                            "tenant '{}' max_allocations ({}) exceeds half its usable \
                             relay ports ({}); worst-case EVEN-PORT reservations may \
                             exhaust the range early",
                            t.id, t.max_allocations, usable
                        );
                    }
                }
                if t.shared_secret.is_empty() && t.static_users.is_empty() {
                    errors.push(format!(
                        "tenant '{}' has neither shared_secret nor static_users — \
                         no client could authenticate",
                        t.id
                    ));
                }
                // I1: a tenant must not ship the public placeholder secret in
                // production. The base shared_secret is already rejected; tenants
                // were not. Mirrors the base-secret placeholder check.
                if !t.shared_secret.is_empty() && t.shared_secret == DEFAULT_SHARED_SECRET && prod {
                    errors.push(format!(
                        "tenant '{}' shared_secret is the public placeholder default; \
                         generate one with `openssl rand -hex 32`",
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
    /// RFC 6156 IPv6 relayed transport: the IPv6 address advertised in
    /// XOR-RELAYED-ADDRESS for allocations that asked for
    /// `REQUESTED-ADDRESS-FAMILY = IPv6`. Empty (the default) keeps the
    /// IPv4-only behaviour, where an explicit IPv6 Allocate is answered
    /// `440 Address Family not Supported`.
    ///
    /// This is separate from `external_ip` on purpose: `external_ip` may itself be
    /// an IPv6 literal, but that only changes what is advertised for *v4-family*
    /// allocations. Relaying over IPv6 needs its own advertised address, and the
    /// relay socket is bound in the requested family.
    pub external_ip6: String,
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
    /// TURN-over-SCTP control transport (experimental). Disabled by default.
    /// Requires the node binary built with `--features sctp`.
    #[serde(default)]
    pub sctp: SctpSection,
    /// RFC 6062 TCP relay. Disabled by default; requires `[tls]` enabled.
    #[serde(default)]
    pub tcp_relay: TcpRelaySection,
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
            external_ip6: String::new(),
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
            sctp: SctpSection::default(),
            tcp_relay: TcpRelaySection::default(),
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
    /// RFC 7635 third-party (OAuth) authorization on the base realm.
    pub oauth: OAuthConfig,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            shared_secret: DEFAULT_SHARED_SECRET.into(),
            token_ttl: 86400,
            static_users: Vec::new(),
            oauth: OAuthConfig::default(),
        }
    }
}

/// RFC 7635 third-party (OAuth 2.0) authorization. Disabled by default and
/// experimental — refused under `production=true` (see `validate`). When
/// enabled, the base realm authenticates clients by an AEAD-sealed ACCESS-TOKEN
/// from an authorization server instead of USERNAME/REALM credentials.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OAuthConfig {
    /// Enable OAuth on the base realm.
    pub enabled: bool,
    /// AEAD associated-data binding tokens to THIS server (RFC 7635 §6.2). A
    /// token sealed for a different `server_name` will not decrypt here.
    pub server_name: String,
    /// Authorization-server identity advertised in the 401 THIRD-PARTY-
    /// AUTHORIZATION challenge (RFC 7635 §6.1). Empty → falls back to server_name.
    pub as_identity: String,
    /// AS-RS symmetric keys shared with the authorization server, hex-encoded
    /// (each decoding to 16 B → AES-128-GCM or 32 B → AES-256-GCM). List more
    /// than one to roll keys: a token sealed with any listed key validates.
    pub as_rs_keys: Vec<String>,
    /// RFC 7635 §6.1 kid-tagged AS-RS keys. When the client's USERNAME carries a
    /// matching `kid`, the server selects that key directly instead of trial-
    /// decrypting the whole keyring; on no match it falls back to trial-decrypt
    /// (incl. `as_rs_keys`). Each `key` is hex (16 B → AES-128-GCM, 32 B →
    /// AES-256-GCM); `kid` must be non-empty and unique.
    pub keys: Vec<OAuthKey>,
    /// RFC 7635 §6.1 strict key selection. When true, a request whose USERNAME
    /// names an unknown `kid` — or omits USERNAME entirely — is rejected instead
    /// of falling back to trial-decrypt. Default false keeps the rotation-friendly
    /// trial-decrypt behaviour; enable for a strict RFC / high-assurance profile.
    pub strict_kid: bool,
}

/// RFC 7635 kid-tagged AS-RS key (see [`OAuthConfig::keys`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OAuthKey {
    /// Key identifier, matched against the client's USERNAME (RFC 7635 §6.1).
    pub kid: String,
    /// Hex-encoded AES key (16 B → AES-128-GCM, 32 B → AES-256-GCM).
    pub key: String,
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
    pub max_bytes_per_sec_per_allocation: u64,
    /// Max simultaneous allocations per username. 0 = unlimited.
    pub max_per_user: usize,
    /// B2: acknowledge running with NO per-allocation bandwidth cap in
    /// production. `max_bytes_per_sec_per_allocation = 0` (unlimited) is refused in production
    /// unless this is explicitly set — an unbounded relay is a DoS amplifier.
    pub allow_unlimited_bandwidth: bool,
}

impl Default for QuotaConfig {
    fn default() -> Self {
        Self {
            max_bytes_per_sec_per_allocation: 0, // unlimited — matches session default
            max_per_user: 100,
            allow_unlimited_bandwidth: false,
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
    /// redirecting *new* clients away for up to this many seconds before
    /// exiting, so a rolling deploy doesn't drop new sessions. Existing sessions
    /// get the SAME window to finish — the node waits until active allocations
    /// reach zero OR this deadline elapses, then proceeds with shutdown **even
    /// if allocations are still active** (logged as "drain grace elapsed with
    /// allocations still active"). So existing sessions are NOT guaranteed to
    /// survive: the default (5s) is far too short to preserve real TURN sessions
    /// across a rolling upgrade — raise it to cover your expected session length
    /// if uninterrupted sessions matter. `0` = exit immediately.
    pub drain_grace_secs: u64,
    pub backend: BackendConfigSection,
    /// Allocation persistence (PR1 scaffolding — task #3).
    ///
    /// Default `mode = "disabled"` preserves pre-PR1 behaviour exactly:
    /// no writer task is spawned, no `WriteOp` events are emitted.
    /// See `docs/design/allocation-store-persistence.md`.
    pub persistence: PersistenceConfig,
    /// Durable command-log retention, bounded migration, and GC settings for
    /// the control plane.
    pub command_log: CommandLogConfig,
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
            command_log: CommandLogConfig::default(),
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
            // B3 / R5: an empty cluster_secret leaves gossip unauthenticated on
            // any shared network. Mirror the ticket_secret rule — hard error when
            // cluster_mode is on (PRODUCTION_READINESS R5, Severity High).
            if self.cluster_secret.trim().is_empty() {
                errors.push(
                    "cluster.cluster_secret must be non-empty when cluster_mode = true \
                     (an empty secret leaves gossip unauthenticated — R5); generate one \
                     with `openssl rand -hex 32` and set the SAME value on every node"
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
    /// R8 live propagation: how often (seconds) a node re-reads runtime users
    /// from the state backend so AddUser/RemoveUser reach it without a restart.
    /// `0` disables periodic refresh (users are loaded only at startup).
    pub user_refresh_secs: u64,
}

impl Default for PersistenceConfig {
    fn default() -> Self {
        Self {
            mode: "disabled".into(),
            channel_capacity: 65_536,
            batch_max_size: 256,
            batch_max_delay_ms: 100,
            user_refresh_secs: 30,
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

/// Durable command-log retention + garbage-collection settings (control-plane).
///
/// Terminal commands are pruned by age *per status*; idempotency records are
/// retained independently and, by the GC sweep's ordering rule, never dropped
/// before the command they guard. Non-terminal states (pending/claimed/running)
/// are never pruned by TTL — stuck commands are handled by claim reclaim and
/// dead-lettering, not by GC.
///
/// The control plane uses these limits for bounded, resumable migration and
/// per-backend command-log garbage collection.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CommandLogConfig {
    /// Retain `done` commands this many seconds after completion (default 7d).
    pub retain_done_secs: u64,
    /// Retain `failed` commands this many seconds after completion (default 30d).
    pub retain_failed_secs: u64,
    /// Retain `superseded` commands this many seconds after completion (7d).
    pub retain_superseded_secs: u64,
    /// Retain `expired` commands this many seconds after completion (7d).
    pub retain_expired_secs: u64,
    /// Minimum retention for idempotency records (default 30d). They are never
    /// pruned before the command they reference regardless of this value.
    pub retain_idempotency_secs: u64,
    /// GC sweep cadence in seconds (default 900 = 15 min). `0` disables GC.
    pub sweep_interval_secs: u64,
    /// Max records deleted per batch inside a sweep (default 1000). Bounds the
    /// per-transaction work so GC never holds a long transaction.
    pub batch_size: usize,
    /// Max batches per sweep pass (default 10): a large backlog drains across
    /// several sweeps rather than one long run.
    pub max_batches_per_sweep: u32,
    /// Random jitter (seconds) added to each sweep start so multiple
    /// control-plane instances don't sweep in lockstep (default 60).
    pub sweep_jitter_secs: u64,
}

impl Default for CommandLogConfig {
    fn default() -> Self {
        Self {
            retain_done_secs: 7 * 24 * 3600,
            retain_failed_secs: 30 * 24 * 3600,
            retain_superseded_secs: 7 * 24 * 3600,
            retain_expired_secs: 7 * 24 * 3600,
            retain_idempotency_secs: 30 * 24 * 3600,
            sweep_interval_secs: 900,
            batch_size: 1000,
            max_batches_per_sweep: 10,
            sweep_jitter_secs: 60,
        }
    }
}

impl CommandLogConfig {
    /// GC runs only when a sweep interval is configured.
    pub fn gc_enabled(&self) -> bool {
        self.sweep_interval_secs > 0
    }

    /// Returns Err with a list of validation issues, if any.
    pub(crate) fn validate(&self) -> std::result::Result<(), Vec<String>> {
        let mut errors = Vec::new();
        if self.gc_enabled() {
            if self.batch_size == 0 {
                errors.push("cluster.command_log.batch_size must be > 0 when GC is enabled".into());
            }
            if self.max_batches_per_sweep == 0 {
                errors.push(
                    "cluster.command_log.max_batches_per_sweep must be > 0 when GC is enabled"
                        .into(),
                );
            }
            // Idempotency records guard destructive replays; they MUST outlive
            // every command they can guard. Commands live under four independent
            // terminal windows (done/failed/superseded/expired), so the record
            // window must be >= the LONGEST of them — otherwise a command in the
            // longest-retained state (e.g. a 60d `done`) could still exist after
            // its 30d idempotency record was pruned, and a replay would slip
            // through with the command row gone.
            let max_terminal = self
                .retain_done_secs
                .max(self.retain_failed_secs)
                .max(self.retain_superseded_secs)
                .max(self.retain_expired_secs);
            if self.retain_idempotency_secs < max_terminal {
                errors.push(format!(
                    "cluster.command_log.retain_idempotency_secs ({}) must be >= the longest \
                     terminal retention (max of done/failed/superseded/expired = {}) so an \
                     idempotency record can never be pruned before a command it guards",
                    self.retain_idempotency_secs, max_terminal
                ));
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
    /// Max concurrent TURNS connections from one source IP (anti
    /// slot-exhaustion, mirrors `[turn.dtls].max_sessions_per_ip`).
    /// 0 = unlimited.
    pub max_connections_per_ip: usize,
    /// Re-read `cert_path`/`key_path` every N seconds and pick up a rotated
    /// certificate without a restart (new connections use the new material;
    /// established ones keep their session). 0 disables reloading.
    pub cert_reload_secs: u64,
    /// Advertise ALPN (`stun.turn`).
    pub enable_alpn: bool,
    /// Per-source-IP handshake **rate** limit, handshakes/second (0 = unlimited).
    /// `max_connections_per_ip` caps concurrent connections only, so a source
    /// that connects and drops in a loop never trips it while still costing a TLS
    /// handshake each time. Mirrors `[turn.quic].max_handshakes_per_sec_per_ip`.
    pub max_handshakes_per_sec_per_ip: u32,
    /// Burst allowance for the rate limit. 0 = twice the rate, so a client
    /// opening a few connections at once is not penalised.
    pub handshake_burst_per_ip: u32,
    /// PEM bundle of CAs allowed to sign a TURNS **client** certificate. Empty
    /// (default) = no client-certificate verification, which is what a public TURN
    /// server wants. Setting it enables mTLS on the TURNS listener only; the
    /// management plane has its own `[grpc] tls_ca` and is unaffected.
    ///
    /// No CRL/OCSP, deliberately — same position as the management plane
    /// (`docs/MTLS.md` → Revocation). Revoke by rotating the CA.
    pub client_ca: String,
    /// Refuse a TURNS client that presents no certificate. Requires `client_ca`.
    /// `false` (default) lets an unauthenticated client through TLS and leaves it
    /// to the normal long-term credential check, which is what allows a staged
    /// rollout across an existing fleet.
    pub require_client_cert: bool,
    /// RFC 7443 strict mode: refuse clients that negotiate no ALPN protocol.
    /// Requires `enable_alpn = true`. Default false = compatible mode (a client
    /// that offers no ALPN is served).
    pub alpn_required: bool,
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
            max_connections_per_ip: 0,
            cert_reload_secs: 30,
            enable_alpn: true,
            max_handshakes_per_sec_per_ip: 0,
            handshake_burst_per_ip: 0,
            alpn_required: false,
            client_ca: String::new(),
            require_client_cert: false,
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
    /// Max concurrent QUIC/WebTransport sessions. 0 = unlimited.
    /// Mirrors `[turn.dtls].max_sessions`.
    pub max_sessions: usize,
    /// Max concurrent sessions from one source IP (anti slot-exhaustion).
    /// 0 = unlimited. Mirrors `[turn.dtls].max_sessions_per_ip`.
    pub max_sessions_per_ip: usize,
    /// Re-read `cert_path`/`key_path` every N seconds and hot-reload the
    /// listener's certificate without dropping live sessions. WebTransport path
    /// only (`web_transport = true`); the raw-QUIC endpoint has no reload hook.
    /// 0 disables reloading.
    pub cert_reload_secs: u64,
    /// Max new handshakes per second from one source IP (`0` = unlimited).
    /// Unlike `max_sessions_per_ip`, which bounds *concurrent* sessions, this
    /// bounds the *rate* — a source that opens and drops sessions in a loop
    /// stays under a concurrency cap while still burning CPU on handshakes.
    pub max_handshakes_per_sec_per_ip: u32,
    /// Burst allowance for `max_handshakes_per_sec_per_ip`. Ignored when the
    /// rate limit is disabled. Defaults to twice the rate so a page load that
    /// opens several sessions at once is not penalised.
    pub handshake_burst_per_ip: u32,
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
            max_sessions: 10_000,
            max_sessions_per_ip: 0,
            cert_reload_secs: 30,
            max_handshakes_per_sec_per_ip: 0,
            handshake_burst_per_ip: 0,
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
    /// Use the owned UDP demultiplexer instead of `webrtc_dtls::listen()`.
    ///
    /// Off by default. `listen()` runs handshakes serially inside `accept()`
    /// (webrtc-rs/webrtc#614), which forces three compromises: admission control
    /// can only happen *after* the crypto, there is nowhere to put a handshake
    /// rate limit, and the certificate is fixed at bind time. The demux path
    /// fixes all three at once — but it replaces the code path that has recorded
    /// verification behind it, so it stays opt-in until its own interop run is on
    /// record (`docs/verification/encrypted-transports.md`).
    pub demux: bool,
    /// Per-source-IP handshake **rate** limit, handshakes/second (0 = unlimited).
    /// Requires `demux = true`; on the stock path the handshake runs below
    /// `accept()`, so there is nowhere to enforce it.
    pub max_handshakes_per_sec_per_ip: u32,
    /// Burst allowance for the rate limit. 0 = twice the rate.
    pub handshake_burst_per_ip: u32,
    /// Poll `cert_path`/`key_path` every N seconds and pick up a rotated
    /// certificate without a restart. 0 disables. Requires `demux = true`:
    /// `listen()` fixes its config at bind time, which is why the stock path can
    /// only warn that the files changed.
    pub cert_reload_secs: u64,
    /// Upper bound, in seconds, on one DTLS `accept()` — i.e. on a single
    /// handshake. 0 disables the bound.
    ///
    /// This is a liveness guard, not tuning. `webrtc-dtls` runs the whole
    /// handshake inline inside `accept()` with no timeout of its own
    /// (webrtc-rs/webrtc#614), so a peer that starts a handshake and goes silent
    /// parks the accept loop forever and the DTLS listener stops serving *anyone*
    /// while the process still looks healthy. Bounding the accept restores
    /// liveness; the cost is that a legitimately slow handshake is abandoned, so
    /// keep this comfortably above real-world handshake latency.
    pub accept_timeout_secs: u64,
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
            accept_timeout_secs: 10,
            demux: false,
            max_handshakes_per_sec_per_ip: 0,
            handshake_burst_per_ip: 0,
            cert_reload_secs: 0,
        }
    }
}

/// TURN-over-SCTP listener (experimental client CONTROL transport; the relayed
/// side stays UDP). No TURN RFC defines SCTP relaying — see docs/protocol-gap.md.
/// Disabled by default. Requires the node binary built with `--features sctp`
/// and a host with the SCTP kernel module.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SctpSection {
    /// Enable the SCTP listener.
    pub enabled: bool,
    /// Listen address (no standardized TURN-over-SCTP port; 3478 by default).
    pub listen: SocketAddr,
    /// Max framed STUN/ChannelData message size, bytes.
    pub max_frame_size: usize,
    /// Per-connection idle read timeout, seconds.
    pub read_timeout_secs: u64,
    /// Max concurrent SCTP connections.
    pub max_connections: usize,
    /// Per-source-IP association cap. 0 = unlimited.
    ///
    /// Without it one source can hold every one of `max_connections` — the gap
    /// the DTLS and TURNS listeners already closed.
    pub max_connections_per_ip: usize,
    /// Per-source-IP association rate limit, associations/second. 0 = unlimited.
    ///
    /// `max_connections_per_ip` bounds concurrency only: a source that
    /// associates and drops in a loop never trips it.
    pub max_associations_per_sec_per_ip: u32,
    /// Burst allowance for the rate limit. 0 = twice the rate.
    pub association_burst_per_ip: u32,
    /// listen(2) backlog.
    pub backlog: i32,
}

impl Default for SctpSection {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: "0.0.0.0:3478".parse().unwrap(),
            max_frame_size: 64 * 1024,
            read_timeout_secs: 300,
            max_connections: 10_000,
            // Off by default, matching TURNS: a limit that surprises an operator
            // on upgrade is worse than one they had to opt into.
            max_connections_per_ip: 0,
            max_associations_per_sec_per_ip: 0,
            association_burst_per_ip: 0,
            backlog: 1024,
        }
    }
}

/// RFC 6062 TCP relay (client uses CONNECT/CONNECTION-BIND to reach a peer over
/// TCP; the relayed transport is TCP, not UDP). Disabled by default; the control
/// channel uses the TURNS (TLS) listener, so `[tls]` must also be enabled.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TcpRelaySection {
    /// Enable RFC 6062 TCP relaying (accept Allocate with REQUESTED-TRANSPORT=TCP).
    pub enabled: bool,
    /// Outbound connect timeout to the peer, seconds.
    pub connect_timeout_secs: u64,
    /// Idle timeout for a connected-but-unbound peer connection, seconds.
    pub idle_timeout_secs: u64,
    /// Max concurrent TCP relay connections per allocation.
    pub max_per_allocation: usize,
    /// Max concurrent TCP relay connections total.
    pub max_total: usize,
    /// Per-direction relay buffer size, bytes.
    pub buffer_size: usize,
}

impl Default for TcpRelaySection {
    fn default() -> Self {
        Self {
            enabled: false,
            connect_timeout_secs: 30,
            idle_timeout_secs: 30,
            max_per_allocation: 10,
            max_total: 50_000,
            buffer_size: 16384,
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
// S4: runtime-config update mechanism (versioned immutable snapshot)
// ---------------------------------------------------------------------------
//
// The control-plane `update_config` command changes a *whitelisted* subset of
// configuration on a live node without a restart. The design rules are
// enforced jointly by the config domain, node apply path, durable backend and
// management RPC layer:
//
//   * Immutable snapshot: a change never mutates fields in place. It builds a
//     whole new `RuntimeSnapshot`, validates it in full, and only then publishes
//     it atomically through the node's `ArcSwap`. Validation failure changes
//     nothing.
//   * Optimistic concurrency: the caller passes `expected_version`; the apply
//     is rejected unless it equals the current snapshot version, so a stale
//     writer can never silently clobber a newer state.
//   * Observed version: every successful *change* bumps `version` by 1. A
//     command is terminal only after the node reports the resulting observed
//     snapshot.
//   * Whitelist only: fields that require rebinding/restart (listeners,
//     transport, relay port range, identity, backend credentials, production
//     safety flags) are NOT in `DynamicLimits` and are rejected up front as
//     `RestartRequired` — never applied "half way".
//
// The live read points are in `turna-session::AllocationStore`: bandwidth is
// read from the immutable limits snapshot on the packet path, while per-user,
// tenant and global allocation caps are enforced through atomic reservations.

/// The whitelisted, runtime-changeable configuration subset.
///
/// `0` keeps the existing "unlimited" convention for the quota fields and
/// "no per-user cap" for `max_per_user`, matching `QuotaConfig`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynamicLimits {
    /// Per-allocation bytes/sec cap. 0 = unlimited.
    pub max_bytes_per_sec_per_allocation: u64,
    /// Simultaneous allocations per username. 0 = no per-user cap.
    pub max_per_user: usize,
    /// Global allocation cap for this node.
    pub max_allocations: usize,
}

/// Immutable context needed to validate a `DynamicLimits` change. These are
/// restart-only fields (they are NOT changeable at runtime) but the dynamic
/// fields are validated against them — e.g. a global cap can never exceed the
/// usable relay-port count, which is fixed for the process lifetime.
#[derive(Debug, Clone, Copy)]
pub struct RuntimeValidationCtx {
    pub min_port: u16,
    pub max_port: u16,
    pub production: bool,
    pub allow_unlimited_bandwidth: bool,
}

impl RuntimeValidationCtx {
    pub fn from_config(cfg: &TurnaConfig) -> Self {
        Self {
            min_port: cfg.turn.relay.min_port,
            max_port: cfg.turn.relay.max_port,
            production: cfg.is_production(),
            allow_unlimited_bandwidth: cfg.turn.relay.quota.allow_unlimited_bandwidth,
        }
    }
}

impl DynamicLimits {
    pub fn from_config(cfg: &TurnaConfig) -> Self {
        Self {
            max_bytes_per_sec_per_allocation: cfg.turn.relay.quota.max_bytes_per_sec_per_allocation,
            max_per_user: cfg.turn.relay.quota.max_per_user,
            max_allocations: cfg.turn.relay.max_allocations,
        }
    }

    /// Validate this candidate against the immutable context. Mirrors the
    /// relevant rules in `TurnaConfig::validate` so a runtime change can never
    /// reach a state the startup validator would have rejected. Returns the
    /// list of hard errors (empty = valid). Reducing a limit below current
    /// live usage is intentionally NOT an error here — the store blocks new
    /// reservations until usage falls, without tearing active allocations.
    pub fn validate(&self, ctx: &RuntimeValidationCtx) -> Vec<String> {
        let mut errors = Vec::new();
        if ctx.min_port < ctx.max_port {
            let usable = (ctx.max_port - ctx.min_port) as usize + 1;
            if self.max_allocations > usable {
                errors.push(format!(
                    "max_allocations ({}) exceeds usable relay ports ({}) for range \
                     [{}, {}] — a cap above the port count is unreachable",
                    self.max_allocations, usable, ctx.min_port, ctx.max_port
                ));
            }
        }
        if ctx.production
            && self.max_bytes_per_sec_per_allocation == 0
            && !ctx.allow_unlimited_bandwidth
        {
            errors.push(
                "max_bytes_per_sec_per_allocation is 0 (unlimited) in production; set a per-allocation \
                 byte/sec cap (allow_unlimited_bandwidth is a restart-only opt-in)"
                    .into(),
            );
        }
        errors
    }
}

/// A partial change request. `None` fields are left unchanged. The apply step
/// builds the full candidate, validates it, and either swaps the whole thing
/// or rejects the whole thing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DynamicLimitsPatch {
    pub max_bytes_per_sec_per_allocation: Option<u64>,
    pub max_per_user: Option<usize>,
    pub max_allocations: Option<usize>,
}

impl DynamicLimitsPatch {
    pub fn is_empty(&self) -> bool {
        self.max_bytes_per_sec_per_allocation.is_none()
            && self.max_per_user.is_none()
            && self.max_allocations.is_none()
    }
}

/// The versioned, immutable runtime snapshot published on the node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeSnapshot {
    /// Monotonic observed version. The boot snapshot is version 0; every
    /// successful *change* increments it by 1.
    pub version: u64,
    pub limits: DynamicLimits,
}

/// Result of a successful apply. `changed = false` means the patch was a no-op
/// (already at the desired state): the version is unchanged and the caller
/// reports the current observed version — an idempotent success, not an error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedConfig {
    pub snapshot: RuntimeSnapshot,
    pub changed: bool,
}

/// Why a runtime config update was refused. Maps onto gRPC status codes in the
/// RPC mapping: `VersionMismatch`/`RestartRequired` → FailedPrecondition,
/// `ValidationFailed` → InvalidArgument.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigUpdateError {
    /// `expected_version` did not match the node's current version.
    VersionMismatch { expected: u64, actual: u64 },
    /// The candidate snapshot failed validation; nothing was changed.
    ValidationFailed(Vec<String>),
    /// One or more requested keys require a restart and were not applied.
    RestartRequired(Vec<String>),
    /// The version counter would overflow `u64`; nothing was changed.
    VersionOverflow,
}

impl std::fmt::Display for ConfigUpdateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigUpdateError::VersionMismatch { expected, actual } => write!(
                f,
                "version mismatch: expected {expected}, node is at {actual}"
            ),
            ConfigUpdateError::ValidationFailed(errs) => {
                write!(f, "config validation failed: {}", errs.join("; "))
            }
            ConfigUpdateError::RestartRequired(keys) => write!(
                f,
                "these fields require a restart and were not applied: {}",
                keys.join(", ")
            ),
            ConfigUpdateError::VersionOverflow => {
                write!(f, "config version counter overflow")
            }
        }
    }
}
impl std::error::Error for ConfigUpdateError {}

impl RuntimeSnapshot {
    /// The boot snapshot (version 0) derived from the startup config.
    pub fn from_config(cfg: &TurnaConfig) -> Self {
        Self {
            version: 0,
            limits: DynamicLimits::from_config(cfg),
        }
    }

    /// Apply a patch under optimistic concurrency. On success returns the next
    /// snapshot (version bumped) or a no-op (version unchanged). On any error
    /// the current snapshot is untouched — there is no partial application.
    pub fn apply(
        &self,
        patch: &DynamicLimitsPatch,
        expected_version: u64,
        ctx: &RuntimeValidationCtx,
    ) -> std::result::Result<AppliedConfig, ConfigUpdateError> {
        if expected_version != self.version {
            return Err(ConfigUpdateError::VersionMismatch {
                expected: expected_version,
                actual: self.version,
            });
        }
        let mut candidate = self.limits.clone();
        if let Some(v) = patch.max_bytes_per_sec_per_allocation {
            candidate.max_bytes_per_sec_per_allocation = v;
        }
        if let Some(v) = patch.max_per_user {
            candidate.max_per_user = v;
        }
        if let Some(v) = patch.max_allocations {
            candidate.max_allocations = v;
        }
        if candidate == self.limits {
            // No-op: idempotent success at the current version.
            return Ok(AppliedConfig {
                snapshot: self.clone(),
                changed: false,
            });
        }
        let errors = candidate.validate(ctx);
        if !errors.is_empty() {
            return Err(ConfigUpdateError::ValidationFailed(errors));
        }
        let next_version = self
            .version
            .checked_add(1)
            .ok_or(ConfigUpdateError::VersionOverflow)?;
        Ok(AppliedConfig {
            snapshot: RuntimeSnapshot {
                version: next_version,
                limits: candidate,
            },
            changed: true,
        })
    }
}

/// Whether a fully-qualified config key may be changed at runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldClass {
    /// In the runtime whitelist — expressible as a `DynamicLimitsPatch` field.
    Dynamic,
    /// Requires a restart (rebinding, identity, credentials, safety flags).
    RestartRequired,
    /// Not a recognised config key.
    Unknown,
}

/// Classify a fully-qualified config key for the `update_config` RPC. The RPC
/// rejects `RestartRequired`/`Unknown` keys up front (FailedPrecondition /
/// InvalidArgument) rather than silently ignoring them.
pub fn classify_config_key(key: &str) -> FieldClass {
    match key {
        "turn.relay.max_allocations"
        | "turn.relay.quota.max_bytes_per_sec_per_allocation"
        | "turn.relay.quota.max_per_user" => FieldClass::Dynamic,
        // Rebinding / identity / credentials / safety — restart only.
        "turn.listen"
        | "turn.external_ip"
        | "turn.realm"
        | "turn.transport"
        | "turn.relay.min_port"
        | "turn.relay.max_port"
        | "turn.relay.quota.allow_unlimited_bandwidth"
        | "production"
        | "health.listen"
        | "management.listen"
        | "cluster.node_id"
        | "cluster.backend.uri"
        | "cluster.backend.user"
        | "cluster.backend.password" => FieldClass::RestartRequired,
        _ => FieldClass::Unknown,
    }
}

#[cfg(test)]
mod runtime_update_tests {
    use super::*;

    fn ctx() -> RuntimeValidationCtx {
        RuntimeValidationCtx {
            min_port: 49152,
            max_port: 65535,
            production: false,
            allow_unlimited_bandwidth: false,
        }
    }

    fn snap() -> RuntimeSnapshot {
        RuntimeSnapshot {
            version: 3,
            limits: DynamicLimits {
                max_bytes_per_sec_per_allocation: 1_000_000,
                max_per_user: 100,
                max_allocations: 10_000,
            },
        }
    }

    #[test]
    fn version_mismatch_is_rejected_and_changes_nothing() {
        let s = snap();
        let patch = DynamicLimitsPatch {
            max_per_user: Some(50),
            ..Default::default()
        };
        let err = s.apply(&patch, 2, &ctx()).unwrap_err();
        assert_eq!(
            err,
            ConfigUpdateError::VersionMismatch {
                expected: 2,
                actual: 3
            }
        );
    }

    #[test]
    fn happy_path_bumps_version_and_applies() {
        let s = snap();
        let patch = DynamicLimitsPatch {
            max_per_user: Some(50),
            max_bytes_per_sec_per_allocation: Some(2_000_000),
            ..Default::default()
        };
        let applied = s.apply(&patch, 3, &ctx()).unwrap();
        assert!(applied.changed);
        assert_eq!(applied.snapshot.version, 4);
        assert_eq!(applied.snapshot.limits.max_per_user, 50);
        assert_eq!(
            applied.snapshot.limits.max_bytes_per_sec_per_allocation,
            2_000_000
        );
        // Untouched field preserved.
        assert_eq!(applied.snapshot.limits.max_allocations, 10_000);
    }

    #[test]
    fn version_counter_overflow_is_refused_without_change() {
        let mut s = snap();
        s.version = u64::MAX;
        // A real, validating change at the u64 boundary must refuse rather than
        // wrap/saturate: no snapshot is produced, so nothing is published.
        let patch = DynamicLimitsPatch {
            max_per_user: Some(50),
            ..Default::default()
        };
        let err = s.apply(&patch, u64::MAX, &ctx()).unwrap_err();
        assert_eq!(err, ConfigUpdateError::VersionOverflow);
    }

    #[test]
    fn empty_or_equal_patch_is_noop_without_version_bump() {
        let s = snap();
        let applied = s.apply(&DynamicLimitsPatch::default(), 3, &ctx()).unwrap();
        assert!(!applied.changed);
        assert_eq!(applied.snapshot.version, 3);
        // A patch that re-sets the same values is also a no-op.
        let same = DynamicLimitsPatch {
            max_per_user: Some(100),
            ..Default::default()
        };
        let applied = s.apply(&same, 3, &ctx()).unwrap();
        assert!(!applied.changed);
        assert_eq!(applied.snapshot.version, 3);
    }

    #[test]
    fn lowering_max_per_user_below_usage_still_validates() {
        // Validation does not know live usage; a lower cap is valid here and the
        // store blocks new reservations until usage falls (no active teardown).
        let s = snap();
        let patch = DynamicLimitsPatch {
            max_per_user: Some(1),
            ..Default::default()
        };
        let applied = s.apply(&patch, 3, &ctx()).unwrap();
        assert!(applied.changed);
        assert_eq!(applied.snapshot.limits.max_per_user, 1);
    }

    #[test]
    fn max_allocations_above_usable_ports_fails_validation() {
        let s = snap();
        let patch = DynamicLimitsPatch {
            // usable ports for [49152, 65535] = 16384
            max_allocations: Some(20_000),
            ..Default::default()
        };
        let err = s.apply(&patch, 3, &ctx()).unwrap_err();
        match err {
            ConfigUpdateError::ValidationFailed(errs) => {
                assert!(errs.iter().any(|e| e.contains("max_allocations")));
            }
            other => panic!("expected ValidationFailed, got {other:?}"),
        }
        // Snapshot untouched: still the original.
        assert_eq!(s.limits.max_allocations, 10_000);
    }

    #[test]
    fn external_ip6_must_be_ipv6_or_empty() {
        // Empty = IPv4-only relaying, the default.
        let cfg = TurnaConfig::default();
        assert!(
            cfg.turn.external_ip6.is_empty(),
            "IPv6 relaying is opt-in, so the default must be empty"
        );
        assert!(cfg.validate().is_ok(), "default config must validate");

        // An IPv4 literal here would advertise the wrong family for a v6-family
        // allocation, which is exactly what the 443 check exists to prevent.
        let mut cfg = TurnaConfig::default();
        cfg.turn.external_ip6 = "203.0.113.10".into();
        let err = cfg
            .validate()
            .expect_err("an IPv4 literal in external_ip6 must be rejected")
            .to_string()
            .to_lowercase();
        assert!(err.contains("external_ip6"), "unexpected error: {err}");

        // Garbage is rejected too.
        let mut cfg = TurnaConfig::default();
        cfg.turn.external_ip6 = "not-an-address".into();
        assert!(
            cfg.validate().is_err(),
            "garbage external_ip6 must be rejected"
        );

        // A real v6 literal validates.
        let mut cfg = TurnaConfig::default();
        cfg.turn.external_ip6 = "2001:db8::1".into();
        assert!(
            cfg.validate().is_ok(),
            "a valid IPv6 literal must be accepted"
        );
    }

    #[test]
    fn production_unlimited_bandwidth_fails_without_optin() {
        let s = snap();
        let prod = RuntimeValidationCtx {
            production: true,
            ..ctx()
        };
        let patch = DynamicLimitsPatch {
            max_bytes_per_sec_per_allocation: Some(0),
            ..Default::default()
        };
        let err = s.apply(&patch, 3, &prod).unwrap_err();
        assert!(matches!(err, ConfigUpdateError::ValidationFailed(_)));
    }

    #[test]
    fn field_classification() {
        assert_eq!(
            classify_config_key("turn.relay.max_allocations"),
            FieldClass::Dynamic
        );
        assert_eq!(
            classify_config_key("turn.relay.quota.max_per_user"),
            FieldClass::Dynamic
        );
        assert_eq!(
            classify_config_key("turn.listen"),
            FieldClass::RestartRequired
        );
        assert_eq!(
            classify_config_key("production"),
            FieldClass::RestartRequired
        );
        assert_eq!(
            classify_config_key("turn.relay.min_port"),
            FieldClass::RestartRequired
        );
        assert_eq!(classify_config_key("nonsense.key"), FieldClass::Unknown);
    }
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
    fn max_allocations_above_usable_ports_is_rejected() {
        // Default relay range 49152..=65535 => 16384 usable ports.
        let _guard = production_env_lock();
        let saved = std::env::var_os("TURNA_PRODUCTION");
        std::env::remove_var("TURNA_PRODUCTION");

        let mut cfg = TurnaConfig::default();
        cfg.turn.relay.max_allocations = 50_000; // > 16384 usable
        let over = cfg.validate();
        cfg.turn.relay.max_allocations = 16_384; // == usable -> ok
        let at_ceiling = cfg.validate();
        cfg.turn.relay.max_allocations = 8_192; // conservative -> ok (may warn)
        let conservative = cfg.validate();

        restore_turna_production(saved);
        assert!(over.is_err(), "cap above usable relay ports must fail");
        at_ceiling.unwrap();
        conservative.unwrap();
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
        // Session caps: bounded by default, per-IP opt-in. A config written
        // before these keys existed must keep parsing and get these values.
        assert_eq!(q.max_sessions, 10_000);
        assert_eq!(q.max_sessions_per_ip, 0, "per-IP cap is opt-in");
        assert_eq!(cfg.turn.quic.max_sessions, 10_000);
        assert_eq!(cfg.turn.quic.max_sessions_per_ip, 0);
    }

    #[test]
    fn quic_session_caps_parse() {
        let toml = r#"
            [turn]
            listen = "0.0.0.0:3478"

            [turn.quic]
            enabled = true
            max_sessions = 500
            max_sessions_per_ip = 4
            max_handshakes_per_sec_per_ip = 20
            handshake_burst_per_ip = 50
            cert_reload_secs = 0
        "#;
        let cfg: TurnaConfig = toml::from_str(toml).expect("quic caps parse");
        assert_eq!(cfg.turn.quic.max_sessions, 500);
        assert_eq!(cfg.turn.quic.max_sessions_per_ip, 4);
        assert_eq!(cfg.turn.quic.max_handshakes_per_sec_per_ip, 20);
        assert_eq!(cfg.turn.quic.handshake_burst_per_ip, 50);
        assert_eq!(cfg.turn.quic.cert_reload_secs, 0);
    }

    #[test]
    fn quic_rate_limit_is_off_by_default() {
        // Both rate knobs default to 0 (disabled), so an existing deployment sees
        // no behaviour change from their introduction.
        let q = QuicConfigSection::default();
        assert_eq!(q.max_handshakes_per_sec_per_ip, 0);
        assert_eq!(q.handshake_burst_per_ip, 0);
        assert_eq!(q.cert_reload_secs, 30);
    }

    #[test]
    fn tls_section_defaults_and_parse() {
        // TURNS lives in the ROOT `[tls]` section (not under `[turn]`).
        let t = TlsConfig::default();
        assert!(!t.enabled, "TURNS is opt-in");
        assert_eq!(t.listen.port(), 5349, "IANA TURNS port");
        assert_eq!(t.max_connections, 10_000);
        assert_eq!(t.max_connections_per_ip, 0, "per-IP cap is opt-in");
        assert_eq!(
            t.cert_reload_secs, 30,
            "certificate hot-reload on by default"
        );
        assert!(t.enable_alpn);
        assert_eq!(
            t.max_handshakes_per_sec_per_ip, 0,
            "handshake rate limit is opt-in, like the QUIC one"
        );
        assert_eq!(t.handshake_burst_per_ip, 0);
        assert!(!t.alpn_required, "ALPN strict mode is opt-in");
        assert!(
            t.client_ca.is_empty(),
            "client-certificate verification is opt-in: a public TURN server must \
             not require one"
        );
        assert!(!t.require_client_cert);

        let toml = r#"
            [turn]
            listen = "0.0.0.0:3478"

            [tls]
            enabled = true
            listen = "0.0.0.0:5349"
            cert_path = "/etc/turna/tls/cert.pem"
            key_path = "/etc/turna/tls/key.pem"
            max_connections = 200
            max_connections_per_ip = 8
            cert_reload_secs = 0
        "#;
        let cfg: TurnaConfig = toml::from_str(toml).expect("tls section parses");
        assert!(cfg.tls.enabled);
        assert_eq!(cfg.tls.max_connections, 200);
        assert_eq!(cfg.tls.max_connections_per_ip, 8);
        assert_eq!(cfg.tls.cert_reload_secs, 0, "0 disables hot-reload");
        // Untouched fields fall back to defaults.
        assert_eq!(cfg.tls.handshake_timeout_secs, 5);
        assert_eq!(cfg.tls.max_frame_size, 64 * 1024);
    }

    #[test]
    fn tls_section_rejects_unknown_key() {
        // deny_unknown_fields: a typo must fail loudly rather than be ignored
        // (an ignored `max_connections_per_ips` would silently leave the cap off).
        let toml = r#"
            [turn]
            listen = "0.0.0.0:3478"

            [tls]
            enabled = true
            max_connections_per_ips = 8
        "#;
        assert!(
            toml::from_str::<TurnaConfig>(toml).is_err(),
            "unknown [tls] key must be rejected"
        );
    }

    #[test]
    fn transport_sections_omitted_entirely_still_parse() {
        // Backward compatibility: a config predating the new keys (and the new
        // sections altogether) must parse and land on safe defaults.
        let toml = r#"
            [turn]
            listen = "0.0.0.0:3478"
            realm = "turna"
        "#;
        let cfg: TurnaConfig = toml::from_str(toml).expect("minimal config parses");
        assert!(!cfg.tls.enabled);
        assert!(!cfg.turn.quic.enabled);
        assert!(!cfg.turn.dtls.enabled);
        assert_eq!(cfg.tls.cert_reload_secs, 30);
        assert_eq!(cfg.turn.quic.max_sessions, 10_000);
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
        assert_eq!(cfg.turn.dtls.max_sessions_per_ip, 0, "per-IP cap is opt-in");
        assert_eq!(cfg.turn.dtls.outbound_queue_capacity, 1024);
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
    fn cluster_mode_empty_cluster_secret_is_hard_error() {
        // B3 / R5: unauthenticated gossip must not pass validation.
        let mut cfg = TurnaConfig::default();
        cfg.turn.external_ip = "203.0.113.1".into();
        cfg.cluster.cluster_mode = true;
        cfg.cluster.node_id = "node-a".into();
        cfg.cluster.cluster_name = "turna".into();
        cfg.cluster.cluster_secret.clear();

        let msg = cfg
            .validate()
            .expect_err("empty cluster_secret + cluster_mode must fail validation")
            .to_string();
        assert!(
            msg.contains("cluster_secret"),
            "validation error should call out cluster_secret, got: {msg}"
        );
    }

    #[test]
    fn tenant_placeholder_secret_in_production_is_error() {
        // I1: a tenant using the public placeholder secret must fail in prod.
        let mut cfg = TurnaConfig {
            production: true,
            ..Default::default()
        };
        cfg.turn.external_ip = "203.0.113.1".into();
        cfg.turn.auth.shared_secret = "a-real-non-placeholder-secret".into();
        cfg.signaling.turn_shared_secret = "a-real-non-placeholder-secret".into();
        cfg.tenants = vec![TenantConfig {
            id: "t1".into(),
            realm: "t1realm".into(),
            relay_port_range: [50000, 50100],
            shared_secret: DEFAULT_SHARED_SECRET.into(),
            static_users: Vec::new(),
            max_allocations: 0,
            quota: QuotaConfig::default(),
            listen: None,
        }];

        let msg = cfg
            .validate()
            .expect_err("tenant placeholder secret in production must fail")
            .to_string();
        assert!(
            msg.contains("placeholder"),
            "validation error should call out the placeholder secret, got: {msg}"
        );
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
        // Isolate from the process-global TURNA_PRODUCTION env: a concurrent
        // test (production_mode_validation_scenarios) sets it, and this minimal
        // dev config has no [turn.relay.quota], so a leaked prod flag would trip
        // B2's unlimited-bandwidth gate. Same pattern as example_config_parseable.
        let _guard = production_env_lock();
        let saved_turna_production = std::env::var_os("TURNA_PRODUCTION");
        std::env::remove_var("TURNA_PRODUCTION");

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

        match saved_turna_production {
            Some(v) => std::env::set_var("TURNA_PRODUCTION", v),
            None => std::env::remove_var("TURNA_PRODUCTION"),
        }
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
        // The example is a dev template; whether it validates now depends on
        // production mode (B2's unlimited-bandwidth gate). TURNA_PRODUCTION is
        // process-global and flipped by other tests, so serialise on the shared
        // lock and pin dev mode for the duration.
        let _guard = production_env_lock();
        let saved_turna_production = std::env::var_os("TURNA_PRODUCTION");
        std::env::remove_var("TURNA_PRODUCTION");
        // Set env var that example config references
        std::env::set_var("TURNA_SHARED_SECRET", "test");
        let config = TurnaConfig::from_str(&example_config()).unwrap();
        assert_eq!(config.turn.listen.port(), 3478);
        std::env::remove_var("TURNA_SHARED_SECRET");
        restore_turna_production(saved_turna_production);
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

[turn.relay.quota]
allow_unlimited_bandwidth = true

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

#[cfg(test)]
mod b2_bandwidth_optin_tests {
    use super::*;

    fn prod_base(quota_section: &str) -> String {
        format!(
            "production = true\n\n\
             [turn]\nexternal_ip = \"1.2.3.4\"\n\n\
             [turn.auth]\nshared_secret = \"deadbeef-this-is-a-real-secret-honest\"\n\n\
             {quota_section}\
             [signaling]\nturn_shared_secret = \"another-not-placeholder\"\n"
        )
    }

    #[test]
    fn b2_prod_unlimited_bandwidth_requires_optin() {
        // production=true in the file, so is_production() is true regardless of
        // the process-global TURNA_PRODUCTION env — no env lock needed.

        // Default quota (max_bytes_per_sec_per_allocation = 0) in prod, no opt-in → rejected.
        let err = TurnaConfig::from_str(&prod_base("")).expect_err("unlimited bw must fail");
        let msg = err.to_string().to_lowercase();
        assert!(
            msg.contains("bandwidth") || msg.contains("max_bytes_per_sec_per_allocation"),
            "expected a bandwidth error, got: {err}"
        );

        // Explicit opt-in → accepted.
        TurnaConfig::from_str(&prod_base(
            "[turn.relay.quota]\nallow_unlimited_bandwidth = true\n\n",
        ))
        .expect("explicit opt-in must validate");

        // A real cap → accepted.
        TurnaConfig::from_str(&prod_base(
            "[turn.relay.quota]\nmax_bytes_per_sec_per_allocation = 1000000\n\n",
        ))
        .expect("a concrete cap must validate");
    }

    #[test]
    fn unknown_backend_type_is_rejected() {
        let toml = "[cluster.backend]\ntype = \"tarantol\"\n";
        let err = TurnaConfig::from_str(toml)
            .expect_err("unknown backend type must fail validation")
            .to_string();
        assert!(
            err.contains("not a known backend"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn cluster_mode_with_memory_backend_is_rejected() {
        let toml = "[turn]\nexternal_ip = \"1.2.3.4\"\n\n\
                    [cluster]\ncluster_mode = true\nnode_id = \"n1\"\n\
                    cluster_name = \"turna\"\ncluster_secret = \"s3cr3t-not-empty\"\n\n\
                    [cluster.backend]\ntype = \"memory\"\n";
        let err = TurnaConfig::from_str(toml)
            .expect_err("cluster_mode + memory must fail")
            .to_string();
        assert!(
            err.contains("requires a shared state backend"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn command_log_config_defaults_and_invariants() {
        // Defaults enable GC and pass validation.
        let d = CommandLogConfig::default();
        assert!(d.gc_enabled());
        assert!(d.validate().is_ok());

        // Idempotency retention must outlive failed commands.
        let bad = CommandLogConfig {
            retain_idempotency_secs: CommandLogConfig::default().retain_failed_secs - 1,
            ..CommandLogConfig::default()
        };
        assert!(bad.validate().is_err());

        // ...and it must outlive the LONGEST terminal window, not just failed.
        // done = 60d while idempotency = 30d must be rejected (a long-retained
        // done command would outlive its idempotency guard otherwise).
        let day = 24 * 3600;
        let bad_done = CommandLogConfig {
            retain_done_secs: 60 * day,
            retain_failed_secs: 30 * day,
            retain_idempotency_secs: 30 * day,
            ..CommandLogConfig::default()
        };
        assert!(
            bad_done.validate().is_err(),
            "idempotency (30d) < done (60d) must be rejected"
        );
        // Raising idempotency to cover the longest window fixes it.
        let ok = CommandLogConfig {
            retain_idempotency_secs: 60 * day,
            ..bad_done
        };
        assert!(ok.validate().is_ok());

        // Disabling GC (interval 0) skips the batch/idempotency checks.
        let off = CommandLogConfig {
            sweep_interval_secs: 0,
            batch_size: 0,
            ..CommandLogConfig::default()
        };
        assert!(!off.gc_enabled());
        assert!(off.validate().is_ok());
    }
}
