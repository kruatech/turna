//! Regression tests for the in-repo example config and the
//! `deny_unknown_fields` schema discipline.
//!
//! # Why this used to be one literal assertion
//!
//! A previous version of `deploy/turn.toml` used the old flat `[auth]`
//! section instead of `[turn.auth]`. Serde silently dropped it and the
//! server fell back to `AuthConfig::default()` (with the placeholder
//! secret `change-me-in-production`). Nobody noticed for a long time
//! because no test loaded the actual example file.
//!
//! That regression is now caught two ways:
//!
//! 1. `#[serde(deny_unknown_fields)]` across the config schema. Unknown
//!    sections / typos produce a parse error rather than a silent
//!    fallback. See `unknown_top_level_key_is_rejected` and
//!    `unknown_nested_key_is_rejected` below.
//!
//! 2. This test loads `deploy/turn.toml` from disk and round-trips its
//!    `${VAR:-default}` substitutions, asserting both the default and
//!    the env-override path actually flow through.
//!
//! # Why one test, not three, for the on-disk loader
//!
//! `expand_env_vars` reads process-wide environment variables. Two
//! Rust tests touching the same env var concurrently race. We funnel
//! the file-loading scenarios through ONE `#[test]` function that
//! drives the env serially. The downside is less granular failure
//! messages; the upside is no flaky CI and no extra `serial_test`
//! crate dependency.
use std::path::PathBuf;
use turna_config::{TurnaConfig, DEFAULT_SHARED_SECRET};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

fn clear_turna_env() {
    for k in [
        "TURNA_PRODUCTION",
        "TURNA_LISTEN_ADDR",
        "TURNA_EXTERNAL_IP",
        "TURNA_REALM",
        "TURNA_SHARED_SECRET",
        "TURNA_OTLP_ENDPOINT",
        "TURNA_SIGNALING_ADDR",
        "TURNA_TURN_URL",
        "TURNA_HEALTH_ADDR",
        "TURNA_NODE_ID",
        "TURNA_CLUSTER_MODE",
        "TURNA_GOSSIP_BIND",
        "TURNA_GOSSIP_SEEDS",
        "TURNA_GOSSIP_INTERVAL_SECS",
        "TURNA_GOSSIP_TIMEOUT_SECS",
        "TURNA_TURN_ANNOUNCE_ADDR",
        "TURNA_BACKEND_TYPE",
        "TURNA_BACKEND_URI",
        "TURNA_PERSISTENCE_MODE",
        "TURNA_GRPC_ADDR",
        "TURNA_GRPC_TLS_MODE",
        "TURNA_GRPC_TLS_CERT",
        "TURNA_GRPC_TLS_KEY",
        "TURNA_GRPC_TLS_CA",
        "TURNA_USER_ALICE_PASSWORD",
        "TURNA_USER_BOB_PASSWORD",
    ] {
        std::env::remove_var(k);
    }
}

#[test]
fn deploy_turn_toml_load_scenarios() {
    let path = repo_root().join("deploy").join("turn.toml");
    assert!(
        path.exists(),
        "example config missing: {} — repo layout changed?",
        path.display()
    );

    // ── Scenario 1: load without any TURNA_* env vars set ────────────────────
    clear_turna_env();
    let config = TurnaConfig::load(path.to_str().unwrap())
        .expect("deploy/turn.toml failed to load with defaults — schema regression?");

    assert_eq!(
        config.turn.auth.shared_secret, DEFAULT_SHARED_SECRET,
        "without TURNA_SHARED_SECRET, the file's default should kick in"
    );
    assert_eq!(config.turn.realm, "turna");
    assert!(!config.signaling.turn_shared_secret.is_empty());
    assert!(!config.is_production());
    assert_eq!(config.grpc.tls_mode, "disabled");
    assert!(!config.grpc.is_enabled());

    // ── Scenario 2: env override flows through ${VAR:-default} ─────────────
    let real_secret = "real-secret-deadbeef-0123456789abcdef";
    std::env::set_var("TURNA_SHARED_SECRET", real_secret);
    std::env::set_var("TURNA_EXTERNAL_IP", "203.0.113.10");
    std::env::set_var("TURNA_REALM", "prod.example.com");

    let config = TurnaConfig::load(path.to_str().unwrap())
        .expect("deploy/turn.toml with env overrides must still validate");

    assert_eq!(config.turn.auth.shared_secret, real_secret);
    assert_eq!(config.signaling.turn_shared_secret, real_secret);
    assert_eq!(config.turn.external_ip, "203.0.113.10");
    assert_eq!(config.turn.realm, "prod.example.com");

    // ── Scenario 3: env-driven production mode rejects placeholder secret ──
    clear_turna_env();
    std::env::set_var("TURNA_PRODUCTION", "true");
    std::env::set_var("TURNA_EXTERNAL_IP", "203.0.113.10");
    let err = TurnaConfig::load(path.to_str().unwrap())
        .expect_err("production mode with default shared_secret must fail");
    let msg = err.to_string().to_lowercase();
    assert!(
        msg.contains("placeholder") || msg.contains("shared_secret"),
        "expected placeholder-secret error, got: {err}"
    );

    // ── Scenario 4: gRPC TLS overrides through env ─────────────────────────
    clear_turna_env();
    std::env::set_var("TURNA_GRPC_TLS_MODE", "mtls");
    std::env::set_var("TURNA_GRPC_TLS_CERT", "/etc/turna/server.pem");
    std::env::set_var("TURNA_GRPC_TLS_KEY", "/etc/turna/server-key.pem");
    std::env::set_var("TURNA_GRPC_TLS_CA", "/etc/turna/ca.pem");
    let config = TurnaConfig::load(path.to_str().unwrap())
        .expect("grpc env overrides must validate cleanly");
    assert_eq!(config.grpc.tls_mode, "mtls");
    assert_eq!(config.grpc.tls_cert, "/etc/turna/server.pem");
    assert_eq!(config.grpc.tls_key, "/etc/turna/server-key.pem");
    assert_eq!(config.grpc.tls_ca, "/etc/turna/ca.pem");
    assert!(config.grpc.is_enabled());
    assert!(config.grpc.requires_client_ca());

    // ── Scenario 5: mtls without tls_ca is rejected ────────────────────────
    clear_turna_env();
    std::env::set_var("TURNA_GRPC_TLS_MODE", "mtls");
    std::env::set_var("TURNA_GRPC_TLS_CERT", "/etc/turna/server.pem");
    std::env::set_var("TURNA_GRPC_TLS_KEY", "/etc/turna/server-key.pem");
    let err = TurnaConfig::load(path.to_str().unwrap())
        .expect_err("mtls with empty tls_ca must be rejected at validate()");
    let msg = err.to_string().to_lowercase();
    assert!(
        msg.contains("tls_ca") || msg.contains("ca"),
        "expected tls_ca error, got: {err}"
    );

    clear_turna_env();
}

#[test]
fn unknown_top_level_key_is_rejected() {
    let bad = r#"
[turn]
listen = "0.0.0.0:3478"

[turn.auth]
shared_secret = "s"

# Typo / stale schema: top-level [auth] (old layout). Must be rejected.
[auth]
shared_secret = "this would be silently dropped without deny_unknown_fields"

[signaling]
listen = "0.0.0.0:9001"
turn_shared_secret = "s"
"#;
    let err = TurnaConfig::from_str(bad).expect_err(
        "expected parse error for unknown top-level [auth] section, but load succeeded",
    );
    let msg = err.to_string().to_lowercase();
    assert!(
        msg.contains("unknown") || msg.contains("auth") || msg.contains("parse"),
        "unexpected error message: {err}"
    );
}

#[test]
fn unknown_nested_key_is_rejected() {
    let bad = r#"
[turn]
listen = "0.0.0.0:3478"

[turn.auth]
shared_secret = "s"
# Typo: not a real field of AuthConfig.
shared_seret = "typo"

[signaling]
listen = "0.0.0.0:9001"
turn_shared_secret = "s"
"#;
    let err = TurnaConfig::from_str(bad)
        .expect_err("expected parse error for typo `shared_seret`, but load succeeded");
    let msg = err.to_string().to_lowercase();
    assert!(
        msg.contains("unknown") || msg.contains("seret") || msg.contains("parse"),
        "unexpected error message: {err}"
    );
}
