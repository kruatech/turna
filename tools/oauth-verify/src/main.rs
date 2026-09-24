//! `turna-oauth-verify` — RFC 7635 verification kit for turna.
//!
//! The procedure that uses it is `docs/runbooks/oauth-verification.md`. In short:
//!
//! ```text
//! # 1. Does turna read your AS's token format? (no node needed)
//! turna-oauth-verify inspect --server-name turn.example.com \
//!     --as-rs-key-hex <key the AS and turna share> --token <access_token from the AS>
//!
//! # 2. Does the node accept it, end to end?
//! turna-oauth-verify exercise --server 203.0.113.10:3478 \
//!     --token <access_token> --mac-key-b64 <key from the AS response> [--kid <kid>]
//!
//! # Plumbing check without an AS (NOT evidence for lifting the gate):
//! turna-oauth-verify selftest --server 127.0.0.1:3478 \
//!     --as-rs-key-hex <key in the node's config> --server-name turn.example.com
//! ```
//!
//! Exit status 0 when every step passed, 1 when any failed, 2 on bad input.

use std::net::SocketAddr;
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand};
use turna_oauth_verify::{
    exercise, expect_refused, inspect, mint, now_secs, parse_b64, parse_hex, to_b64, to_hex,
    ExerciseOptions, Step,
};

#[derive(Parser)]
#[command(
    name = "turna-oauth-verify",
    about = "Mint, inspect and exercise RFC 7635 self-contained OAuth tokens against turna"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Mint a token exactly as an authorization server does and print the AS
    /// response (RFC 7635 §4.1 shape).
    Mint {
        #[arg(long)]
        as_rs_key_hex: String,
        #[arg(long)]
        server_name: String,
        /// Seconds the token is valid.
        #[arg(long, default_value_t = 3600)]
        lifetime: u32,
        /// mac_key size: 20 (HMAC-SHA-1) or 32 (HMAC-SHA-256).
        #[arg(long, default_value_t = 32)]
        mac_key_len: usize,
        /// Echoed as "kid" in the output; configure the same kid on the node.
        #[arg(long)]
        kid: Option<String>,
    },
    /// Open a token minted by your AS with turna's decoder.
    Inspect {
        /// base64 (standard or URL-safe)
        #[arg(long)]
        token: String,
        /// Repeat for every key in the node's keyring.
        #[arg(long = "as-rs-key-hex", required = true)]
        as_rs_keys_hex: Vec<String>,
        #[arg(long)]
        server_name: String,
    },
    /// Run the full client flow against a node with a token from your AS.
    Exercise {
        #[arg(long)]
        server: SocketAddr,
        /// base64 access_token from the AS.
        #[arg(long)]
        token: String,
        /// The session key from the AS response, base64 (the RFC 7635 "key").
        #[arg(long, conflicts_with = "mac_key_hex")]
        mac_key_b64: Option<String>,
        /// The session key, hex.
        #[arg(long)]
        mac_key_hex: Option<String>,
        /// Sent as USERNAME for kid-based key selection.
        #[arg(long)]
        kid: Option<String>,
        /// Sign with MESSAGE-INTEGRITY-SHA256 (RFC 8489) instead of SHA-1.
        #[arg(long)]
        sha256: bool,
        /// Peer address for CreatePermission (no traffic is sent to it).
        #[arg(long, default_value = "8.8.8.8")]
        peer: std::net::IpAddr,
        #[arg(long, default_value_t = 1000)]
        timeout_ms: u64,
        /// Skip the tampered-token and wrong-key cases.
        #[arg(long)]
        no_negative: bool,
    },
    /// Mint tokens for the node's own key and exercise it, including expired and
    /// wrong-server tokens. Proves the plumbing, not interop with a real AS.
    Selftest {
        #[arg(long)]
        server: SocketAddr,
        #[arg(long)]
        as_rs_key_hex: String,
        #[arg(long)]
        server_name: String,
        #[arg(long)]
        kid: Option<String>,
        #[arg(long, default_value = "8.8.8.8")]
        peer: std::net::IpAddr,
        #[arg(long, default_value_t = 1000)]
        timeout_ms: u64,
    },
}

fn report(steps: &[Step]) -> ExitCode {
    for s in steps {
        println!("{s}");
    }
    let failed = steps.iter().filter(|s| !s.ok).count();
    if failed == 0 && !steps.is_empty() {
        println!("RESULT: PASS ({} steps)", steps.len());
        ExitCode::SUCCESS
    } else {
        println!("RESULT: FAIL ({failed} of {} steps)", steps.len());
        ExitCode::from(1)
    }
}

fn bad(msg: impl std::fmt::Display) -> ExitCode {
    eprintln!("error: {msg}");
    ExitCode::from(2)
}

fn main() -> ExitCode {
    match Cli::parse().cmd {
        Cmd::Mint {
            as_rs_key_hex,
            server_name,
            lifetime,
            mac_key_len,
            kid,
        } => {
            let key = match parse_hex(&as_rs_key_hex) {
                Ok(k) => k,
                Err(e) => return bad(format!("--as-rs-key-hex: {e}")),
            };
            match mint(&key, &server_name, mac_key_len, now_secs(), lifetime) {
                Ok(m) => {
                    // The shape of an RFC 7635 §4.1 AS response. The mac_key is
                    // printed because that is what an AS hands the client; treat
                    // the output as a credential.
                    println!("{{");
                    println!("  \"access_token\": \"{}\",", to_b64(&m.token));
                    println!("  \"token_type\": \"pop\",");
                    println!("  \"expires_in\": {},", m.lifetime);
                    if let Some(k) = kid {
                        println!("  \"kid\": \"{k}\",");
                    }
                    println!("  \"key\": \"{}\",", to_b64(&m.mac_key));
                    println!("  \"key_hex\": \"{}\",", to_hex(&m.mac_key));
                    println!(
                        "  \"alg\": \"{}\",",
                        if m.mac_key.len() == 20 {
                            "HMAC-SHA-1"
                        } else {
                            "HMAC-SHA-256"
                        }
                    );
                    println!("  \"issued_at\": {}", m.timestamp_secs);
                    println!("}}");
                    ExitCode::SUCCESS
                }
                Err(e) => bad(e),
            }
        }
        Cmd::Inspect {
            token,
            as_rs_keys_hex,
            server_name,
        } => {
            let token = match parse_b64(&token) {
                Ok(t) => t,
                Err(e) => return bad(format!("--token: {e}")),
            };
            let mut keys = Vec::new();
            for k in &as_rs_keys_hex {
                match parse_hex(k) {
                    Ok(k) => keys.push(k),
                    Err(e) => return bad(format!("--as-rs-key-hex: {e}")),
                }
            }
            match inspect(&token, &keys, &server_name) {
                Ok(r) => {
                    print!("{r}");
                    println!("RESULT: PASS (turna opens this token)");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    println!("RESULT: FAIL — {e}");
                    ExitCode::from(1)
                }
            }
        }
        Cmd::Exercise {
            server,
            token,
            mac_key_b64,
            mac_key_hex,
            kid,
            sha256,
            peer,
            timeout_ms,
            no_negative,
        } => {
            let token = match parse_b64(&token) {
                Ok(t) => t,
                Err(e) => return bad(format!("--token: {e}")),
            };
            let mac_key = match (mac_key_b64, mac_key_hex) {
                (Some(b), None) => parse_b64(&b),
                (None, Some(h)) => parse_hex(&h),
                _ => Err("give exactly one of --mac-key-b64 / --mac-key-hex".into()),
            };
            let mac_key = match mac_key {
                Ok(k) => k,
                Err(e) => return bad(format!("mac key: {e}")),
            };
            report(&exercise(&ExerciseOptions {
                server,
                token,
                mac_key,
                kid,
                sha256,
                peer,
                timeout: Duration::from_millis(timeout_ms),
                negative: !no_negative,
            }))
        }
        Cmd::Selftest {
            server,
            as_rs_key_hex,
            server_name,
            kid,
            peer,
            timeout_ms,
        } => {
            let key = match parse_hex(&as_rs_key_hex) {
                Ok(k) => k,
                Err(e) => return bad(format!("--as-rs-key-hex: {e}")),
            };
            let timeout = Duration::from_millis(timeout_ms);
            let mut steps = Vec::new();
            for (mac_len, sha256) in [(20usize, false), (32, true)] {
                let m = match mint(&key, &server_name, mac_len, now_secs(), 600) {
                    Ok(m) => m,
                    Err(e) => return bad(e),
                };
                println!(
                    "-- minted token, {mac_len}-byte mac_key, {}",
                    if sha256 {
                        "MESSAGE-INTEGRITY-SHA256"
                    } else {
                        "MESSAGE-INTEGRITY (SHA-1)"
                    }
                );
                steps.extend(exercise(&ExerciseOptions {
                    server,
                    token: m.token,
                    mac_key: m.mac_key,
                    kid: kid.clone(),
                    sha256,
                    peer,
                    timeout,
                    negative: true,
                }));
            }
            match mint(&key, &server_name, 20, now_secs() - 7_200, 60) {
                Ok(m) => steps.push(expect_refused(
                    server,
                    timeout,
                    &m.token,
                    &m.mac_key,
                    "expired token refused",
                )),
                Err(e) => return bad(e),
            }
            match mint(&key, "not-this-server.invalid", 20, now_secs(), 600) {
                Ok(m) => steps.push(expect_refused(
                    server,
                    timeout,
                    &m.token,
                    &m.mac_key,
                    "other server's token refused",
                )),
                Err(e) => return bad(e),
            }
            println!("NOTE: selftest proves the node and this kit agree. Evidence for");
            println!("      lifting the production gate is `exercise` with tokens from");
            println!("      your real authorization server.");
            report(&steps)
        }
    }
}
