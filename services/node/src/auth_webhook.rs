//! The HTTP side of `[turn.auth.webhook]`: drains the credential cache's fetch
//! queue, asks the operator's endpoint, and records the answer.
//!
//! The datapath never waits on anything in this file — see
//! `turna_auth::webhook` for where the cache sits and why. This is a plain
//! async worker: a bounded queue in, a semaphore on concurrency, one `reqwest`
//! client, redirects off, environment proxies ignored.
//!
//! TLS is rustls with an **explicit ring `CryptoProvider`** handed to reqwest as
//! a preconfigured `ClientConfig` (see [`tls_config`]). Nothing here depends on
//! which provider, if any, is installed as the process default, and nothing
//! here asks for aws-lc-rs. No OpenSSL.
//!
//! # What is logged
//!
//! Status codes, error kinds and latency. Never the USERNAME, the password or
//! keys in a response, the bearer token or the signature — the same rule as
//! the rest of the node (`docs/security/log-data-audit-2026-08-27.md`). A
//! failing endpoint logs at most once per power of two failures.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, Semaphore};
use tracing::{info, warn};
#[cfg(test)]
use turna_auth::webhook::WebhookSettings;
use turna_auth::webhook::{CredentialCache, FetchJob, FetchOutcome};
use turna_auth::UserKeys;
use turna_config::WebhookConfig;
use turna_health::Metrics;

/// Response bodies larger than this are a failure, not something to buffer.
const MAX_BODY_BYTES: usize = 16 * 1024;

/// The configured endpoint and the client that talks to it.
pub(crate) struct WebhookClient {
    client: reqwest::Client,
    url: String,
    bearer_token: String,
    signing_secret: Vec<u8>,
}

/// Start the fetcher for a cache the auth backend already holds.
///
/// Fails when the client cannot be built (an unreadable `ca_file`, a bad PEM):
/// startup stops rather than running with a credential path that can only ever
/// fail closed.
pub(crate) fn spawn_fetcher(
    cfg: &WebhookConfig,
    cache: Arc<CredentialCache>,
    rx: mpsc::Receiver<FetchJob>,
    metrics: Arc<Metrics>,
) -> Result<(), String> {
    let client = Arc::new(WebhookClient::new(cfg)?);
    tokio::spawn(run(
        rx,
        cache.clone(),
        client,
        cfg.max_concurrency,
        metrics.clone(),
    ));
    tokio::spawn(mirror(cache.clone(), metrics));
    info!(
        realm = cache.realm(),
        timeout_ms = cfg.timeout_ms,
        max_concurrency = cfg.max_concurrency,
        positive_ttl_secs = cfg.positive_ttl_secs,
        negative_ttl_secs = cfg.negative_ttl_secs,
        signed = !cfg.signing_secret.is_empty(),
        bearer = !cfg.bearer_token.is_empty(),
        "auth webhook enabled for users not configured locally"
    );
    Ok(())
}

/// Build a cache from `cfg` and start its fetcher. For tests; the node builds
/// the cache before the runtime exists and calls [`spawn_fetcher`].
#[cfg(test)]
pub(crate) fn start(
    cfg: &WebhookConfig,
    realm: &str,
    metrics: Arc<Metrics>,
) -> Result<Arc<CredentialCache>, String> {
    let (cache, rx) = CredentialCache::new(
        realm,
        WebhookSettings {
            positive_ttl: Duration::from_secs(cfg.positive_ttl_secs),
            negative_ttl: Duration::from_secs(cfg.negative_ttl_secs),
            error_ttl: Duration::from_secs(cfg.error_ttl_secs),
            max_entries: cfg.max_entries,
            queue_depth: cfg.queue_depth,
        },
    );
    spawn_fetcher(cfg, cache.clone(), rx, metrics)?;
    Ok(cache)
}

impl WebhookClient {
    pub(crate) fn new(cfg: &WebhookConfig) -> Result<Self, String> {
        let https = cfg.url.to_ascii_lowercase().starts_with("https://");
        let b = reqwest::Client::builder()
            .timeout(Duration::from_millis(cfg.timeout_ms))
            .connect_timeout(Duration::from_millis(cfg.timeout_ms))
            // A redirect would re-send the credential to wherever the response
            // points. The endpoint is configured; it has no reason to move.
            .redirect(reqwest::redirect::Policy::none())
            // Direct connection. HTTP(S)_PROXY in the node's environment is
            // for something else, and a proxy would see the bearer token on
            // plain-http test setups.
            .no_proxy()
            .pool_max_idle_per_host(cfg.max_concurrency)
            .user_agent(concat!("turna/", env!("CARGO_PKG_VERSION")))
            .https_only(https);
        // Always a preconfigured rustls config, so reqwest never picks a
        // provider itself. It is harmless on plain http:// (dev stubs).
        let b = b.tls_backend_preconfigured(tls_config(&cfg.ca_file)?);
        let client = b.build().map_err(|e| format!("auth webhook client: {e}"))?;
        Ok(Self {
            client,
            url: cfg.url.clone(),
            bearer_token: cfg.bearer_token.clone(),
            signing_secret: cfg.signing_secret.as_bytes().to_vec(),
        })
    }

    /// One lookup. Every path that is not a clean 200 or 404 is `Failed`.
    pub(crate) async fn fetch(&self, job: &FetchJob) -> (FetchOutcome, &'static str) {
        let body = serde_json::json!({
            "username": job.username,
            "realm": job.realm,
        })
        .to_string()
        .into_bytes();
        let mut req = self
            .client
            .post(&self.url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(reqwest::header::ACCEPT, "application/json");
        if !self.bearer_token.is_empty() {
            req = req.bearer_auth(&self.bearer_token);
        }
        if !self.signing_secret.is_empty() {
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            req = req.header("X-Turna-Timestamp", ts.to_string()).header(
                "X-Turna-Signature",
                turna_auth::webhook::sign_request(&self.signing_secret, ts, &body),
            );
        }
        let mut resp = match req.body(body).send().await {
            Ok(r) => r,
            Err(e) if e.is_timeout() => return (FetchOutcome::Failed, "timeout"),
            Err(e) if e.is_connect() => return (FetchOutcome::Failed, "connect"),
            Err(_) => return (FetchOutcome::Failed, "transport"),
        };
        match resp.status().as_u16() {
            200 => {}
            404 => return (FetchOutcome::NotFound, "not_found"),
            401 | 403 => return (FetchOutcome::Failed, "endpoint_rejected_turna"),
            _ => return (FetchOutcome::Failed, "status"),
        }
        if resp
            .content_length()
            .is_some_and(|n| n as usize > MAX_BODY_BYTES)
        {
            return (FetchOutcome::Failed, "body_too_large");
        }
        let mut buf = Vec::new();
        loop {
            match resp.chunk().await {
                Ok(Some(c)) => {
                    if buf.len() + c.len() > MAX_BODY_BYTES {
                        return (FetchOutcome::Failed, "body_too_large");
                    }
                    buf.extend_from_slice(&c);
                }
                Ok(None) => break,
                Err(e) if e.is_timeout() => return (FetchOutcome::Failed, "timeout"),
                Err(_) => return (FetchOutcome::Failed, "transport"),
            }
        }
        let outcome = parse_found(&buf, &job.username, &job.realm);
        // Zeroize the body: it may hold a plaintext password.
        {
            use zeroize::Zeroize;
            buf.zeroize();
        }
        match outcome {
            Some(o) => (o, "ok"),
            None => (FetchOutcome::Failed, "malformed_body"),
        }
    }
}

/// The rustls client configuration: ring, explicitly, with either the system
/// roots (through rustls-platform-verifier, built on the same ring provider) or
/// only the certificates in `ca_file`.
pub(crate) fn tls_config(ca_file: &str) -> Result<rustls::ClientConfig, String> {
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("auth webhook TLS: {e}"))?;
    let mut config = if ca_file.is_empty() {
        let verifier = rustls_platform_verifier::Verifier::new(provider)
            .map_err(|e| format!("auth webhook TLS: system roots: {e}"))?;
        builder
            .dangerous()
            .with_custom_certificate_verifier(std::sync::Arc::new(verifier))
            .with_no_client_auth()
    } else {
        use rustls::pki_types::{pem::PemObject, CertificateDer};
        let pem = std::fs::read(ca_file)
            .map_err(|e| format!("turn.auth.webhook.ca_file {ca_file}: {e}"))?;
        let mut roots = rustls::RootCertStore::empty();
        for cert in CertificateDer::pem_slice_iter(&pem) {
            let cert = cert.map_err(|e| format!("turn.auth.webhook.ca_file {ca_file}: {e}"))?;
            roots
                .add(cert)
                .map_err(|e| format!("turn.auth.webhook.ca_file {ca_file}: {e}"))?;
        }
        if roots.is_empty() {
            return Err(format!(
                "turn.auth.webhook.ca_file {ca_file} holds no certificate"
            ));
        }
        builder.with_root_certificates(roots).with_no_client_auth()
    };
    // reqwest is built without HTTP/2 here; say so in ALPN.
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}

/// The 200 body: `{"password": "..."}` or `{"key_md5": "<32 hex>",
/// "key_sha256": "<64 hex>"}` (either or both), plus optional `"ttl_secs"`.
/// `None` when it is none of those.
pub(crate) fn parse_found(body: &[u8], username: &str, realm: &str) -> Option<FetchOutcome> {
    #[derive(serde::Deserialize)]
    struct Found {
        #[serde(default)]
        password: Option<String>,
        #[serde(default)]
        key_md5: Option<String>,
        #[serde(default)]
        key_sha256: Option<String>,
        #[serde(default)]
        ttl_secs: Option<u64>,
    }
    let mut f: Found = serde_json::from_slice(body).ok()?;
    let ttl = f.ttl_secs.map(Duration::from_secs);
    let keys = if let Some(pw) = f.password.as_mut() {
        if f.key_md5.is_some() || f.key_sha256.is_some() || pw.is_empty() {
            use zeroize::Zeroize;
            pw.zeroize();
            return None;
        }
        let keys = UserKeys::derive(username, realm, pw);
        use zeroize::Zeroize;
        pw.zeroize();
        keys
    } else {
        let md5 = match &f.key_md5 {
            Some(h) => Some(decode_hex_exact(h, 16)?),
            None => None,
        };
        let sha = match &f.key_sha256 {
            Some(h) => Some(decode_hex_exact(h, 32)?),
            None => None,
        };
        if md5.is_none() && sha.is_none() {
            return None;
        }
        UserKeys {
            key_md5: md5.unwrap_or_default(),
            key_sha256: sha.unwrap_or_default(),
        }
    };
    Some(FetchOutcome::Found { keys, ttl })
}

fn decode_hex_exact(s: &str, len: usize) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() != len * 2 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    (0..len)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok())
        .collect()
}

static FAILURES: AtomicU64 = AtomicU64::new(0);

async fn run(
    mut rx: mpsc::Receiver<FetchJob>,
    cache: Arc<CredentialCache>,
    client: Arc<WebhookClient>,
    max_concurrency: usize,
    metrics: Arc<Metrics>,
) {
    let slots = Arc::new(Semaphore::new(max_concurrency.max(1)));
    while let Some(job) = rx.recv().await {
        // Back-pressure: while every slot is busy, jobs wait in the bounded
        // queue, and once that is full the datapath fails new lookups closed.
        let Ok(permit) = slots.clone().acquire_owned().await else {
            break;
        };
        let cache = cache.clone();
        let client = client.clone();
        let metrics = metrics.clone();
        tokio::spawn(async move {
            let started = Instant::now();
            metrics
                .auth_webhook_requests
                .fetch_add(1, Ordering::Relaxed);
            let (outcome, kind) = client.fetch(&job).await;
            metrics
                .histograms
                .observe("turna_auth_webhook_duration_seconds", started.elapsed());
            match &outcome {
                FetchOutcome::Found { .. } => {}
                FetchOutcome::NotFound => {
                    metrics
                        .auth_webhook_not_found
                        .fetch_add(1, Ordering::Relaxed);
                }
                FetchOutcome::Failed => {
                    metrics.auth_webhook_errors.fetch_add(1, Ordering::Relaxed);
                    let n = FAILURES.fetch_add(1, Ordering::Relaxed) + 1;
                    if n.is_power_of_two() {
                        // No username, no URL query, no credential: the kind
                        // and the count are what an operator can act on.
                        warn!(
                            reason = kind,
                            occurrences = n,
                            elapsed_ms = started.elapsed().as_millis() as u64,
                            "auth webhook lookup failed; requests for that user are \
                             refused (500) until error_ttl_secs passes"
                        );
                    }
                }
            }
            cache.complete(&job.username, outcome);
            drop(permit);
        });
    }
}

/// Copy the cache's counters into Prometheus and sweep expired entries.
async fn mirror(cache: Arc<CredentialCache>, metrics: Arc<Metrics>) {
    let mut tick = tokio::time::interval(Duration::from_secs(5));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tick.tick().await;
        cache.sweep();
        let s = &cache.stats;
        let l = |a: &AtomicU64| a.load(Ordering::Relaxed);
        metrics
            .auth_webhook_cache_hits
            .store(l(&s.hits), Ordering::Relaxed);
        metrics
            .auth_webhook_cache_negative_hits
            .store(l(&s.negative_hits), Ordering::Relaxed);
        metrics
            .auth_webhook_cache_misses
            .store(l(&s.misses), Ordering::Relaxed);
        metrics
            .auth_webhook_rejected
            .store(l(&s.rejected), Ordering::Relaxed);
        metrics
            .auth_webhook_cache_entries
            .store(cache.len() as u64, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    // Fixtures come from the environment (.env.test.example), never literals.
    fn env(name: &str) -> String {
        std::env::var(name).unwrap_or_else(|_| panic!("{name} is not set — source .env.test"))
    }

    fn secret() -> String {
        env("TURNA_TEST_PW_V1")
    }

    /// A one-shot HTTP/1.1 server: answers each connection with `status` and
    /// `body`, and hands the raw request back for inspection.
    async fn stub(
        status: u16,
        body: &'static str,
        delay: Duration,
    ) -> (String, mpsc::Receiver<String>) {
        let (url, rx, _) = stub_counted(status, body, delay).await;
        (url, rx)
    }

    /// As [`stub`], also reporting the most requests it ever held at once.
    async fn stub_counted(
        status: u16,
        body: &'static str,
        delay: Duration,
    ) -> (String, mpsc::Receiver<String>, Arc<AtomicU64>) {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/turn/credentials", l.local_addr().unwrap());
        let (tx, rx) = mpsc::channel(64);
        let active = Arc::new(AtomicU64::new(0));
        let peak = Arc::new(AtomicU64::new(0));
        let peak_out = peak.clone();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                let tx = tx.clone();
                let active = active.clone();
                let peak = peak.clone();
                tokio::spawn(async move {
                    let now = active.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(now, Ordering::SeqCst);
                    let mut buf = vec![0u8; 8192];
                    let mut got = 0;
                    // Read until the headers and the declared body are in.
                    loop {
                        let n = s.read(&mut buf[got..]).await.unwrap_or(0);
                        if n == 0 {
                            break;
                        }
                        got += n;
                        let text = String::from_utf8_lossy(&buf[..got]).to_string();
                        if let Some(h) = text.find("\r\n\r\n") {
                            let cl = text
                                .lines()
                                .find_map(|l| {
                                    l.to_ascii_lowercase()
                                        .strip_prefix("content-length:")
                                        .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                                })
                                .unwrap_or(0);
                            if got >= h + 4 + cl {
                                break;
                            }
                        }
                    }
                    let _ = tx
                        .send(String::from_utf8_lossy(&buf[..got]).to_string())
                        .await;
                    tokio::time::sleep(delay).await;
                    let resp = format!(
                        "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\n\
                         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = s.write_all(resp.as_bytes()).await;
                    active.fetch_sub(1, Ordering::SeqCst);
                });
            }
        });
        (url, rx, peak_out)
    }

    fn cfg(url: &str) -> WebhookConfig {
        WebhookConfig {
            enabled: true,
            url: url.into(),
            bearer_token: env("TURNA_TEST_PW_T1"),
            signing_secret: env("TURNA_TEST_PW_V2"),
            timeout_ms: 500,
            ..WebhookConfig::default()
        }
    }

    fn job() -> FetchJob {
        FetchJob {
            username: "alice".into(),
            realm: "turna".into(),
        }
    }

    #[tokio::test]
    async fn found_by_password_is_derived_and_the_request_is_signed() {
        let body: &'static str = Box::leak(
            format!("{{\"password\":\"{}\",\"ttl_secs\":60}}", secret()).into_boxed_str(),
        );
        let (url, mut seen) = stub(200, body, Duration::ZERO).await;
        let c = WebhookClient::new(&cfg(&url)).unwrap();
        let (out, kind) = c.fetch(&job()).await;
        assert_eq!(kind, "ok");
        match out {
            FetchOutcome::Found { keys, ttl } => {
                let want = UserKeys::derive("alice", "turna", &secret());
                assert_eq!(keys.key_md5, want.key_md5);
                assert_eq!(keys.key_sha256, want.key_sha256);
                assert_eq!(ttl, Some(Duration::from_secs(60)));
            }
            other => panic!("expected Found, got {other:?}"),
        }
        let req = seen.recv().await.unwrap();
        assert!(req.starts_with("POST /turn/credentials HTTP/1.1"));
        let lower = req.to_ascii_lowercase();
        assert!(
            lower.contains(&format!(
                "authorization: bearer {}",
                env("TURNA_TEST_PW_T1").to_ascii_lowercase()
            )),
            "bearer token header"
        );
        let ts: u64 = lower
            .lines()
            .find_map(|l| l.strip_prefix("x-turna-timestamp:"))
            .map(|v| v.trim().parse().unwrap())
            .expect("timestamp header");
        let body_sent = &req[req.find("\r\n\r\n").unwrap() + 4..];
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(body_sent).unwrap(),
            serde_json::json!({"username": "alice", "realm": "turna"})
        );
        let want_sig = turna_auth::webhook::sign_request(
            env("TURNA_TEST_PW_V2").as_bytes(),
            ts,
            body_sent.as_bytes(),
        );
        assert!(
            lower.contains(&format!("x-turna-signature: {want_sig}")),
            "signature header must be v1=HMAC-SHA256(secret, ts.body)"
        );
    }

    #[tokio::test]
    async fn found_by_keys_404_and_errors() {
        let md5 = "00112233445566778899aabbccddeeff";
        let body: &'static str = Box::leak(format!("{{\"key_md5\":\"{md5}\"}}").into_boxed_str());
        let (url, _) = stub(200, body, Duration::ZERO).await;
        let (out, _) = WebhookClient::new(&cfg(&url)).unwrap().fetch(&job()).await;
        match out {
            FetchOutcome::Found { keys, .. } => {
                assert_eq!(keys.key_md5.len(), 16);
                assert!(keys.key_sha256.is_empty());
            }
            other => panic!("{other:?}"),
        }

        let (url, _) = stub(404, "{}", Duration::ZERO).await;
        let (out, _) = WebhookClient::new(&cfg(&url)).unwrap().fetch(&job()).await;
        assert!(matches!(out, FetchOutcome::NotFound));

        for (status, body, want) in [
            (500, "{}", "status"),
            (403, "{}", "endpoint_rejected_turna"),
            (200, "not json", "malformed_body"),
            (200, "{}", "malformed_body"),
            (200, "{\"key_md5\":\"zz\"}", "malformed_body"),
        ] {
            let (url, _) = stub(status, body, Duration::ZERO).await;
            let (out, kind) = WebhookClient::new(&cfg(&url)).unwrap().fetch(&job()).await;
            assert!(matches!(out, FetchOutcome::Failed), "{status} {body}");
            assert_eq!(kind, want, "{status} {body}");
        }
    }

    #[tokio::test]
    async fn timeout_is_a_failure() {
        let (url, _) = stub(200, "{}", Duration::from_secs(3)).await;
        let started = Instant::now();
        let (out, kind) = WebhookClient::new(&cfg(&url)).unwrap().fetch(&job()).await;
        assert!(matches!(out, FetchOutcome::Failed));
        assert_eq!(kind, "timeout");
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[tokio::test]
    async fn unreachable_endpoint_is_a_failure() {
        // Bind and drop: the port is closed.
        let port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let (out, _) = WebhookClient::new(&cfg(&format!("http://127.0.0.1:{port}/x")))
            .unwrap()
            .fetch(&job())
            .await;
        assert!(matches!(out, FetchOutcome::Failed));
    }

    #[tokio::test]
    async fn end_to_end_through_the_cache_with_bounded_concurrency() {
        let body: &'static str =
            Box::leak(format!("{{\"password\":\"{}\"}}", secret()).into_boxed_str());
        let (url, _, peak) = stub_counted(200, body, Duration::from_millis(100)).await;
        let metrics = Arc::new(Metrics::new());
        let mut c = cfg(&url);
        c.max_concurrency = 2;
        let cache = start(&c, "turna", metrics.clone()).unwrap();
        let mut waits = Vec::new();
        for i in 0..6 {
            match cache.lookup(&format!("user{i}")) {
                turna_auth::webhook::Lookup::Pending(w) => waits.push(w),
                other => panic!("{other:?}"),
            }
        }
        for w in waits {
            tokio::time::timeout(Duration::from_secs(5), w.wait())
                .await
                .expect("every lookup completes");
        }
        assert!(matches!(
            cache.lookup("user3"),
            turna_auth::webhook::Lookup::Found(_)
        ));
        assert_eq!(metrics.auth_webhook_requests.load(Ordering::Relaxed), 6);
        assert_eq!(metrics.auth_webhook_errors.load(Ordering::Relaxed), 0);
        let peak = peak.load(Ordering::SeqCst);
        assert!(
            (1..=2).contains(&peak),
            "max_concurrency = 2, but the endpoint saw {peak} requests at once"
        );
    }

    #[test]
    fn parse_rejects_ambiguous_or_malformed_answers() {
        assert!(parse_found(
            br#"{"password":"a","key_md5":"00112233445566778899aabbccddeeff"}"#,
            "u",
            "r"
        )
        .is_none());
        assert!(parse_found(br#"{"password":""}"#, "u", "r").is_none());
        assert!(parse_found(br#"{"key_sha256":"0011"}"#, "u", "r").is_none());
        assert!(parse_found(br#"[]"#, "u", "r").is_none());
    }

    #[test]
    fn tls_uses_ring_whatever_the_process_default() {
        let c = tls_config("").expect("system roots load");
        // The whole provider (suites, key provider, RNG) is ring's.
        assert_eq!(
            format!("{:?}", c.crypto_provider()),
            format!("{:?}", rustls::crypto::ring::default_provider())
        );
        // A PEM file that holds no certificate is refused.
        let dir = std::env::temp_dir().join(format!("turna-wh-ca-{}", std::process::id()));
        std::fs::write(&dir, b"not a pem").unwrap();
        assert!(tls_config(dir.to_str().unwrap()).is_err());
        let _ = std::fs::remove_file(&dir);
    }

    /// reqwest accepts the preconfigured ring `ClientConfig` (a version skew
    /// would make `build()` fail with an unknown TLS backend), and an https
    /// request goes through it.
    #[tokio::test]
    async fn https_client_builds_on_the_preconfigured_ring_config() {
        let port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let c = WebhookClient::new(&cfg(&format!("https://127.0.0.1:{port}/x")))
            .expect("client builds");
        let (out, kind) = c.fetch(&job()).await;
        assert!(matches!(out, FetchOutcome::Failed));
        assert_eq!(kind, "connect");
    }

    #[test]
    fn a_bad_ca_file_fails_startup() {
        let mut c = cfg("https://sig.example/turn");
        c.ca_file = "/nonexistent/ca.pem".into();
        assert!(WebhookClient::new(&c).is_err());
    }
}
