//! Usage accounting sinks: JSON-lines file and HTTP(S) webhook.
//!
//! # Shape
//!
//! ```text
//! AllocationStore ──try_send──▶ [queue_capacity] ──▶ dispatcher ──▶ file (append, one line per record)
//!   (Stop records at teardown)                         │  ▲
//!                                                      │  └─ interim tick: store.interim_usage_records()
//!                                                      └─try_send──▶ [max_pending_batches × batch_size] ──▶ webhook sender
//!                                                                                      (batch, POST, retry with backoff)
//! ```
//!
//! Every hand-off is a bounded `try_send`. A full queue drops the record and
//! counts it (`turna_accounting_records_dropped_total{reason=…}`); nothing here
//! can block allocation teardown or the datapath. That is a deliberate trade: a
//! billing record lost under an overload is visible and bounded, a relay stalled
//! by a slow billing endpoint is an outage for every user.
//!
//! # Delivery
//!
//! At least once. A POST that timed out may have been processed, and is retried.
//! Every record carries a deterministic `record_id` (node, allocation id, kind,
//! event time), which is what the receiver deduplicates on.
//!
//! # Segments
//!
//! Counters are per node. An allocation that moves to another node (failover
//! rehydrate) starts from zero there, and its records carry that node's `node`.
//! Sum `stop` records per `(allocation_id, node)` segment.

use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, watch};
use tracing::{info, warn};
use turna_session::{AllocationStore, UsageRecord, UsageRecordKind};

/// Resolved `[turn.accounting]`.
#[derive(Debug, Clone)]
pub struct AccountingSettings {
    pub node_id: String,
    pub include_addresses: bool,
    pub queue_capacity: usize,
    pub interim: Option<Duration>,
    pub file: Option<PathBuf>,
    pub webhook: Option<WebhookSettings>,
}

#[derive(Clone)]
pub struct WebhookSettings {
    pub url: String,
    pub authorization: String,
    pub batch_size: usize,
    pub flush_interval: Duration,
    pub max_retries: u32,
    pub timeout: Duration,
    pub max_pending_batches: usize,
}

// Hand-written so the Authorization header can never reach a log line through a
// `{:?}` of the settings.
impl std::fmt::Debug for WebhookSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebhookSettings")
            .field("url", &self.url)
            .field(
                "authorization",
                &if self.authorization.is_empty() {
                    "<none>"
                } else {
                    "<set>"
                },
            )
            .field("batch_size", &self.batch_size)
            .field("flush_interval", &self.flush_interval)
            .field("max_retries", &self.max_retries)
            .field("timeout", &self.timeout)
            .field("max_pending_batches", &self.max_pending_batches)
            .finish()
    }
}

impl AccountingSettings {
    /// `None` when accounting is off.
    pub fn from_config(cfg: &turna_config::AccountingConfig, node_id: &str) -> Option<Self> {
        if !cfg.enabled {
            return None;
        }
        let w = &cfg.webhook;
        Some(Self {
            node_id: node_id.to_string(),
            include_addresses: cfg.include_addresses,
            queue_capacity: cfg.queue_capacity.max(1),
            interim: (cfg.interim_interval_secs > 0)
                .then(|| Duration::from_secs(cfg.interim_interval_secs)),
            file: (!cfg.file.path.is_empty()).then(|| PathBuf::from(&cfg.file.path)),
            webhook: (!w.url.is_empty()).then(|| WebhookSettings {
                url: w.url.clone(),
                authorization: w.authorization.clone(),
                batch_size: w.batch_size.max(1),
                flush_interval: Duration::from_secs(w.flush_interval_secs.max(1)),
                max_retries: w.max_retries,
                timeout: Duration::from_secs(w.timeout_secs.max(1)),
                max_pending_batches: w.max_pending_batches.max(1),
            }),
        })
    }
}

/// Counters mirrored into `turna_health::Metrics` by the node.
#[derive(Default)]
pub struct AccountingCounters {
    pub stop_records: AtomicU64,
    pub interim_records: AtomicU64,
    pub dropped_webhook_queue_full: AtomicU64,
    pub dropped_webhook_failed: AtomicU64,
    pub dropped_file_error: AtomicU64,
    pub webhook_batches: AtomicU64,
    pub webhook_retries: AtomicU64,
}

/// One record as a JSON object. Schema version `v = 1`; field names are a
/// contract with whatever bills from them.
pub fn record_json(r: &UsageRecord, node_id: &str, include_addresses: bool) -> serde_json::Value {
    let mut o = serde_json::json!({
        "v": 1,
        "record_id": format!("{node_id}:{}:{}:{}", r.allocation_id, r.kind.as_str(), r.event_ms),
        "type": r.kind.as_str(),
        "node": node_id,
        "allocation_id": r.allocation_id,
        "username": r.username,
        "realm": r.realm,
        "tenant": r.tenant,
        "transport": r.transport,
        "relay_addr": r.relay_addr.to_string(),
        "start_ms": r.start_ms,
        "event_ms": r.event_ms,
        "duration_secs": r.duration_secs(),
        "bytes_counted": r.bytes_counted,
        "bytes_from_client": r.usage.bytes_from_client,
        "packets_from_client": r.usage.packets_from_client,
        "bytes_to_client": r.usage.bytes_to_client,
        "packets_to_client": r.usage.packets_to_client,
    });
    if let Some(reason) = r.end_reason {
        o["end_reason"] = reason.as_str().into();
    }
    if include_addresses {
        o["client_addr"] = r.client_addr.to_string().into();
    }
    o
}

/// A running accounting pipeline.
pub struct Accounting {
    pub counters: Arc<AccountingCounters>,
    pub handle: tokio::task::JoinHandle<()>,
}

/// Open the sinks, attach the store, and start the pipeline.
///
/// Fails — and the node refuses to start — when a configured sink cannot be
/// set up: an accounting file that cannot be opened, or a webhook client that
/// cannot be built. Billing that silently records nothing is found at the end
/// of the month, which is the most expensive time to find it.
pub fn start(
    settings: AccountingSettings,
    store: Arc<AllocationStore>,
    shutdown: watch::Receiver<bool>,
) -> Result<Accounting, String> {
    let file = match &settings.file {
        Some(p) => Some(
            FileSink::open(p.clone())
                .map_err(|e| format!("[turn.accounting.file] {}: {e}", p.display()))?,
        ),
        None => None,
    };
    let webhook = match &settings.webhook {
        Some(w) => Some(build_client(w).map_err(|e| format!("[turn.accounting.webhook] {e}"))?),
        None => None,
    };
    let counters = Arc::new(AccountingCounters::default());
    let (tx, rx) = mpsc::channel::<UsageRecord>(settings.queue_capacity);
    store.attach_usage_sink(tx);

    let webhook_tx = match (webhook, &settings.webhook) {
        (Some(client), Some(w)) => {
            let (wtx, wrx) =
                mpsc::channel::<serde_json::Value>(w.max_pending_batches * w.batch_size);
            tokio::spawn(run_webhook(client, w.clone(), wrx, counters.clone()));
            Some(wtx)
        }
        _ => None,
    };

    info!(
        file = ?settings.file,
        webhook = settings.webhook.as_ref().map(|w| w.url.as_str()).unwrap_or(""),
        interim_secs = settings.interim.map(|d| d.as_secs()).unwrap_or(0),
        include_addresses = settings.include_addresses,
        "usage accounting enabled"
    );

    let handle = tokio::spawn(run_dispatcher(
        settings,
        store,
        rx,
        file,
        webhook_tx,
        counters.clone(),
        shutdown,
    ));
    Ok(Accounting { counters, handle })
}

struct FileSink {
    path: PathBuf,
    file: std::fs::File,
}

impl FileSink {
    fn open(path: PathBuf) -> std::io::Result<Self> {
        let mut o = std::fs::OpenOptions::new();
        o.create(true).append(true);
        // Usernames and byte counts: readable by the service and its group.
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o640);
        }
        let file = o.open(&path)?;
        Ok(Self { path, file })
    }

    fn reopen(&mut self) -> std::io::Result<()> {
        *self = Self::open(self.path.clone())?;
        Ok(())
    }

    /// One `write(2)` per record, so a line is never split across a rotation or
    /// interleaved with anything.
    fn write_line(&mut self, v: &serde_json::Value) -> std::io::Result<()> {
        let mut line = serde_json::to_vec(v).map_err(std::io::Error::other)?;
        line.push(b'\n');
        self.file.write_all(&line)
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_dispatcher(
    settings: AccountingSettings,
    store: Arc<AllocationStore>,
    mut rx: mpsc::Receiver<UsageRecord>,
    mut file: Option<FileSink>,
    webhook_tx: Option<mpsc::Sender<serde_json::Value>>,
    counters: Arc<AccountingCounters>,
    mut shutdown: watch::Receiver<bool>,
) {
    let dispatch = |r: &UsageRecord, file: &mut Option<FileSink>| {
        match r.kind {
            UsageRecordKind::Stop => counters.stop_records.fetch_add(1, Ordering::Relaxed),
            UsageRecordKind::Interim => counters.interim_records.fetch_add(1, Ordering::Relaxed),
        };
        let v = record_json(r, &settings.node_id, settings.include_addresses);
        if let Some(f) = file.as_mut() {
            if let Err(e) = f.write_line(&v) {
                let prev = counters.dropped_file_error.fetch_add(1, Ordering::Relaxed);
                if prev == 0 || (prev + 1).is_power_of_two() {
                    warn!(error = %e, dropped_total = prev + 1,
                          "accounting file write failed — record lost from the file sink");
                }
            }
        }
        if let Some(tx) = webhook_tx.as_ref() {
            if tx.try_send(v).is_err() {
                counters
                    .dropped_webhook_queue_full
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    };

    let mut interim = settings.interim.map(|d| {
        let mut t = tokio::time::interval_at(tokio::time::Instant::now() + d, d);
        t.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        t
    });

    #[cfg(unix)]
    let mut sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()).ok();

    loop {
        #[cfg(unix)]
        let hup = async {
            match sighup.as_mut() {
                Some(s) => {
                    s.recv().await;
                }
                None => std::future::pending::<()>().await,
            }
        };
        #[cfg(not(unix))]
        let hup = std::future::pending::<()>();

        tokio::select! {
            rec = rx.recv() => match rec {
                Some(r) => dispatch(&r, &mut file),
                None => break,
            },
            _ = async {
                match interim.as_mut() {
                    Some(t) => { t.tick().await; }
                    None => std::future::pending::<()>().await,
                }
            } => {
                for r in store.interim_usage_records() {
                    dispatch(&r, &mut file);
                }
            }
            _ = hup => {
                if let Some(f) = file.as_mut() {
                    match f.reopen() {
                        Ok(()) => info!("SIGHUP: accounting file reopened"),
                        Err(e) => warn!(error = %e, "SIGHUP: accounting file could not be reopened; still writing the old handle"),
                    }
                }
            }
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    // Records already queued first, so a stop record is never
                    // overtaken by the shutdown snapshot of the same allocation.
                    while let Ok(r) = rx.try_recv() {
                        dispatch(&r, &mut file);
                    }
                    // Allocations still live when the node stops get a final
                    // interim record: whatever they relayed on this node is
                    // otherwise unrecorded, because no stop will follow here.
                    let live = store.interim_usage_records();
                    let n = live.len();
                    for r in live {
                        dispatch(&r, &mut file);
                    }
                    info!(live_allocations = n, "accounting: shutdown snapshot written");
                    break;
                }
            }
        }
    }
    // Dropping the webhook sender closes its channel; the sender task flushes
    // what it holds and exits.
    drop(webhook_tx);
}

fn build_client(w: &WebhookSettings) -> Result<reqwest::Client, String> {
    // The node's rustls uses ring everywhere else (turna-transport picks it
    // explicitly). reqwest is built without a provider of its own and takes the
    // process default, so install ring as that default; an Err means one is
    // already installed, which is fine.
    let _ = rustls::crypto::ring::default_provider().install_default();
    reqwest::Client::builder()
        .timeout(w.timeout)
        .user_agent(concat!("turna/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| format!("could not build the HTTP client: {e}"))
}

/// Delay before retry number `attempt` (1-based): 1 s, 2 s, 4 s … capped at 60 s.
pub fn backoff(attempt: u32) -> Duration {
    Duration::from_secs(1u64 << attempt.saturating_sub(1).min(6)).min(Duration::from_secs(60))
}

/// Retry a failed POST? 5xx, 408, 429 and transport errors are transient; any
/// other 4xx means the receiver rejected the batch and sending it again will
/// not change its mind.
fn is_retryable(status: Option<reqwest::StatusCode>) -> bool {
    match status {
        None => true,
        Some(s) => s.is_server_error() || s.as_u16() == 408 || s.as_u16() == 429,
    }
}

async fn run_webhook(
    client: reqwest::Client,
    w: WebhookSettings,
    mut rx: mpsc::Receiver<serde_json::Value>,
    counters: Arc<AccountingCounters>,
) {
    let mut batch: Vec<serde_json::Value> = Vec::with_capacity(w.batch_size);
    let mut flush_at: Option<tokio::time::Instant> = None;
    loop {
        let deadline = async {
            match flush_at {
                Some(t) => tokio::time::sleep_until(t).await,
                None => std::future::pending::<()>().await,
            }
        };
        tokio::select! {
            item = rx.recv() => match item {
                Some(v) => {
                    if batch.is_empty() {
                        flush_at = Some(tokio::time::Instant::now() + w.flush_interval);
                    }
                    batch.push(v);
                    if batch.len() >= w.batch_size {
                        post_batch(&client, &w, std::mem::take(&mut batch), &counters).await;
                        flush_at = None;
                    }
                }
                None => {
                    if !batch.is_empty() {
                        post_batch(&client, &w, std::mem::take(&mut batch), &counters).await;
                    }
                    return;
                }
            },
            _ = deadline => {
                post_batch(&client, &w, std::mem::take(&mut batch), &counters).await;
                flush_at = None;
            }
        }
    }
}

async fn post_batch(
    client: &reqwest::Client,
    w: &WebhookSettings,
    batch: Vec<serde_json::Value>,
    counters: &AccountingCounters,
) {
    if batch.is_empty() {
        return;
    }
    let n = batch.len() as u64;
    let body = match serde_json::to_vec(&batch) {
        Ok(b) => b,
        Err(_) => {
            counters
                .dropped_webhook_failed
                .fetch_add(n, Ordering::Relaxed);
            return;
        }
    };
    let mut attempt = 0u32;
    loop {
        let mut req = client
            .post(&w.url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body.clone());
        if !w.authorization.is_empty() {
            req = req.header(reqwest::header::AUTHORIZATION, &w.authorization);
        }
        let (status, err) = match req.send().await {
            Ok(resp) if resp.status().is_success() => {
                counters.webhook_batches.fetch_add(1, Ordering::Relaxed);
                return;
            }
            Ok(resp) => (Some(resp.status()), None),
            // The error's Display can carry the URL; never the header.
            Err(e) => (None, Some(e.to_string())),
        };
        if attempt >= w.max_retries || !is_retryable(status) {
            counters
                .dropped_webhook_failed
                .fetch_add(n, Ordering::Relaxed);
            warn!(
                records = n,
                attempts = attempt + 1,
                status = status.map(|s| s.as_u16()),
                error = err.as_deref().unwrap_or(""),
                "accounting webhook batch dropped after retries"
            );
            return;
        }
        attempt += 1;
        counters.webhook_retries.fetch_add(1, Ordering::Relaxed);
        tokio::time::sleep(backoff(attempt)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn store() -> Arc<AllocationStore> {
        Arc::new(AllocationStore::new(40_000, 40_100, 100))
    }

    fn client() -> SocketAddr {
        "192.0.2.10:5000".parse().unwrap()
    }

    fn settings(file: Option<PathBuf>, webhook: Option<WebhookSettings>) -> AccountingSettings {
        AccountingSettings {
            node_id: "node-a".into(),
            include_addresses: false,
            queue_capacity: 16,
            interim: None,
            file,
            webhook,
        }
    }

    #[test]
    fn backoff_doubles_and_caps() {
        assert_eq!(backoff(1), Duration::from_secs(1));
        assert_eq!(backoff(2), Duration::from_secs(2));
        assert_eq!(backoff(3), Duration::from_secs(4));
        assert_eq!(backoff(7), Duration::from_secs(60));
        assert_eq!(backoff(40), Duration::from_secs(60));
    }

    #[test]
    fn retry_policy() {
        assert!(is_retryable(None));
        assert!(is_retryable(Some(reqwest::StatusCode::SERVICE_UNAVAILABLE)));
        assert!(is_retryable(Some(reqwest::StatusCode::TOO_MANY_REQUESTS)));
        assert!(!is_retryable(Some(reqwest::StatusCode::BAD_REQUEST)));
        assert!(!is_retryable(Some(reqwest::StatusCode::UNAUTHORIZED)));
    }

    #[test]
    fn debug_never_prints_the_authorization_header() {
        let w = WebhookSettings {
            url: "https://billing.example/ingest".into(),
            authorization: "Bearer very-secret".into(),
            batch_size: 1,
            flush_interval: Duration::from_secs(1),
            max_retries: 0,
            timeout: Duration::from_secs(1),
            max_pending_batches: 1,
        };
        let s = format!("{w:?}");
        assert!(!s.contains("very-secret"), "{s}");
        assert!(s.contains("<set>"), "{s}");
    }

    /// Address inclusion is the sink's decision and is off by default.
    #[test]
    fn json_record_shape_and_address_opt_in() {
        let s = store();
        s.create(
            client(),
            "10.0.0.1:40000".parse().unwrap(),
            "alice".into(),
            vec![],
            600,
        )
        .unwrap();
        {
            let a = s.get(&client()).unwrap();
            a.add_bytes(100);
            a.add_bytes_to_client(40);
            a.add_bytes_to_client(60);
        }
        let r = s.interim_usage_records().pop().unwrap();
        let v = record_json(&r, "node-a", false);
        assert_eq!(v["v"], 1);
        assert_eq!(v["type"], "interim");
        assert_eq!(v["username"], "alice");
        assert_eq!(v["transport"], "udp");
        assert_eq!(v["bytes_from_client"], 100);
        assert_eq!(v["packets_from_client"], 1);
        assert_eq!(v["bytes_to_client"], 100);
        assert_eq!(v["packets_to_client"], 2);
        assert_eq!(v["bytes_counted"], true);
        assert!(v.get("client_addr").is_none(), "addresses are opt-in");
        assert!(
            v.get("end_reason").is_none(),
            "interim records carry no end reason"
        );
        assert!(v["record_id"].as_str().unwrap().starts_with("node-a:"));
        let with = record_json(&r, "node-a", true);
        assert_eq!(with["client_addr"], "192.0.2.10:5000");
    }

    /// End to end: a released allocation produces exactly one stop record in
    /// the file, with its totals and reason; shutdown snapshots the rest.
    #[tokio::test]
    async fn file_sink_gets_stop_records_and_a_shutdown_snapshot() {
        let dir = std::env::temp_dir().join(format!("turna-acct-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("usage.jsonl");
        let s = store();
        let (stx, srx) = watch::channel(false);
        let acct = start(settings(Some(path.clone()), None), s.clone(), srx).unwrap();

        let relay: SocketAddr = "10.0.0.1:40001".parse().unwrap();
        s.create(client(), relay, "alice".into(), vec![], 600)
            .unwrap();
        s.get(&client()).unwrap().add_bytes(1200);
        s.remove(&client(), relay).unwrap();

        let other: SocketAddr = "192.0.2.11:6000".parse().unwrap();
        s.create(
            other,
            "10.0.0.1:40002".parse().unwrap(),
            "bob".into(),
            vec![],
            600,
        )
        .unwrap();

        // Let the dispatcher take the stop record, then shut down.
        tokio::time::sleep(Duration::from_millis(100)).await;
        stx.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(5), acct.handle)
            .await
            .expect("dispatcher exits on shutdown")
            .unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<serde_json::Value> = text
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(lines.len(), 2, "{text}");
        assert_eq!(lines[0]["type"], "stop");
        assert_eq!(lines[0]["end_reason"], "released");
        assert_eq!(lines[0]["username"], "alice");
        assert_eq!(lines[0]["bytes_from_client"], 1200);
        assert_eq!(lines[1]["type"], "interim");
        assert_eq!(lines[1]["username"], "bob");
        assert_eq!(acct.counters.stop_records.load(Ordering::Relaxed), 1);
        assert_eq!(acct.counters.interim_records.load(Ordering::Relaxed), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unopenable_file_refuses_to_start() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let (_stx, srx) = watch::channel(false);
            let r = start(
                settings(Some(PathBuf::from("/nonexistent-dir/usage.jsonl")), None),
                store(),
                srx,
            );
            assert!(r.is_err());
        });
    }

    /// Minimal HTTP/1.1 receiver: answers each request with the next status in
    /// `statuses` and hands the body back to the test.
    async fn receiver(statuses: Vec<u16>) -> (String, mpsc::UnboundedReceiver<(String, Vec<u8>)>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/ingest", l.local_addr().unwrap());
        let (tx, rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            for status in statuses {
                let Ok((mut sock, _)) = l.accept().await else {
                    return;
                };
                let mut buf = Vec::new();
                let mut tmp = [0u8; 4096];
                // Read headers, then Content-Length bytes of body.
                let (head, body_start) = loop {
                    let n = sock.read(&mut tmp).await.unwrap();
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                    if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        break (String::from_utf8_lossy(&buf[..i]).to_string(), i + 4);
                    }
                };
                let len: usize = head
                    .lines()
                    .find_map(|l| {
                        let (k, v) = l.split_once(':')?;
                        k.eq_ignore_ascii_case("content-length")
                            .then(|| v.trim().parse().ok())?
                    })
                    .unwrap_or(0);
                while buf.len() < body_start + len {
                    let n = sock.read(&mut tmp).await.unwrap();
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                }
                let _ = tx.send((head, buf[body_start..body_start + len].to_vec()));
                let resp = format!(
                    "HTTP/1.1 {status} X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                );
                let _ = sock.write_all(resp.as_bytes()).await;
            }
        });
        (url, rx)
    }

    fn webhook(url: String, retries: u32) -> WebhookSettings {
        WebhookSettings {
            url,
            authorization: "Bearer t0k".into(),
            batch_size: 2,
            flush_interval: Duration::from_millis(200),
            max_retries: retries,
            timeout: Duration::from_secs(5),
            max_pending_batches: 4,
        }
    }

    /// A 503 is retried, the batch arrives as a JSON array with the auth
    /// header, and the retry is counted.
    #[tokio::test]
    async fn webhook_batches_retries_and_authenticates() {
        let (url, mut got) = receiver(vec![503, 200]).await;
        let s = store();
        let (_stx, srx) = watch::channel(false);
        let acct = start(settings(None, Some(webhook(url, 3))), s.clone(), srx).unwrap();
        for (i, port) in [(0u16, 40010u16), (1, 40011)] {
            let c: SocketAddr = format!("192.0.2.20:{}", 7000 + i).parse().unwrap();
            let r: SocketAddr = format!("10.0.0.1:{port}").parse().unwrap();
            s.create(c, r, format!("u{i}"), vec![], 600).unwrap();
            s.remove(&c, r).unwrap();
        }
        let (h1, b1) = tokio::time::timeout(Duration::from_secs(10), got.recv())
            .await
            .unwrap()
            .unwrap();
        let (_h2, b2) = tokio::time::timeout(Duration::from_secs(10), got.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(h1.starts_with("POST /ingest "), "{h1}");
        assert!(
            h1.to_ascii_lowercase()
                .contains("authorization: bearer t0k"),
            "{h1}"
        );
        assert_eq!(b1, b2, "the retry resends the same batch");
        let arr: Vec<serde_json::Value> = serde_json::from_slice(&b2).unwrap();
        assert_eq!(arr.len(), 2);
        assert!(arr.iter().all(|r| r["type"] == "stop"));
        // Counters settle once the 200 is read.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while acct.counters.webhook_batches.load(Ordering::Relaxed) == 0
            && tokio::time::Instant::now() < deadline
        {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(acct.counters.webhook_batches.load(Ordering::Relaxed), 1);
        assert_eq!(acct.counters.webhook_retries.load(Ordering::Relaxed), 1);
        assert_eq!(
            acct.counters.dropped_webhook_failed.load(Ordering::Relaxed),
            0
        );
    }

    /// A 4xx is the receiver refusing the batch: not retried, dropped, counted.
    #[tokio::test]
    async fn webhook_client_error_is_not_retried() {
        let (url, mut got) = receiver(vec![400]).await;
        let s = store();
        let (_stx, srx) = watch::channel(false);
        let acct = start(settings(None, Some(webhook(url, 5))), s.clone(), srx).unwrap();
        let c: SocketAddr = "192.0.2.30:7000".parse().unwrap();
        let r: SocketAddr = "10.0.0.1:40020".parse().unwrap();
        s.create(c, r, "u".into(), vec![], 600).unwrap();
        s.remove(&c, r).unwrap();
        // One record, batch of 2: goes out on the flush interval.
        tokio::time::timeout(Duration::from_secs(10), got.recv())
            .await
            .unwrap()
            .unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while acct.counters.dropped_webhook_failed.load(Ordering::Relaxed) == 0
            && tokio::time::Instant::now() < deadline
        {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(
            acct.counters.dropped_webhook_failed.load(Ordering::Relaxed),
            1
        );
        assert_eq!(acct.counters.webhook_retries.load(Ordering::Relaxed), 0);
    }
}
