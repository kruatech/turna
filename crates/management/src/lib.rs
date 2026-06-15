//! turna-management — HTTP management client and server for turnactl.
//!
//! # Wiring in turna-node main.rs
//!
//! ```ignore
//! tokio::spawn(turna_management::serve_management(
//!     "0.0.0.0:9091".parse().unwrap(),
//!     metrics.clone(),
//!     None, // or Some(Arc::new(MyStoreHandler { store, backend }))
//! ));
//! ```

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info, warn};

use turna_health::Metrics;

// ── Pluggable store handler ───────────────────────────────────────────────────

/// Implement this to wire AllocationStore / Backend into the management server.
/// Without it, allocation list/get/kill commands return an explanatory error.
#[async_trait::async_trait]
pub trait StoreHandler: Send + Sync {
    async fn count(&self) -> u64;
    async fn list(&self, limit: usize) -> Vec<serde_json::Value>;
    async fn get(&self, relay_port: u16) -> Option<serde_json::Value>;
    async fn kill(&self, relay_port: u16) -> bool;
    async fn list_rooms(&self, limit: usize) -> Vec<serde_json::Value>;
}

// ── Response type ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagementResponse {
    pub ok: bool,
    pub data: Option<serde_json::Value>,
    pub error: Option<String>,
}

impl ManagementResponse {
    pub fn ok(data: serde_json::Value) -> Self {
        Self {
            ok: true,
            data: Some(data),
            error: None,
        }
    }
    pub fn err(msg: impl Into<String>) -> Self {
        Self {
            ok: false,
            data: None,
            error: Some(msg.into()),
        }
    }
    pub fn empty() -> Self {
        Self {
            ok: true,
            data: None,
            error: None,
        }
    }
}

// ── Client ────────────────────────────────────────────────────────────────────

pub struct ManagementClient {
    addr: SocketAddr,
}

impl ManagementClient {
    pub fn new(addr: SocketAddr) -> Self {
        Self { addr }
    }

    pub async fn send(
        &self,
        command: &str,
        params: serde_json::Value,
    ) -> Result<ManagementResponse, String> {
        match command {
            // These work against the plain health server on 9090.
            "ping" => {
                let body = self.get("/health").await?;
                Ok(ManagementResponse::ok(
                    serde_json::json!({"status": body.trim()}),
                ))
            }
            "node.status" => {
                let body = self.get("/status").await?;
                let v: serde_json::Value =
                    serde_json::from_str(&body).map_err(|e| format!("parse /status: {e}"))?;
                Ok(ManagementResponse::ok(v))
            }
            "allocations.count" => {
                let body = self.get("/metrics").await?;
                let n = parse_prom_gauge(&body, "turna_active_allocations").unwrap_or(0);
                Ok(ManagementResponse::ok(serde_json::json!({"count": n})))
            }
            "cluster.nodes" => {
                let body = self.get("/cluster").await?;
                let v: serde_json::Value =
                    serde_json::from_str(&body).map_err(|e| format!("parse /cluster: {e}"))?;
                Ok(ManagementResponse::ok(v))
            }
            // Everything else → POST /manage (needs management server on 9091).
            _ => {
                let req = serde_json::to_string(
                    &serde_json::json!({"command": command, "params": params}),
                )
                .unwrap();
                let resp = self.post("/manage", &req).await?;
                serde_json::from_str(&resp).map_err(|e| format!("parse response: {e}"))
            }
        }
    }

    async fn get(&self, path: &str) -> Result<String, String> {
        http_get(self.addr, path)
            .await
            .map_err(|e| format!("GET {path}: {e}"))
    }
    async fn post(&self, path: &str, body: &str) -> Result<String, String> {
        http_post(self.addr, path, body)
            .await
            .map_err(|e| format!("POST {path}: {e}"))
    }
}

// ── Server ────────────────────────────────────────────────────────────────────

pub async fn serve_management(
    addr: SocketAddr,
    metrics: Arc<Metrics>,
    store_handler: Option<Arc<dyn StoreHandler>>,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    info!(%addr, "management server started");
    loop {
        let (stream, _) = listener.accept().await?;
        let m = metrics.clone();
        let h = store_handler.clone();
        tokio::spawn(handle_conn(stream, m, h));
    }
}

async fn handle_conn(
    mut stream: TcpStream,
    metrics: Arc<Metrics>,
    handler: Option<Arc<dyn StoreHandler>>,
) {
    let mut buf = vec![0u8; 8192];
    let n = match stream.read(&mut buf).await {
        Ok(n) if n > 0 => n,
        _ => return,
    };

    let request = String::from_utf8_lossy(&buf[..n]);
    let first = request.lines().next().unwrap_or("");
    let mut parts_iter = first.split_whitespace();
    let method = parts_iter.next().unwrap_or("GET");
    let path = parts_iter.next().unwrap_or("/");

    let body_off = request
        .find("\r\n\r\n")
        .map(|i| i + 4)
        .or_else(|| request.find("\n\n").map(|i| i + 2))
        .unwrap_or(n);
    let body = request[body_off.min(request.len())..].to_string();

    let (code, ct, resp) = match (method, path) {
        ("GET", "/health") => {
            let (s, c) = if metrics.is_draining() {
                ("draining", "503 Service Unavailable")
            } else {
                ("ok", "200 OK")
            };
            (c, "text/plain", s.to_string())
        }
        ("GET", "/status") => ("200 OK", "application/json", status_json(&metrics)),
        ("POST", "/manage") => {
            let r = dispatch(&body, &metrics, handler.as_deref()).await;
            (
                "200 OK",
                "application/json",
                serde_json::to_string(&r).unwrap(),
            )
        }
        _ => ("404 Not Found", "text/plain", "not found".into()),
    };

    let http = format!(
        "HTTP/1.1 {code}\r\nContent-Type: {ct}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{resp}",
        resp.len()
    );
    let _ = stream.write_all(http.as_bytes()).await;
}

async fn dispatch(
    body: &str,
    metrics: &Metrics,
    handler: Option<&dyn StoreHandler>,
) -> ManagementResponse {
    #[derive(Deserialize)]
    struct Req {
        command: String,
        #[serde(default)]
        params: serde_json::Value,
    }

    let req: Req = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(e) => return ManagementResponse::err(format!("bad JSON: {e}")),
    };
    debug!(command = %req.command, "management dispatch");

    match req.command.as_str() {
        "ping" => ManagementResponse::ok(serde_json::json!({"status":"ok"})),

        "node.status" => {
            ManagementResponse::ok(serde_json::from_str(&status_json(metrics)).unwrap())
        }

        "failover.status" => {
            ManagementResponse::ok(serde_json::from_str(&failover_json(metrics)).unwrap())
        }

        "node.drain" => {
            metrics.set_draining(true);
            info!("drain ENABLED via turnactl");
            ManagementResponse::empty()
        }
        "node.undrain" => {
            metrics.set_draining(false);
            info!("drain DISABLED via turnactl");
            ManagementResponse::empty()
        }

        "allocations.count" => {
            let n = if let Some(h) = handler {
                h.count().await
            } else {
                metrics.active_allocations.load(Ordering::Relaxed)
            };
            ManagementResponse::ok(serde_json::json!({"count": n}))
        }

        cmd @ ("allocations.list" | "allocations.get" | "allocations.kill" | "rooms.list") => {
            let Some(h) = handler else {
                return ManagementResponse::err(format!(
                    "{cmd} requires store_handler — wire it in turna-node main.rs:\n\
                     tokio::spawn(turna_management::serve_management(addr, metrics, Some(Arc::new(handler))));"
                ));
            };
            match cmd {
                "allocations.list" => {
                    let limit = req.params["limit"].as_u64().unwrap_or(50) as usize;
                    let items = h.list(limit).await;
                    ManagementResponse::ok(serde_json::json!({"allocations": items}))
                }
                "allocations.get" => {
                    let port = match req.params["relay_port"].as_u64() {
                        Some(p) => p as u16,
                        None => return ManagementResponse::err("missing relay_port"),
                    };
                    match h.get(port).await {
                        Some(v) => ManagementResponse::ok(v),
                        None => ManagementResponse::err(format!("no allocation on port {port}")),
                    }
                }
                "allocations.kill" => {
                    let port = match req.params["relay_port"].as_u64() {
                        Some(p) => p as u16,
                        None => return ManagementResponse::err("missing relay_port"),
                    };
                    if h.kill(port).await {
                        warn!(port, "allocation killed via turnactl");
                        ManagementResponse::ok(serde_json::json!({"killed": port}))
                    } else {
                        ManagementResponse::err(format!("no allocation on port {port}"))
                    }
                }
                "rooms.list" => {
                    let limit = req.params["limit"].as_u64().unwrap_or(50) as usize;
                    let rooms = h.list_rooms(limit).await;
                    ManagementResponse::ok(serde_json::json!({"rooms": rooms}))
                }
                _ => unreachable!(),
            }
        }

        other => ManagementResponse::err(format!("unknown command: {other}")),
    }
}

fn status_json(m: &Metrics) -> String {
    serde_json::json!({
        "status":             if m.is_draining() { "draining" } else { "ok" },
        "draining":           m.is_draining(),
        "uptime_secs":        m.start_time.elapsed().as_secs(),
        "active_allocations": m.active_allocations.load(Ordering::Relaxed),
        "total_allocations":  m.total_allocations.load(Ordering::Relaxed),
        "packets_received":   m.packets_received.load(Ordering::Relaxed),
        "packets_sent":       m.packets_sent.load(Ordering::Relaxed),
        "bytes_received":     m.bytes_received.load(Ordering::Relaxed),
        "bytes_sent":         m.bytes_sent.load(Ordering::Relaxed),
        "auth_failures":      m.auth_failures.load(Ordering::Relaxed),
    })
    .to_string()
}

/// Failover counters for this node, surfaced to `turnactl failover status`.
/// All four counters live in the shared [`Metrics`] and are updated by the
/// failover sweep task (`failover::run_failover`), so this reflects live
/// takeover activity for the node serving the request.
fn failover_json(m: &Metrics) -> String {
    serde_json::json!({
        "claimed_total":   m.failover_claimed_total.load(Ordering::Relaxed),
        "lost_race_total": m.failover_lost_race_total.load(Ordering::Relaxed),
        "errors_total":    m.failover_errors_total.load(Ordering::Relaxed),
        "last_sweep_us":   m.failover_sweep_duration_us.load(Ordering::Relaxed),
        "draining":        m.is_draining(),
    })
    .to_string()
}

pub fn parse_prom_gauge(text: &str, name: &str) -> Option<u64> {
    text.lines()
        .filter(|l| !l.starts_with('#'))
        .find(|l| l.split_whitespace().next() == Some(name))
        .and_then(|l| l.split_whitespace().nth(1)?.parse().ok())
}

// ── Raw HTTP ──────────────────────────────────────────────────────────────────

async fn http_get(addr: SocketAddr, path: &str) -> std::io::Result<String> {
    let mut s = TcpStream::connect(addr).await?;
    s.write_all(
        format!("GET {path} HTTP/1.0\r\nHost: {addr}\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await?;
    let mut r = String::new();
    s.read_to_string(&mut r).await?;
    Ok(r.split("\r\n\r\n").nth(1).unwrap_or("").to_string())
}

async fn http_post(addr: SocketAddr, path: &str, body: &str) -> std::io::Result<String> {
    let mut s = TcpStream::connect(addr).await?;
    s.write_all(format!(
        "POST {path} HTTP/1.0\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    ).as_bytes()).await?;
    let mut r = String::new();
    s.read_to_string(&mut r).await?;
    Ok(r.split("\r\n\r\n").nth(1).unwrap_or("").to_string())
}
