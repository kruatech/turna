//! Management API integration with real Turna services.
//!
//! Connects the JSON-over-TCP management API to:
//! - StateBackend (allocation CRUD, node heartbeats)
//! - DrainOrchestrator (graceful shutdown)
//! - Metrics (Prometheus counters)
//! - Config (runtime changes)
//!
//! Usage in turna-node main():
//! ```ignore
//! let backend = Arc::new(create_backend(&config.cluster.backend).await?);
//! let drain = Arc::new(DrainOrchestrator::new(drain_config));
//! let mgmt = ManagementIntegration::new(backend, drain, config);
//! mgmt.serve(config.management.listen).await?;
//! ```

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tracing::info;

use turna_common::drain::{DrainOrchestrator, DrainState};
use turna_state_backend::Backend;

/// Request from turnactl or other client.
#[derive(serde::Deserialize)]
struct Request {
    command: String,
    #[serde(default)]
    params: serde_json::Value,
}

/// Response to client.
#[derive(serde::Serialize)]
struct Response {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl Response {
    fn success(data: serde_json::Value) -> Self { Self { ok: true, data: Some(data), error: None } }
    fn error(msg: impl Into<String>) -> Self { Self { ok: false, data: None, error: Some(msg.into()) } }
}

/// Integrated management server.
pub struct ManagementIntegration {
    backend: Arc<Backend>,
    drain: Arc<DrainOrchestrator>,
    node_id: String,
    start_time: std::time::Instant,
    // Reserved metric: incremented once the management RPC layer is wired to
    // record per-integration request counts. Kept to avoid churn in the
    // struct + its constructor when that lands.
    request_count: AtomicU64,
}

impl ManagementIntegration {
    pub fn new(
        backend: Arc<Backend>,
        drain: Arc<DrainOrchestrator>,
        node_id: String,
    ) -> Self {
        Self {
            backend,
            drain,
            node_id,
            start_time: std::time::Instant::now(),
            request_count: AtomicU64::new(0),
        }
    }

    /// Start management API server.
    pub async fn serve(&self, addr: SocketAddr) -> std::io::Result<()> {
        let listener = TcpListener::bind(addr).await?;
        info!(%addr, "management API listening (integrated)");

        loop {
            let (stream, _) = listener.accept().await?;
            let backend = self.backend.clone();
            let drain = self.drain.clone();
            let node_id = self.node_id.clone();
            let start_time = self.start_time;

            tokio::spawn(async move {
                let (reader, mut writer) = stream.into_split();
                let mut lines = BufReader::new(reader).lines();

                while let Ok(Some(line)) = lines.next_line().await {
                    let req: Request = match serde_json::from_str(&line) {
                        Ok(r) => r,
                        Err(e) => {
                            let resp = Response::error(format!("parse: {e}"));
                            let _ = write_resp(&mut writer, &resp).await;
                            continue;
                        }
                    };

                    let resp = handle(&req, &backend, &drain, &node_id, start_time).await;
                    if write_resp(&mut writer, &resp).await.is_err() { break; }
                }
            });
        }
    }
}

async fn write_resp(w: &mut tokio::net::tcp::OwnedWriteHalf, r: &Response) -> std::io::Result<()> {
    let mut json = serde_json::to_string(r).unwrap();
    json.push('\n');
    w.write_all(json.as_bytes()).await
}

async fn handle(
    req: &Request,
    backend: &Backend,
    drain: &DrainOrchestrator,
    node_id: &str,
    start_time: std::time::Instant,
) -> Response {
    match req.command.as_str() {
        "ping" => Response::success(serde_json::json!("pong")),

        "node.status" => {
            let count = backend.count_allocations().await.unwrap_or(0);
            let drain_state = match drain.state() {
                DrainState::Active => "active",
                DrainState::Draining => "draining",
                DrainState::Drained => "drained",
            };
            Response::success(serde_json::json!({
                "node_id": node_id,
                "uptime_secs": start_time.elapsed().as_secs(),
                "active_allocations": count,
                "drain_state": drain_state,
            }))
        }

        "node.drain" => {
            if drain.is_draining() {
                return Response::error("already draining");
            }
            drain.draining_flag().store(true, std::sync::atomic::Ordering::SeqCst);
            info!("drain initiated via management API");
            Response::success(serde_json::json!({"drain_state": "draining"}))
        }

        "node.undrain" => {
            drain.cancel();
            Response::success(serde_json::json!({"drain_state": "active"}))
        }

        "allocations.count" => {
            match backend.count_allocations().await {
                Ok(n) => Response::success(serde_json::json!({"count": n})),
                Err(e) => Response::error(e.to_string()),
            }
        }

        "allocations.list" => {
            let offset = req.params.get("offset").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
            let limit = req.params.get("limit").and_then(|v| v.as_u64()).unwrap_or(50) as usize;
            match backend.list_allocations(offset, limit).await {
                Ok(allocs) => Response::success(serde_json::to_value(&allocs).unwrap()),
                Err(e) => Response::error(e.to_string()),
            }
        }

        "allocations.get" => {
            let port = req.params.get("relay_port").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
            match backend.get_allocation(port).await {
                Ok(Some(a)) => Response::success(serde_json::to_value(&a).unwrap()),
                Ok(None) => Response::error(format!("not found: {port}")),
                Err(e) => Response::error(e.to_string()),
            }
        }

        "allocations.kill" => {
            let port = req.params.get("relay_port").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
            match backend.remove_allocation(port).await {
                Ok(()) => {
                    info!(relay_port = port, "allocation killed");
                    Response::success(serde_json::json!({"killed": port}))
                }
                Err(e) => Response::error(e.to_string()),
            }
        }

        "allocations.find_user" => {
            let user = req.params.get("user_id").and_then(|v| v.as_str()).unwrap_or("");
            match backend.find_by_user(user).await {
                Ok(allocs) => Response::success(serde_json::to_value(&allocs).unwrap()),
                Err(e) => Response::error(e.to_string()),
            }
        }

        "cluster.nodes" => {
            match backend.get_live_nodes(std::time::Duration::from_secs(30)).await {
                Ok(nodes) => Response::success(serde_json::to_value(&nodes).unwrap()),
                Err(e) => Response::error(e.to_string()),
            }
        }

        _ => Response::error(format!("unknown: {}", req.command)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use turna_state_backend::InMemoryBackend;

    #[tokio::test]
    async fn handle_ping() {
        let backend = Backend::Memory(InMemoryBackend::new());
        let drain = DrainOrchestrator::new(Default::default());
        let req = Request { command: "ping".into(), params: serde_json::json!({}) };
        let resp = handle(&req, &backend, &drain, "test", std::time::Instant::now()).await;
        assert!(resp.ok);
    }

    #[tokio::test]
    async fn handle_status() {
        let backend = Backend::Memory(InMemoryBackend::new());
        let drain = DrainOrchestrator::new(Default::default());
        let req = Request { command: "node.status".into(), params: serde_json::json!({}) };
        let resp = handle(&req, &backend, &drain, "n1", std::time::Instant::now()).await;
        assert!(resp.ok);
        let data = resp.data.unwrap();
        assert_eq!(data["drain_state"], "active");
    }

    #[tokio::test]
    async fn handle_unknown() {
        let backend = Backend::Memory(InMemoryBackend::new());
        let drain = DrainOrchestrator::new(Default::default());
        let req = Request { command: "foo.bar".into(), params: serde_json::json!({}) };
        let resp = handle(&req, &backend, &drain, "n1", std::time::Instant::now()).await;
        assert!(!resp.ok);
    }
}
