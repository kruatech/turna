//! Thin read-only HTTP client to the turna node health/metrics plane (:9090).
//!
//! Only GET requests. All mutating operations go through the gRPC client in
//! grpc_client.rs. `post_json` has been intentionally removed — there is one
//! mutating transport (gRPC+mTLS to :5350), not two.

use anyhow::{bail, Result};

/// GET a JSON body (used for /status, /cluster).
pub async fn fetch_json(client: &reqwest::Client, url: &str) -> Result<serde_json::Value> {
    let resp = client.get(url).send().await?;
    let status = resp.status();
    if !status.is_success() {
        bail!("upstream returned {}", status);
    }
    Ok(resp.json::<serde_json::Value>().await?)
}

/// GET a text body (used for /metrics, Prometheus text format).
pub async fn fetch_text(client: &reqwest::Client, url: &str) -> Result<String> {
    let resp = client.get(url).send().await?;
    let status = resp.status();
    if !status.is_success() {
        bail!("upstream returned {}", status);
    }
    Ok(resp.text().await?)
}

/// GET and return only the HTTP status code (used for /health, /ready).
pub async fn fetch_status_code(client: &reqwest::Client, url: &str) -> Result<u16> {
    let resp = client.get(url).send().await?;
    Ok(resp.status().as_u16())
}
