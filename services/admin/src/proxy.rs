//! Thin read-only HTTP client to the turna node health/metrics plane (:9090).
//!
//! Only GET requests. All mutating operations go through the gRPC client in
//! grpc_client.rs. `post_json` has been intentionally removed — there is one
//! mutating transport (gRPC+mTLS to :5350), not two.

use anyhow::{bail, Result};

/// Refuse a URL that is not the health plane this module is for.
///
/// The address comes from configuration, not from a request, so this is not
/// closing an open door. It does two things worth having anyway: it turns a
/// malformed address into a clear error instead of a confusing request failure,
/// and it makes the constraint explicit for anyone reading — including
/// CodeQL's request-forgery rule, which cannot otherwise tell where the string
/// came from.
fn check_upstream(url: &str) -> Result<()> {
    if !url.starts_with("http://") && !url.starts_with("https://") {
        bail!("upstream URL must be http or https: {url}");
    }
    if url.contains("..") || url.contains('@') {
        bail!("upstream URL must not contain path traversal or credentials: {url}");
    }
    Ok(())
}

/// GET a JSON body (used for /status, /cluster).
pub async fn fetch_json(client: &reqwest::Client, url: &str) -> Result<serde_json::Value> {
    check_upstream(url)?;
    let resp = client.get(url).send().await?;
    let status = resp.status();
    if !status.is_success() {
        bail!("upstream returned {}", status);
    }
    Ok(resp.json::<serde_json::Value>().await?)
}

/// GET a text body (used for /metrics, Prometheus text format).
pub async fn fetch_text(client: &reqwest::Client, url: &str) -> Result<String> {
    check_upstream(url)?;
    let resp = client.get(url).send().await?;
    let status = resp.status();
    if !status.is_success() {
        bail!("upstream returned {}", status);
    }
    Ok(resp.text().await?)
}

/// GET and return only the HTTP status code (used for /health, /ready).
pub async fn fetch_status_code(client: &reqwest::Client, url: &str) -> Result<u16> {
    check_upstream(url)?;
    let resp = client.get(url).send().await?;
    Ok(resp.status().as_u16())
}
