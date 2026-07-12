//! gRPC client to turna control-plane.
//!
//! TLS modes:
//!   1. `https://` address, no --tls-* flags  → TLS with system roots (works with LE certs)
//!   2. `https://` address + --tls-ca/cert/key → mTLS (custom CA + client cert)
//!   3. `http://`  address                     → plaintext (loopback dev only)
//!
//! tonic's `tls-roots` feature bundles webpki-roots, so Let's Encrypt certs
//! are accepted without any extra configuration.

use anyhow::{bail, Context, Result};
use std::path::PathBuf;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};
use tracing::info;

pub mod proto {
    tonic::include_proto!("turna.management.v1");
}
use proto::{
    turna_management_client::TurnaManagementClient, AddUserRequest, DeleteAllocationRequest,
    GetServerStatsRequest, ListAllocationsRequest, RemoveUserRequest, SetDrainingRequest,
    SetUserLimitsRequest,
};

/// Optional mTLS material (all three paths required together).
/// When absent and address is `https://`, TLS with system roots is used.
#[derive(Debug, Clone)]
pub struct AdminTlsConfig {
    pub ca_cert: PathBuf,
    pub client_cert: PathBuf,
    pub client_key: PathBuf,
}

/// Build a tonic Channel.
///
/// - `https://` + no tls config  → TLS, system roots (LE works out of the box)
/// - `https://` + tls config     → mTLS with custom CA + client cert
/// - `http://`                   → plaintext (loopback only)
pub async fn build_channel(addr: &str, tls: Option<&AdminTlsConfig>) -> Result<Channel> {
    let is_tls = addr.starts_with("https://");
    let endpoint = tonic::transport::Endpoint::new(addr.to_string())
        .context("invalid control-plane address")?;

    let channel = if is_tls {
        let tls_cfg = match tls {
            Some(cfg) => {
                // mTLS: custom CA + client certificate
                let ca = tokio::fs::read(&cfg.ca_cert)
                    .await
                    .with_context(|| format!("read ca_cert {:?}", cfg.ca_cert))?;
                let cert = tokio::fs::read(&cfg.client_cert)
                    .await
                    .with_context(|| format!("read client_cert {:?}", cfg.client_cert))?;
                let key = tokio::fs::read(&cfg.client_key)
                    .await
                    .with_context(|| format!("read client_key {:?}", cfg.client_key))?;
                info!(ca = ?cfg.ca_cert, cert = ?cfg.client_cert, "gRPC mTLS configured");
                ClientTlsConfig::new()
                    .ca_certificate(Certificate::from_pem(ca))
                    .identity(Identity::from_pem(cert, key))
            }
            None => {
                // Server-TLS with system roots — works with Let's Encrypt
                info!(
                    addr,
                    "gRPC TLS with system roots (Let's Encrypt compatible)"
                );
                ClientTlsConfig::new()
            }
        };
        endpoint
            .tls_config(tls_cfg)?
            .connect()
            .await
            .context("connect to control-plane with TLS")?
    } else {
        // plaintext
        endpoint
            .connect()
            .await
            .context("connect to control-plane (plaintext)")?
    };

    Ok(channel)
}

/// Dispatch a JSON command to the correct gRPC RPC.
pub async fn dispatch(
    channel: Channel,
    command: &str,
    params: &serde_json::Value,
) -> Result<serde_json::Value> {
    let mut c = TurnaManagementClient::new(channel);

    match command {
        "ping" => {
            let r = c
                .get_server_stats(GetServerStatsRequest {})
                .await?
                .into_inner();
            Ok(serde_json::json!({
                "status": "ok",
                "active_allocations": r.active_allocations,
                "uptime_seconds": r.uptime_seconds,
            }))
        }
        "node.drain" => {
            let r = c
                .set_draining(SetDrainingRequest { draining: true })
                .await?
                .into_inner();
            Ok(serde_json::json!({ "ok": r.success, "active_allocations": r.active_allocations }))
        }
        "node.undrain" => {
            let r = c
                .set_draining(SetDrainingRequest { draining: false })
                .await?
                .into_inner();
            Ok(serde_json::json!({ "ok": r.success, "active_allocations": r.active_allocations }))
        }
        "failover.status" => {
            let r = c
                .get_server_stats(GetServerStatsRequest {})
                .await?
                .into_inner();
            Ok(serde_json::json!({
                "draining": r.draining,
                "active_allocations": r.active_allocations,
                "uptime_seconds": r.uptime_seconds,
                "avg_latency_us": r.avg_latency_us,
                "p99_latency_us": r.p99_latency_us,
            }))
        }
        "allocations.count" => {
            let r = c
                .get_server_stats(GetServerStatsRequest {})
                .await?
                .into_inner();
            Ok(serde_json::json!({ "count": r.active_allocations }))
        }
        "allocations.list" => {
            let r = c
                .list_allocations(ListAllocationsRequest {
                    username_filter: params["username_filter"].as_str().unwrap_or("").into(),
                    organization_filter: params["org_filter"].as_str().unwrap_or("").into(),
                    page_size: params["limit"].as_u64().unwrap_or(50) as u32,
                    page_token: String::new(),
                })
                .await?
                .into_inner();
            let allocs: Vec<_> = r
                .allocations
                .iter()
                .map(|a| {
                    serde_json::json!({
                        "id": a.id, "username": a.username, "realm": a.realm,
                        "client_address": a.client_address, "relay_address": a.relay_address,
                        "transport": a.transport, "created_at": a.created_at,
                        "expires_at": a.expires_at, "remaining_lifetime": a.remaining_lifetime,
                        "address_family": a.address_family, "organization": a.organization,
                        "traffic": a.traffic.as_ref().map(|t| serde_json::json!({
                            "bytes_from_client": t.bytes_from_client,
                            "bytes_to_client":   t.bytes_to_client,
                            "bytes_from_peers":  t.bytes_from_peers,
                            "bytes_to_peers":    t.bytes_to_peers,
                        })),
                    })
                })
                .collect();
            Ok(serde_json::json!({
                "allocations": allocs,
                "total_count": r.total_count,
                "next_page_token": r.next_page_token,
            }))
        }
        "allocations.get" => {
            let id = params["id"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("missing id"))?;
            let a = c
                .get_allocation(proto::GetAllocationRequest { id: id.into() })
                .await?
                .into_inner();
            Ok(serde_json::json!({
                "id": a.id, "username": a.username,
                "relay_address": a.relay_address, "client_address": a.client_address,
                "transport": a.transport, "remaining_lifetime": a.remaining_lifetime,
            }))
        }
        "allocations.kill" => {
            let id = params["id"].as_str()
                .ok_or_else(|| anyhow::anyhow!(
                    "missing id — use allocations.list to get the allocation id (string, not relay_port)"))?;
            let r = c
                .delete_allocation(DeleteAllocationRequest {
                    id: id.into(),
                    reason: params["reason"]
                        .as_str()
                        .unwrap_or("killed via turna-admin")
                        .into(),
                })
                .await?
                .into_inner();
            Ok(serde_json::json!({ "ok": r.success }))
        }
        "users.add" => {
            let r = c
                .add_user(AddUserRequest {
                    username: params["username"]
                        .as_str()
                        .ok_or_else(|| anyhow::anyhow!("missing username"))?
                        .into(),
                    password: params["password"]
                        .as_str()
                        .ok_or_else(|| anyhow::anyhow!("missing password"))?
                        .into(),
                    organization: params["organization"].as_str().unwrap_or("").into(),
                })
                .await?
                .into_inner();
            Ok(serde_json::json!({ "ok": r.success }))
        }
        "users.remove" => {
            let r = c
                .remove_user(RemoveUserRequest {
                    username: params["username"]
                        .as_str()
                        .ok_or_else(|| anyhow::anyhow!("missing username"))?
                        .into(),
                    force_delete_allocations: params["force"].as_bool().unwrap_or(false),
                })
                .await?
                .into_inner();
            Ok(serde_json::json!({ "ok": r.success, "allocations_deleted": r.allocations_deleted }))
        }
        "users.set_limits" => {
            let r = c
                .set_user_limits(SetUserLimitsRequest {
                    username: params["username"]
                        .as_str()
                        .ok_or_else(|| anyhow::anyhow!("missing username"))?
                        .into(),
                    max_allocations: params["max_allocations"].as_u64().unwrap_or(0) as u32,
                    max_bandwidth_bps: params["max_bandwidth_bps"].as_u64().unwrap_or(0),
                    max_lifetime: params["max_lifetime"].as_u64().unwrap_or(0) as u32,
                })
                .await?
                .into_inner();
            Ok(serde_json::json!({ "ok": r.success }))
        }
        "server.stats" => {
            let r = c
                .get_server_stats(GetServerStatsRequest {})
                .await?
                .into_inner();
            Ok(serde_json::json!({
                "uptime_seconds": r.uptime_seconds, "active_allocations": r.active_allocations,
                "total_allocations": r.total_allocations, "active_users": r.active_users,
                "pps": r.pps, "allocated_ports": r.allocated_ports,
                "available_ports": r.available_ports, "draining": r.draining,
                "avg_latency_us": r.avg_latency_us, "p99_latency_us": r.p99_latency_us,
                "blocked_ips": r.blocked_ips,
            }))
        }
        "config.get" => {
            let r = c.get_config(proto::GetConfigRequest {}).await?.into_inner();
            Ok(serde_json::json!({
                "realm": r.realm, "min_port": r.min_port, "max_port": r.max_port,
                "default_lifetime": r.default_lifetime, "max_lifetime": r.max_lifetime,
                "max_allocations_per_user": r.max_allocations_per_user,
                "max_bandwidth_per_user_bps": r.max_bandwidth_per_user_bps,
                "draining": r.draining, "external_ipv4": r.external_ipv4,
                "external_ipv6": r.external_ipv6,
            }))
        }
        "config.update" => {
            let r = c
                .update_config(proto::UpdateConfigRequest {
                    max_lifetime: params["max_lifetime"].as_u64().map(|v| v as u32),
                    max_allocations_per_user: params["max_allocations_per_user"]
                        .as_u64()
                        .map(|v| v as u32),
                    max_bandwidth_per_user_bps: params["max_bandwidth_per_user_bps"].as_u64(),
                    draining: params["draining"].as_bool(),
                })
                .await?
                .into_inner();
            Ok(serde_json::json!({ "ok": r.success, "warnings": r.warnings }))
        }
        "top_talkers" => {
            let r = c
                .get_top_talkers(proto::GetTopTalkersRequest {
                    limit: params["limit"].as_u64().unwrap_or(10) as u32,
                    sort_by: params["sort_by"].as_str().unwrap_or("bytes").into(),
                })
                .await?
                .into_inner();
            let talkers: Vec<_> = r
                .talkers
                .iter()
                .map(|t| {
                    serde_json::json!({
                        "username": t.username, "organization": t.organization,
                        "allocations": t.allocations, "total_bytes": t.total_bytes,
                        "bandwidth_bps": t.bandwidth_bps,
                    })
                })
                .collect();
            Ok(serde_json::json!({ "talkers": talkers }))
        }
        other => bail!("unknown command: {other}"),
    }
}
