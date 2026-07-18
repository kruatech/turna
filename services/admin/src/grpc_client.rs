//! gRPC client to turna control-plane.
//!
//! TLS modes:
//!   1. `https://` address, no --tls-* flags  → TLS with system roots (works with LE certs)
//!   2. `https://` address + --tls-ca/cert/key → mTLS (custom CA + client cert)
//!   3. `http://`  address                     → plaintext (loopback dev only)
//!
//! tonic 0.14: system roots are opt-in — the `tls-native-roots` feature plus
//! `ClientTlsConfig::with_native_roots()` load the OS trust store, so Let's
//! Encrypt certs are accepted (runtime image ships ca-certificates).

use anyhow::{bail, Context, Result};
use std::path::PathBuf;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};
use tracing::info;

pub mod proto {
    tonic::include_proto!("turna.management.v1");
}
use proto::{
    turna_management_client::TurnaManagementClient, AddUserRequest, DeleteAllocationRequest,
    GetConfigRequest, GetServerStatsRequest, LimitMode, ListAllocationsRequest, RemoveUserRequest,
    SetDrainingRequest, SetUserLimitsRequest, UInt32Limit, UInt64Limit, UpdateConfigRequest,
    UserLimitScope, UserLimitTarget, UserLimitsPatch,
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
                ClientTlsConfig::new().with_native_roots()
            }
        };
        endpoint.tls_config(tls_cfg)?.connect_lazy()
    } else {
        // Lazy plaintext channel: the admin container can start and serve its
        // own health/static assets while the control-plane is temporarily down.
        // Individual management requests still fail explicitly at dispatch.
        endpoint.connect_lazy()
    };

    Ok(channel)
}

fn required_str<'a>(params: &'a serde_json::Value, key: &str) -> Result<&'a str> {
    params[key]
        .as_str()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("missing {key}"))
}

fn limit_mode(value: &serde_json::Value) -> Result<i32> {
    let mode = match value["mode"].as_str().unwrap_or("inherit") {
        "inherit" => LimitMode::Inherit,
        "value" => LimitMode::Value,
        "unlimited" => LimitMode::Unlimited,
        "disabled" => LimitMode::Disabled,
        other => bail!("invalid limit mode {other:?}"),
    };
    Ok(mode as i32)
}

fn optional_u32(params: &serde_json::Value, key: &str) -> Result<Option<u32>> {
    let Some(value) = params.get(key) else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let raw = value
        .as_u64()
        .ok_or_else(|| anyhow::anyhow!("{key} must be an unsigned integer"))?;
    let parsed = u32::try_from(raw).map_err(|_| anyhow::anyhow!("{key} exceeds u32::MAX"))?;
    Ok(Some(parsed))
}

fn required_u64(params: &serde_json::Value, key: &str) -> Result<u64> {
    params
        .get(key)
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| anyhow::anyhow!("missing or invalid {key}"))
}

fn u32_limit(params: &serde_json::Value, key: &str) -> Result<Option<UInt32Limit>> {
    let Some(value) = params.get(key) else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let mode = limit_mode(value)?;
    let raw = value
        .get("value")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let parsed = u32::try_from(raw).map_err(|_| anyhow::anyhow!("{key}.value exceeds u32::MAX"))?;
    Ok(Some(UInt32Limit {
        mode,
        value: parsed,
    }))
}

fn u64_limit(params: &serde_json::Value, key: &str) -> Result<Option<UInt64Limit>> {
    let Some(value) = params.get(key) else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let mode = limit_mode(value)?;
    let parsed = value
        .get("value")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    Ok(Some(UInt64Limit {
        mode,
        value: parsed,
    }))
}

fn snapshot_json(snapshot: Option<proto::RuntimeConfigSnapshot>) -> serde_json::Value {
    match snapshot {
        Some(value) => serde_json::json!({
            "version": value.version,
            "max_allocations": value.max_allocations,
            "max_allocations_per_user": value.max_allocations_per_user,
            "max_bytes_per_sec_per_allocation": value.max_bytes_per_sec_per_allocation,
        }),
        None => serde_json::Value::Null,
    }
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
            // The command routes to a specific node via the command log, so a
            // node_id is required (an empty one is rejected server-side). An
            // optional idempotency_key lets a retried drain dedup (P0.3).
            let node_id = params["node_id"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("missing node_id — which node to drain"))?;
            let r = c
                .set_draining(SetDrainingRequest {
                    draining: true,
                    node_id: node_id.into(),
                    idempotency_key: params["idempotency_key"].as_str().unwrap_or("").into(),
                })
                .await?
                .into_inner();
            Ok(serde_json::json!({ "ok": r.success, "active_allocations": r.active_allocations }))
        }
        "node.undrain" => {
            let node_id = params["node_id"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("missing node_id — which node to undrain"))?;
            let r = c
                .set_draining(SetDrainingRequest {
                    draining: false,
                    node_id: node_id.into(),
                    idempotency_key: params["idempotency_key"].as_str().unwrap_or("").into(),
                })
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
                    idempotency_key: params["idempotency_key"].as_str().unwrap_or("").into(),
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
            let scope = match params["scope"].as_str().unwrap_or("user") {
                "global" => UserLimitScope::Global,
                "tenant" => UserLimitScope::Tenant,
                "user" => UserLimitScope::User,
                other => bail!("invalid user-limit scope {other:?}"),
            };
            let r = c
                .set_user_limits(SetUserLimitsRequest {
                    node_id: required_str(params, "node_id")?.into(),
                    target: Some(UserLimitTarget {
                        scope: scope as i32,
                        tenant: params["tenant"].as_str().unwrap_or("").into(),
                        realm: params["realm"].as_str().unwrap_or("").into(),
                        username: params["username"].as_str().unwrap_or("").into(),
                    }),
                    idempotency_key: required_str(params, "idempotency_key")?.into(),
                    expected_version: required_u64(params, "expected_version")?,
                    patch: Some(UserLimitsPatch {
                        max_allocations: u32_limit(params, "max_allocations")?,
                        max_bytes_per_sec_per_allocation: u64_limit(
                            params,
                            "max_bytes_per_sec_per_allocation",
                        )?,
                        max_lifetime_secs: u32_limit(params, "max_lifetime_secs")?,
                    }),
                    reason: params["reason"].as_str().unwrap_or("").into(),
                })
                .await?
                .into_inner();
            let effective = r.effective.map(|value| {
                serde_json::json!({
                    "max_allocations": value.max_allocations,
                    "max_bytes_per_sec_per_allocation": value.max_bytes_per_sec_per_allocation,
                    "max_lifetime_secs": value.max_lifetime_secs,
                    "allocations_disabled": value.allocations_disabled,
                    "bandwidth_disabled": value.bandwidth_disabled,
                    "lifetime_disabled": value.lifetime_disabled,
                    "inherited_fields": value.inherited_fields,
                    "capped_fields": value.capped_fields,
                })
            });
            Ok(serde_json::json!({
                "request_id": r.request_id,
                "previous_version": r.previous_version,
                "observed_version": r.observed_version,
                "effective": effective,
                "max_user_allocations_in_scope": r.max_user_allocations_in_scope,
                "max_user_allocations_above_limit": r.max_user_allocations_above_limit,
                "terminal_status": r.terminal_status,
                "error": r.error,
            }))
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
            let r = c
                .get_config(GetConfigRequest {
                    node_id: required_str(params, "node_id")?.into(),
                })
                .await?
                .into_inner();
            Ok(serde_json::json!({
                "node_id": r.node_id,
                "desired_version": r.desired_version,
                "observed_version": r.observed_version,
                "observed": snapshot_json(r.observed),
                "pending_desired": snapshot_json(r.pending_desired),
                "status": r.status,
                "last_apply_error": r.last_apply_error,
                "updated_at_ms": r.updated_at_ms,
            }))
        }
        "config.update" => {
            let r = c
                .update_config(UpdateConfigRequest {
                    node_id: required_str(params, "node_id")?.into(),
                    idempotency_key: required_str(params, "idempotency_key")?.into(),
                    expected_version: required_u64(params, "expected_version")?,
                    max_allocations: optional_u32(params, "max_allocations")?,
                    max_allocations_per_user: optional_u32(params, "max_allocations_per_user")?,
                    max_bytes_per_sec_per_allocation: params
                        .get("max_bytes_per_sec_per_allocation")
                        .filter(|value| !value.is_null())
                        .map(|value| {
                            value.as_u64().ok_or_else(|| {
                                anyhow::anyhow!(
                                    "max_bytes_per_sec_per_allocation must be an unsigned integer"
                                )
                            })
                        })
                        .transpose()?,
                    reason: params["reason"].as_str().unwrap_or("").into(),
                })
                .await?
                .into_inner();
            Ok(serde_json::json!({
                "request_id": r.request_id,
                "previous_version": r.previous_version,
                "observed_version": r.observed_version,
                "changed": r.changed,
                "applied": snapshot_json(r.applied),
                "terminal_status": r.terminal_status,
                "error": r.error,
                "rolled_back": r.rolled_back,
            }))
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
