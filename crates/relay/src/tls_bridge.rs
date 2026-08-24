//! TURNS bridge — connects the TLS-over-TCP transport (`turna_transport::tcp_tls`)
//! to the transport-agnostic [`PacketProcessor`].
//!
//! Data flow:
//! ```text
//!   client --TLS--> TlsTransportServer --event--> bridge --process()--> Action
//!                                                              |
//!         control response (Action::Send)  <--TcpSendCommand--+
//!         client→peer (Action::Forward)     --OutMsg::Relay--> relay socket --UDP--> peer
//!         peer→client                        <--client_sinks-- relay-recv task (server.rs)
//! ```
//!
//! The bridge shares two things with the UDP [`RelayServer`](crate::server):
//!   * the relay [`OutMsg`] channel — so client→peer forwarding and relay
//!     socket (de)registration use the exact same machinery as UDP;
//!   * the [`ClientSinks`] registry — so the relay return path (peer→client),
//!     which lives in the UDP server, can deliver to a TLS connection.
//!
//! Only the client↔server *control* channel and client↔peer *data* travel over
//! TLS here; the relay socket to the peer remains UDP (TURN relays UDP to peers).

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use turna_transport::tcp_tls::{
    DetachRequest, DetachedConn, TcpSendCommand, TcpTransportEvent, TlsStats, TlsTransportConfig,
    TlsTransportServer,
};

use crate::processor::{Action, ConnBindDecision, ConnectDecision, PacketProcessor};
use crate::server::{ClientSinks, OutMsg};
use crate::tcp_relay::{AllocationId, TcpRelayManager};
use turna_proto_stun::header::MessageClass;
use turna_proto_stun::message::StunMessage;
use turna_proto_stun::method::Method;

type BridgeResult = std::result::Result<(), Box<dyn std::error::Error + Send + Sync>>;

/// Run the TURNS bridge. Returns when the TLS event stream ends (server stopped).
///
/// * `cfg` — TLS listener config (cert/key paths, listen addr, limits).
/// * `processor` — shared TURN processor (same instance as the UDP path).
/// * `relay_tx` — the UDP server's relay [`OutMsg`] channel.
/// * `client_sinks` — shared addr→TLS-writer registry.
pub(crate) async fn run_tls_bridge(
    cfg: TlsTransportConfig,
    processor: Arc<PacketProcessor>,
    relay_tx: mpsc::Sender<OutMsg>,
    client_sinks: ClientSinks,
    tcp_relay: Option<Arc<TcpRelayManager>>,
    shutdown: tokio::sync::watch::Receiver<bool>,
) -> BridgeResult {
    let server = TlsTransportServer::new(cfg)?;

    // Shared counters for the TURNS listener, mirrored into the Prometheus
    // metrics below. Before this the TLS transport exported nothing at all.
    let stats = Arc::new(TlsStats::default());
    spawn_tls_metrics_mirror(stats.clone(), processor.metrics().clone());

    // Events from the TLS server (opened / packet / closed).
    let (event_tx, mut event_rx) = mpsc::channel::<TcpTransportEvent>(8192);
    // Commands to the TLS server (write to a connection, keyed by conn_id).
    let (tls_send_tx, tls_send_rx) = mpsc::channel::<TcpSendCommand>(8192);
    // RFC 6062 role transition: detach requests (bridge -> transport) and the
    // detached raw client streams handed back (transport -> bridge).
    let (detach_req_tx, detach_req_rx) = mpsc::channel::<DetachRequest>(256);
    let (detach_out_tx, mut detach_out_rx) = mpsc::channel::<DetachedConn>(256);

    let server_stats = stats.clone();
    let server_shutdown = shutdown.clone();
    tokio::spawn(async move {
        if let Err(e) = server
            .run_full(
                event_tx,
                tls_send_rx,
                detach_req_rx,
                detach_out_tx,
                server_stats,
                server_shutdown,
            )
            .await
        {
            error!(error = %e, "TURNS server stopped");
        }
    });

    // Raw handoff consumer: splice each detached client data connection to its
    // claimed peer connection (RFC 6062 phase 2). Drops the stream if TCP relay
    // is disabled (no detaches are ever requested in that case).
    let detach_mgr = tcp_relay.clone();
    tokio::spawn(async move {
        while let Some(d) = detach_out_rx.recv().await {
            if let Some(mgr) = &detach_mgr {
                let id = crate::tcp_relay::TcpConnectionId::from_raw(d.connection_id);
                if let Err(e) = mgr.attach_bound(id, d).await {
                    warn!(error = %e, "RFC 6062 ConnectionBind attach failed");
                }
            }
        }
    });

    info!("TURNS bridge started");

    // RFC 6062 §4.4 peer-initiated: per-allocation relayed TCP accept loops,
    // keyed by relay port so CloseRelay can abort them.
    let mut tcp_listeners: std::collections::HashMap<u16, tokio::task::JoinHandle<()>> =
        std::collections::HashMap::new();

    while let Some(ev) = event_rx.recv().await {
        match ev {
            TcpTransportEvent::ConnectionOpened { conn_id, peer_addr } => {
                // Per-connection sink: the relay return path (server.rs) and any
                // cross-client control Send push raw message bytes here; we forward
                // each as a framed write to *this* connection.
                let (sink_tx, mut sink_rx) = mpsc::channel::<Vec<u8>>(256);
                client_sinks.insert(peer_addr, sink_tx);

                let stx = tls_send_tx.clone();
                tokio::spawn(async move {
                    while let Some(bytes) = sink_rx.recv().await {
                        if stx
                            .send(TcpSendCommand {
                                conn_id,
                                data: bytes,
                            })
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                });
                debug!(%peer_addr, %conn_id, "TURNS connection opened");
            }

            TcpTransportEvent::PacketReceived {
                conn_id,
                peer_addr,
                data,
            } => {
                // `data` is one self-framed STUN/ChannelData message (the TLS
                // codec already split the stream). Process it exactly like a UDP
                // datagram from `peer_addr`.
                let raw = data.freeze();
                // RFC 6062 CONNECT needs an async outbound connect — it cannot go
                // through the sync process(); handle it out-of-band here.
                if let Some(mgr) = &tcp_relay {
                    if let Ok(m) = StunMessage::decode(&raw) {
                        if matches!(m.method, Method::Connect)
                            && matches!(m.class, MessageClass::Request)
                        {
                            bridge_handle_connect(
                                &processor,
                                mgr,
                                conn_id,
                                peer_addr,
                                &m,
                                &raw,
                                &tls_send_tx,
                            )
                            .await;
                            continue;
                        }
                        if matches!(m.method, Method::ConnectionBind)
                            && matches!(m.class, MessageClass::Request)
                        {
                            bridge_handle_connection_bind(
                                &processor,
                                mgr,
                                conn_id,
                                peer_addr,
                                &m,
                                &raw,
                                &tls_send_tx,
                                &detach_req_tx,
                            )
                            .await;
                            continue;
                        }
                    }
                }
                // TCP/TLS control-connection ingress: `process_tcp_control` sets
                // `ingress_tcp`, without which `handle_allocate` rejects every
                // RFC 6062 TCP allocation with 400 (§4.1 requires a TCP/TLS
                // control connection) — making the whole CONNECT /
                // ConnectionBind / detach path below unreachable.
                for action in processor.process_tcp_control(raw, peer_addr) {
                    match action {
                        Action::Send { data, target } => {
                            if target == peer_addr {
                                // Control response to this client over its TLS conn.
                                let _ = tls_send_tx
                                    .send(TcpSendCommand {
                                        conn_id,
                                        data: data.to_vec(),
                                    })
                                    .await;
                            } else if let Some(sink) = client_sinks.get(&target) {
                                // Destined for another TLS client (rare on the
                                // control path); route via its sink.
                                let _ = sink.try_send(data.to_vec());
                            } else {
                                // Unknown / UDP target on a TLS control response —
                                // nothing we can do from the bridge; drop.
                                debug!(%target, "TURNS Send to unknown target dropped");
                            }
                        }
                        Action::Forward {
                            data,
                            target,
                            relay_port,
                        }
                        | Action::SendViaRelay {
                            data,
                            target,
                            relay_port,
                        } => {
                            // client→peer: relay over UDP via the shared machinery.
                            let _ = relay_tx
                                .send(OutMsg::Relay {
                                    port: relay_port,
                                    data,
                                    target,
                                })
                                .await;
                        }
                        Action::RegisterRelay { port, socket, .. } => {
                            // Allocate: the relay socket was bound during process();
                            // hand it to the UDP server, which adopts it and spawns
                            // the peer→client relay-recv task (TLS-aware via sinks).
                            let _ = relay_tx.send(OutMsg::RegisterRelay { port, socket }).await;
                        }
                        Action::RegisterTcpListener {
                            relay_port,
                            listener,
                            client_addr,
                            owner_key,
                        } => {
                            // RFC 6062 §4.4 peer-initiated: accept peer TCP
                            // connections on the relayed port, register each with
                            // the TCP relay manager, and notify the client over its
                            // control connection with a ConnectionAttempt
                            // indication. The client then opens a new connection and
                            // ConnectionBinds the id (ownership-checked in claim()).
                            if let Some(mgr) = &tcp_relay {
                                let mgr = mgr.clone();
                                let sinks = client_sinks.clone();
                                let proc = processor.clone();
                                listener.set_nonblocking(true).ok();
                                match tokio::net::TcpListener::from_std(listener) {
                                    Ok(l) => {
                                        let handle = tokio::spawn(async move {
                                            let alloc = AllocationId(relay_port as u64);
                                            loop {
                                                match l.accept().await {
                                                    Ok((stream, peer)) => {
                                                        match mgr
                                                            .register_incoming(
                                                                alloc,
                                                                peer,
                                                                stream,
                                                                owner_key.clone(),
                                                            )
                                                            .await
                                                        {
                                                            Ok(id) => {
                                                                let ind = proc
                                                                    .build_connection_attempt_indication(
                                                                        id.value(),
                                                                        peer,
                                                                    );
                                                                let delivered = match ind {
                                                                    Some(bytes) => sinks
                                                                        .get(&client_addr)
                                                                        .map(|s| {
                                                                            s.try_send(bytes)
                                                                                .is_ok()
                                                                        })
                                                                        .unwrap_or(false),
                                                                    None => false,
                                                                };
                                                                if !delivered {
                                                                    // Client gone / queue full / encode
                                                                    // error: the pending peer conn would
                                                                    // never be bound — drop it.
                                                                    mgr.release(id).await;
                                                                }
                                                            }
                                                            Err(e) => {
                                                                debug!(%peer, error = %e, "RFC 6062 peer connection rejected");
                                                            }
                                                        }
                                                    }
                                                    Err(e) => {
                                                        warn!(port = relay_port, error = %e, "relayed TCP accept failed; stopping listener");
                                                        break;
                                                    }
                                                }
                                            }
                                        });
                                        tcp_listeners.insert(relay_port, handle);
                                    }
                                    Err(e) => {
                                        warn!(port = relay_port, error = %e, "failed to adopt relayed TCP listener")
                                    }
                                }
                            }
                        }
                        Action::CloseRelay { port } => {
                            let _ = relay_tx.send(OutMsg::CloseRelay { port }).await;
                            // Stop the peer-initiated accept loop (frees the fd).
                            if let Some(h) = tcp_listeners.remove(&port) {
                                h.abort();
                            }
                        }
                        Action::ForwardZeroCopy { .. } => {
                            // Emitted only by `process_slice` on borrowed-slice
                            // ingress (io_uring / AF_XDP). The TLS bridge uses
                            // `process_tcp_control()`, which emits
                            // `Forward { data }`, and the original recv buffer is
                            // moved into it, so the payload cannot be
                            // reconstructed from offset/len here. Unreachable on
                            // this path; drop defensively (a hit would be a logic
                            // error) rather than panic.
                            tracing::warn!(
                                %peer_addr,
                                "TURNS bridge: unexpected ForwardZeroCopy on owning-process path; dropping"
                            );
                        }
                        Action::None => {}
                    }
                }
            }

            TcpTransportEvent::ConnectionClosed {
                conn_id,
                peer_addr,
                reason,
            } => {
                client_sinks.remove(&peer_addr);
                debug!(%peer_addr, %conn_id, %reason, "TURNS connection closed");
                // §2c: release the allocation now instead of waiting for the TTL.
                // For TURN over TCP the control connection *is* the allocation's
                // 5-tuple, so once it closes the allocation can never be
                // refreshed or used again — holding it (and its relay port/fd)
                // for the rest of the lifetime only blocks capacity and makes a
                // reconnecting client collide with 437 Allocation Mismatch.
                for action in processor.release_for_closed_connection(peer_addr) {
                    if let Action::CloseRelay { port } = action {
                        let _ = relay_tx.send(OutMsg::CloseRelay { port }).await;
                        if let Some(h) = tcp_listeners.remove(&port) {
                            h.abort();
                        }
                        // RFC 6062: drop any pending/bound peer connections that
                        // belonged to this (TCP) allocation.
                        if let Some(mgr) = &tcp_relay {
                            mgr.cleanup_allocation(AllocationId(port as u64)).await;
                        }
                    }
                }
            }
        }
    }

    warn!("TURNS bridge event stream ended");
    Ok(())
}

/// Copy `TlsStats` into the shared Prometheus `Metrics` every few seconds and
/// derive `turna_tls_readiness` from the listener's bound state. The transport
/// crate is leaf-level and cannot depend on `turna-health`, so — exactly like
/// the DTLS/QUIC listeners do in the node — the copy lives on this side.
fn spawn_tls_metrics_mirror(stats: Arc<TlsStats>, metrics: Arc<turna_health::Metrics>) {
    tokio::spawn(async move {
        use std::sync::atomic::Ordering::Relaxed;
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(5));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            let s = stats.snapshot();
            metrics.tls_active.store(s.active as u64, Relaxed);
            metrics.tls_conns_total.store(s.accepted, Relaxed);
            metrics.tls_closed_total.store(s.closed, Relaxed);
            metrics
                .tls_handshake_failures
                .store(s.handshake_failures, Relaxed);
            metrics
                .tls_handshake_timeouts
                .store(s.handshake_timeouts, Relaxed);
            metrics
                .tls_rejected_over_cap
                .store(s.rejected_over_cap, Relaxed);
            metrics
                .tls_rejected_per_ip
                .store(s.rejected_per_ip, Relaxed);
            metrics.tls_idle_timeouts.store(s.idle_timeouts, Relaxed);
            metrics.tls_framing_errors.store(s.framing_errors, Relaxed);
            metrics.tls_accept_errors.store(s.accept_errors, Relaxed);
            metrics.tls_bytes_rx.store(s.bytes_rx, Relaxed);
            metrics.tls_bytes_tx.store(s.bytes_tx, Relaxed);
            metrics.tls_cert_reloads.store(s.cert_reloads, Relaxed);
            metrics
                .tls_cert_reload_failures
                .store(s.cert_reload_failures, Relaxed);
            metrics
                .tls_rejected_rate_limit
                .store(s.rejected_rate_limit, Relaxed);
            metrics.tls_alpn_rejected.store(s.alpn_rejected, Relaxed);
            metrics.set_tls_readiness(if s.listening {
                turna_health::Readiness::Ready
            } else {
                turna_health::Readiness::Degraded
            });
        }
    });
}

/// Handle one RFC 6062 CONNECT request on a client's TLS control connection:
/// validate synchronously (auth + TCP allocation + permission) via the processor,
/// then perform the async outbound TCP connect to the peer and reply with
/// CONNECTION-ID (or 447 on failure). The relayed data itself flows once the
/// client issues CONNECTION-BIND on a fresh connection (handled elsewhere).
async fn bridge_handle_connect(
    processor: &Arc<PacketProcessor>,
    mgr: &Arc<TcpRelayManager>,
    conn_id: turna_transport::tcp_tls::TcpConnectionId,
    peer_addr: SocketAddr,
    msg: &StunMessage,
    raw: &[u8],
    tls_send_tx: &mpsc::Sender<TcpSendCommand>,
) {
    match processor.connect_decision(msg, raw, peer_addr) {
        ConnectDecision::Reject(actions) => {
            for a in actions {
                if let Action::Send { data, target } = a {
                    if target == peer_addr {
                        let _ = tls_send_tx
                            .send(TcpSendCommand {
                                conn_id,
                                data: data.to_vec(),
                            })
                            .await;
                    }
                }
            }
        }
        ConnectDecision::Proceed {
            peer,
            key,
            relay_port,
        } => {
            let alloc = AllocationId(relay_port as u64);
            // Record the authenticated owner so only the same credentials can
            // later ConnectionBind this peer connection (RFC 6062 §4.4, O#1).
            let bytes = match mgr.handle_connect(alloc, peer, key.clone()).await {
                Ok(id) => processor.build_connect_success(id.value(), &key, msg),
                Err(e) => {
                    debug!(%peer, error = %e, "RFC 6062 CONNECT failed");
                    processor
                        .encode_connect_error(msg, peer_addr, 447, "Connection Timeout or Failure")
                        .into_iter()
                        .find_map(|a| match a {
                            Action::Send { data, .. } => Some(data.to_vec()),
                            _ => None,
                        })
                }
            };
            if let Some(bytes) = bytes {
                let _ = tls_send_tx
                    .send(TcpSendCommand {
                        conn_id,
                        data: bytes,
                    })
                    .await;
            }
        }
    }
}

/// Handle one RFC 6062 ConnectionBind on a fresh TLS data connection: validate,
/// atomically claim the pending peer connection, and on success ask the transport
/// to write the success response and detach this connection into raw relay mode.
/// A bad or already-used CONNECTION-ID gets 400 and the connection stays framed.
#[allow(clippy::too_many_arguments)]
async fn bridge_handle_connection_bind(
    processor: &Arc<PacketProcessor>,
    mgr: &Arc<TcpRelayManager>,
    conn_id: turna_transport::tcp_tls::TcpConnectionId,
    peer_addr: SocketAddr,
    msg: &StunMessage,
    raw: &[u8],
    tls_send_tx: &mpsc::Sender<TcpSendCommand>,
    detach_req_tx: &mpsc::Sender<DetachRequest>,
) {
    match processor.connection_bind_decision(msg, raw, peer_addr) {
        ConnBindDecision::Reject(actions) => {
            for a in actions {
                if let Action::Send { data, target } = a {
                    if target == peer_addr {
                        let _ = tls_send_tx
                            .send(TcpSendCommand {
                                conn_id,
                                data: data.to_vec(),
                            })
                            .await;
                    }
                }
            }
        }
        ConnBindDecision::Proceed {
            connection_id,
            key,
            success,
        } => {
            let id = crate::tcp_relay::TcpConnectionId::from_raw(connection_id);
            match mgr.claim(id, &key).await {
                Ok(()) => {
                    // Success + raw switch travel the same per-connection queue, so
                    // the success is written before the detach (ordering held by
                    // the transport). If the detach handoff cannot be delivered
                    // (transport gone), the claimed peer connection would leak in
                    // `Claimed` forever — roll the claim back (O#2).
                    if detach_req_tx
                        .send(DetachRequest {
                            conn_id,
                            connection_id,
                            success,
                        })
                        .await
                        .is_err()
                    {
                        warn!(
                            conn = connection_id,
                            "RFC 6062 detach handoff failed — releasing claimed connection"
                        );
                        mgr.release(id).await;
                    }
                }
                Err(e) => {
                    debug!(error = %e, "RFC 6062 ConnectionBind claim rejected");
                    let bytes = processor
                        .encode_connect_error(msg, peer_addr, 400, "Bad Request")
                        .into_iter()
                        .find_map(|a| match a {
                            Action::Send { data, .. } => Some(data.to_vec()),
                            _ => None,
                        });
                    if let Some(bytes) = bytes {
                        let _ = tls_send_tx
                            .send(TcpSendCommand {
                                conn_id,
                                data: bytes,
                            })
                            .await;
                    }
                }
            }
        }
    }
}
