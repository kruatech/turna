//! TURN-over-SCTP bridge — connects an SCTP client *control* transport to the
//! transport-agnostic [`PacketProcessor`], exactly like [`tls_bridge`](crate::tls_bridge).
//!
//! IMPORTANT SCOPE NOTE: there is **no TURN RFC** defining SCTP as a *relayed*
//! transport. This bridge treats SCTP purely as a client↔server **control**
//! transport (STUN/TURN messages length-framed over an SCTP association, same
//! framing as TURN-over-TCP). The relay socket to the peer stays **UDP**, shared
//! with the UDP [`RelayServer`](crate::server) via the same [`OutMsg`] channel and
//! [`ClientSinks`] registry — identical to the TLS bridge.
//!
//! CONTRACT for `turna_transport::sctp` (must be implemented there — this bridge is
//! the relay-side glue only): an `SctpTransportServer::new(SctpTransportConfig)`
//! whose `run(event_tx, send_rx)` emits the SAME transport-agnostic stream events
//! as the TLS server (`TcpTransportEvent::{ConnectionOpened, PacketReceived,
//! ConnectionClosed}`) and consumes `TcpSendCommand`. Each `PacketReceived.data`
//! MUST be exactly one de-framed STUN/ChannelData message (the SCTP codec splits
//! the stream), so the processor can treat it like a UDP datagram.

use std::sync::Arc;

use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

// Reuse the transport-agnostic stream event/command types (defined in tcp_tls):
// they are not TCP-specific, and the SCTP transport server emits/consumes them.
use turna_transport::sctp::{SctpTransportConfig, SctpTransportServer};
use turna_transport::tcp_tls::{TcpSendCommand, TcpTransportEvent};

use crate::processor::{Action, PacketProcessor};
use crate::server::{ClientSinks, OutMsg};

type BridgeResult = std::result::Result<(), Box<dyn std::error::Error + Send + Sync>>;

/// Run the TURN-over-SCTP bridge. Returns when the SCTP event stream ends.
///
/// * `cfg` — SCTP listener config (listen addr, limits).
/// * `processor` — shared TURN processor (same instance as the UDP path).
/// * `relay_tx` — the UDP server's relay [`OutMsg`] channel.
/// * `client_sinks` — shared addr→writer registry (relay return path lives in server.rs).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_sctp_bridge(
    cfg: SctpTransportConfig,
    processor: Arc<PacketProcessor>,
    relay_tx: mpsc::Sender<OutMsg>,
    client_sinks: ClientSinks,
    metrics: Arc<turna_health::Metrics>,
    shutdown: tokio::sync::watch::Receiver<bool>,
) -> BridgeResult {
    let server = SctpTransportServer::new(cfg)?;

    let (event_tx, mut event_rx) = mpsc::channel::<TcpTransportEvent>(8192);
    let (sctp_send_tx, sctp_send_rx) = mpsc::channel::<TcpSendCommand>(8192);

    let stats = Arc::new(turna_transport::sctp::SctpStats::default());

    // Mirror the transport's counters into Prometheus on a ticker, the same way
    // the TURNS bridge does. Without this the counters exist and nothing scrapes
    // them, which is the state pass 1 left behind.
    {
        let stats = stats.clone();
        let metrics = metrics.clone();
        tokio::spawn(async move {
            use std::sync::atomic::Ordering::Relaxed;
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(5));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tick.tick().await;
                let s = stats.snapshot();
                metrics.sctp_active.store(s.active as u64, Relaxed);
                metrics.sctp_conns_total.store(s.accepted, Relaxed);
                metrics.sctp_closed_total.store(s.closed, Relaxed);
                metrics
                    .sctp_rejected_over_cap
                    .store(s.rejected_over_cap, Relaxed);
                metrics
                    .sctp_rejected_per_ip
                    .store(s.rejected_per_ip, Relaxed);
                metrics
                    .sctp_rejected_rate_limit
                    .store(s.rejected_rate_limit, Relaxed);
                metrics.sctp_idle_timeouts.store(s.idle_timeouts, Relaxed);
                metrics.sctp_framing_errors.store(s.framing_errors, Relaxed);
                metrics.sctp_accept_errors.store(s.accept_errors, Relaxed);
                metrics.sctp_send_dropped.store(s.send_dropped, Relaxed);
                metrics.sctp_bytes_rx.store(s.bytes_rx, Relaxed);
                metrics.sctp_bytes_tx.store(s.bytes_tx, Relaxed);
                // Readiness follows the listener's own flag rather than a
                // separate belief about it: `listening` is set after bind and
                // cleared on drain, so a listener that stopped accepting cannot
                // keep reporting Ready.
                metrics.set_sctp_readiness(if s.listening {
                    turna_health::Readiness::Ready
                } else {
                    turna_health::Readiness::Draining
                });
            }
        });
    }

    {
        let stats = stats.clone();
        tokio::spawn(async move {
            if let Err(e) = server
                .run_with_shutdown(event_tx, sctp_send_rx, stats, shutdown)
                .await
            {
                error!(error = %e, "TURN-over-SCTP server stopped");
            }
        });
    }

    info!("TURN-over-SCTP bridge started");

    while let Some(ev) = event_rx.recv().await {
        match ev {
            TcpTransportEvent::ConnectionOpened { conn_id, peer_addr } => {
                let (sink_tx, mut sink_rx) = mpsc::channel::<Vec<u8>>(256);
                client_sinks.insert(peer_addr, sink_tx);

                let stx = sctp_send_tx.clone();
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
                debug!(%peer_addr, %conn_id, "SCTP connection opened");
            }

            TcpTransportEvent::PacketReceived {
                conn_id,
                peer_addr,
                data,
            } => {
                // One de-framed STUN/ChannelData message — process like a UDP datagram.
                let raw = data.freeze();
                for action in processor.process(raw, peer_addr) {
                    match action {
                        Action::Send { data, target } => {
                            if target == peer_addr {
                                let _ = sctp_send_tx
                                    .send(TcpSendCommand {
                                        conn_id,
                                        data: data.to_vec(),
                                    })
                                    .await;
                            } else if let Some(sink) = client_sinks.get(&target) {
                                let _ = sink.try_send(data.to_vec());
                            } else {
                                debug!(%target, "SCTP Send to unknown target dropped");
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
                            // client→peer: relayed over UDP via the shared machinery.
                            let _ = relay_tx
                                .send(OutMsg::Relay {
                                    port: relay_port,
                                    data,
                                    target,
                                })
                                .await;
                        }
                        Action::RegisterRelay { port, socket, .. } => {
                            let _ = relay_tx.send(OutMsg::RegisterRelay { port, socket }).await;
                        }
                        Action::CloseRelay { port } => {
                            let _ = relay_tx.send(OutMsg::CloseRelay { port }).await;
                        }
                        Action::RegisterTcpListener { .. } => {
                            // Peer-initiated TCP listeners are a TLS-bridge feature
                            // (tcp_relay is not set on the SCTP path); never produced
                            // here. Keep the match exhaustive.
                            warn!("SCTP bridge: unexpected RegisterTcpListener; dropping");
                        }
                        Action::ForwardZeroCopy { .. } => {
                            // Only produced on borrowed-slice ingress (io_uring/AF_XDP);
                            // the bridge uses process() which emits Forward{data}. Drop
                            // defensively rather than panic (a hit is a logic error).
                            warn!(
                                %peer_addr,
                                "SCTP bridge: unexpected ForwardZeroCopy on process() path; dropping"
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
                debug!(%peer_addr, %conn_id, %reason, "SCTP connection closed");
                // Release the allocation now instead of waiting for the TTL —
                // same reasoning as the TURNS bridge: for TURN over a stream
                // transport the control connection *is* the allocation's 5-tuple,
                // so once it closes the allocation can never be refreshed or used
                // again. Holding it only blocks a relay port and makes a
                // reconnecting client collide with 437 Allocation Mismatch.
                // (This was missing here while `tls_bridge` had it, so every
                // closed SCTP association leaked its allocation until expiry.)
                for action in processor.release_for_closed_connection(peer_addr) {
                    if let Action::CloseRelay { port } = action {
                        let _ = relay_tx.send(OutMsg::CloseRelay { port }).await;
                    }
                }
            }
        }
    }

    warn!("TURN-over-SCTP bridge event stream ended");
    Ok(())
}
