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

use std::sync::Arc;

use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use turna_transport::tcp_tls::{
    TcpSendCommand, TcpTransportEvent, TlsTransportConfig, TlsTransportServer,
};

use crate::processor::{Action, PacketProcessor};
use crate::server::{ClientSinks, OutMsg};

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
) -> BridgeResult {
    let server = TlsTransportServer::new(cfg)?;

    // Events from the TLS server (opened / packet / closed).
    let (event_tx, mut event_rx) = mpsc::channel::<TcpTransportEvent>(8192);
    // Commands to the TLS server (write to a connection, keyed by conn_id).
    let (tls_send_tx, tls_send_rx) = mpsc::channel::<TcpSendCommand>(8192);

    tokio::spawn(async move {
        if let Err(e) = server.run(event_tx, tls_send_rx).await {
            error!(error = %e, "TURNS server stopped");
        }
    });

    info!("TURNS bridge started");

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
                for action in processor.process(raw, peer_addr) {
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
                            let _ = relay_tx
                                .send(OutMsg::RegisterRelay { port, socket })
                                .await;
                        }
                        Action::CloseRelay { port } => {
                            let _ = relay_tx.send(OutMsg::CloseRelay { port }).await;
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
                // The client's allocation is left to expire by TTL. A prompt
                // release would need a store hook keyed by client address; see
                // the §2c follow-up.
                let _ = conn_id;
            }
        }
    }

    warn!("TURNS bridge event stream ended");
    Ok(())
}
