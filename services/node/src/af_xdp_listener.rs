//! AF_XDP transport backend (AF_XDP Phase 4).
//!
//! Drives the xsk-rs ring datapath (`turna_transport::af_xdp::xsk`) for the
//! main TURN socket: `recv_batch` → `PacketProcessor::process_slice` →
//! `send_to`. This is a transport *backend* (selected via
//! `transport = "af_xdp"`), not an additional listener like QUIC.
//!
//! Scope: handles the main client↔server control path AND the relay data plane.
//! Because the XDP redirect funnels all ingress on the queue into the xsk, relay
//! traffic is demuxed here by destination port (main TURN port → `process_slice`;
//! relay ports → `process_relay_recv`) and emitted via the xsk (`send_to` for
//! client responses, `send_to_from` for client→peer with the relay source port).
//! Peer MACs use the configured `dst_mac` (same-subnet); general ARP/neighbor
//! resolution is a follow-up. The loop is blocking; the caller runs it via
//! `spawn_blocking`.

use std::net::SocketAddr;
use std::sync::Arc;

#[cfg(all(target_os = "linux", feature = "af-xdp"))]
use turna_relay::processor::Action;
use turna_relay::PacketProcessor;

type DynErr = Box<dyn std::error::Error + Send + Sync>;

/// Run the AF_XDP datapath loop. Blocks until the process exits (shutdown
/// signalling is a follow-up).
#[cfg(all(target_os = "linux", feature = "af-xdp"))]
pub fn run_af_xdp(
    cfg: turna_config::AfXdpSection,
    processor: Arc<PacketProcessor>,
    listen: SocketAddr,
) -> Result<(), DynErr> {
    use turna_transport::af_xdp::xsk::XskDatapath;
    use turna_transport::af_xdp::AfXdpConfig;

    let src_mac = parse_mac(&cfg.src_mac)?;
    let dst_mac = parse_mac(&cfg.dst_mac)?;

    let xdp_cfg = AfXdpConfig {
        interface: cfg.interface.clone(),
        queue_id: cfg.queue_id,
        frame_count: cfg.frame_count,
        frame_size: cfg.frame_size,
        fill_ring_size: cfg.fill_ring_size,
        comp_ring_size: cfg.comp_ring_size,
        rx_ring_size: cfg.rx_ring_size,
        tx_ring_size: cfg.tx_ring_size,
        zero_copy: cfg.zero_copy,
        need_wakeup: cfg.need_wakeup,
    };

    let mut dp = XskDatapath::bind(&xdp_cfg, listen, src_mac, dst_mac)
        .map_err(|e| -> DynErr { Box::new(e) })?;

    tracing::info!(
        interface = %cfg.interface,
        queue = cfg.queue_id,
        "AF_XDP datapath running (main TURN socket)"
    );

    // Relay ports owned by this datapath. The XDP redirect funnels ALL ingress
    // on the queue into the xsk, so relay traffic (peer→client) arrives here too
    // — there are no separate kernel relay sockets to receive it. We demux by
    // destination port: the main TURN port goes to `process_slice`; an
    // allocation's relay port goes to `process_relay_recv`. `held` keeps the
    // kernel relay socket alive purely to reserve the OS port; its I/O is unused.
    let mut relay_ports: std::collections::HashSet<u16> = std::collections::HashSet::new();
    let mut held: std::collections::HashMap<u16, std::net::UdpSocket> =
        std::collections::HashMap::new();
    let listen_port = listen.port();

    // Busy-poll RX → process → TX, backing off briefly when idle so a quiet
    // socket doesn't peg a core.
    loop {
        let frames = dp.recv_batch(64);
        if frames.is_empty() {
            std::thread::sleep(std::time::Duration::from_micros(50));
            continue;
        }
        for f in frames {
            tracing::debug!(src = %f.source, dst = %f.dst, len = f.data.len(), "AF_XDP rx");
            let dport = f.dst.port();
            let actions = if dport == listen_port {
                processor.process_slice(&f.data, f.source)
            } else if relay_ports.contains(&dport) {
                // Peer→client relay data arriving on an allocation's relay port.
                processor.process_relay_recv(&f.data, f.source, f.dst)
            } else {
                continue;
            };
            for action in actions {
                match action {
                    Action::Send { data, target } => {
                        if let Err(e) = dp.send_to(&data, target) {
                            tracing::debug!(%e, "AF_XDP send_to failed");
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
                        // Client→peer relay: emit from the allocation's relay port.
                        if let Err(e) = dp.send_to_from(relay_port, &data, target) {
                            tracing::debug!(%e, port = relay_port, "AF_XDP relay send failed");
                        }
                    }
                    Action::RegisterRelay { port, socket, .. } => {
                        relay_ports.insert(port);
                        held.insert(port, socket);
                        tracing::debug!(port, "AF_XDP: relay port registered");
                    }
                    Action::CloseRelay { port } => {
                        relay_ports.remove(&port);
                        held.remove(&port);
                        tracing::debug!(port, "AF_XDP: relay port closed");
                    }
                    Action::None => {}
                }
            }
        }
    }
}

/// Stub for non-Linux / non-`af-xdp` builds: AF_XDP can't be selected here.
#[cfg(not(all(target_os = "linux", feature = "af-xdp")))]
pub fn run_af_xdp(
    _cfg: turna_config::AfXdpSection,
    _processor: Arc<PacketProcessor>,
    _listen: SocketAddr,
) -> Result<(), DynErr> {
    Err("transport=af_xdp requires a Linux build with the `af-xdp` feature".into())
}

/// Parse "aa:bb:cc:dd:ee:ff" into 6 octets. Empty string → all-zero placeholder
/// (until ARP/netlink neighbor resolution is implemented).
#[cfg(all(target_os = "linux", feature = "af-xdp"))]
fn parse_mac(s: &str) -> Result<[u8; 6], DynErr> {
    if s.is_empty() {
        return Ok([0u8; 6]);
    }
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return Err(format!("invalid MAC '{s}': expected 6 colon-separated octets").into());
    }
    let mut mac = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(p, 16)
            .map_err(|_| -> DynErr { format!("invalid MAC octet '{p}'").into() })?;
    }
    Ok(mac)
}
