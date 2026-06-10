//! AF_XDP transport backend (AF_XDP Phase 4).
//!
//! Drives the xsk-rs ring datapath (`turna_transport::af_xdp::xsk`) for the
//! main TURN socket: `recv_batch` → `PacketProcessor::process_slice` →
//! `send_to`. This is a transport *backend* (selected via
//! `transport = "af_xdp"`), not an additional listener like QUIC.
//!
//! Scope: handles the main client↔server control path. Relay-data-plane actions
//! (Forward / SendViaRelay / RegisterRelay / CloseRelay) need regular relay
//! sockets and are not yet wired through AF_XDP — they are skipped (logged).
//! The loop is blocking; the caller runs it via `spawn_blocking`.

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

    // Busy-poll RX → process → TX, backing off briefly when idle so a quiet
    // socket doesn't peg a core.
    loop {
        let frames = dp.recv_batch(64);
        if frames.is_empty() {
            std::thread::sleep(std::time::Duration::from_micros(50));
            continue;
        }
        for f in frames {
            for action in processor.process_slice(&f.data, f.source) {
                match action {
                    Action::Send { data, target } => {
                        if let Err(e) = dp.send_to(&data, target) {
                            tracing::debug!(%e, "AF_XDP send_to failed");
                        }
                    }
                    _ => {
                        // Relay-plane actions (Forward/RegisterRelay/…) require
                        // regular relay sockets — not yet wired through AF_XDP.
                        tracing::trace!("AF_XDP: non-Send action skipped (relay plane TODO)");
                    }
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
