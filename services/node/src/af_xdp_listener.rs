//! AF_XDP UDP datapath with one XSK per configured RX queue and a shared
//! address/port-scoped XDP filter. TCP, ARP/NDP and unrelated UDP pass to the
//! kernel. The loop owns relay sockets, map updates, expiry and ring maintenance.
//! Per-destination MAC resolution uses the configured interface's routes/neighbors.

use std::net::SocketAddr;
use std::sync::Arc;

#[cfg(all(target_os = "linux", feature = "af-xdp"))]
use turna_relay::processor::Action;
use turna_relay::PacketProcessor;

type DynErr = Box<dyn std::error::Error + Send + Sync>;

/// Run until cooperative shutdown, then drain submitted TX frames.
#[cfg(all(target_os = "linux", feature = "af-xdp"))]
pub fn run_af_xdp(
    cfg: turna_config::AfXdpSection,
    processor: Arc<PacketProcessor>,
    listen: SocketAddr,
    shutdown: tokio::sync::watch::Receiver<bool>,
    metrics: Arc<turna_health::Metrics>,
) -> Result<(), DynErr> {
    use std::sync::atomic::Ordering::Relaxed;
    use turna_transport::af_xdp::xsk::XskDatapath;
    use turna_transport::af_xdp::AfXdpConfig;

    // AFX-2 fail-fast preflight: validate ring/UMEM geometry and the runtime
    // environment (interface, queue, MTU, CAP_NET_RAW) before touching the
    // kernel. A misconfigured AF_XDP backend must abort startup, never run
    // partially.
    if let Err(problems) = preflight_af_xdp(&cfg) {
        for p in &problems {
            tracing::error!(problem = %p, "[turn.af_xdp] preflight failed");
        }
        tracing::error!(
            count = problems.len(),
            "[turn.af_xdp] preflight failed -> aborting startup"
        );
        return Err(format!(
            "[turn.af_xdp] preflight failed ({} problem(s)): {}",
            problems.len(),
            problems.join("; ")
        )
        .into());
    }

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
        native_mode: cfg.attach_mode == "native" || (cfg.attach_mode == "auto" && cfg.zero_copy),
        need_wakeup: cfg.need_wakeup,
    };

    if listen.ip().is_unspecified() {
        return Err("AF_XDP requires a concrete listen IP".into());
    }
    let _main_socket = std::net::UdpSocket::bind(listen)?;
    let queue_ids = if cfg.queue_ids.is_empty() {
        vec![cfg.queue_id]
    } else {
        cfg.queue_ids.clone()
    };
    let mut datapaths: Vec<XskDatapath> = Vec::new();
    for &queue in &queue_ids {
        let mut selected = xdp_cfg.clone();
        selected.queue_id = queue;
        let dp = if let Some(first) = datapaths.first() {
            first.bind_sibling(&selected, src_mac, dst_mac)?
        } else {
            XskDatapath::bind(&selected, listen, src_mac, dst_mac)?
        };
        datapaths.push(dp);
    }

    tracing::info!(
        interface = %cfg.interface,
        queues = ?queue_ids,
        "AF_XDP datapath running (main TURN socket)"
    );

    // Phase 2: per-destination neighbor resolution. We run under
    // spawn_blocking, so the ambient runtime handle is available; spawn the
    // async netlink resolver there and hand the datapath a shared cache. On a
    // cache miss the send paths fall back to the static dst_mac and queue a
    // resolve, so a resolver failure degrades to Phase-1 behaviour.
    {
        use turna_transport::neighbor::{run_resolver_on_interface, NeighborCache};
        let cache = NeighborCache::new();
        // B6: bounded neighbor-resolve queue (drop-on-full in the datapath).
        let (req_tx, req_rx) = tokio::sync::mpsc::channel(1024);
        let resolver_cache = cache.clone();
        let resolver_interface = cfg.interface.clone();
        tokio::runtime::Handle::current().spawn(async move {
            if let Err(e) =
                run_resolver_on_interface(resolver_cache, req_rx, &resolver_interface).await
            {
                tracing::warn!(%e, "AF_XDP neighbor resolver exited; using static dst_mac");
            }
        });
        for dp in &mut datapaths {
            dp.attach_neighbor(
                cache.clone(),
                req_tx.clone(),
                std::time::Duration::from_secs(30),
            );
        }
    }

    // Relay ports owned by this datapath. The selective XDP map redirects their
    // traffic across all configured queues. We demux by
    // destination port: the main TURN port goes to `process_slice`; an
    // allocation's relay port goes to `process_relay_recv`. `held` keeps the
    // kernel relay socket alive purely to reserve the OS port; its I/O is unused.
    let mut relay_ports: std::collections::HashSet<u16> = std::collections::HashSet::new();
    let mut held: std::collections::HashMap<u16, std::net::UdpSocket> =
        std::collections::HashMap::new();
    let listen_port = listen.port();

    // Own readiness gauge, not the process-level one: on a kernel-bypass datapath
    // "the XSK socket died but the process is fine" is a distinct and far more
    // likely failure than the process dying, and `/ready` will not show it.
    metrics.set_afxdp_readiness(turna_health::Readiness::Ready);
    metrics.set_transport_readiness(turna_health::Readiness::Ready);
    metrics.set_readiness(turna_health::Readiness::Ready);
    let mut maintenance = std::time::Instant::now();
    let mut next_queue = 0usize;
    let mut queue_counts = vec![(0u64, 0u64, 0u64, 0u64); datapaths.len()];
    let mut queue_report = std::time::Instant::now();

    // Busy-poll RX → process → TX, backing off briefly when idle so a quiet
    // socket doesn't peg a core.
    loop {
        // AFX-5: cooperative shutdown. The signal task flips this watch to
        // `true` (after the optional drain grace); recv_batch is non-blocking,
        // so we observe it within one poll interval and return cleanly. RAII
        // Drop releases sockets/UMEM and the shared embedded XDP program.
        // Do not detach an unrelated operator-owned program.
        if *shutdown.borrow() {
            tracing::info!("AF_XDP datapath: shutdown signalled, stopping");
            metrics.set_afxdp_readiness(turna_health::Readiness::Draining);
            for dp in &mut datapaths {
                dp.drain_tx(std::time::Duration::from_secs(1))?;
            }
            for (i, &(rx, tx, parse_drops, tx_drops)) in queue_counts.iter().enumerate() {
                tracing::info!(
                    queue = queue_ids[i],
                    rx,
                    tx,
                    parse_drops,
                    tx_drops,
                    final_snapshot = true,
                    "AF_XDP queue stats"
                );
            }
            return Ok(());
        }
        // Reap even when no client sends another packet. Reconcile held sockets
        // against the store after expiry or management-side deletion.
        if maintenance.elapsed() >= std::time::Duration::from_secs(1) {
            let removed = processor.store().cleanup_expired();
            metrics
                .active_allocations
                .fetch_sub(removed as u64, Relaxed);
            let live: std::collections::HashSet<u16> =
                processor.store().live_relay_ports().into_iter().collect();
            let stale: Vec<u16> = relay_ports.difference(&live).copied().collect();
            for port in stale {
                datapaths[0].del_relay_port(port)?;
                relay_ports.remove(&port);
                held.remove(&port);
            }
            metrics
                .afxdp_relay_ports_registered
                .store(relay_ports.len() as u64, Relaxed);
            maintenance = std::time::Instant::now();
        }
        if queue_report.elapsed() >= std::time::Duration::from_secs(10) {
            for (i, &(rx, tx, parse_drops, tx_drops)) in queue_counts.iter().enumerate() {
                tracing::info!(
                    queue = queue_ids[i],
                    rx,
                    tx,
                    parse_drops,
                    tx_drops,
                    final_snapshot = false,
                    "AF_XDP queue stats"
                );
            }
            queue_report = std::time::Instant::now();
        }
        let index = next_queue;
        next_queue = (next_queue + 1) % datapaths.len();
        let dp = &mut datapaths[index];
        dp.check_io()?;
        let before_parse = dp.parse_drops();
        let frames = dp.recv_batch(64);
        queue_counts[index].0 += frames.len() as u64;
        queue_counts[index].2 += dp.parse_drops() - before_parse;
        metrics
            .afxdp_parse_drops_total
            .fetch_add(dp.parse_drops() - before_parse, Relaxed);
        dp.check_io()?;
        // Ring gauges are aggregated after frame processing below.
        if frames.is_empty() {
            std::thread::sleep(std::time::Duration::from_micros(50));
        }
        metrics
            .afxdp_rx_frames_total
            .fetch_add(frames.len() as u64, Relaxed);
        let rx_bytes: u64 = frames.iter().map(|f| f.data.len() as u64).sum();
        metrics.afxdp_rx_bytes_total.fetch_add(rx_bytes, Relaxed);
        for f in frames {
            let dport = f.dst.port();
            let actions = if dport == listen_port {
                processor.process_slice(&f.data, f.source)
            } else if relay_ports.contains(&dport) {
                // Peer→client relay data arriving on an allocation's relay port.
                processor.process_relay_recv(&f.data, f.source, f.dst)
            } else {
                queue_counts[index].2 += 1;
                metrics.afxdp_parse_drops_total.fetch_add(1, Relaxed);
                continue;
            };
            for action in actions {
                match action {
                    Action::Send { data, target } => match dp.send_to(&data, target) {
                        Ok(()) => {
                            queue_counts[index].1 += 1;
                            metrics.afxdp_tx_frames_total.fetch_add(1, Relaxed);
                            metrics
                                .afxdp_tx_bytes_total
                                .fetch_add(data.len() as u64, Relaxed);
                        }
                        Err(e) => {
                            queue_counts[index].3 += 1;
                            metrics.afxdp_tx_drops_total.fetch_add(1, Relaxed);
                            tracing::debug!(%e, "AF_XDP send_to failed");
                        }
                    },
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
                        match dp.send_to_from(relay_port, &data, target) {
                            Ok(()) => {
                                queue_counts[index].1 += 1;
                                metrics.afxdp_tx_frames_total.fetch_add(1, Relaxed);
                                metrics
                                    .afxdp_tx_bytes_total
                                    .fetch_add(data.len() as u64, Relaxed);
                            }
                            Err(e) => {
                                queue_counts[index].3 += 1;
                                metrics.afxdp_tx_drops_total.fetch_add(1, Relaxed);
                                tracing::debug!(%e, port = relay_port, "AF_XDP relay send failed");
                            }
                        }
                    }
                    Action::ForwardZeroCopy {
                        offset,
                        len,
                        target,
                        relay_port,
                    } => {
                        // P1: forward straight from the recv frame — no owned
                        // Bytes. send_to_from still copies into the TX frame, but
                        // the per-packet Bytes::copy_from_slice in process_slice
                        // is gone. `f.data` is alive for this whole iteration.
                        match dp.send_to_from(relay_port, &f.data[offset..offset + len], target) {
                            Ok(()) => {
                                queue_counts[index].1 += 1;
                                metrics.afxdp_tx_frames_total.fetch_add(1, Relaxed);
                                metrics.afxdp_tx_bytes_total.fetch_add(len as u64, Relaxed);
                            }
                            Err(e) => {
                                queue_counts[index].3 += 1;
                                metrics.afxdp_tx_drops_total.fetch_add(1, Relaxed);
                                tracing::debug!(%e, port = relay_port, "AF_XDP zero-copy relay send failed");
                            }
                        }
                    }
                    Action::RegisterRelay {
                        port,
                        socket,
                        client_addr,
                        ..
                    } => {
                        if let Err(e) = dp.add_relay_port(port) {
                            // Do not emit the queued Allocate success when its relay
                            // cannot receive. Roll back the allocation and fail loudly.
                            let _ = processor.release_for_closed_connection(client_addr);
                            metrics.set_afxdp_readiness(turna_health::Readiness::Degraded);
                            return Err(Box::new(e));
                        }
                        relay_ports.insert(port);
                        held.insert(port, socket);
                        metrics
                            .afxdp_relay_ports_registered
                            .store(relay_ports.len() as u64, Relaxed);
                    }
                    Action::CloseRelay { port } => {
                        dp.del_relay_port(port)?;
                        relay_ports.remove(&port);
                        held.remove(&port);
                        metrics
                            .afxdp_relay_ports_registered
                            .store(relay_ports.len() as u64, Relaxed);
                    }
                    // RFC 6062 TCP relay listeners are bound synchronously
                    // elsewhere and never traverse the af-xdp datagram send
                    // path, so there is nothing to do here.
                    Action::RegisterTcpListener { .. } => {}
                    // UDP: the client retransmits into a warm credential cache.
                    Action::AwaitCredentials { .. } => {}
                    Action::None => {}
                }
            }
        }
        dp.check_io()?;
        metrics.afxdp_umem_free_frames.store(
            datapaths.iter().map(|d| d.free_frames() as u64).sum(),
            Relaxed,
        );
        metrics
            .afxdp_tx_inflight
            .store(datapaths.iter().map(|d| d.tx_inflight()).sum(), Relaxed);
        metrics
            .afxdp_arp_replies_total
            .store(datapaths.iter().map(|d| d.arp_replies()).sum(), Relaxed);
        metrics
            .afxdp_ndp_replies_total
            .store(datapaths.iter().map(|d| d.ndp_replies()).sum(), Relaxed);
        metrics.afxdp_neighbor_unresolved.store(
            u64::from(datapaths.iter().any(|d| !d.neighbor_resolved())),
            Relaxed,
        );
        metrics
            .afxdp_neighbor_cache_entries
            .store(datapaths[0].neighbor_cache_entries(), Relaxed);
    }
}

/// AFX-2 startup preflight for `[turn.af_xdp]`. Pure/synchronous so it runs
/// before any kernel resource is touched and is easy to reason about. Returns
/// the list of problems (empty = OK). Reads only `/sys` and `/proc`.
#[cfg(all(target_os = "linux", feature = "af-xdp"))]
fn preflight_af_xdp(cfg: &turna_config::AfXdpSection) -> Result<(), Vec<String>> {
    use std::path::Path;
    let mut problems = Vec::new();
    let pow2 = |n: u32| n != 0 && (n & (n - 1)) == 0;

    // ring / UMEM geometry (kernel AF_XDP requirements)
    for (name, v) in [
        ("fill_ring_size", cfg.fill_ring_size),
        ("comp_ring_size", cfg.comp_ring_size),
        ("rx_ring_size", cfg.rx_ring_size),
        ("tx_ring_size", cfg.tx_ring_size),
    ] {
        if !pow2(v) {
            problems.push(format!("{name} must be a power of two and > 0 (got {v})"));
        }
    }
    if cfg.frame_count == 0 {
        problems.push("frame_count must be > 0".to_string());
    }
    if !pow2(cfg.frame_size) || cfg.frame_size < 2048 {
        problems.push(format!(
            "frame_size must be a power of two >= 2048 for aligned-mode UMEM (got {})",
            cfg.frame_size
        ));
    }
    if cfg.frame_count < cfg.fill_ring_size {
        problems.push(format!(
            "frame_count ({}) < fill_ring_size ({}); the fill ring cannot be populated",
            cfg.frame_count, cfg.fill_ring_size
        ));
    }

    // interface existence; without it, queue/mtu checks are meaningless
    let if_dir = format!("/sys/class/net/{}", cfg.interface);
    if !Path::new(&if_dir).is_dir() {
        problems.push(format!(
            "interface '{}' not found (no {if_dir}); set [turn.af_xdp].interface to a real NIC",
            cfg.interface
        ));
        return Err(problems);
    }

    // operstate: only an administratively down link is a hard failure;
    // virtual ifaces report "unknown", which is acceptable.
    match std::fs::read_to_string(format!("{if_dir}/operstate")) {
        Ok(st) => {
            if st.trim().eq_ignore_ascii_case("down") {
                problems.push(format!(
                    "interface '{}' is down; bring it up: ip link set {} up",
                    cfg.interface, cfg.interface
                ));
            }
        }
        Err(e) => tracing::warn!(%e, iface = %cfg.interface, "could not read operstate"),
    }

    // Every active RX queue must have an XSK; an unbound queue would PASS
    // TURN traffic to a kernel socket with no datapath reader.
    let selected: std::collections::HashSet<u32> = if cfg.queue_ids.is_empty() {
        [cfg.queue_id].into_iter().collect()
    } else {
        cfg.queue_ids.iter().copied().collect()
    };
    let queues_dir = format!("{if_dir}/queues");
    match std::fs::read_dir(&queues_dir) {
        Ok(entries) => {
            let actual: std::collections::HashSet<u32> = entries
                .filter_map(|e| e.ok())
                .filter_map(|e| {
                    e.file_name()
                        .to_str()
                        .and_then(|s| s.strip_prefix("rx-"))
                        .and_then(|s| s.parse().ok())
                })
                .collect();
            if actual.is_empty() || actual != selected {
                problems.push(format!(
                    "queue_ids must cover all RX queues: selected={selected:?}, actual={actual:?}"
                ));
            }
        }
        Err(e) => problems.push(format!("cannot enumerate RX queues: {e}")),
    }

    // MTU vs frame_size: the frame must hold ETH(14) + the IP MTU
    match std::fs::read_to_string(format!("{if_dir}/mtu")) {
        Ok(s) => {
            if let Ok(mtu) = s.trim().parse::<u32>() {
                let min_frame = mtu + 14;
                if cfg.frame_size < min_frame {
                    problems.push(format!(
                        "frame_size ({}) < interface MTU+14 ({}); raise frame_size or lower the MTU",
                        cfg.frame_size, min_frame
                    ));
                }
            }
        }
        Err(e) => tracing::warn!(%e, iface = %cfg.interface, "could not read mtu"),
    }

    // capability: binding an AF_XDP socket needs CAP_NET_RAW
    match std::fs::read_to_string("/proc/self/status") {
        Ok(status) => {
            let cap_eff = status
                .lines()
                .find_map(|l| l.strip_prefix("CapEff:"))
                .and_then(|h| u64::from_str_radix(h.trim(), 16).ok());
            match cap_eff {
                Some(bits) => {
                    const CAP_NET_RAW: u64 = 13;
                    if bits & (1u64 << CAP_NET_RAW) == 0 {
                        problems.push(
                            "missing CAP_NET_RAW (required to bind an AF_XDP socket); grant it, e.g. setcap cap_net_raw+ep <binary> or add the capability to the container".to_string(),
                        );
                    }
                }
                None => tracing::warn!("could not parse CapEff from /proc/self/status"),
            }
        }
        Err(e) => tracing::warn!(%e, "could not read /proc/self/status to verify CAP_NET_RAW"),
    }

    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems)
    }
}

/// Stub for non-Linux / non-`af-xdp` builds: AF_XDP can't be selected here.
#[cfg(not(all(target_os = "linux", feature = "af-xdp")))]
pub fn run_af_xdp(
    _cfg: turna_config::AfXdpSection,
    _processor: Arc<PacketProcessor>,
    _listen: SocketAddr,
    _shutdown: tokio::sync::watch::Receiver<bool>,
    _metrics: Arc<turna_health::Metrics>,
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

#[cfg(all(test, target_os = "linux", feature = "af-xdp"))]
mod tests {
    use super::*;

    #[test]
    fn preflight_rejects_bad_geometry_and_missing_iface() {
        let cfg = turna_config::AfXdpSection {
            interface: "turna_no_such_iface_xyz".to_string(),
            fill_ring_size: 3000, // not a power of two
            frame_size: 1000,     // < 2048 and not a power of two
            ..Default::default()
        };
        let err = preflight_af_xdp(&cfg).expect_err("invalid config must fail preflight");
        assert!(err.iter().any(|p| p.contains("fill_ring_size")), "{err:?}");
        assert!(err.iter().any(|p| p.contains("frame_size")), "{err:?}");
        assert!(err.iter().any(|p| p.contains("not found")), "{err:?}");
    }
}
