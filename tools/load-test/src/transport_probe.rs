//! Bounded adversarial probes, driven by scripts/verify/transport-lifecycle.py.
//! READY is emitted only after authenticated allocation and verified two-way media.
use crate::turn_client::Creds;
use std::{io::Write, net::SocketAddr, time::Duration};
use tokio::net::UdpSocket;

pub(crate) trait Session {
    fn unreliable_media(&self) -> bool {
        false
    }
    fn network_stats(&self) -> String {
        "null".into()
    }
    async fn bind_peer(&mut self, peer: SocketAddr) -> Result<(), String>;
    async fn send_media(&mut self, payload: &[u8]) -> Result<(), String>;
    async fn receive_media(&mut self) -> Result<Vec<u8>, String>;
    fn pressure_packet(&self) -> Vec<u8>;
    async fn write_control(&mut self, bytes: &[u8]) -> Result<(), String>;
    async fn close_probe(&mut self) -> Result<(), String>;
}

fn mark(event: &str, value: u64) {
    println!("{{\"event\":\"{event}\",\"value\":{value}}}");
    let _ = std::io::stdout().flush();
}

async fn roundtrip<S: Session>(
    s: &mut S,
    peer: &UdpSocket,
    relay: SocketAddr,
    seq: u64,
) -> Result<(), String> {
    let mut payload = vec![0x5a; 159];
    payload[..8].copy_from_slice(&seq.to_be_bytes());
    tokio::time::timeout(Duration::from_secs(3), async {
        s.send_media(&payload).await?;
        let mut buf = [0u8; 2048];
        let (n, source) = peer.recv_from(&mut buf).await.map_err(|e| e.to_string())?;
        if source != relay || buf[..n] != payload {
            return Err("forward media/source mismatch".into());
        }
        peer.send_to(&payload, relay)
            .await
            .map_err(|e| e.to_string())?;
        let frame = s.receive_media().await?;
        let logical = 4 + payload.len();
        if (frame.len() != logical && frame.len() != (logical + 3) & !3)
            || frame.get(..4) != Some(&[0x40, 0, 0, 159][..])
            || frame.get(4..logical) != Some(payload.as_slice())
        {
            return Err("return media/channel mismatch".into());
        }
        Ok(())
    })
    .await
    .map_err(|_| "two-way media timeout".to_string())?
}

pub(crate) async fn exercise<S: Session>(
    mut s: S,
    relay: SocketAddr,
    action: &str,
    hold: u64,
) -> Result<(), String> {
    #[cfg(unix)]
    let mut stop = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined1())
        .map_err(|e| e.to_string())?;
    let peer = UdpSocket::bind("127.0.0.1:0")
        .await
        .map_err(|e| e.to_string())?;
    s.bind_peer(peer.local_addr().map_err(|e| e.to_string())?)
        .await?;
    roundtrip(&mut s, &peer, relay, 0).await?;
    mark("ready", 1);
    if action == "pressure" {
        // Do not read any more reliable replies. Bound both time and total writes.
        // Repeated authenticated Refresh requests generate reliable replies without
        // depending on the unauthenticated Binding rate limiter.
        let packet = s.pressure_packet();
        let batch = packet.repeat(32);
        let mut bytes = 0u64;
        mark("pressure_started", 1);
        let outcome = tokio::time::timeout(Duration::from_secs(12), async {
            while bytes < 8 * 1024 * 1024 {
                s.write_control(&batch).await?;
                bytes += batch.len() as u64;
            }
            Ok::<(), String>(())
        })
        .await;
        mark("pressure_bytes", bytes);
        match outcome {
            Ok(Ok(())) => mark("write_budget_reached", 1),
            Ok(Err(_)) => mark("write_rejected", 1),
            Err(_) => mark("write_blocked", 1),
        }
        // Remain alive: the harness must observe SERVER cleanup, not client drop.
        tokio::time::sleep(Duration::from_secs(hold)).await;
        return Ok(());
    }
    let until = tokio::time::Instant::now() + Duration::from_secs(hold);
    let mut seq = 1;
    while tokio::time::Instant::now() < until {
        roundtrip(&mut s, &peer, relay, seq).await?;
        mark("healthy", seq);
        seq += 1;
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(200)) => {},
            _ = async {
                #[cfg(unix)]
                { stop.recv().await; }
                #[cfg(not(unix))]
                std::future::pending::<()>().await;
            } => break,
        }
    }
    s.close_probe().await?;
    mark("closed", 1);
    Ok(())
}

pub async fn run(
    transport: &str,
    server: SocketAddr,
    creds: &Creds,
    action: &str,
    hold: u64,
) -> Result<(), String> {
    if !matches!(action, "hold" | "pressure") || hold > 120 {
        return Err("probe requires action hold|pressure and hold-secs <= 120".into());
    }
    match transport {
        #[cfg(feature = "quic")]
        "quic" => crate::quic_client::run_probe(server, creds, action, hold).await,
        #[cfg(feature = "web-transport")]
        "wt" => crate::wt_client::run_probe(server, creds, action, hold).await,
        #[cfg(all(feature = "sctp", target_os = "linux"))]
        "sctp" => crate::sctp_client::run_probe(server, creds, action, hold).await,
        _ => Err(format!(
            "transport {transport} is unknown or not compiled for this platform"
        )),
    }
}

/// A bitmap keeps duplicate detection exact and bounded by the configured send
/// budget (at most 10.8 MB for 86400 seconds at 1000 pps), even under total loss.
#[derive(Default)]
struct NetworkReport {
    sent: u64,
    recv: u64,
    refreshes: u64,
    echo_timeouts: u64,
    late_echoes: u64,
    received: Vec<u64>,
    pending: std::collections::BTreeMap<u64, tokio::time::Instant>,
    peak_in_flight: usize,
    total_rtt_ms: f64,
    max_rtt_ms: f64,
    on_time_echoes: u64,
    duration_s: f64,
    completed: bool,
}

impl NetworkReport {
    fn record_send(&mut self, begin: tokio::time::Instant) {
        let seq = self.sent;
        if seq as usize / 64 == self.received.len() {
            self.received.push(0);
        }
        self.pending.insert(seq, begin);
        self.sent += 1;
        self.peak_in_flight = self.peak_in_flight.max(self.pending.len());
    }

    fn accept_echo(&mut self, seq: u64) -> Result<(), String> {
        if seq >= self.sent {
            return Err(format!("duplicate or unknown echo sequence {seq}"));
        }
        let word = &mut self.received[seq as usize / 64];
        let mask = 1 << (seq % 64);
        if *word & mask != 0 {
            return Err(format!("duplicate or unknown echo sequence {seq}"));
        }
        *word |= mask;
        self.recv += 1;
        if let Some(begin) = self.pending.remove(&seq) {
            let rtt = begin.elapsed().as_secs_f64() * 1000.;
            self.total_rtt_ms += rtt;
            self.max_rtt_ms = self.max_rtt_ms.max(rtt);
            self.on_time_echoes += 1;
        } else {
            // Valid, previously expired echo: count it once, but preserve the
            // deadline violation. It must not reset the loss history to PASS.
            self.late_echoes += 1;
        }
        Ok(())
    }

    fn expire(&mut self, now: tokio::time::Instant, timeout: Duration) {
        while let Some((&seq, &begin)) = self.pending.first_key_value() {
            if now < begin + timeout {
                break;
            }
            self.pending.remove(&seq);
            self.echo_timeouts += 1;
            // Bound stderr during a complete outage; totals and missing sample
            // remain in the final JSON. No automatic retransmission hides loss.
            if self.echo_timeouts <= 32 {
                eprintln!("network echo deadline exceeded: sequence={seq}");
            }
        }
    }

    fn missing_sample(&self) -> Vec<u64> {
        (0..self.sent)
            .filter(|&seq| self.received[seq as usize / 64] & (1 << (seq % 64)) == 0)
            .take(32)
            .collect()
    }
}

#[derive(Clone, Copy)]
struct NetworkTiming {
    echo: Duration,
    refresh: Duration,
}
impl Default for NetworkTiming {
    fn default() -> Self {
        Self {
            echo: Duration::from_secs(5),
            refresh: Duration::from_secs(240),
        }
    }
}

/// DATAGRAM timeouts are observations, not connection errors. Reliable SCTP
/// retains its fail-fast deadline. Overall acceptance still requires zero loss.
async fn network_loop<S: Session>(
    s: &mut S,
    peer: SocketAddr,
    seconds: u64,
    pps: u64,
    timing: NetworkTiming,
    report: &mut NetworkReport,
) -> Result<(), String> {
    s.bind_peer(peer)
        .await
        .map_err(|e| format!("initial bind: {e}"))?;
    let start = tokio::time::Instant::now();
    let until = start + Duration::from_secs(seconds);
    let mut refresh = start + timing.refresh;
    let mut tick = tokio::time::interval(Duration::from_nanos(1_000_000_000 / pps));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let token: [u8; 16] = rand::random();
    let outcome = async {
        loop {
            let now = tokio::time::Instant::now();
            let stopping = now >= until;
            let refreshing = now >= refresh;
            let expired = report
                .pending
                .first_key_value()
                .is_some_and(|(_, begin)| now >= *begin + timing.echo);
            if expired {
                if !s.unreliable_media() {
                    return Err(format!(
                        "network echo timeout; {} packets pending",
                        report.pending.len()
                    ));
                }
                report.expire(now, timing.echo);
            }
            if report.pending.is_empty() {
                if stopping {
                    report.completed = true;
                    break;
                }
                if refreshing {
                    // Bound refresh even when a peer stops answering. Drain
                    // SCTP first; QUIC/WT control uses a separate reliable stream.
                    tokio::time::timeout(Duration::from_secs(15), s.bind_peer(peer))
                        .await
                        .map_err(|_| "network refresh timeout".to_string())?
                        .map_err(|e| format!("network refresh failed: {e}"))?;
                    report.refreshes += 1;
                    refresh = tokio::time::Instant::now() + timing.refresh;
                    continue;
                }
            }
            let deadline = report
                .pending
                .first_key_value()
                .map(|(_, begin)| *begin + timing.echo)
                .unwrap_or(until);
            tokio::select! {
                biased;
                frame = s.receive_media() => {
                    let frame = frame.map_err(|e| format!("network receive failed: {e}"))?;
                    let seq = network_echo_sequence(&frame, &token)?;
                    report.accept_echo(seq)?;
                }
                _ = tokio::time::sleep_until(deadline), if !report.pending.is_empty() => {},
                _ = tick.tick(), if !stopping && !refreshing => {
                    if tokio::time::Instant::now() >= until { continue; }
                    if report.pending.len() >= 128 {
                        return Err("network in-flight limit reached (128 packets)".into());
                    }
                    let payload = network_payload(&token, report.sent);
                    let begin = tokio::time::Instant::now();
                    tokio::time::timeout(Duration::from_secs(5), s.send_media(&payload))
                        .await.map_err(|_| "network send timeout".to_string())??;
                    report.record_send(begin);
                }
            }
        }
        Ok(())
    }
    .await;
    report.duration_s = start.elapsed().as_secs_f64();
    outcome
}

pub(crate) async fn network_session<S: Session>(
    mut s: S,
    peer: SocketAddr,
    seconds: u64,
    pps: u64,
) -> Result<(), String> {
    let mut report = NetworkReport::default();
    let outcome = network_loop(
        &mut s,
        peer,
        seconds,
        pps,
        NetworkTiming::default(),
        &mut report,
    )
    .await;
    let transport_stats = s.network_stats(); // Before locally closing the connection.
    let close = tokio::time::timeout(Duration::from_secs(6), s.close_probe()).await;
    let error = outcome.err().or_else(|| match close {
        Ok(Ok(())) => None,
        Ok(Err(e)) => Some(e),
        Err(_) => Some("session close timeout".into()),
    });
    let errs = u64::from(error.is_some());
    let missing = report.sent - report.recv;
    let mean_rtt_ms = report.total_rtt_ms / report.on_time_echoes.max(1) as f64;
    let loss_percent = 100. * missing as f64 / report.sent.max(1) as f64;
    println!(concat!("{{\"schema_version\":2,\"sent\":{},\"recv\":{},\"errs\":{},",
        "\"duration_s\":{},\"completed\":{},\"refreshes\":{},\"mean_rtt_ms\":{},\"max_rtt_ms\":{},",
        "\"peak_in_flight\":{},\"missing_echoes\":{},\"loss_percent\":{},\"echo_timeouts\":{},",
        "\"late_echoes\":{},\"pending_at_end\":{},\"missing_sequences_sample\":{:?},\"transport_stats\":{}}}"),
        report.sent, report.recv, errs, report.duration_s, report.completed, report.refreshes,
        mean_rtt_ms, report.max_rtt_ms, report.peak_in_flight, missing, loss_percent,
        report.echo_timeouts, report.late_echoes, report.pending.len(), report.missing_sample(), transport_stats);
    if let Some(e) = error {
        return Err(e);
    }
    // Do not silently relax acceptance: a full-duration diagnostic with loss is
    // still nonzero exit, while errs only describes operational/protocol errors.
    if missing != 0 || report.echo_timeouts != 0 {
        return Err(format!("network delivery check failed: missing={missing}, deadline_exceeded={}, late={}; diagnostic run completed={}",
            report.echo_timeouts, report.late_echoes, report.completed));
    }
    Ok(())
}

fn network_payload(token: &[u8; 16], seq: u64) -> Vec<u8> {
    let mut payload = vec![0x5a; 160];
    payload[..16].copy_from_slice(token);
    payload[16..24].copy_from_slice(&seq.to_be_bytes());
    payload
}

fn network_echo_sequence(frame: &[u8], token: &[u8; 16]) -> Result<u64, String> {
    let bytes = frame.get(20..28).ok_or("short echo frame")?;
    let seq = u64::from_be_bytes(bytes.try_into().map_err(|_| "invalid echo sequence")?);
    if !network_frame_matches(frame, &network_payload(token, seq)) {
        return Err("echo payload/channel/token mismatch".into());
    }
    Ok(seq)
}

fn network_frame_matches(frame: &[u8], payload: &[u8]) -> bool {
    let logical = payload.len() + 4;
    (frame.len() == logical || frame.len() == (logical + 3) & !3)
        && frame.get(..2) == Some(&[0x40, 0][..])
        && frame.get(2..4) == Some(&(payload.len() as u16).to_be_bytes()[..])
        && frame.get(4..logical) == Some(payload)
}

pub async fn network(
    transport: &str,
    server: SocketAddr,
    creds: &Creds,
    peer: SocketAddr,
    seconds: u64,
    pps: u64,
) -> Result<(), String> {
    if seconds == 0 || seconds > 86400 || pps == 0 || pps > 1000 {
        return Err("duration must be 1..86400 seconds and pps 1..1000".into());
    }
    match transport {
        #[cfg(feature = "quic")]
        "quic" => crate::quic_client::run_network(server, creds, peer, seconds, pps).await,
        #[cfg(feature = "web-transport")]
        "wt" => crate::wt_client::run_network(server, creds, peer, seconds, pps).await,
        #[cfg(all(feature = "sctp", target_os = "linux"))]
        "sctp" => crate::sctp_client::run_network(server, creds, peer, seconds, pps).await,
        _ => Err(format!("transport {transport} not available")),
    }
}

#[cfg(test)]
mod network_tests {
    use super::network_frame_matches;
    #[test]
    fn echo_checks_channel_length_payload_and_padding() {
        let payload = vec![0x5a; 159];
        let mut frame = vec![0x40, 0, 0, 159];
        frame.extend_from_slice(&payload);
        assert!(network_frame_matches(&frame, &payload));
        frame.push(0);
        assert!(network_frame_matches(&frame, &payload));
        frame[20] ^= 1;
        assert!(!network_frame_matches(&frame, &payload));
        frame[20] ^= 1;
        frame[1] = 1;
        assert!(!network_frame_matches(&frame, &payload));
        frame[1] = 0;
        frame[3] = 158;
        assert!(!network_frame_matches(&frame, &payload));
        frame[3] = 159;
        frame.push(0);
        assert!(!network_frame_matches(&frame, &payload));
        assert!(!network_frame_matches(&frame[..3], &payload));
    }

    #[derive(Default)]
    struct DelayedEcho {
        queue: Vec<(tokio::time::Instant, Vec<u8>)>,
        sent: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        duplicate: bool,
        drop_all: bool,
        unreliable: bool,
        drop_first: bool,
        corrupt: bool,
        receive_error: bool,
        refresh_error: bool,
        binds: usize,
    }
    impl super::Session for DelayedEcho {
        fn unreliable_media(&self) -> bool {
            self.unreliable
        }
        async fn bind_peer(&mut self, _: std::net::SocketAddr) -> Result<(), String> {
            self.binds += 1;
            if self.refresh_error && self.binds > 1 {
                return Err("injected refresh failure".into());
            }
            Ok(())
        }
        async fn send_media(&mut self, payload: &[u8]) -> Result<(), String> {
            let n = self.sent.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if self.drop_all || (self.drop_first && n == 0) {
                return Ok(());
            }
            let mut frame = vec![0x40, 0, 0, 160];
            frame.extend_from_slice(payload);
            if self.corrupt {
                frame[40] ^= 1;
            }
            let delay = if n.is_multiple_of(2) { 250 } else { 80 };
            let ready = tokio::time::Instant::now() + std::time::Duration::from_millis(delay);
            self.queue.push((ready, frame.clone()));
            if self.duplicate {
                self.queue.push((ready, frame));
            }
            Ok(())
        }
        async fn receive_media(&mut self) -> Result<Vec<u8>, String> {
            if self.receive_error {
                return Err("injected connection failure".into());
            }
            if self.queue.is_empty() {
                return std::future::pending().await;
            }
            let (index, (ready, _)) = self
                .queue
                .iter()
                .enumerate()
                .min_by_key(|(_, (t, _))| *t)
                .unwrap();
            tokio::time::sleep_until(*ready).await;
            Ok(self.queue.remove(index).1)
        }
        fn pressure_packet(&self) -> Vec<u8> {
            vec![]
        }
        async fn write_control(&mut self, _: &[u8]) -> Result<(), String> {
            Ok(())
        }
        async fn close_probe(&mut self) -> Result<(), String> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn paced_media_keeps_rate_with_delayed_reordered_echoes() {
        let sent = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let session = DelayedEcho {
            queue: vec![],
            sent: sent.clone(),
            duplicate: false,
            drop_all: false,
            ..Default::default()
        };
        super::network_session(session, "127.0.0.1:39001".parse().unwrap(), 1, 20)
            .await
            .unwrap();
        assert!(sent.load(std::sync::atomic::Ordering::Relaxed) >= 19);
    }

    #[tokio::test]
    async fn duplicate_echo_fails_instead_of_counting_twice() {
        let session = DelayedEcho {
            queue: vec![],
            sent: Default::default(),
            duplicate: true,
            drop_all: false,
            ..Default::default()
        };
        let error = super::network_session(session, "127.0.0.1:39001".parse().unwrap(), 1, 20)
            .await
            .unwrap_err();
        assert!(error.contains("duplicate or unknown"), "{error}");
    }

    #[tokio::test]
    async fn outstanding_packet_must_return_after_send_window_ends() {
        let session = DelayedEcho {
            queue: vec![],
            sent: Default::default(),
            duplicate: false,
            drop_all: true,
            ..Default::default()
        };
        let error = super::network_session(session, "127.0.0.1:39001".parse().unwrap(), 1, 1)
            .await
            .unwrap_err();
        assert!(error.contains("echo timeout"), "{error}");
    }

    async fn diagnostic(
        session: &mut DelayedEcho,
        refresh_ms: u64,
    ) -> (super::NetworkReport, Result<(), String>) {
        let mut report = super::NetworkReport::default();
        let result = super::network_loop(
            session,
            "127.0.0.1:39001".parse().unwrap(),
            1,
            20,
            super::NetworkTiming {
                echo: std::time::Duration::from_millis(400),
                refresh: std::time::Duration::from_millis(refresh_ms),
            },
            &mut report,
        )
        .await;
        (report, result)
    }

    #[tokio::test]
    async fn datagram_loss_does_not_stop_sends_or_refresh() {
        let mut session = DelayedEcho {
            unreliable: true,
            drop_first: true,
            ..Default::default()
        };
        let (r, result) = diagnostic(&mut session, 450).await;
        result.unwrap();
        assert!(r.completed && r.duration_s >= 1. && r.refreshes > 0);
        assert!(r.sent > 10);
        assert_eq!(r.sent - r.recv, 1);
        assert_eq!(r.echo_timeouts, 1);
        assert_eq!(r.missing_sample(), vec![0]);
        assert!(r.pending.is_empty());
    }

    #[tokio::test]
    async fn complete_datagram_blackout_is_measured_for_full_window() {
        let mut session = DelayedEcho {
            unreliable: true,
            drop_all: true,
            ..Default::default()
        };
        let (r, result) = diagnostic(&mut session, 240000).await;
        result.unwrap();
        assert!(r.completed && r.duration_s >= 1.);
        assert!(r.sent >= 19);
        assert_eq!(r.recv, 0);
        assert_eq!(r.echo_timeouts, r.sent);
        assert!(r.pending.is_empty());
    }

    #[tokio::test]
    async fn late_echo_is_counted_once_without_erasing_deadline_failure() {
        let mut r = super::NetworkReport::default();
        let now = tokio::time::Instant::now();
        r.record_send(now);
        r.expire(
            now + std::time::Duration::from_secs(6),
            std::time::Duration::from_secs(5),
        );
        r.accept_echo(0).unwrap();
        assert_eq!((r.recv, r.late_echoes, r.echo_timeouts), (1, 1, 1));
        assert!(r.missing_sample().is_empty());
        assert!(r.accept_echo(0).is_err());
        assert!(r.accept_echo(1).is_err());
    }

    #[tokio::test]
    async fn datagram_integrity_connection_and_refresh_errors_remain_fatal() {
        for kind in 0..3 {
            let mut session = DelayedEcho {
                unreliable: true,
                corrupt: kind == 0,
                receive_error: kind == 1,
                refresh_error: kind == 2,
                ..Default::default()
            };
            let (r, result) = diagnostic(&mut session, 100).await;
            let error = result.unwrap_err();
            assert!(
                error.contains(["mismatch", "connection failure", "refresh failed"][kind]),
                "{error}"
            );
            assert!(!r.completed);
        }
    }

    #[test]
    fn other_session_token_is_rejected() {
        let mut frame = vec![0x40, 0, 0, 160];
        frame.extend_from_slice(&super::network_payload(&[1; 16], 3));
        assert_eq!(super::network_echo_sequence(&frame, &[1; 16]).unwrap(), 3);
        assert!(super::network_echo_sequence(&frame, &[2; 16]).is_err());
    }
}
