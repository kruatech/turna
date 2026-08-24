//! TURN over WebTransport (HTTP/3) — a client, so the browser-facing path can be
//! verified at all.
//!
//! # Why this exists
//!
//! The WebTransport path has never been exercised by anything. It is the path a
//! browser would use, and browsers cannot drive it without a page that speaks TURN
//! inside `new WebTransport()` — so nothing did.
//!
//! # What it is and is not
//!
//! This is a Rust client over `wtransport`, the same library the server uses. It
//! verifies the server side: the H3 CONNECT, the session, the bidi control stream
//! and the TURN exchange on it, including relayed media.
//!
//! It does **not** stand in for a browser. Client and server here are the same
//! library and the same reading of the spec, so anything both get wrong stays
//! invisible. A browser page remains the real interop check; this one catches the
//! server-side faults that would break that page before anyone writes it.
//!
//! # Framing
//!
//! Identical to raw QUIC — the stream carries STUN delimited by its own header
//! length, and ChannelData padded to four bytes. `stream_common` owns it, so the
//! three stream transports cannot drift.
//!
//! # API assumptions
//!
//! Three things here are taken from the shape of `wtransport`'s client API rather
//! than read from the version in the lock file, and are the first suspects if this
//! does not compile:
//!
//! * `ClientConfig::builder().with_bind_default().with_no_cert_validation().build()`
//! * `Endpoint::client(config)` then `endpoint.connect(url)`
//! * `connection.open_bi()` returning a future that yields *another* future — the
//!   two-stage open that wtransport uses to signal flow-control readiness.

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::Stats;

use crate::stream_common::next_stream_message;
use crate::turn_client::{
    channel_data_frame, error_code, get_nonce, get_realm, get_relayed_addr, is_success,
    long_term_key, Creds, Msg, M_ALLOCATE, M_CHANNEL_BIND, M_CREATE_PERM, M_REFRESH,
};

/// The control stream plus its reassembly buffer.
struct WtStream {
    send: wtransport::SendStream,
    recv: wtransport::RecvStream,
    buf: Vec<u8>,
}

impl WtStream {
    async fn request(&mut self, pkt: &[u8], rtt_ms: u64) -> Result<Vec<u8>, String> {
        self.send
            .write_all(pkt)
            .await
            .map_err(|e| format!("stream write: {e}"))?;
        self.read_message(Duration::from_millis(rtt_ms.max(2000)))
            .await
    }

    async fn read_message(&mut self, within: Duration) -> Result<Vec<u8>, String> {
        let deadline = tokio::time::Instant::now() + within;
        loop {
            if let Some(msg) = next_stream_message(&mut self.buf) {
                return Ok(msg);
            }
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            if left.is_zero() {
                return Err("timeout waiting for a response on the WebTransport stream".into());
            }
            let mut chunk = vec![0u8; 4096];
            // `RecvStream::read` yields `Option<usize>`, not `usize`: `None` means the
            // peer finished the stream, mirroring quinn underneath. Treating it as a
            // plain count is a type error rather than a silent one, which is the good
            // kind — but it is worth naming, because every other transport here
            // returns a bare count and the loops otherwise look identical.
            match tokio::time::timeout(left, self.recv.read(&mut chunk)).await {
                Ok(Ok(None)) | Ok(Ok(Some(0))) => return Err("stream closed by the server".into()),
                Ok(Ok(Some(n))) => self.buf.extend_from_slice(&chunk[..n]),
                Ok(Err(e)) => return Err(format!("stream read: {e}")),
                Err(_) => {
                    return Err("timeout waiting for a response on the WebTransport stream".into())
                }
            }
        }
    }
}

/// An established WebTransport session carrying TURN: the connection, the control
/// stream, and the credential state the server handed back.
///
/// Extracted from the probe so the load driver can hold one open for hours. The probe
/// only ever needed a few seconds, so this used to live in local variables.
pub struct WtSession {
    conn: wtransport::Connection,
    ctl: WtStream,
    user: String,
    realm: String,
    nonce: Vec<u8>,
    key: [u8; 16],
    rtt_ms: u64,
    pub relayed: SocketAddr,
}

impl WtSession {
    /// Connect, open the control stream, authenticate, allocate.
    pub async fn connect(url: &str, creds: &Creds, rtt_ms: u64) -> Result<Self, String> {
        let config = wtransport::ClientConfig::builder()
            .with_bind_default()
            .with_no_cert_validation()
            .build();
        let endpoint =
            wtransport::Endpoint::client(config).map_err(|e| format!("client endpoint: {e}"))?;
        let conn = endpoint.connect(url).await.map_err(|e| {
            format!(
                "WebTransport connect to {url} failed: {e}. Check that [turn.quic] has \
                 web_transport = true and that the certificate is one the client trusts; \
                 a browser additionally requires a chain it trusts, with no exception \
                 dialogue available."
            )
        })?;

        // wtransport opens in two stages: the first await reserves the stream, the
        // second yields it once flow control allows.
        let opening = conn
            .open_bi()
            .await
            .map_err(|e| format!("open_bi (reserve): {e}"))?;
        let (send, recv) = opening
            .await
            .map_err(|e| format!("open_bi (accept): {e}"))?;
        let mut ctl = WtStream {
            send,
            recv,
            buf: Vec::new(),
        };

        // Unauthenticated Allocate → 401.
        let mut m = Msg::request(M_ALLOCATE);
        m.add_requested_transport_udp();
        m.add_lifetime(600);
        let resp = ctl.request(&m.encode(), rtt_ms).await?;
        if error_code(&resp) != Some(401) {
            return Err(format!(
                "expected a 401 challenge over WebTransport, got {:?}",
                error_code(&resp)
            ));
        }
        let realm = get_realm(&resp).ok_or("401 without REALM")?;
        let mut nonce = get_nonce(&resp).ok_or("401 without NONCE")?;
        let (user, pass) = creds.materialize();
        let key = long_term_key(&user, &realm, &pass);

        let mut relayed = None;
        for _ in 0..2 {
            let mut m = Msg::request(M_ALLOCATE);
            m.add_requested_transport_udp();
            m.add_lifetime(600);
            m.add_username(&user);
            m.add_realm(&realm);
            m.add_nonce(&nonce);
            let txid = m.txid();
            let resp = ctl.request(&m.encode_with_integrity(&key), rtt_ms).await?;
            if is_success(&resp) {
                relayed = get_relayed_addr(&resp, &txid);
                break;
            }
            match error_code(&resp) {
                Some(438) | Some(401) => {
                    nonce = get_nonce(&resp).ok_or("stale nonce without a replacement")?
                }
                other => return Err(format!("Allocate over WebTransport rejected: {other:?}")),
            }
        }
        let relayed = relayed.ok_or("Allocate over WebTransport never succeeded")?;

        Ok(Self {
            conn,
            ctl,
            user,
            realm,
            nonce,
            key,
            rtt_ms,
            relayed,
        })
    }

    async fn authed(&mut self, method: u16, build: impl FnOnce(&mut Msg)) -> Result<(), String> {
        let mut m = Msg::request(method);
        build(&mut m);
        m.add_username(&self.user);
        m.add_realm(&self.realm);
        m.add_nonce(&self.nonce);
        let pkt = m.encode_with_integrity(&self.key);
        let resp = self.ctl.request(&pkt, self.rtt_ms).await?;
        if is_success(&resp) {
            return Ok(());
        }
        Err(format!("{method:#06x} rejected: {:?}", error_code(&resp)))
    }

    pub async fn create_permission(&mut self, peer: SocketAddr) -> Result<(), String> {
        self.authed(M_CREATE_PERM, |m| m.add_xor_peer(peer)).await
    }

    pub async fn channel_bind(&mut self, ch: u16, peer: SocketAddr) -> Result<(), String> {
        self.authed(M_CHANNEL_BIND, |m| {
            m.add_channel_number(ch);
            m.add_xor_peer(peer);
        })
        .await
    }

    /// Renew the allocation, permission and channel binding.
    ///
    /// Mandatory for anything long-running: the allocation and channel last 600 s and
    /// the permission 300 s, and past those the server correctly drops ChannelData for
    /// a binding that no longer exists — silently, because there is nobody left to send
    /// an error to. A 24 h soak measured exactly that before the TLS client learned to
    /// refresh (`docs/soak/endurance-24h-2026-08-22.md`).
    pub async fn refresh(&mut self, ch: u16, peer: SocketAddr) -> Result<(), String> {
        self.authed(M_REFRESH, |m| m.add_lifetime(600)).await?;
        self.create_permission(peer).await?;
        self.channel_bind(ch, peer).await
    }

    pub async fn send_channel_data(&mut self, ch: u16, payload: &[u8]) -> Result<usize, String> {
        let frame = channel_data_frame(ch, payload);
        self.ctl
            .send
            .write_all(&frame)
            .await
            .map_err(|e| format!("ChannelData write: {e}"))?;
        Ok(frame.len())
    }

    pub fn close(&self) {
        self.conn.close(0u32.into(), b"done");
    }
}

/// Full TURN-over-WebTransport exercise. Returns a step-by-step log.
pub async fn webtransport_check(
    url: &str,
    creds: &Creds,
    rtt_ms: u64,
) -> Result<Vec<String>, String> {
    let mut log = Vec::new();

    let mut sess = WtSession::connect(url, creds, rtt_ms).await?;
    log.push(format!("WebTransport session established to {url}"));
    log.push(format!(
        "401 challenge, then Allocate ok — relayed address {}",
        sess.relayed
    ));

    let peer_sock = tokio::net::UdpSocket::bind(crate::turn_client::peer_bind_addr(false))
        .await
        .map_err(|e| format!("peer bind: {e}"))?;
    let peer_addr = peer_sock
        .local_addr()
        .map_err(|e| format!("peer local_addr: {e}"))?;

    sess.create_permission(peer_addr).await.map_err(|e| {
        format!(
            "{e}. If this is 403, the server forbids loopback peers — a local test needs \
             [turn.peer_filter] allow_loopback_peers = true."
        )
    })?;
    let channel: u16 = 0x4000;
    sess.channel_bind(channel, peer_addr).await?;
    log.push(format!(
        "CreatePermission and ChannelBind ok for {peer_addr}"
    ));

    const N: usize = 20;
    for i in 0..N {
        let mut body = b"turn-over-webtransport probe".to_vec();
        body.push(i as u8);
        sess.send_channel_data(channel, &body).await?;
    }

    let mut got = 0usize;
    let mut buf = vec![0u8; 2048];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while got < N {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            break;
        }
        match tokio::time::timeout(left, peer_sock.recv_from(&mut buf)).await {
            Ok(Ok((n, _))) if n > 0 => got += 1,
            Ok(Ok(_)) => {}
            Ok(Err(e)) => return Err(format!("peer recv: {e}")),
            Err(_) => break,
        }
    }
    if got == 0 {
        return Err(
            "sent 20 ChannelData frames over WebTransport and the peer received none — \
             the session carries control messages and the relay egress forwards nothing"
                .into(),
        );
    }
    log.push(format!("client → relay → peer: {got}/{N} frames arrived"));

    peer_sock
        .send_to(b"echo-from-peer", sess.relayed)
        .await
        .map_err(|e| format!("peer send: {e}"))?;

    // Relayed data comes back as a WebTransport **datagram**, not on the control
    // stream — the same split as raw QUIC, and for the same reason: media is unreliable,
    // and a reliable stream would add retransmission and head-of-line blocking that UDP
    // does not have. The stream carries control messages.
    //
    // Reading only the stream produced a five-second timeout while the server had
    // already delivered the reply. Both are accepted, so a server that chooses reliable
    // delivery is not reported as broken either.
    let via;
    let back;
    tokio::select! {
        dg = sess.conn.receive_datagram() => {
            let d = dg.map_err(|e| format!("receive_datagram: {e}"))?;
            back = d.to_vec();
            via = "datagram";
        }
        msg = sess.ctl.read_message(Duration::from_secs(5)) => {
            back = msg?;
            via = "stream";
        }
    }
    if back.is_empty() || !(0x40..=0x7f).contains(&back[0]) {
        return Err(format!(
            "expected ChannelData back, got a {} byte {via} starting with {:#04x}",
            back.len(),
            back.first().copied().unwrap_or(0)
        ));
    }
    log.push(format!(
        "peer → relay → client: ChannelData returned as a WebTransport {via} ({} bytes)",
        back.len()
    ));

    sess.close();
    Ok(log)
}

/// Sustained relayed media over WebTransport: `concurrency` sessions, each holding an
/// allocation and pumping ChannelData at `pps`.
///
/// Written out rather than shared with `tls_client::run_tls_load`. The shape is the
/// same, but the session types are not, and generalising a working driver to save fifty
/// lines is the kind of change that has already cost this project a day.
#[allow(clippy::too_many_arguments)]
pub async fn run_wt_load(
    url: String,
    concurrency: usize,
    pps: u64,
    payload: usize,
    duration: Duration,
    warmup: Duration,
    json: bool,
    creds: Creds,
    rtt_ms: u64,
) -> Arc<Stats> {
    let stats = Arc::new(Stats::new());
    let barrier = Arc::new(tokio::sync::Barrier::new(concurrency + 1));
    let payload = payload.max(16);
    let mut handles = Vec::new();

    for i in 0..concurrency {
        let stats = stats.clone();
        let barrier = barrier.clone();
        let creds = creds.clone();
        let url = url.clone();
        handles.push(tokio::spawn(async move {
            let peer_sock = match tokio::net::UdpSocket::bind(crate::turn_client::peer_bind_addr(
                false,
            ))
            .await
            {
                Ok(s) => s,
                Err(_) => {
                    stats.errs.fetch_add(1, Ordering::Relaxed);
                    barrier.wait().await;
                    return;
                }
            };
            let peer_addr = match peer_sock.local_addr() {
                Ok(a) => a,
                Err(_) => {
                    stats.errs.fetch_add(1, Ordering::Relaxed);
                    barrier.wait().await;
                    return;
                }
            };

            barrier.wait().await;

            let mut sess = match WtSession::connect(&url, &creds, rtt_ms).await {
                Ok(s) => s,
                Err(_) => {
                    stats.errs.fetch_add(1, Ordering::Relaxed);
                    return;
                }
            };
            let ch: u16 = 0x4000 + (i as u16 & 0x3FFF);
            if sess.create_permission(peer_addr).await.is_err()
                || sess.channel_bind(ch, peer_addr).await.is_err()
            {
                stats.errs.fetch_add(1, Ordering::Relaxed);
                return;
            }

            // Receiver: what actually came out of the relay.
            let recv_stats = stats.clone();
            let recv_task = tokio::spawn(async move {
                let mut buf = vec![0u8; 2048];
                loop {
                    match tokio::time::timeout(
                        Duration::from_secs(1),
                        peer_sock.recv_from(&mut buf),
                    )
                    .await
                    {
                        Ok(Ok((n, _))) => {
                            recv_stats.recv.fetch_add(1, Ordering::Relaxed);
                            recv_stats.bytes_in.fetch_add(n as u64, Ordering::Relaxed);
                        }
                        Ok(Err(_)) => break,
                        Err(_) => {
                            if !recv_stats.is_running() {
                                break;
                            }
                        }
                    }
                }
            });

            let body = vec![0u8; payload];
            let mut tick = tokio::time::interval(Duration::from_nanos(1_000_000_000 / pps.max(1)));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Burst);
            // Inside the 300 s permission deadline, the shortest of the three.
            let mut next_refresh = Instant::now() + Duration::from_secs(240);
            while stats.is_running() {
                tick.tick().await;
                if Instant::now() >= next_refresh {
                    if sess.refresh(ch, peer_addr).await.is_err() {
                        stats.errs.fetch_add(1, Ordering::Relaxed);
                        break;
                    }
                    next_refresh = Instant::now() + Duration::from_secs(240);
                }
                match sess.send_channel_data(ch, &body).await {
                    Ok(n) => {
                        stats.sent.fetch_add(1, Ordering::Relaxed);
                        stats.bytes_out.fetch_add(n as u64, Ordering::Relaxed);
                    }
                    Err(_) => {
                        stats.errs.fetch_add(1, Ordering::Relaxed);
                        break;
                    }
                }
            }
            sess.close();
            let _ = recv_task.await;
        }));
    }

    barrier.wait().await;
    crate::progress_reporter(&stats, json);
    if !warmup.is_zero() {
        tokio::time::sleep(warmup).await;
        stats.reset();
    }
    tokio::time::sleep(duration).await;
    stats.stop();
    for h in handles {
        let _ = h.await;
    }
    stats
}
