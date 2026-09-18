//! TURN over raw QUIC — a client, so the QUIC ingress can be verified at all.
//!
//! # Why this exists
//!
//! `[turn.quic]` had no interop evidence of any kind, and the reason given was
//! that no off-the-shelf TURN-over-QUIC client exists. That is true and it is not
//! an excuse: the wire format inside a QUIC bidi stream is the same
//! length-delimited STUN that TURN-over-TCP uses (see
//! `relay::quic_bridge::StreamFramer` — the STUN header's own length field
//! delimits messages, ChannelData is padded to a 4-byte boundary on the wire),
//! and `quinn` is already a workspace dependency. So the client is a few hundred
//! lines, not a project.
//!
//! # Scope and honesty about the certificate
//!
//! This is a **verification client**, not a library. It accepts any server
//! certificate, because the point is to exercise the TURN path against a
//! self-signed test cert. That makes it unfit for anything but testing, which is
//! why the verifier is named for what it does and why this module is behind the
//! `quic` feature rather than compiled by default.
//!
//! # What a passing run proves
//!
//! A full authenticated Allocate over QUIC, a relayed address, a permission, a
//! channel binding, and **relayed media in both directions**: ChannelData pushed
//! down the QUIC stream arriving at a real peer socket, and the peer's reply coming
//! back as ChannelData on the same stream.
//!
//! That last part matters more than it looks. A datapath can answer every control
//! request correctly and forward nothing — the io_uring backend did exactly that,
//! at 10 800 allocations per second, for three hours, while relaying zero bytes.
//! Only a media check catches it.

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::stream_common::{next_stream_message, AcceptAnyServerCert};
use crate::turn_client::{
    channel_data_frame, error_code, get_nonce, get_realm, get_relayed_addr, is_success,
    long_term_key, Creds, Msg, M_ALLOCATE, M_CHANNEL_BIND, M_CREATE_PERM, M_REFRESH,
};
use crate::Stats;

/// A control stream carrying framed STUN, plus the reassembly buffer.
///
/// Reassembly is required, not optional: QUIC delivers stream bytes, not
/// messages, so a response can arrive split across reads and two responses can
/// arrive in one. This mirrors `StreamFramer` on the server side.
struct ControlStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    buf: Vec<u8>,
}

impl ControlStream {
    async fn request(&mut self, pkt: &[u8], rtt_ms: u64) -> Result<Vec<u8>, String> {
        self.send
            .write_all(pkt)
            .await
            .map_err(|e| format!("stream write: {e}"))?;

        let deadline = Duration::from_millis(rtt_ms.max(1000));
        let fut = async {
            loop {
                if let Some(msg) = next_stream_message(&mut self.buf) {
                    return Ok(msg);
                }
                let mut chunk = vec![0u8; 4096];
                match self.recv.read(&mut chunk).await {
                    Ok(Some(0)) | Ok(None) => return Err("stream closed by server".to_string()),
                    Ok(Some(n)) => self.buf.extend_from_slice(&chunk[..n]),
                    Err(e) => return Err(format!("stream read: {e}")),
                }
            }
        };
        match tokio::time::timeout(deadline, fut).await {
            Ok(r) => r,
            Err(_) => Err("timeout waiting for a response on the control stream".to_string()),
        }
    }
}

/// An established raw-QUIC session carrying TURN.
///
/// Added for the load driver: the probe only needed a few seconds and kept its state in
/// local variables, but a soak holds one of these open for hours and has to refresh it.
pub struct QuicSession {
    conn: quinn::Connection,
    ctl: ControlStream,
    user: String,
    realm: String,
    nonce: Vec<u8>,
    key: [u8; 16],
    rtt_ms: u64,
    // The relayed address is returned from `connect` rather than stored, matching
    // `DtlsSession`. The load driver does not need it — it sends to the peer and the
    // relay forwards there — and `quic_allocate_check` still has its own copy of the
    // setup, so a field here would be dead. When that check is rewritten on this
    // session, take the address from `connect`.
    _ep: quinn::Endpoint,
}

impl QuicSession {
    pub async fn connect(
        server: SocketAddr,
        server_name: &str,
        alpn: &str,
        creds: &Creds,
        rtt_ms: u64,
    ) -> Result<(Self, SocketAddr), String> {
        let ep = client_endpoint(alpn)?;
        let conn = ep
            .connect(server, server_name)
            .map_err(|e| format!("connect setup: {e}"))?
            .await
            .map_err(|e| format!("QUIC handshake to {server} failed: {e}"))?;

        let (send, recv) = conn.open_bi().await.map_err(|e| format!("open_bi: {e}"))?;
        let mut ctl = ControlStream {
            send,
            recv,
            buf: Vec::new(),
        };

        let mut m = Msg::request(M_ALLOCATE);
        m.add_requested_transport_udp();
        m.add_lifetime(600);
        let resp = ctl.request(&m.encode(), rtt_ms).await?;
        if error_code(&resp) != Some(401) {
            return Err(format!(
                "expected a 401 challenge over QUIC, got {:?}",
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
                other => return Err(format!("Allocate over QUIC rejected: {other:?}")),
            }
        }
        let relayed = relayed.ok_or("Allocate over QUIC never succeeded")?;

        Ok((
            Self {
                conn,
                ctl,
                user,
                realm,
                nonce,
                key,
                rtt_ms,
                _ep: ep,
            },
            relayed,
        ))
    }

    async fn authed(&mut self, method: u16, build: impl Fn(&mut Msg)) -> Result<(), String> {
        // Rebuild with a new transaction ID and integrity after a stale nonce.
        // One retry only: a rejecting server must not cause an infinite loop.
        for attempt in 0..2 {
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
            if attempt == 0 && error_code(&resp) == Some(438) {
                self.nonce = get_nonce(&resp)
                    .filter(|nonce| !nonce.is_empty())
                    .ok_or("438 Stale Nonce without replacement NONCE")?;
                continue;
            }
            return Err(format!("{method:#06x} rejected: {:?}", error_code(&resp)));
        }
        unreachable!("bounded authenticated request loop")
    }

    /// Exercise the server's stale-nonce challenge without waiting 630 seconds.
    async fn check_stale_nonce(&mut self, ch: u16, peer: SocketAddr) -> Result<(), String> {
        for method in [M_REFRESH, M_CREATE_PERM, M_CHANNEL_BIND] {
            // The server classifies an invalid nonce as stale, just like expiry.
            self.nonce = b"turna-stale-nonce-regression".to_vec();
            self.authed(method, |m| match method {
                M_REFRESH => m.add_lifetime(600),
                M_CREATE_PERM => m.add_xor_peer(peer),
                M_CHANNEL_BIND => {
                    m.add_channel_number(ch);
                    m.add_xor_peer(peer);
                }
                _ => unreachable!(),
            })
            .await?;
        }
        Ok(())
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

    /// Renew the allocation, permission and channel binding — required past ten
    /// minutes, see `docs/soak/endurance-24h-2026-08-22.md`.
    pub async fn refresh(&mut self, ch: u16, peer: SocketAddr) -> Result<(), String> {
        self.authed(M_REFRESH, |m| m.add_lifetime(600)).await?;
        self.create_permission(peer).await?;
        self.channel_bind(ch, peer).await
    }

    pub async fn send_channel_data(&mut self, ch: u16, payload: &[u8]) -> Result<usize, String> {
        let mut frame = channel_data_frame(ch, payload);
        frame.truncate(4 + payload.len()); // datagrams have no stream padding
        let len = frame.len();
        self.conn
            .send_datagram(frame.into())
            .map_err(|e| format!("ChannelData datagram: {e}"))?;
        Ok(len)
    }

    pub async fn close(&self) {
        self.conn.close(0u32.into(), b"done");
        self._ep.wait_idle().await;
    }
}

/// Sustained relayed media over raw QUIC.
///
/// Note what this does **not** establish: an independent implementation. There is no
/// second TURN-over-QUIC client in existence, so both ends here share one reading of a
/// protocol combination no RFC defines. Endurance is real; interop is not available to
/// be had.
#[allow(clippy::too_many_arguments)]
pub async fn run_quic_load(
    server: SocketAddr,
    server_name: String,
    alpn: String,
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
        let server_name = server_name.clone();
        let alpn = alpn.clone();
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

            let (mut sess, _relayed) =
                match QuicSession::connect(server, &server_name, &alpn, &creds, rtt_ms).await {
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

            let recv_done = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let recv_done_task = recv_done.clone();
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
                            if recv_done_task.load(Ordering::Relaxed) {
                                break;
                            }
                        }
                    }
                }
            });

            let body = vec![0u8; payload];
            let mut tick = tokio::time::interval(Duration::from_nanos(1_000_000_000 / pps.max(1)));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Burst);
            let mut next_refresh = Instant::now() + Duration::from_secs(240);
            while stats.is_running() {
                tick.tick().await;
                if !stats.is_running() {
                    break;
                }
                if Instant::now() >= next_refresh {
                    if let Err(e) = sess.refresh(ch, peer_addr).await {
                        eprintln!("transport refresh failed: {e}");
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
            recv_done.store(true, Ordering::Relaxed);
            // Let the peer drain queued media while the connection still exists.
            let _ = recv_task.await;
            sess.close().await;
        }));
    }

    barrier.wait().await;
    crate::progress_reporter(&stats, json);
    if !warmup.is_zero() {
        tokio::time::sleep(warmup).await;
        stats.reset_preserving_errors();
    }
    tokio::time::sleep(duration).await;
    stats.stop();
    for h in handles {
        let _ = h.await;
    }
    stats
}

fn client_endpoint(alpn: &str) -> Result<quinn::Endpoint, String> {
    // No `install_default()`: `install_default` consumes a `CryptoProvider` by
    // value, and every path below takes the provider explicitly, so there is
    // nothing for a process-wide default to do here.
    let provider = AcceptAnyServerCert::provider();

    let mut tls = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("tls versions: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert(provider)))
        .with_no_client_auth();
    tls.alpn_protocols = vec![alpn.as_bytes().to_vec()];

    let qcc = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
        .map_err(|e| format!("quic client crypto: {e}"))?;
    let mut ep = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())
        .map_err(|e| format!("client endpoint: {e}"))?;
    ep.set_default_client_config(quinn::ClientConfig::new(Arc::new(qcc)));
    Ok(ep)
}

/// Run a full TURN allocation over raw QUIC. Returns a human-readable report of
/// each step, and `Err` on the first step that fails — the step name is the
/// diagnosis.
pub async fn quic_allocate_check(
    server: SocketAddr,
    server_name: &str,
    alpn: &str,
    creds: &Creds,
    rtt_ms: u64,
    peer: SocketAddr,
) -> Result<Vec<String>, String> {
    let mut log = Vec::new();

    let ep = client_endpoint(alpn)?;
    let conn = ep
        .connect(server, server_name)
        .map_err(|e| format!("connect setup: {e}"))?
        .await
        .map_err(|e| {
            format!(
                "QUIC handshake failed: {e}. Check that [turn.quic] is enabled, that the \
                 binary has --features quic, and that ALPN matches ([turn.quic].alpn, \
                 default \"stun.turn\")"
            )
        })?;
    log.push(format!("QUIC handshake ok (alpn {alpn})"));
    for _ in 0..64 {
        let a = tokio::time::timeout(Duration::from_secs(5), conn.open_bi())
            .await
            .map_err(|_| "open_bi timed out (stream credit leak)")?
            .map_err(|e| e.to_string())?;
        let b = tokio::time::timeout(Duration::from_secs(5), conn.open_bi())
            .await
            .map_err(|_| "open_bi timed out (stream credit leak)")?
            .map_err(|e| e.to_string())?;
        crate::stream_common::check_parallel_streams(a, b).await?;
        // Binding has a per-IP unauthenticated-reply budget (8/s).
        // Pace the probe so it exercises stream lifecycle, not that budget.
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    log.push("128 streams: interleaving, reply routing, half-close and credit recovery ok".into());

    let (send, recv) = conn.open_bi().await.map_err(|e| format!("open_bi: {e}"))?;
    let mut ctl = ControlStream {
        send,
        recv,
        buf: Vec::new(),
    };

    // 1. Unauthenticated Allocate -> 401 challenge.
    let mut m = Msg::request(M_ALLOCATE);
    m.add_requested_transport_udp();
    m.add_lifetime(600);
    let resp = ctl.request(&m.encode(), rtt_ms).await?;
    if is_success(&resp) {
        log.push("Allocate succeeded unauthenticated (server has no auth configured)".into());
    }
    let (realm, mut nonce) = if is_success(&resp) {
        (String::new(), Vec::new())
    } else {
        if error_code(&resp) != Some(401) {
            return Err(format!(
                "expected a 401 challenge over QUIC, got {:?}",
                error_code(&resp)
            ));
        }
        log.push("401 challenge received over the control stream".into());
        (
            get_realm(&resp).ok_or("401 without REALM")?,
            get_nonce(&resp).ok_or("401 without NONCE")?,
        )
    };

    // 2. Authenticated Allocate.
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
                nonce = get_nonce(&resp).ok_or("stale nonce without a replacement")?;
            }
            other => {
                return Err(format!(
                    "authenticated Allocate over QUIC rejected: {other:?}"
                ))
            }
        }
    }
    let relayed = relayed.ok_or("Allocate over QUIC never succeeded")?;
    log.push(format!(
        "Allocate ok over QUIC, relayed address {relayed} — the ingress, the stream \
         framer and the per-stream reply routing all agree"
    ));

    // 3. CreatePermission, which proves the session is usable and not just that
    //    one request/response pair happened to work.
    let mut m = Msg::request(M_CREATE_PERM);
    m.add_xor_peer(peer);
    m.add_username(&user);
    m.add_realm(&realm);
    m.add_nonce(&nonce);
    let resp = ctl.request(&m.encode_with_integrity(&key), rtt_ms).await?;
    if is_success(&resp) {
        log.push(format!("CreatePermission ok for {peer}"));
    } else {
        return Err(format!(
            "CreatePermission over QUIC rejected: {:?}",
            error_code(&resp)
        ));
    }

    // 4. Relayed media. This is the half a control-plane check cannot reach: bind a
    //    peer socket, channel-bind it, push ChannelData through the QUIC stream, and
    //    require the bytes to arrive at the peer — then the reverse, peer → relay →
    //    QUIC stream. An allocation that answers correctly can still forward nothing,
    //    which is exactly the failure the io_uring datapath had.
    // Named `peer_sock` rather than `peer`: the function already takes a
    // `peer: SocketAddr` for the CreatePermission step above, and shadowing an
    // address with a socket is a good way to misread this later.
    let peer_sock = tokio::net::UdpSocket::bind(crate::turn_client::peer_bind_addr(false))
        .await
        .map_err(|e| format!("peer bind: {e}"))?;
    let peer_addr = peer_sock
        .local_addr()
        .map_err(|e| format!("peer local_addr: {e}"))?;

    let mut m = Msg::request(M_CREATE_PERM);
    m.add_xor_peer(peer_addr);
    m.add_username(&user);
    m.add_realm(&realm);
    m.add_nonce(&nonce);
    let resp = ctl.request(&m.encode_with_integrity(&key), rtt_ms).await?;
    if !is_success(&resp) {
        return Err(format!(
            "CreatePermission for the media peer rejected: {:?}. If this is 403, the \
             server forbids loopback peers — set [turn.peer_filter] \
             allow_loopback_peers = true for a local test.",
            error_code(&resp)
        ));
    }

    let channel: u16 = 0x4000;
    let mut m = Msg::request(M_CHANNEL_BIND);
    m.add_channel_number(channel);
    m.add_xor_peer(peer_addr);
    m.add_username(&user);
    m.add_realm(&realm);
    m.add_nonce(&nonce);
    let resp = ctl.request(&m.encode_with_integrity(&key), rtt_ms).await?;
    if !is_success(&resp) {
        return Err(format!("ChannelBind rejected: {:?}", error_code(&resp)));
    }
    log.push(format!(
        "ChannelBind ok for {peer_addr} on channel {channel:#06x}"
    ));

    // Rebind the same connection, retaining the allocation and relay port.
    let old_local = ep.local_addr().map_err(|e| e.to_string())?;
    let socket = std::net::UdpSocket::bind(if old_local.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })
    .map_err(|e| e.to_string())?;
    let new_port = socket.local_addr().map_err(|e| e.to_string())?.port();
    ep.rebind(socket).map_err(|e| format!("QUIC rebind: {e}"))?;
    // Send on the new path, then allow the server's 2s migration poll to run.
    let binding = Msg::request(0x0001).encode();
    ctl.request(&binding, rtt_ms).await?;
    tokio::time::sleep(Duration::from_secs(3)).await;
    log.push(format!(
        "QUIC endpoint rebound {} -> {new_port}; testing existing relay",
        old_local.port()
    ));

    // client → relay → peer
    const N: usize = 20;
    let payload = b"turn-over-quic media probe";
    for i in 0..N {
        let mut body = payload.to_vec();
        body.push(i as u8);
        let frame = channel_data_frame(channel, &body);
        ctl.send
            .write_all(&frame)
            .await
            .map_err(|e| format!("ChannelData write: {e}"))?;
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
        return Err(format!(
            "sent {N} ChannelData frames over QUIC and the peer received none. The \
             allocation and the channel binding both succeeded, so the control plane \
             works and the relay egress does not — the same shape as the io_uring \
             slot leak."
        ));
    }
    log.push(format!(
        "client → relay → peer: {got}/{N} frames arrived at the peer"
    ));

    // peer → relay → client, which must come back as ChannelData on the same stream
    peer_sock
        .send_to(b"echo-from-peer", relayed)
        .await
        .map_err(|e| format!("peer send: {e}"))?;

    // Relayed data comes back as a QUIC **datagram**, not as a stream frame.
    //
    // That is the right design and it caught this client out: media is unreliable by
    // nature, and putting it on a reliable stream would impose retransmission and
    // head-of-line blocking that UDP does not have. The stream carries control
    // messages; `[turn.quic] enable_datagrams` and `max_datagram_size` govern the
    // media path. A client that reads only the stream sees the allocation work and
    // the media vanish — the server-side proof was
    // `turna_quic_datagrams_tx_total = 1` with
    // `turna_quic_control_dropped_no_stream_total = 0`.
    //
    // Both are accepted here: a datagram is what this server sends, and the stream is
    // checked too so that a server which chooses reliable delivery is not reported as
    // broken.
    let back = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(msg) = next_stream_message(&mut ctl.buf) {
                return Ok::<(Vec<u8>, &'static str), String>((msg, "stream"));
            }
            let mut chunk = vec![0u8; 4096];
            tokio::select! {
                dg = conn.read_datagram() => match dg {
                    Ok(bytes) => return Ok((bytes.to_vec(), "datagram")),
                    Err(e) => return Err(format!("read_datagram: {e}")),
                },
                r = ctl.recv.read(&mut chunk) => match r {
                    Ok(Some(0)) | Ok(None) => return Err("stream closed".into()),
                    Ok(Some(n)) => ctl.buf.extend_from_slice(&chunk[..n]),
                    Err(e) => return Err(format!("stream read: {e}")),
                },
            }
        }
    })
    .await;

    match back {
        Ok(Ok((msg, via))) if !msg.is_empty() && (0x40..=0x7f).contains(&msg[0]) => {
            log.push(format!(
                "peer → relay → client: ChannelData returned as a QUIC {via} ({} bytes)",
                msg.len()
            ));
        }
        Ok(Ok((msg, via))) => {
            return Err(format!(
                "expected ChannelData back, got a {} byte {via} starting with {:#04x}",
                msg.len(),
                msg.first().copied().unwrap_or(0)
            ))
        }
        Ok(Err(e)) => return Err(format!("waiting for the relayed reply: {e}")),
        Err(_) => {
            return Err(
                "the peer's packet came back on neither a datagram nor the stream — the \
                 relay→client direction is not working"
                    .into(),
            )
        }
    }

    conn.close(0u32.into(), b"done");
    ep.wait_idle().await;
    log.push("session closed cleanly".into());
    let (mut retry_session, _) =
        QuicSession::connect(server, server_name, alpn, creds, rtt_ms).await?;
    retry_session.check_stale_nonce(channel, peer_addr).await?;
    retry_session.close().await;
    log.push("438 Stale Nonce recovery: Refresh, CreatePermission, ChannelBind ok".into());
    // A malformed stream must close its session, release the allocation, and
    // leave the listener able to authenticate a fresh connection.
    let (mut bad, _) = QuicSession::connect(server, server_name, alpn, creds, rtt_ms).await?;
    bad.ctl
        .send
        .write_all(&[0xff, 0, 0, 0])
        .await
        .map_err(|e| e.to_string())?;
    tokio::time::timeout(Duration::from_secs(5), bad.conn.closed())
        .await
        .map_err(|_| "malformed stream did not close its session")?;
    bad.close().await;
    let (fresh, _) = QuicSession::connect(server, server_name, alpn, creds, rtt_ms).await?;
    fresh.close().await;
    log.push("malformed stream rejected; reconnect and allocation ok".into());

    Ok(log)
}

impl crate::transport_probe::Session for QuicSession {
    fn unreliable_media(&self) -> bool {
        true
    }
    fn network_stats(&self) -> String {
        let stats = self.conn.stats();
        format!(
            concat!(
                "{{\"udp_tx\":{},\"udp_rx\":{},\"datagram_frames_tx\":{},",
                "\"datagram_frames_rx\":{},\"path_lost_packets\":{},\"path_sent_packets\":{},",
                "\"congestion_events\":{},\"rtt_ms\":{}}}"
            ),
            stats.udp_tx.datagrams,
            stats.udp_rx.datagrams,
            stats.frame_tx.datagram,
            stats.frame_rx.datagram,
            stats.path.lost_packets,
            stats.path.sent_packets,
            stats.path.congestion_events,
            stats.path.rtt.as_secs_f64() * 1000.
        )
    }

    async fn bind_peer(&mut self, peer: SocketAddr) -> Result<(), String> {
        self.refresh(0x4000, peer).await
    }
    async fn send_media(&mut self, payload: &[u8]) -> Result<(), String> {
        self.send_channel_data(0x4000, payload).await.map(|_| ())
    }
    async fn receive_media(&mut self) -> Result<Vec<u8>, String> {
        self.conn
            .read_datagram()
            .await
            .map(|d| d.to_vec())
            .map_err(|e| e.to_string())
    }
    fn pressure_packet(&self) -> Vec<u8> {
        let mut m = Msg::request(M_REFRESH);
        m.add_lifetime(600);
        m.add_username(&self.user);
        m.add_realm(&self.realm);
        m.add_nonce(&self.nonce);
        m.encode_with_integrity(&self.key)
    }
    async fn write_control(&mut self, bytes: &[u8]) -> Result<(), String> {
        self.ctl
            .send
            .write_all(bytes)
            .await
            .map_err(|e| e.to_string())
    }
    async fn close_probe(&mut self) -> Result<(), String> {
        self.close().await;
        Ok(())
    }
}
pub async fn run_probe(
    server: SocketAddr,
    creds: &Creds,
    action: &str,
    hold: u64,
) -> Result<(), String> {
    let (session, relay) =
        QuicSession::connect(server, "localhost", "stun.turn", creds, 3000).await?;
    crate::transport_probe::exercise(session, relay, action, hold).await
}

/// Cross-host media probe; echo peer runs on the TURN server host.
pub async fn run_network(
    server: SocketAddr,
    creds: &Creds,
    peer: SocketAddr,
    seconds: u64,
    pps: u64,
) -> Result<(), String> {
    let (session, _) = QuicSession::connect(server, "localhost", "stun.turn", creds, 5000).await?;
    crate::transport_probe::network_session(session, peer, seconds, pps).await
}
