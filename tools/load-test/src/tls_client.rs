//! TURN over TLS (TURNS) — a client, so the transport browsers actually use can be
//! put under load.
//!
//! # Why this exists
//!
//! TURNS had browser interop but no endurance evidence, and could not get any: the
//! load tool spoke UDP only, so there was no way to place load on the TLS path at
//! all. That is what kept TURNS at `beta` — not a defect, an inability to measure.
//!
//! The framing inside the TLS stream is the same one `quic_client` uses and the same
//! one `transport::tcp_tls` implements on the server: raw STUN delimited by the
//! length in its own header, ChannelData padded to a 4-byte boundary. Framing lives
//! in `stream_common` so the three transports cannot drift apart.
//!
//! # Two things it does
//!
//! * `tls_probe` — one session, end to end, including relayed media in both
//!   directions. The functional check.
//! * `run_tls_load` — N concurrent sessions doing allocation churn or sustained
//!   ChannelData, feeding the same `Stats` as the UDP modes so the numbers are
//!   comparable and the soak harness can consume them unchanged.
//!
//! # The certificate
//!
//! Any certificate is accepted (`stream_common::AcceptAnyServerCert`). This is a
//! verification client pointed at test servers; validating a chain is not its job and
//! it must not be mistaken for a library.

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Barrier;

use crate::stream_common::{next_stream_message, AcceptAnyServerCert};
use crate::turn_client::{
    channel_data_frame, error_code, get_nonce, get_realm, get_relayed_addr, is_success,
    long_term_key, Creds, Msg, M_ALLOCATE, M_CHANNEL_BIND, M_CREATE_PERM, M_REFRESH,
};
use crate::Stats;

type TlsStream = tokio_rustls::client::TlsStream<TcpStream>;

/// One TURNS control connection: the stream plus its reassembly buffer and the
/// credential state the server handed back in its 401.
pub struct TlsSession {
    stream: TlsStream,
    buf: Vec<u8>,
    user: String,
    realm: String,
    nonce: Vec<u8>,
    key: [u8; 16],
    pub relayed: SocketAddr,
    rtt_ms: u64,
}

/// Load a PEM chain and private key for client authentication.
///
/// Client certificates come from a **private** CA, not a public one: Let's Encrypt and
/// its peers issue server certificates only. That is not a limitation to work around —
/// it is how mTLS is meant to work, and `docs/MTLS.md` says the same about the
/// management plane. The server side is `[tls] client_ca` plus `require_client_cert`.
fn load_client_auth(
    cert_path: &str,
    key_path: &str,
) -> Result<
    (
        Vec<rustls::pki_types::CertificateDer<'static>>,
        rustls::pki_types::PrivateKeyDer<'static>,
    ),
    String,
> {
    // `rustls-pki-types` rather than `rustls-pemfile`: the latter was archived in
    // August 2025 (RUSTSEC-2025-0134) and its final release is a thin wrapper around
    // exactly this code. rustls already pulls pki-types in, so this removes a
    // dependency rather than adding one.
    use rustls::pki_types::pem::PemObject;

    let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
        rustls::pki_types::CertificateDer::pem_file_iter(cert_path)
            .map_err(|e| format!("read {cert_path}: {e}"))?
            .collect::<std::result::Result<_, _>>()
            .map_err(|e| format!("parse {cert_path}: {e}"))?;
    if certs.is_empty() {
        return Err(format!("{cert_path} contains no certificate"));
    }
    let key = rustls::pki_types::PrivateKeyDer::from_pem_file(key_path)
        .map_err(|e| format!("read {key_path}: {e}"))?;
    Ok((certs, key))
}

fn client_config(
    alpn: &[String],
    client_auth: Option<(&str, &str)>,
) -> Result<Arc<rustls::ClientConfig>, String> {
    let provider = AcceptAnyServerCert::provider();
    let base = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("tls versions: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert(provider)));
    let mut cfg = match client_auth {
        Some((cert, key)) => {
            let (chain, key) = load_client_auth(cert, key)?;
            base.with_client_auth_cert(chain, key)
                .map_err(|e| format!("client certificate rejected by rustls: {e}"))?
        }
        None => base.with_no_client_auth(),
    };
    if !alpn.is_empty() {
        cfg.alpn_protocols = alpn.iter().map(|a| a.as_bytes().to_vec()).collect();
    }
    Ok(Arc::new(cfg))
}

impl TlsSession {
    /// Connect, authenticate, allocate. `server_name` is what goes in SNI; with a
    /// certificate the client does not verify it only has to be syntactically valid.
    #[allow(clippy::too_many_arguments)]
    pub async fn connect(
        server: SocketAddr,
        server_name: &str,
        alpn: &[String],
        creds: &Creds,
        rtt_ms: u64,
        client_auth: Option<(&str, &str)>,
    ) -> Result<Self, String> {
        let cfg = client_config(alpn, client_auth)?;
        let name = rustls::pki_types::ServerName::try_from(server_name.to_string())
            .map_err(|e| format!("bad server name {server_name:?}: {e}"))?;
        let tcp = TcpStream::connect(server)
            .await
            .map_err(|e| format!("tcp connect {server}: {e}"))?;
        // Nagle would batch our small STUN writes and distort every latency number
        // this client reports.
        let _ = tcp.set_nodelay(true);
        let stream = tokio_rustls::TlsConnector::from(cfg)
            .connect(name, tcp)
            .await
            .map_err(|e| {
                format!(
                    "TLS handshake failed: {e}. Check that [tls] is enabled, that the \
                     port is the TURNS one (5349 by convention, not 3478), and that \
                     alpn matches [tls].enable_alpn."
                )
            })?;

        let mut s = Self {
            stream,
            buf: Vec::new(),
            user: String::new(),
            realm: String::new(),
            nonce: Vec::new(),
            key: [0u8; 16],
            relayed: "0.0.0.0:0".parse().unwrap(),
            rtt_ms,
        };

        // Unauthenticated Allocate → 401 with REALM and NONCE.
        let mut m = Msg::request(M_ALLOCATE);
        m.add_requested_transport_udp();
        m.add_lifetime(600);
        let resp = s.request(&m.encode()).await?;
        if is_success(&resp) {
            let txid: [u8; 12] = resp[8..20].try_into().unwrap();
            s.relayed = get_relayed_addr(&resp, &txid).ok_or("no relayed address")?;
            return Ok(s);
        }
        if error_code(&resp) != Some(401) {
            return Err(format!(
                "expected a 401 challenge over TURNS, got {:?}",
                error_code(&resp)
            ));
        }
        s.realm = get_realm(&resp).ok_or("401 without REALM")?;
        s.nonce = get_nonce(&resp).ok_or("401 without NONCE")?;

        let (user, pass) = creds.materialize();
        s.key = long_term_key(&user, &s.realm, &pass);
        s.user = user;

        for _ in 0..2 {
            let mut m = Msg::request(M_ALLOCATE);
            m.add_requested_transport_udp();
            m.add_lifetime(600);
            m.add_username(&s.user);
            m.add_realm(&s.realm);
            m.add_nonce(&s.nonce);
            let txid = m.txid();
            let pkt = m.encode_with_integrity(&s.key);
            let resp = s.request(&pkt).await?;
            if is_success(&resp) {
                s.relayed = get_relayed_addr(&resp, &txid).ok_or("no relayed address")?;
                return Ok(s);
            }
            match error_code(&resp) {
                // A stale nonce is normal under churn; retry once with the new one.
                Some(438) | Some(401) => {
                    s.nonce = get_nonce(&resp).ok_or("stale nonce without a replacement")?;
                }
                other => return Err(format!("authenticated Allocate rejected: {other:?}")),
            }
        }
        Err("Allocate over TURNS never succeeded".into())
    }

    /// Write a message and read the next one back, bounded by `rtt_ms`.
    async fn request(&mut self, pkt: &[u8]) -> Result<Vec<u8>, String> {
        self.stream
            .write_all(pkt)
            .await
            .map_err(|e| format!("tls write: {e}"))?;
        self.read_message(Duration::from_millis(self.rtt_ms.max(1000)))
            .await
    }

    /// Read one framed message, or time out.
    async fn read_message(&mut self, within: Duration) -> Result<Vec<u8>, String> {
        let deadline = Instant::now() + within;
        loop {
            if let Some(msg) = next_stream_message(&mut self.buf) {
                return Ok(msg);
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err("timeout waiting for a TURNS response".into());
            }
            let mut chunk = [0u8; 4096];
            match tokio::time::timeout(left, self.stream.read(&mut chunk)).await {
                Ok(Ok(0)) => return Err("server closed the TURNS connection".into()),
                Ok(Ok(n)) => self.buf.extend_from_slice(&chunk[..n]),
                Ok(Err(e)) => return Err(format!("tls read: {e}")),
                Err(_) => return Err("timeout waiting for a TURNS response".into()),
            }
        }
    }

    async fn authed(&mut self, method: u16, build: impl FnOnce(&mut Msg)) -> Result<(), String> {
        let mut m = Msg::request(method);
        build(&mut m);
        m.add_username(&self.user);
        m.add_realm(&self.realm);
        m.add_nonce(&self.nonce);
        let pkt = m.encode_with_integrity(&self.key);
        let resp = self.request(&pkt).await?;
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

    /// Refresh the allocation and re-assert the permission and channel binding.
    ///
    /// **A long-lived session has to do this or it quietly stops working.** An
    /// allocation lasts 600 s (RFC 8656 §7.2), a permission 300 s (§9), and a channel
    /// binding 600 s (§11.2). None of them renew themselves. Past those deadlines the
    /// server is *required* to drop ChannelData for the expired binding, and it does so
    /// silently — there is no error to receive, because the client is talking to a
    /// channel that no longer exists.
    ///
    /// This is what a 24 h soak measured before this existed: phases of 1755 s
    /// delivered 600/1755 ≈ 34 % of what they sent, on every transport, and it read
    /// like a capacity cliff. Shorter rehearsals passed cleanly because 244 s never
    /// reached the deadline.
    pub async fn refresh(&mut self, ch: u16, peer: SocketAddr) -> Result<(), String> {
        self.authed(M_REFRESH, |m| m.add_lifetime(600)).await?;
        self.create_permission(peer).await?;
        self.channel_bind(ch, peer).await?;
        Ok(())
    }

    pub async fn send_channel_data(&mut self, ch: u16, payload: &[u8]) -> Result<usize, String> {
        let frame = channel_data_frame(ch, payload);
        self.stream
            .write_all(&frame)
            .await
            .map_err(|e| format!("ChannelData write: {e}"))?;
        Ok(frame.len())
    }
}

/// One TURNS session end to end, including relayed media both ways.
///
/// Returns a step-by-step log. The media half is the point: a TURNS connection that
/// allocates and then forwards nothing looks identical to a working one from the
/// control plane, which is not a hypothetical — see
/// `docs/soak/endurance-2026-08-19.md`.
#[allow(clippy::too_many_arguments)]
pub async fn tls_probe(
    server: SocketAddr,
    server_name: &str,
    alpn: &[String],
    creds: &Creds,
    rtt_ms: u64,
    client_auth: Option<(&str, &str)>,
) -> Result<Vec<String>, String> {
    let mut log = Vec::new();
    let mut sess =
        TlsSession::connect(server, server_name, alpn, creds, rtt_ms, client_auth).await?;
    log.push(format!(
        "TLS handshake and Allocate ok{}, relayed address {}",
        if client_auth.is_some() {
            " (client certificate presented)"
        } else {
            ""
        },
        sess.relayed
    ));

    let peer_sock = UdpSocket::bind(crate::turn_client::peer_bind_addr(false))
        .await
        .map_err(|e| format!("peer bind: {e}"))?;
    let peer_addr = peer_sock
        .local_addr()
        .map_err(|e| format!("peer local_addr: {e}"))?;

    sess.create_permission(peer_addr).await.map_err(|e| {
        format!(
            "{e}. If this is 403, the server forbids loopback peers — a local test \
             needs [turn.peer_filter] allow_loopback_peers = true."
        )
    })?;
    let channel: u16 = 0x4000;
    sess.channel_bind(channel, peer_addr).await?;
    log.push(format!(
        "CreatePermission and ChannelBind ok for {peer_addr}"
    ));

    const N: usize = 20;
    for i in 0..N {
        let mut body = b"turns media probe".to_vec();
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
            "sent 20 ChannelData frames over TURNS and the peer received none — the \
             control plane works and the relay egress does not"
                .into(),
        );
    }
    log.push(format!("client → relay → peer: {got}/{N} frames arrived"));

    peer_sock
        .send_to(b"echo-from-peer", sess.relayed)
        .await
        .map_err(|e| format!("peer send: {e}"))?;
    // Unlike QUIC and WebTransport, TURNS has no datagram channel: the relayed reply
    // has to come back in-band on the same TLS stream. Do not "fix" this the way the
    // QUIC client had to be fixed.
    let back = sess.read_message(Duration::from_secs(5)).await?;
    if back.is_empty() || !(0x40..=0x7f).contains(&back[0]) {
        return Err(format!(
            "expected ChannelData back on the TLS stream, got {} bytes starting with {:#04x}",
            back.len(),
            back.first().copied().unwrap_or(0)
        ));
    }
    log.push(format!(
        "peer → relay → client: ChannelData returned on the TLS stream ({} bytes)",
        back.len()
    ));

    Ok(log)
}

/// Sustained load over TURNS: `concurrency` sessions, each allocating and then
/// either churning allocations or pumping ChannelData.
///
/// Feeds the same `Stats` as the UDP modes so `--json` output, the soak harness and
/// the analyser all work unchanged.
#[allow(clippy::too_many_arguments)]
pub async fn run_tls_load(
    server: SocketAddr,
    server_name: String,
    alpn: Vec<String>,
    client_cert: Option<String>,
    client_key: Option<String>,
    concurrency: usize,
    channel_data: bool,
    pps: u64,
    payload: usize,
    duration: Duration,
    warmup: Duration,
    json: bool,
    creds: Creds,
    rtt_ms: u64,
) -> Arc<Stats> {
    let stats = Arc::new(Stats::new());
    let barrier = Arc::new(Barrier::new(concurrency + 1));
    let payload = payload.max(16);
    let mut handles = Vec::new();

    for i in 0..concurrency {
        let stats = stats.clone();
        let barrier = barrier.clone();
        let creds = creds.clone();
        let server_name = server_name.clone();
        let alpn = alpn.clone();
        let client_cert = client_cert.clone();
        let client_key = client_key.clone();
        handles.push(tokio::spawn(async move {
            // Rebuilt per task rather than shared: `connect` takes borrowed paths, and
            // a per-task pair keeps the signature simple at the cost of re-reading two
            // small files per session.
            let auth = match (client_cert.as_deref(), client_key.as_deref()) {
                (Some(c), Some(k)) => Some((c, k)),
                _ => None,
            };
            let peer_sock = if channel_data {
                match UdpSocket::bind(crate::turn_client::peer_bind_addr(false)).await {
                    Ok(s) => Some(s),
                    Err(_) => {
                        stats.errs.fetch_add(1, Ordering::Relaxed);
                        barrier.wait().await;
                        return;
                    }
                }
            } else {
                None
            };

            barrier.wait().await;

            // Allocation churn: connect, allocate, drop, repeat. The TLS handshake is
            // part of the cost being measured, which is the point — it is what a
            // reconnecting client actually pays.
            if !channel_data {
                while stats.is_running() {
                    let t0 = Instant::now();
                    match TlsSession::connect(server, &server_name, &alpn, &creds, rtt_ms, auth)
                        .await
                    {
                        Ok(_sess) => {
                            stats.recv.fetch_add(1, Ordering::Relaxed);
                            stats.record_latency(t0.elapsed());
                        }
                        Err(_) => {
                            stats.errs.fetch_add(1, Ordering::Relaxed);
                            // Back off briefly: hammering a refusing server just
                            // measures the refusal path.
                            tokio::time::sleep(Duration::from_millis(20)).await;
                        }
                    }
                    stats.sent.fetch_add(1, Ordering::Relaxed);
                }
                return;
            }

            // Sustained relayed media over one long-lived TURNS session.
            let peer_sock = peer_sock.expect("bound above when channel_data");
            let peer_addr = match peer_sock.local_addr() {
                Ok(a) => a,
                Err(_) => {
                    stats.errs.fetch_add(1, Ordering::Relaxed);
                    return;
                }
            };
            let mut sess = match TlsSession::connect(
                server,
                &server_name,
                &alpn,
                &creds,
                rtt_ms,
                auth,
            )
            .await
            {
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
            // Well inside the shortest deadline: permissions expire at 300 s, so 240 s
            // leaves room for a slow round trip without ever letting one lapse.
            let mut next_refresh = Instant::now() + Duration::from_secs(240);
            while stats.is_running() {
                tick.tick().await;
                if Instant::now() >= next_refresh {
                    if let Err(_e) = sess.refresh(ch, peer_addr).await {
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
