//! TURN over DTLS — a client, so an allocation can finally be made over it.
//!
//! # Why this exists
//!
//! DTLS has recorded evidence of a *transport handshake* and nothing more: no TURN
//! client has ever completed an allocation over it. That is what holds it at `beta`,
//! and it is not a code gap — no common client speaks TURN-over-DTLS, so there was
//! nothing to run.
//!
//! # What differs from the TLS client
//!
//! DTLS is datagram-oriented, so there is **no stream framing**: one datagram is one
//! message, exactly as over UDP. The reassembly `stream_common` exists for does not
//! apply here — a `read` returns a whole STUN message or a whole ChannelData frame,
//! and a partial read is an error rather than a signal to wait for more.
//!
//! Getting this backwards is easy and quiet: the TLS and QUIC clients in this crate
//! both need framing, and copying their loop into a datagram transport would appear
//! to work until a message arrived whose length field disagreed with the datagram
//! boundary.
//!
//! # Run it against both server paths
//!
//! `[turn.dtls] demux` selects between `webrtc_dtls::listen()` (default) and the
//! owned UDP demultiplexer. They differ in how handshakes are accepted — serially
//! versus one task each — so a result from one says little about the other. The
//! stock path is what ships enabled, so it is the one that matters most.

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::Stats;

use tokio::net::UdpSocket;

use crate::stream_common::AcceptAnyServerCert;
use crate::turn_client::{
    channel_data_frame, error_code, get_nonce, get_realm, get_relayed_addr, is_success,
    long_term_key, Creds, Msg, M_ALLOCATE, M_CHANNEL_BIND, M_CREATE_PERM, M_REFRESH,
};

/// A `webrtc_util::Conn` over one connected UDP socket.
///
/// `webrtc-dtls` drives its handshake through this trait, and the client side needs
/// a connected socket: everything goes to and comes from the one server address.
struct UdpConn {
    sock: UdpSocket,
    remote: SocketAddr,
}

fn io_err(what: &str, e: std::io::Error) -> webrtc_util::Error {
    webrtc_util::Error::from_std(std::io::Error::new(e.kind(), format!("{what}: {e}")))
}

#[async_trait::async_trait]
impl webrtc_util::conn::Conn for UdpConn {
    async fn connect(&self, _addr: SocketAddr) -> webrtc_util::Result<()> {
        Ok(())
    }

    async fn recv(&self, buf: &mut [u8]) -> webrtc_util::Result<usize> {
        self.sock.recv(buf).await.map_err(|e| io_err("recv", e))
    }

    async fn recv_from(&self, buf: &mut [u8]) -> webrtc_util::Result<(usize, SocketAddr)> {
        let n = self.recv(buf).await?;
        Ok((n, self.remote))
    }

    async fn send(&self, buf: &[u8]) -> webrtc_util::Result<usize> {
        self.sock.send(buf).await.map_err(|e| io_err("send", e))
    }

    async fn send_to(&self, buf: &[u8], target: SocketAddr) -> webrtc_util::Result<usize> {
        self.sock
            .send_to(buf, target)
            .await
            .map_err(|e| io_err("send_to", e))
    }

    fn local_addr(&self) -> webrtc_util::Result<SocketAddr> {
        self.sock.local_addr().map_err(|e| io_err("local_addr", e))
    }

    fn remote_addr(&self) -> Option<SocketAddr> {
        Some(self.remote)
    }

    async fn close(&self) -> webrtc_util::Result<()> {
        Ok(())
    }

    fn as_any(&self) -> &(dyn std::any::Any + Send + Sync) {
        self
    }
}

/// One established DTLS association carrying TURN.
pub struct DtlsSession {
    conn: webrtc_dtls::conn::DTLSConn,
    user: String,
    realm: String,
    nonce: Vec<u8>,
    key: [u8; 16],
    rtt_ms: u64,
}

impl DtlsSession {
    /// Send one message and read one back. Datagram-oriented: no reassembly, and a
    /// short read is a real error rather than "wait for more".
    async fn request(&mut self, pkt: &[u8]) -> Result<Vec<u8>, String> {
        use webrtc_util::conn::Conn;
        self.conn
            .send(pkt)
            .await
            .map_err(|e| format!("dtls send: {e}"))?;
        let mut buf = vec![0u8; 2048];
        let within = Duration::from_millis(self.rtt_ms.max(2000));
        match tokio::time::timeout(within, self.conn.recv(&mut buf)).await {
            Ok(Ok(n)) if n >= 20 => Ok(buf[..n].to_vec()),
            Ok(Ok(n)) => Err(format!("short DTLS record: {n} bytes")),
            Ok(Err(e)) => Err(format!("dtls recv: {e}")),
            Err(_) => Err("timeout waiting for a DTLS response".into()),
        }
    }

    fn authed(&self, method: u16, build: impl FnOnce(&mut Msg)) -> Vec<u8> {
        let mut m = Msg::request(method);
        build(&mut m);
        m.add_username(&self.user);
        m.add_realm(&self.realm);
        m.add_nonce(&self.nonce);
        m.encode_with_integrity(&self.key)
    }

    /// Handshake, then the 401 exchange, then allocate. Returns the session and its
    /// relayed address.
    pub async fn connect(
        server: SocketAddr,
        creds: &Creds,
        rtt_ms: u64,
    ) -> Result<(Self, SocketAddr), String> {
        // Control socket: the family has to match the server's, or the association
        // cannot even be attempted.
        let sock = UdpSocket::bind(crate::turn_client::control_bind_addr(server))
            .await
            .map_err(|e| format!("udp bind: {e}"))?;
        sock.connect(server)
            .await
            .map_err(|e| format!("udp connect {server}: {e}"))?;
        let conn: Arc<dyn webrtc_util::conn::Conn + Send + Sync> = Arc::new(UdpConn {
            sock,
            remote: server,
        });

        // Process-global, and `install_default` fails if something already set one, so
        // the result is deliberately ignored rather than unwrapped.
        let _ = AcceptAnyServerCert::owned_provider().install_default();

        let cfg = webrtc_dtls::config::Config {
            insecure_skip_verify: true,
            ..Default::default()
        };
        let dtls = tokio::time::timeout(
            Duration::from_secs(10),
            webrtc_dtls::conn::DTLSConn::new(conn, cfg, true, None),
        )
        .await
        .map_err(|_| {
            "DTLS handshake timed out. On the stock listener path handshakes are \
             accepted serially, so another stalled handshake can hold this one up; see \
             [turn.dtls].accept_timeout_secs."
                .to_string()
        })?
        .map_err(|e| format!("DTLS handshake failed: {e}"))?;

        let mut sess = DtlsSession {
            conn: dtls,
            user: String::new(),
            realm: String::new(),
            nonce: Vec::new(),
            key: [0u8; 16],
            rtt_ms,
        };

        let mut m = Msg::request(M_ALLOCATE);
        m.add_requested_transport_udp();
        m.add_lifetime(600);
        let resp = sess.request(&m.encode()).await?;
        if error_code(&resp) != Some(401) {
            return Err(format!(
                "expected a 401 challenge over DTLS, got {:?}",
                error_code(&resp)
            ));
        }
        sess.realm = get_realm(&resp).ok_or("401 without REALM")?;
        sess.nonce = get_nonce(&resp).ok_or("401 without NONCE")?;
        let (user, pass) = creds.materialize();
        sess.key = long_term_key(&user, &sess.realm, &pass);
        sess.user = user;

        let pkt = sess.authed(M_ALLOCATE, |m| {
            m.add_requested_transport_udp();
            m.add_lifetime(600);
        });
        let txid: [u8; 12] = pkt[8..20].try_into().expect("txid");
        let resp = sess.request(&pkt).await?;
        if !is_success(&resp) {
            return Err(format!(
                "authenticated Allocate over DTLS rejected: {:?}",
                error_code(&resp)
            ));
        }
        let relayed =
            get_relayed_addr(&resp, &txid).ok_or("Allocate without a relayed address")?;
        Ok((sess, relayed))
    }

    pub async fn create_permission(&mut self, peer: SocketAddr) -> Result<(), String> {
        let pkt = self.authed(M_CREATE_PERM, |m| m.add_xor_peer(peer));
        let resp = self.request(&pkt).await?;
        if is_success(&resp) {
            Ok(())
        } else {
            Err(format!("CreatePermission rejected: {:?}", error_code(&resp)))
        }
    }

    pub async fn channel_bind(&mut self, ch: u16, peer: SocketAddr) -> Result<(), String> {
        let pkt = self.authed(M_CHANNEL_BIND, |m| {
            m.add_channel_number(ch);
            m.add_xor_peer(peer);
        });
        let resp = self.request(&pkt).await?;
        if is_success(&resp) {
            Ok(())
        } else {
            Err(format!("ChannelBind rejected: {:?}", error_code(&resp)))
        }
    }

    /// Renew the allocation, permission and channel binding.
    ///
    /// Required past ten minutes: allocation and channel last 600 s, permission 300 s,
    /// and the server then correctly drops ChannelData for a binding that is gone —
    /// with no error, because there is nobody to send one to
    /// (`docs/soak/endurance-24h-2026-08-22.md`).
    pub async fn refresh(&mut self, ch: u16, peer: SocketAddr) -> Result<(), String> {
        let pkt = self.authed(M_REFRESH, |m| m.add_lifetime(600));
        let resp = self.request(&pkt).await?;
        if !is_success(&resp) {
            return Err(format!("Refresh rejected: {:?}", error_code(&resp)));
        }
        self.create_permission(peer).await?;
        self.channel_bind(ch, peer).await
    }

    /// Send one ChannelData frame.
    ///
    /// No framing: DTLS is datagram-oriented, one record is one message. Copying the
    /// stream clients' reassembly loop in here would appear to work until a message
    /// arrived whose length field disagreed with the record boundary.
    pub async fn send_channel_data(&mut self, ch: u16, payload: &[u8]) -> Result<usize, String> {
        use webrtc_util::conn::Conn;
        let frame = channel_data_frame(ch, payload);
        self.conn
            .send(&frame)
            .await
            .map_err(|e| format!("ChannelData send: {e}"))?;
        Ok(frame.len())
    }
}

/// Full TURN-over-DTLS exercise: handshake, allocation, permission, channel and
/// relayed media in both directions. Returns a step-by-step log.
pub async fn dtls_check(
    server: SocketAddr,
    creds: &Creds,
    rtt_ms: u64,
) -> Result<Vec<String>, String> {
    let mut log = Vec::new();

    let (mut sess, relayed) = DtlsSession::connect(server, creds, rtt_ms).await?;
    log.push("DTLS handshake ok".into());
    log.push("401 challenge received over the DTLS association".into());
    log.push(format!(
        "Allocate ok over DTLS, relayed address {relayed} — the first TURN allocation \
         this transport completed here"
    ));

    let peer_sock = UdpSocket::bind(crate::turn_client::peer_bind_addr(false))
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
    log.push(format!("CreatePermission and ChannelBind ok for {peer_addr}"));

    const N: usize = 20;
    for i in 0..N {
        let mut body = b"turn-over-dtls media probe".to_vec();
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
            "sent 20 ChannelData frames over DTLS and the peer received none — the \
             association carries control messages and the relay egress forwards nothing"
                .into(),
        );
    }
    log.push(format!("client → relay → peer: {got}/{N} frames arrived"));

    peer_sock
        .send_to(b"echo-from-peer", relayed)
        .await
        .map_err(|e| format!("peer send: {e}"))?;

    // Unlike QUIC and WebTransport, DTLS has no separate datagram channel: the
    // association *is* datagrams, so the relayed reply arrives in band.
    use webrtc_util::conn::Conn;
    let mut back = vec![0u8; 2048];
    match tokio::time::timeout(Duration::from_secs(5), sess.conn.recv(&mut back)).await {
        Ok(Ok(n)) if n > 0 && (0x40..=0x7f).contains(&back[0]) => log.push(format!(
            "peer → relay → client: ChannelData returned over DTLS ({n} bytes)"
        )),
        Ok(Ok(n)) => {
            return Err(format!(
                "expected ChannelData back, got {n} bytes starting with {:#04x}",
                back.first().copied().unwrap_or(0)
            ))
        }
        Ok(Err(e)) => return Err(format!("dtls recv: {e}")),
        Err(_) => {
            return Err(
                "the peer's packet never came back over the DTLS association — the \
                 relay→client direction is not working"
                    .into(),
            )
        }
    }

    Ok(log)
}

/// Sustained relayed media over DTLS: `concurrency` associations, each holding an
/// allocation and pumping ChannelData at `pps`.
///
/// Written out rather than shared with the stream transports' drivers. The shape is
/// similar, but DTLS is datagram-oriented — there is no reassembly here and a short
/// read is an error, not a signal to wait for more — and folding that difference into
/// a shared abstraction is how it would get lost.
#[allow(clippy::too_many_arguments)]
pub async fn run_dtls_load(
    server: SocketAddr,
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
        handles.push(tokio::spawn(async move {
            let peer_sock =
                match UdpSocket::bind(crate::turn_client::peer_bind_addr(false)).await {
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

            // Handshakes are staggered: on the stock listener path the server accepts
            // them serially, so launching N at once measures the queue rather than the
            // datapath.
            tokio::time::sleep(Duration::from_millis(20 * i as u64)).await;

            let (mut sess, _relayed) = match DtlsSession::connect(server, &creds, rtt_ms).await {
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
            let mut tick =
                tokio::time::interval(Duration::from_nanos(1_000_000_000 / pps.max(1)));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Burst);
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
