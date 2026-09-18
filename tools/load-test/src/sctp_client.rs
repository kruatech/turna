//! Native Linux SCTP one-to-one client. Independent TURN framing, UDP relay peers.
//! The kernel socket is IPPROTO_SCTP (132), never TCP. Tokio's stream wrapper
//! supplies readiness/read/write for the connected SOCK_STREAM descriptor.
use crate::{
    stream_common::next_stream_message,
    turn_client::{
        channel_data_frame, error_code, get_nonce, get_realm, get_relayed_addr, is_success,
        long_term_key, Creds, Msg, M_ALLOCATE, M_CHANNEL_BIND, M_CREATE_PERM, M_REFRESH,
    },
    Stats,
};
use std::{
    net::SocketAddr,
    sync::{atomic::Ordering, Arc},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
};

async fn connect_socket(server: SocketAddr) -> Result<TcpStream, String> {
    let socket = tokio::task::spawn_blocking(move || {
        let domain = if server.is_ipv4() {
            socket2::Domain::IPV4
        } else {
            socket2::Domain::IPV6
        };
        let s = socket2::Socket::new(
            domain,
            socket2::Type::STREAM,
            Some(socket2::Protocol::from(132)),
        )?;
        // Send small media frames immediately instead of waiting for delayed SACKs.
        use std::os::fd::AsRawFd;
        let enabled: libc::c_int = 1;
        // SAFETY: live SCTP socket, valid integer pointer and matching length.
        let rc = unsafe {
            libc::setsockopt(
                s.as_raw_fd(),
                libc::IPPROTO_SCTP,
                libc::SCTP_NODELAY,
                &enabled as *const _ as *const libc::c_void,
                std::mem::size_of_val(&enabled) as libc::socklen_t,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
        s.connect_timeout(&server.into(), Duration::from_secs(5))?;
        s.set_nonblocking(true)?;
        Ok::<std::net::TcpStream, std::io::Error>(s.into())
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(|e| format!("SCTP connect: {e}"))?;
    TcpStream::from_std(socket).map_err(|e| e.to_string())
}

struct Session {
    stream: TcpStream,
    buf: Vec<u8>,
    user: String,
    realm: String,
    nonce: Vec<u8>,
    key: [u8; 16],
    relayed: SocketAddr,
    deadline: Duration,
}
impl Session {
    async fn request(&mut self, packet: &[u8]) -> Result<Vec<u8>, String> {
        tokio::time::timeout(self.deadline, async {
            self.stream
                .write_all(packet)
                .await
                .map_err(|e| e.to_string())?;
            loop {
                if let Some(m) = next_stream_message(&mut self.buf) {
                    return Ok(m);
                }
                let mut chunk = [0u8; 8192];
                let n = self
                    .stream
                    .read(&mut chunk)
                    .await
                    .map_err(|e| e.to_string())?;
                if n == 0 {
                    return Err("SCTP EOF waiting for response".into());
                }
                self.buf.extend_from_slice(&chunk[..n]);
            }
        })
        .await
        .map_err(|_| "SCTP request timeout".to_string())?
    }
    async fn authed(&mut self, method: u16, build: impl Fn(&mut Msg)) -> Result<Vec<u8>, String> {
        for attempt in 0..2 {
            let mut m = Msg::request(method);
            build(&mut m);
            m.add_username(&self.user);
            m.add_realm(&self.realm);
            m.add_nonce(&self.nonce);
            let resp = self.request(&m.encode_with_integrity(&self.key)).await?;
            if is_success(&resp) {
                return Ok(resp);
            }
            if attempt == 0 && error_code(&resp) == Some(438) {
                self.nonce = get_nonce(&resp)
                    .filter(|n| !n.is_empty())
                    .ok_or("438 without NONCE")?;
                continue;
            }
            return Err(format!(
                "SCTP {method:#x} rejected: {:?}",
                error_code(&resp)
            ));
        }
        unreachable!()
    }
    async fn connect(server: SocketAddr, creds: &Creds, rtt: u64) -> Result<Self, String> {
        let stream = connect_socket(server).await?;
        let (user, pass) = creds.materialize();
        let mut s = Self {
            stream,
            buf: Vec::new(),
            user,
            realm: String::new(),
            nonce: Vec::new(),
            key: [0; 16],
            relayed: server,
            deadline: Duration::from_millis(rtt.max(1000)),
        };
        let mut req = Msg::request(M_ALLOCATE);
        req.add_requested_transport_udp();
        let resp = s.request(&req.encode()).await?;
        if error_code(&resp) != Some(401) {
            return Err("expected SCTP 401 challenge".into());
        }
        s.realm = get_realm(&resp).ok_or("401 without REALM")?;
        s.nonce = get_nonce(&resp).ok_or("401 without NONCE")?;
        s.key = long_term_key(&s.user, &s.realm, &pass);
        let resp = s
            .authed(M_ALLOCATE, |m| {
                m.add_requested_transport_udp();
                m.add_lifetime(600);
            })
            .await?;
        let txid: [u8; 12] = resp
            .get(8..20)
            .ok_or("short Allocate response")?
            .try_into()
            .unwrap();
        s.relayed = get_relayed_addr(&resp, &txid).ok_or("Allocate without relay address")?;
        Ok(s)
    }
    async fn refresh(&mut self, peer: SocketAddr) -> Result<(), String> {
        self.authed(M_REFRESH, |m| m.add_lifetime(600)).await?;
        self.authed(M_CREATE_PERM, |m| m.add_xor_peer(peer)).await?;
        self.authed(M_CHANNEL_BIND, |m| {
            m.add_channel_number(0x4000);
            m.add_xor_peer(peer);
        })
        .await?;
        Ok(())
    }
    async fn close(&mut self) -> Result<(), String> {
        self.authed(M_REFRESH, |m| m.add_lifetime(0)).await?;
        self.stream.shutdown().await.map_err(|e| e.to_string())
    }
    async fn send(&mut self, data: &[u8]) -> Result<(), String> {
        tokio::time::timeout(
            self.deadline,
            self.stream.write_all(&channel_data_frame(0x4000, data)),
        )
        .await
        .map_err(|_| "SCTP media write timeout".to_string())?
        .map_err(|e| e.to_string())
    }
}

pub async fn check(server: SocketAddr, creds: &Creds, rtt: u64) -> Result<Vec<String>, String> {
    let peer = UdpSocket::bind("127.0.0.1:0")
        .await
        .map_err(|e| e.to_string())?;
    let addr = peer.local_addr().map_err(|e| e.to_string())?;
    let mut s = Session::connect(server, creds, rtt).await?;
    s.nonce = b"stale-sctp-regression".to_vec();
    s.refresh(addr).await?;
    s.nonce = b"stale-sctp-permission".to_vec();
    s.authed(M_CREATE_PERM, |m| m.add_xor_peer(addr)).await?;
    s.nonce = b"stale-sctp-channel".to_vec();
    s.authed(M_CHANNEL_BIND, |m| {
        m.add_channel_number(0x4000);
        m.add_xor_peer(addr);
    })
    .await?;
    let mut buf = [0u8; 2048];
    for i in 0..20u8 {
        let body = [i; 159]; // deliberately not 4-aligned
        s.send(&body).await?;
        let (n, _) = tokio::time::timeout(Duration::from_secs(3), peer.recv_from(&mut buf))
            .await
            .map_err(|_| "SCTP relay-to-peer timeout")?
            .map_err(|e| e.to_string())?;
        if buf[..n] != body {
            return Err("SCTP peer payload mismatch".into());
        }
    }
    peer.send_to(b"sctp-return", s.relayed)
        .await
        .map_err(|e| e.to_string())?;
    let back = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if let Some(m) = next_stream_message(&mut s.buf) {
                break Ok::<_, String>(m);
            }
            let n = s.stream.read(&mut buf).await.map_err(|e| e.to_string())?;
            if n == 0 {
                break Err("SCTP return EOF".into());
            }
            s.buf.extend_from_slice(&buf[..n]);
        }
    })
    .await
    .map_err(|_| "SCTP peer-to-client timeout")??;
    if back.get(..2) != Some(&[0x40, 0][..]) || back.get(4..) != Some(b"sctp-return".as_slice()) {
        return Err("SCTP return ChannelData/payload mismatch".into());
    }
    s.close().await?;
    // Fragmented Binding, then await its response before SCTP shutdown.
    let mut stream = connect_socket(server).await?;
    let req = Msg::request(1).encode();
    stream
        .write_all(&req[..9])
        .await
        .map_err(|e| e.to_string())?;
    stream
        .write_all(&req[9..])
        .await
        .map_err(|e| e.to_string())?;
    let mut reply = vec![0u8; 20];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut reply))
        .await
        .map_err(|_| "SCTP fragmented Binding timeout")?
        .map_err(|e| e.to_string())?;
    if !is_success(&reply) || reply.get(8..20) != req.get(8..20) {
        return Err("SCTP Binding reply mismatch".into());
    }
    let body_len = u16::from_be_bytes([reply[2], reply[3]]) as usize;
    let mut body = vec![0; body_len];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut body))
        .await
        .map_err(|_| "SCTP Binding body timeout")?
        .map_err(|e| e.to_string())?;
    stream.shutdown().await.map_err(|e| e.to_string())?;
    Ok(vec![
        "SCTP allocation, stale nonce recovery and refresh ok".into(),
        "20/20 unaligned ChannelData frames relayed; return payload verified".into(),
        "fragmentation, final reply and SCTP shutdown ok".into(),
    ])
}

#[allow(clippy::too_many_arguments)]
pub async fn load(
    server: SocketAddr,
    creds: Creds,
    rtt: u64,
    concurrency: usize,
    pps: u64,
    payload: usize,
    duration: Duration,
    warmup: Duration,
    json: bool,
) -> Arc<Stats> {
    let stats = Arc::new(Stats::new());
    let barrier = Arc::new(tokio::sync::Barrier::new(concurrency + 1));
    let mut tasks = Vec::new();
    for _ in 0..concurrency {
        let stats = stats.clone();
        let creds = creds.clone();
        let barrier = barrier.clone();
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            let outcome = async {
                let peer = UdpSocket::bind("127.0.0.1:0")
                    .await
                    .map_err(|e| e.to_string())?;
                let addr = peer.local_addr().map_err(|e| e.to_string())?;
                let mut s = Session::connect(server, &creds, rtt).await?;
                s.refresh(addr).await?;
                let data = vec![7u8; payload];
                let mut buf = vec![0u8; payload + 1];
                let mut tick =
                    tokio::time::interval(Duration::from_nanos(1_000_000_000 / pps.max(1)));
                tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                let mut refresh = Instant::now() + Duration::from_secs(240);
                while stats.is_running() {
                    tick.tick().await;
                    if !stats.is_running() {
                        break;
                    }
                    if Instant::now() >= refresh {
                        s.refresh(addr).await?;
                        refresh = Instant::now() + Duration::from_secs(240);
                    }
                    s.send(&data).await?;
                    stats.sent.fetch_add(1, Ordering::Relaxed);
                    stats
                        .bytes_out
                        .fetch_add((payload + 4) as u64, Ordering::Relaxed);
                    let (n, _) =
                        tokio::time::timeout(Duration::from_secs(3), peer.recv_from(&mut buf))
                            .await
                            .map_err(|_| "SCTP relay receive timeout")?
                            .map_err(|e| e.to_string())?;
                    if buf[..n] != data {
                        return Err("SCTP load payload mismatch".into());
                    }
                    stats.recv.fetch_add(1, Ordering::Relaxed);
                    stats.bytes_in.fetch_add(n as u64, Ordering::Relaxed);
                }
                s.close().await
            }
            .await;
            if let Err(e) = outcome {
                eprintln!("SCTP load failed: {e}");
                stats.errs.fetch_add(1, Ordering::Relaxed);
            }
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
    for t in tasks {
        if t.await.is_err() {
            stats.errs.fetch_add(1, Ordering::Relaxed);
        }
    }
    stats
}
