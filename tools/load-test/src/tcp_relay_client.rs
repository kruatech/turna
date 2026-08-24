//! TURN TCP relay (RFC 6062) — a client, so the feature can leave its production
//! gate.
//!
//! # Why this exists
//!
//! `[turn.tcp_relay]` is refused under `production = true` for want of interop
//! evidence, not for want of code: the server side implements `CONNECT`,
//! `ConnectionBind`, ownership checks and the pipelined-bytes handling. Nothing
//! could exercise it, because no client in this repo speaks RFC 6062 and browsers
//! do not either.
//!
//! # The case that matters most
//!
//! RFC 6062 §5.4: after the `ConnectionBind` success response, the connection
//! becomes a raw data channel. A client is entitled to send application bytes
//! **immediately**, in the same TCP segment as the request — and a server that reads
//! its response buffer and then starts a fresh read will lose them. `tcp_tls.rs`
//! carries a `prebuffer` in its detach path specifically to preserve those bytes.
//! That code has never been exercised by a real client, so `pipelined` below sends
//! exactly that shape: `ConnectionBind` and payload in one write.
//!
//! # It runs over TURNS, not plain TCP
//!
//! turna has no plain-TCP TURN listener — the only TCP ingress is TURNS, and the
//! RFC 6062 connection state is adopted by the TLS bridge (`relay::handler`, on
//! `Action::RegisterTcpListener`). So both connections here are TLS on the TURNS
//! port, and pointing this at 3478 gets `Connection refused`.
//!
//! # Shape of the exchange
//!
//! ```text
//!   control conn:  Allocate(RequestedTransport=TCP) → CreatePermission → Connect(peer)
//!                  ← Connect success carrying CONNECTION-ID
//!   data conn:     (new TCP connection) ConnectionBind(CONNECTION-ID)
//!                  ← success, then raw bytes in both directions
//! ```

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::stream_common::{next_stream_message, AcceptAnyServerCert};
use crate::turn_client::{
    error_code, get_nonce, get_realm, get_relayed_addr, is_success, long_term_key, Creds, Msg,
    M_ALLOCATE, M_CREATE_PERM,
};

/// RFC 6062 method codes. Kept here rather than in `turn_client` because nothing
/// else in this tool speaks them.
pub const M_CONNECT: u16 = 0x000A;
pub const M_CONNECTION_BIND: u16 = 0x000B;

/// `REQUESTED-TRANSPORT` with the TCP protocol number (RFC 6062 §4.1), as opposed
/// to the UDP 17 the other modes send.
const TRANSPORT_TCP: u8 = 6;

type Tls = tokio_rustls::client::TlsStream<TcpStream>;

/// One TURN control connection over TURNS.
struct Control {
    stream: Tls,
    buf: Vec<u8>,
    user: String,
    realm: String,
    nonce: Vec<u8>,
    key: [u8; 16],
    rtt_ms: u64,
}

impl Control {
    async fn request(&mut self, pkt: &[u8]) -> Result<Vec<u8>, String> {
        self.stream
            .write_all(pkt)
            .await
            .map_err(|e| format!("control write: {e}"))?;
        let deadline = Instant::now() + Duration::from_millis(self.rtt_ms.max(2000));
        loop {
            if let Some(msg) = next_stream_message(&mut self.buf) {
                return Ok(msg);
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err("timeout waiting for a control response".into());
            }
            let mut chunk = [0u8; 4096];
            match tokio::time::timeout(left, self.stream.read(&mut chunk)).await {
                Ok(Ok(0)) => return Err("server closed the control connection".into()),
                Ok(Ok(n)) => self.buf.extend_from_slice(&chunk[..n]),
                Ok(Err(e)) => return Err(format!("control read: {e}")),
                Err(_) => return Err("timeout waiting for a control response".into()),
            }
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
}

/// Open one TLS connection to the TURNS port.
async fn tls_connect(server: SocketAddr, server_name: &str) -> Result<Tls, String> {
    let provider = AcceptAnyServerCert::provider();
    let cfg = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("tls versions: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert(provider)))
        .with_no_client_auth();
    let name = rustls::pki_types::ServerName::try_from(server_name.to_string())
        .map_err(|e| format!("bad server name: {e}"))?;
    let tcp = TcpStream::connect(server)
        .await
        .map_err(|e| format!("connect {server}: {e}"))?;
    let _ = tcp.set_nodelay(true);
    tokio_rustls::TlsConnector::from(Arc::new(cfg))
        .connect(name, tcp)
        .await
        .map_err(|e| {
            format!(
                "TLS handshake failed: {e}. RFC 6062 runs over TURNS here, so --server                  must be the TURNS port (5349 by convention), not 3478."
            )
        })
}

/// Add `REQUESTED-TRANSPORT` for TCP. The UDP helper in `turn_client` hardcodes 17.
fn add_requested_transport_tcp(m: &mut Msg) {
    m.add(0x0019, &[TRANSPORT_TCP, 0, 0, 0]);
}

fn get_connection_id(resp: &[u8]) -> Option<u32> {
    // CONNECTION-ID is 0x002A, a 4-byte value.
    let mut off = 20usize;
    while off + 4 <= resp.len() {
        let t = u16::from_be_bytes([resp[off], resp[off + 1]]);
        let l = u16::from_be_bytes([resp[off + 2], resp[off + 3]]) as usize;
        let v = resp.get(off + 4..off + 4 + l)?;
        if t == 0x002A && l == 4 {
            return Some(u32::from_be_bytes([v[0], v[1], v[2], v[3]]));
        }
        off += 4 + l + ((4 - (l % 4)) % 4);
    }
    None
}

/// Full RFC 6062 exercise. Returns a step-by-step log.
///
/// `pipelined` controls the shape of the ConnectionBind write: with it, the request
/// and the first application bytes go out in a single write, which is the case the
/// server's detach prebuffer exists for and the one most likely to be broken.
pub async fn tcp_relay_check(
    server: SocketAddr,
    server_name: &str,
    creds: &Creds,
    rtt_ms: u64,
    pipelined: bool,
) -> Result<Vec<String>, String> {
    let mut log = Vec::new();

    // A local TCP listener stands in for the peer: the relay will connect *to* it,
    // which is what CONNECT means. Port 0 so the kernel picks a free one — and
    // deliberately loopback, so a local test needs `allow_loopback_peers`.
    let peer_listener = TcpListener::bind(crate::turn_client::peer_bind_addr(false))
        .await
        .map_err(|e| format!("peer listener bind: {e}"))?;
    let peer_addr = peer_listener
        .local_addr()
        .map_err(|e| format!("peer local_addr: {e}"))?;

    // ── control connection ──
    let stream = tls_connect(server, server_name).await?;
    let mut ctl = Control {
        stream,
        buf: Vec::new(),
        user: String::new(),
        realm: String::new(),
        nonce: Vec::new(),
        key: [0u8; 16],
        rtt_ms,
    };

    let mut m = Msg::request(M_ALLOCATE);
    add_requested_transport_tcp(&mut m);
    m.add_lifetime(600);
    let resp = ctl.request(&m.encode()).await?;
    if error_code(&resp) != Some(401) {
        return Err(format!(
            "expected a 401 challenge, got {:?}. A 442 here means the server refuses \
             REQUESTED-TRANSPORT = TCP — check that [turn.tcp_relay] enabled = true \
             and that production = false (RFC 6062 is gated in production).",
            error_code(&resp)
        ));
    }
    ctl.realm = get_realm(&resp).ok_or("401 without REALM")?;
    ctl.nonce = get_nonce(&resp).ok_or("401 without NONCE")?;
    let (user, pass) = creds.materialize();
    ctl.key = long_term_key(&user, &ctl.realm, &pass);
    ctl.user = user;

    let pkt = ctl.authed(M_ALLOCATE, |m| {
        add_requested_transport_tcp(m);
        m.add_lifetime(600);
    });
    let txid: [u8; 12] = pkt[8..20].try_into().expect("txid");
    let resp = ctl.request(&pkt).await?;
    if !is_success(&resp) {
        return Err(format!("TCP Allocate rejected: {:?}", error_code(&resp)));
    }
    let relayed = get_relayed_addr(&resp, &txid).ok_or("TCP Allocate without a relayed address")?;
    log.push(format!("TCP Allocate ok, relayed address {relayed}"));

    // ── permission, then CONNECT ──
    let pkt = ctl.authed(M_CREATE_PERM, |m| m.add_xor_peer(peer_addr));
    let resp = ctl.request(&pkt).await?;
    if !is_success(&resp) {
        return Err(format!(
            "CreatePermission rejected: {:?}. If this is 403, the server forbids \
             loopback peers — set [turn.peer_filter] allow_loopback_peers = true.",
            error_code(&resp)
        ));
    }

    let pkt = ctl.authed(M_CONNECT, |m| m.add_xor_peer(peer_addr));
    // The relay dials the peer while this request is in flight, so accept
    // concurrently rather than after: a sequential wait can deadlock on a fast relay.
    let accept = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(5), peer_listener.accept()).await
    });
    let resp = ctl.request(&pkt).await?;
    if !is_success(&resp) {
        return Err(format!(
            "Connect rejected: {:?}. 447 means the relay could not reach the peer.",
            error_code(&resp)
        ));
    }
    let cid = get_connection_id(&resp).ok_or("Connect success without CONNECTION-ID")?;
    log.push(format!("Connect ok, CONNECTION-ID {cid:#010x}"));

    let (mut peer_conn, from) = accept
        .await
        .map_err(|e| format!("accept task: {e}"))?
        .map_err(|_| "the relay never dialled the peer within 5 s".to_string())?
        .map_err(|e| format!("peer accept: {e}"))?;
    log.push(format!("relay dialled the peer from {from}"));

    // ── data connection ──
    let data = tls_connect(server, server_name).await?;
    let mut data_conn = Control {
        stream: data,
        buf: Vec::new(),
        // Same credentials as the control connection — RFC 6062 §4.3 requires it, and
        // the server checks that this CONNECTION-ID belongs to them. The realm and
        // nonce are left empty on purpose: they are per-connection and come from this
        // connection's own 401 below.
        user: ctl.user.clone(),
        realm: String::new(),
        nonce: Vec::new(),
        key: ctl.key,
        rtt_ms,
    };

    // The data connection needs its OWN 401 exchange. The nonce is bound to the
    // client's 5-tuple, and this is a new connection from a different source port, so
    // reusing the control connection's nonce earns a `438 Stale Nonce` — which is the
    // server being right. Credentials are the same; only the nonce is per-connection.
    let probe = {
        let mut m = Msg::request(M_CONNECTION_BIND);
        m.add(0x002A, &cid.to_be_bytes());
        m.encode()
    };
    let resp = data_conn.request(&probe).await?;
    match error_code(&resp) {
        Some(401) => {
            data_conn.realm = get_realm(&resp).ok_or("401 without REALM on the data connection")?;
            data_conn.nonce = get_nonce(&resp).ok_or("401 without NONCE on the data connection")?;
            log.push("data connection challenged with its own nonce".into());
        }
        // A server that binds without a challenge is unusual but not wrong here; the
        // authenticated attempt below still has to succeed.
        None if is_success(&resp) => log.push("data connection bound without a challenge".into()),
        other => {
            return Err(format!(
                "unauthenticated ConnectionBind answered {other:?}; expected a 401 \
                 challenge"
            ))
        }
    }

    let bind_pkt = data_conn.authed(M_CONNECTION_BIND, |m| m.add(0x002A, &cid.to_be_bytes()));

    const PAYLOAD: &[u8] = b"pipelined-after-connectionbind";
    if pipelined {
        // The case the server's detach prebuffer exists for: request and payload in
        // ONE write, so they land in the same segment and the server must not lose
        // the tail when it stops parsing STUN.
        let mut one = bind_pkt.clone();
        one.extend_from_slice(PAYLOAD);
        data_conn
            .stream
            .write_all(&one)
            .await
            .map_err(|e| format!("pipelined ConnectionBind write: {e}"))?;
    } else {
        data_conn
            .stream
            .write_all(&bind_pkt)
            .await
            .map_err(|e| format!("ConnectionBind write: {e}"))?;
    }

    // Read the ConnectionBind response off the data connection.
    let deadline = Instant::now() + Duration::from_millis(rtt_ms.max(2000));
    let resp = loop {
        if let Some(msg) = next_stream_message(&mut data_conn.buf) {
            break msg;
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err("timeout waiting for the ConnectionBind response".into());
        }
        let mut chunk = [0u8; 4096];
        match tokio::time::timeout(left, data_conn.stream.read(&mut chunk)).await {
            Ok(Ok(0)) => return Err("server closed the data connection".into()),
            Ok(Ok(n)) => data_conn.buf.extend_from_slice(&chunk[..n]),
            Ok(Err(e)) => return Err(format!("data read: {e}")),
            Err(_) => return Err("timeout waiting for the ConnectionBind response".into()),
        }
    };
    if !is_success(&resp) {
        return Err(format!(
            "ConnectionBind rejected: {:?}. 400 usually means the CONNECTION-ID is \
             not owned by these credentials — that ownership check is deliberate.",
            error_code(&resp)
        ));
    }
    log.push(format!(
        "ConnectionBind ok ({})",
        if pipelined {
            "payload pipelined in the same write"
        } else {
            "payload sent separately"
        }
    ));

    if !pipelined {
        data_conn
            .stream
            .write_all(PAYLOAD)
            .await
            .map_err(|e| format!("payload write: {e}"))?;
    }

    // ── client → relay → peer ──
    let mut got = vec![0u8; PAYLOAD.len()];
    match tokio::time::timeout(Duration::from_secs(5), peer_conn.read_exact(&mut got)).await {
        Ok(Ok(_)) if got == PAYLOAD => log.push(format!(
            "client → relay → peer: {} bytes arrived intact{}",
            got.len(),
            if pipelined {
                " — the pipelined bytes were NOT lost when the server stopped parsing STUN"
            } else {
                ""
            }
        )),
        Ok(Ok(_)) => {
            return Err(format!(
                "peer received {} bytes but they differ from what was sent: {:?}",
                got.len(),
                String::from_utf8_lossy(&got)
            ))
        }
        Ok(Err(e)) => return Err(format!("peer read: {e}")),
        Err(_) => {
            return Err(if pipelined {
                "the peer never received the pipelined bytes. They were written in the \
                 same segment as ConnectionBind, so the server dropped whatever \
                 followed the request — this is exactly the case the detach prebuffer \
                 exists to handle."
                    .to_string()
            } else {
                "the peer never received the payload; the data connection was bound \
                 but forwards nothing"
                    .to_string()
            })
        }
    }

    // ── peer → relay → client ──
    const BACK: &[u8] = b"reply-from-peer";
    peer_conn
        .write_all(BACK)
        .await
        .map_err(|e| format!("peer write: {e}"))?;
    let mut back = vec![0u8; BACK.len()];
    match tokio::time::timeout(
        Duration::from_secs(5),
        data_conn.stream.read_exact(&mut back),
    )
    .await
    {
        Ok(Ok(_)) if back == BACK => {
            log.push("peer → relay → client: bytes returned on the data connection".into())
        }
        Ok(Ok(_)) => return Err("the reply came back altered".into()),
        Ok(Err(e)) => return Err(format!("data read: {e}")),
        Err(_) => return Err("the peer's reply never reached the client".into()),
    }

    Ok(log)
}
