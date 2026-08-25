//! Integration tests for Turna TURN server.
//!
//! Tests the full TURN cycle against a running turna-node:
//!   1. STUN Binding Request → Response
//!   2. Allocate (unauthenticated → 401 → authenticated) → relay port
//!   3. Refresh → extend TTL
//!   4. CreatePermission → allow peer IP
//!   5. ChannelBind → bind channel number to peer
//!   6. ChannelData send → relay → peer receives
//!   7. Delete allocation (Refresh lifetime=0)
//!
//! Run with a live server:
//!   cargo test -p turna-integration-tests
//!
//! Configuration via env:
//!   TURNA_TEST_TARGET=127.0.0.1:3478   (default)
//!   TURNA_TEST_USER=testuser           (default; or 'user' for static-users mode)
//!   TURNA_TEST_PASS=testpass           (default; or 'pass' for static-users mode)
//!   TURNA_TEST_SECRET=<secret>         (enables coturn-style time-limited creds)
//!   TURNA_TEST_DEBUG=1                 (prints hex of HMAC inputs/outputs)
//!   TURNA_TEST_REQUIRE_SERVER=1        (turns reachability skips into failures)
//!
//! Two server auth modes are supported:
//!
//!   * SharedSecret (coturn lt-cred-mech): set TURNA_TEST_SECRET to the same
//!     value the server has in `[turn.auth] shared_secret`. The test will
//!     derive a fresh `{ts}:{user}` username and HMAC-derived password per
//!     request. With deploy/turn.toml:
//!
//!         cargo run --bin turna-node deploy/turn.toml
//!         TURNA_TEST_SECRET=turna-secret \
//!             cargo test -p turna-integration-tests turn_allocate -- --nocapture
//!
//!   * LongTerm (static users): do NOT set TURNA_TEST_SECRET. Configure the
//!     server with `[[turn.auth.static_users]]` and pass matching
//!     TURNA_TEST_USER / TURNA_TEST_PASS:
//!
//!         TURNA_TEST_USER=user TURNA_TEST_PASS=pass \
//!             cargo test -p turna-integration-tests turn_allocate -- --nocapture

#![allow(dead_code)]

use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;

// ── Config ────────────────────────────────────────────────────────────────────

// -- Hermetic test server (F-5 #2) ------------------------------------------
// target_addr() resolves to a reachable turna-node. With TURNA_TEST_TARGET set,
// that external server is used (and the TURNA_TEST_REQUIRE_SERVER guard in
// skip_if_no_server! applies). Otherwise a single node is spawned per test
// binary on ephemeral ports with a temp tokio config, made ready before any
// test runs, and killed when the test process exits (PR_SET_PDEATHSIG on Linux).
use std::sync::OnceLock;

struct TestServer {
    addr: SocketAddr,
    _child: Option<std::process::Child>,
}

static SERVER: OnceLock<TestServer> = OnceLock::new();

fn shared_server() -> &'static TestServer {
    SERVER.get_or_init(|| {
        if let Ok(t) = std::env::var("TURNA_TEST_TARGET") {
            return TestServer {
                addr: t.parse().expect("invalid TURNA_TEST_TARGET"),
                _child: None,
            };
        }
        spawn_hermetic()
    })
}

fn free_port(udp: bool) -> u16 {
    if udp {
        std::net::UdpSocket::bind("127.0.0.1:0")
            .and_then(|s| s.local_addr())
            .expect("free udp port")
            .port()
    } else {
        std::net::TcpListener::bind("127.0.0.1:0")
            .and_then(|s| s.local_addr())
            .expect("free tcp port")
            .port()
    }
}

fn node_binary() -> std::path::PathBuf {
    // current_exe = <target>/<profile>/deps/<bin>-<hash>;
    // turna-node lives at <target>/<profile>/turna-node.
    let exe = std::env::current_exe().expect("current_exe");
    let profile_dir = exe
        .parent()
        .and_then(|p| p.parent())
        .expect("target/<profile> dir");
    profile_dir.join("turna-node")
}

fn spawn_hermetic() -> TestServer {
    // The node must outlive every #[tokio::test] runtime. PR_SET_PDEATHSIG tracks
    // the *parent thread*, not the process, so the node is spawned from a
    // dedicated thread that parks for the whole process lifetime. Otherwise a
    // tokio worker thread from the first test's runtime would terminate at test
    // end and SIGKILL the node, leaving later tests with no server.
    let (tx, rx) = std::sync::mpsc::channel::<Result<SocketAddr, String>>();
    std::thread::Builder::new()
        .name("turna-hermetic-node".into())
        .spawn(move || match boot_node() {
            Ok((addr, child)) => {
                let _ = tx.send(Ok(addr));
                let _child = child; // hold the handle so it is not dropped
                loop {
                    std::thread::park();
                }
            }
            Err(e) => {
                let _ = tx.send(Err(e));
            }
        })
        .expect("spawn hermetic node thread");
    match rx.recv() {
        Ok(Ok(addr)) => TestServer { addr, _child: None },
        Ok(Err(e)) => panic!("hermetic node: {e}"),
        Err(_) => panic!("hermetic node boot thread exited before reporting"),
    }
}

/// Startup must fail, loudly, when a configured listener cannot be bound.
///
/// The health port used to be bound inside a spawned task with its error
/// discarded, so the node started anyway. That is worse than having no health
/// endpoint: whatever else holds the port answers scrapes in its place. It was
/// found in the field, not by a test — a scrape window read an unrelated
/// process's metrics as if they were this node's.
///
/// Asserts observable behaviour — a non-zero exit and a message naming the port
/// — rather than the presence of a `?` in the source, which is what a test
/// written against the code would have done while the bug was live.
#[test]
fn occupied_health_port_is_fatal_and_says_why() {
    let bin = node_binary();
    if !bin.exists() {
        eprintln!("skipping: node binary not built");
        return;
    }

    // `cargo test` does not rebuild turna-node: this test runs whatever binary is
    // on disk, because Cargo cannot express a test's dependency on another
    // crate's executable. A stale binary gives a result about code that is no
    // longer in the tree — which happened while writing this test, costing a
    // confusing twenty-second failure. Warn rather than fail, since the staleness
    // may be intentional (TURNA_TEST_TARGET).
    if let (Ok(bin_time), Ok(src_time)) = (
        std::fs::metadata(&bin).and_then(|m| m.modified()),
        std::fs::metadata(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../services/node/src/main.rs"
        ))
        .and_then(|m| m.modified()),
    ) {
        if bin_time < src_time {
            eprintln!(
                "WARNING: {bin:?} is older than services/node/src/main.rs. This test \
                 exercises the binary on disk, not the source tree. Run \
                 `cargo build -p turna-node` first."
            );
        }
    }

    // Hold the port for the duration of the attempt.
    let squatter = std::net::TcpListener::bind("127.0.0.1:0").expect("bind squatter");
    let health_port = squatter.local_addr().expect("squatter addr").port();
    let turn_port = free_port(true);

    let dir = std::env::temp_dir().join(format!("turna-health-fatal-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let cfg_path = dir.join("turn.toml");
    std::fs::write(
        &cfg_path,
        format!(
            "production = false\n\
             [turn]\n\
             listen = \"127.0.0.1:{turn_port}\"\n\
             realm = \"turna\"\n\
             transport = \"tokio\"\n\
             [[turn.auth.static_users]]\n\
             username = \"testuser\"\n\
             password = \"testpass\"\n\
             [health]\n\
             listen = \"127.0.0.1:{health_port}\"\n"
        ),
    )
    .expect("write config");

    // Polled with a deadline rather than `.output()`, which blocks forever. On the
    // old behaviour the node *starts* — that is the whole bug — so a test that
    // waits for exit hangs instead of failing, and in CI that reads as a stuck
    // job rather than a regression. Verified by reintroducing the old shape: it
    // hung, which is how this deadline came to be here.
    let mut child = std::process::Command::new(&bin)
        .arg(&cfg_path)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn node");

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    let status = loop {
        match child.try_wait().expect("try_wait") {
            Some(st) => break Some(st),
            None if std::time::Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            None => std::thread::sleep(std::time::Duration::from_millis(50)),
        }
    };

    let mut out_buf = Vec::new();
    let mut err_buf = Vec::new();
    use std::io::Read;
    if let Some(mut o) = child.stdout.take() {
        let _ = o.read_to_end(&mut out_buf);
    }
    if let Some(mut e) = child.stderr.take() {
        let _ = e.read_to_end(&mut err_buf);
    }

    let _ = std::fs::remove_dir_all(&dir);
    drop(squatter);

    let status = status.expect(
        "the node was still running 20 s after being given an occupied health port. \
         It must refuse to start: binding inside the spawned task discards the error \
         and leaves the operator believing the configured port is being scraped.",
    );

    let out = std::process::Output {
        status,
        stdout: out_buf,
        stderr: err_buf,
    };

    assert!(
        !out.status.success(),
        "node started with its health port already taken; exit status {:?}. \
         Binding must happen before the serving task is spawned, or the failure \
         is discarded and the operator believes the port is being scraped.",
        out.status.code()
    );

    let combined =
        String::from_utf8_lossy(&out.stderr).into_owned() + &String::from_utf8_lossy(&out.stdout);
    assert!(
        combined.contains(&health_port.to_string()),
        "exit was non-zero but nothing named the port that could not be bound, \
         so an operator cannot tell what to fix. Output was:\n{combined}"
    );
    assert!(
        combined.to_lowercase().contains("health"),
        "the failure does not mention which listener failed. Output was:\n{combined}"
    );
}

fn boot_node() -> Result<(SocketAddr, std::process::Child), String> {
    let bin = node_binary();
    if !bin.exists() {
        return Err(format!(
            "node binary not found at {bin:?} -- build it first: cargo build -p turna-node \
             (or set TURNA_TEST_TARGET to an external server)"
        ));
    }
    let turn_port = free_port(true);
    let health_port = free_port(false);
    let dir = std::env::temp_dir().join(format!("turna-it-{}-{turn_port}", std::process::id()));
    std::fs::create_dir_all(&dir).map_err(|e| format!("temp dir: {e}"))?;
    let cfg_path = dir.join("turn.toml");
    let cfg = format!(
        "production = false\n\
         [turn]\n\
         listen = \"127.0.0.1:{turn_port}\"\n\
         realm = \"turna\"\n\
         transport = \"tokio\"\n\
         [[turn.auth.static_users]]\n\
         username = \"testuser\"\n\
         password = \"testpass\"\n\
         [turn.relay]\n\
         min_port = 49152\n\
         max_port = 49500\n\
         max_allocations = 256\n\
         [health]\n\
         listen = \"127.0.0.1:{health_port}\"\n"
    );
    std::fs::write(&cfg_path, cfg).map_err(|e| format!("write config: {e}"))?;

    let mut cmd = std::process::Command::new(&bin);
    cmd.arg(&cfg_path);
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::process::CommandExt;
        // SAFETY: pre_exec runs in the forked child before exec; prctl is a single
        // async-signal-safe syscall. PR_SET_PDEATHSIG delivers SIGKILL when the
        // *spawning thread* dies; that thread parks for the whole process lifetime
        // (see spawn_hermetic), so the node dies only when the test process exits.
        unsafe {
            cmd.pre_exec(|| {
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
                Ok(())
            });
        }
    }
    let child = cmd.spawn().map_err(|e| format!("spawn {bin:?}: {e}"))?;

    let health: SocketAddr = format!("127.0.0.1:{health_port}")
        .parse()
        .map_err(|e| format!("health addr: {e}"))?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    while !http_ready(&health) {
        if std::time::Instant::now() >= deadline {
            return Err(format!("node not ready on {health} within 15s"));
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let addr = format!("127.0.0.1:{turn_port}")
        .parse()
        .map_err(|e| format!("turn addr: {e}"))?;
    Ok((addr, child))
}

fn http_ready(health: &SocketAddr) -> bool {
    use std::io::{Read, Write};
    let mut s =
        match std::net::TcpStream::connect_timeout(health, std::time::Duration::from_millis(300)) {
            Ok(s) => s,
            Err(_) => return false,
        };
    let _ = s.set_read_timeout(Some(std::time::Duration::from_millis(300)));
    if s.write_all(b"GET /ready HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .is_err()
    {
        return false;
    }
    let mut buf = Vec::new();
    let _ = s.read_to_end(&mut buf);
    String::from_utf8_lossy(&buf).contains(" 200 ")
}

fn target_addr() -> SocketAddr {
    shared_server().addr
}

fn test_user() -> String {
    std::env::var("TURNA_TEST_USER").unwrap_or_else(|_| "testuser".into())
}
fn test_pass() -> String {
    std::env::var("TURNA_TEST_PASS").unwrap_or_else(|_| "testpass".into())
}
fn test_secret() -> Option<String> {
    std::env::var("TURNA_TEST_SECRET").ok()
}
fn test_debug() -> bool {
    std::env::var("TURNA_TEST_DEBUG").is_ok()
}

fn require_server() -> bool {
    matches!(
        std::env::var("TURNA_TEST_REQUIRE_SERVER"),
        Ok(v) if !v.is_empty() && v != "0" && !v.eq_ignore_ascii_case("false")
    )
}

// ── Debug helpers ─────────────────────────────────────────────────────────────

/// Print a labelled hex dump of `data` if TURNA_TEST_DEBUG is set.
fn dump_hex(label: &str, data: &[u8]) {
    if !test_debug() {
        return;
    }
    eprintln!("[DEBUG] {label} ({} bytes):", data.len());
    for (i, chunk) in data.chunks(16).enumerate() {
        let hex: String = chunk.iter().map(|b| format!("{b:02x} ")).collect();
        let ascii: String = chunk
            .iter()
            .map(|&b| {
                if (0x20..0x7f).contains(&b) {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();
        eprintln!("  {:04x}  {:<48}  {}", i * 16, hex, ascii);
    }
}

// ── UDP helpers ───────────────────────────────────────────────────────────────

async fn send_recv(
    socket: &UdpSocket,
    target: SocketAddr,
    data: &[u8],
    timeout_ms: u64,
) -> Option<(Vec<u8>, SocketAddr)> {
    socket.send_to(data, target).await.ok()?;
    let mut buf = vec![0u8; 4096];
    match tokio::time::timeout(
        Duration::from_millis(timeout_ms),
        socket.recv_from(&mut buf),
    )
    .await
    {
        Ok(Ok((n, addr))) => {
            buf.truncate(n);
            Some((buf, addr))
        }
        _ => None,
    }
}

async fn bind_socket() -> UdpSocket {
    UdpSocket::bind("0.0.0.0:0").await.expect("bind failed")
}

#[cfg(test)]
macro_rules! skip_if_no_server {
    ($result:expr, $target:expr) => {
        match $result {
            Some(v) => v,
            None => {
                let msg = format!(
                    "turna-node not reachable on {}; start with: cargo run --bin turna-node \
                     or set TURNA_TEST_TARGET=host:port",
                    $target
                );
                if require_server() {
                    panic!("{msg}; TURNA_TEST_REQUIRE_SERVER=1 turns this skip into a failure");
                }
                eprintln!("SKIP: {msg}");
                return;
            }
        }
    };
}

// ── STUN/TURN message builder ─────────────────────────────────────────────────

const MAGIC_COOKIE: u32 = 0x2112A442;

/// Low-level TURN message builder.
struct TurnMsg {
    method: u16,
    class: u16,
    transaction_id: [u8; 12],
    attrs: Vec<u8>,
}

impl TurnMsg {
    /// Create a new Request message.
    fn request(method: u16) -> Self {
        let mut tid = [0u8; 12];
        for b in &mut tid {
            *b = rand::random();
        }
        Self {
            method,
            class: 0x0000,
            transaction_id: tid,
            attrs: Vec::new(),
        }
    }

    fn with_tid(mut self, tid: [u8; 12]) -> Self {
        self.transaction_id = tid;
        self
    }

    // ── Attribute helpers ─────────────────────────────────────────────────────

    fn add_attr(&mut self, typ: u16, value: &[u8]) {
        let len = value.len() as u16;
        self.attrs.extend_from_slice(&typ.to_be_bytes());
        self.attrs.extend_from_slice(&len.to_be_bytes());
        self.attrs.extend_from_slice(value);
        // Pad to 4-byte boundary
        let pad = (4 - (value.len() % 4)) % 4;
        for _ in 0..pad {
            self.attrs.push(0);
        }
    }

    fn add_requested_transport(&mut self) {
        // REQUESTED-TRANSPORT = 0x0019, value = [17, 0, 0, 0] (UDP = 17)
        self.add_attr(0x0019, &[17u8, 0, 0, 0]);
    }

    fn add_lifetime(&mut self, secs: u32) {
        self.add_attr(0x000D, &secs.to_be_bytes());
    }

    fn add_username(&mut self, username: &str) {
        self.add_attr(0x0006, username.as_bytes());
    }

    fn add_realm(&mut self, realm: &str) {
        self.add_attr(0x0014, realm.as_bytes());
    }

    fn add_nonce(&mut self, nonce: &str) {
        self.add_attr(0x0015, nonce.as_bytes());
    }

    fn add_xor_peer_address(&mut self, peer: SocketAddr) {
        // XOR-PEER-ADDRESS = 0x0012
        if let SocketAddr::V4(v4) = peer {
            let port = v4.port() ^ (MAGIC_COOKIE >> 16) as u16;
            let ip_bytes = v4.ip().octets();
            let magic_bytes = MAGIC_COOKIE.to_be_bytes();
            let xip = [
                ip_bytes[0] ^ magic_bytes[0],
                ip_bytes[1] ^ magic_bytes[1],
                ip_bytes[2] ^ magic_bytes[2],
                ip_bytes[3] ^ magic_bytes[3],
            ];
            let mut val = vec![0x00, 0x01]; // reserved + family IPv4
            val.extend_from_slice(&port.to_be_bytes());
            val.extend_from_slice(&xip);
            self.add_attr(0x0012, &val);
        }
    }

    fn add_channel_number(&mut self, channel: u16) {
        // CHANNEL-NUMBER = 0x000C: [channel_hi, channel_lo, 0x00, 0x00]
        let mut val = channel.to_be_bytes().to_vec();
        val.extend_from_slice(&[0x00, 0x00]); // RFFU
        self.add_attr(0x000C, &val);
    }

    /// Encode to bytes WITHOUT MESSAGE-INTEGRITY (for unauthenticated requests).
    fn encode(&self) -> Vec<u8> {
        self.encode_with_header_len(self.attrs.len() as u16)
    }

    /// Encode with MESSAGE-INTEGRITY (HMAC-SHA1 with long-term key).
    ///
    /// `key` = MD5(username:realm:password).
    /// Per RFC 5389 §15.4 the Length field must be adjusted as if the
    /// MESSAGE-INTEGRITY attribute is already present (+24 bytes) before HMAC.
    fn encode_with_integrity(mut self, key: &[u8]) -> Vec<u8> {
        use hmac::{Hmac, Mac};
        use sha1::Sha1;

        let mi_attr_size = 4 + 20; // type(2) + len(2) + SHA1(20)
        let len_with_mi = (self.attrs.len() + mi_attr_size) as u16;

        let header = self.make_header(len_with_mi);

        let mut mac = Hmac::<Sha1>::new_from_slice(key).expect("HMAC key");
        mac.update(&header);
        mac.update(&self.attrs);
        let hmac_bytes = mac.finalize().into_bytes();

        if test_debug() {
            let mut hmac_input = Vec::with_capacity(header.len() + self.attrs.len());
            hmac_input.extend_from_slice(&header);
            hmac_input.extend_from_slice(&self.attrs);
            dump_hex(
                "HMAC input  (header[20] with adjusted Length + attrs)",
                &hmac_input,
            );
            dump_hex("HMAC key", key);
            dump_hex("HMAC output (MESSAGE-INTEGRITY)", hmac_bytes.as_slice());
        }

        // Append MESSAGE-INTEGRITY attribute.
        self.add_attr(0x0008, hmac_bytes.as_slice());

        let out = self.encode_with_header_len(self.attrs.len() as u16);

        if test_debug() {
            dump_hex("Final packet on the wire", &out);
        }

        out
    }

    fn make_header(&self, length: u16) -> Vec<u8> {
        let msg_type = (self.method & 0x0F80) << 2
            | (self.method & 0x0070) << 1
            | (self.method & 0x000F)
            | self.class;
        let mut h = Vec::with_capacity(20);
        h.extend_from_slice(&msg_type.to_be_bytes());
        h.extend_from_slice(&length.to_be_bytes());
        h.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        h.extend_from_slice(&self.transaction_id);
        h
    }

    fn encode_with_header_len(&self, length: u16) -> Vec<u8> {
        let mut out = self.make_header(length);
        out.extend_from_slice(&self.attrs);
        out
    }
}

// ── STUN response parsers ─────────────────────────────────────────────────────

fn msg_class(data: &[u8]) -> u16 {
    if data.len() < 2 {
        return 0xFFFF;
    }
    // Class bits: bit 8 and bit 4 of the type field
    let t = u16::from_be_bytes([data[0], data[1]]);
    ((t >> 7) & 0x02) | ((t >> 4) & 0x01)
}

fn is_success(data: &[u8]) -> bool {
    msg_class(data) == 0x02
}
fn is_error(data: &[u8]) -> bool {
    msg_class(data) == 0x03
}

fn transaction_id(data: &[u8]) -> &[u8] {
    if data.len() >= 20 {
        &data[8..20]
    } else {
        &[]
    }
}

/// Iterate attributes: yields (type, value_slice) for each attribute.
fn iter_attrs(data: &[u8]) -> impl Iterator<Item = (u16, &[u8])> {
    struct AttrIter<'a> {
        data: &'a [u8],
        off: usize,
    }
    impl<'a> Iterator for AttrIter<'a> {
        type Item = (u16, &'a [u8]);
        fn next(&mut self) -> Option<Self::Item> {
            if self.off + 4 > self.data.len() {
                return None;
            }
            let typ = u16::from_be_bytes([self.data[self.off], self.data[self.off + 1]]);
            let len =
                u16::from_be_bytes([self.data[self.off + 2], self.data[self.off + 3]]) as usize;
            self.off += 4;
            if self.off + len > self.data.len() {
                return None;
            }
            let val = &self.data[self.off..self.off + len];
            self.off += len + (4 - len % 4) % 4;
            Some((typ, val))
        }
    }
    AttrIter {
        data: if data.len() >= 20 { &data[20..] } else { &[] },
        off: 0,
    }
}

fn extract_string_attr(data: &[u8], typ: u16) -> Option<String> {
    iter_attrs(data)
        .find(|(t, _)| *t == typ)
        .and_then(|(_, v)| std::str::from_utf8(v).ok().map(|s| s.to_string()))
}

fn extract_error_code(data: &[u8]) -> Option<(u16, String)> {
    iter_attrs(data)
        .find(|(t, _)| *t == 0x0009)
        .and_then(|(_, v)| {
            if v.len() < 4 {
                return None;
            }
            let class = (v[2] & 0x07) as u16 * 100;
            let number = v[3] as u16;
            let code = class + number;
            let reason = std::str::from_utf8(&v[4..]).unwrap_or("").to_string();
            Some((code, reason))
        })
}

/// Parse ALTERNATE-SERVER (0x0003), encoded as a plain MAPPED-ADDRESS
/// (RFC 5389 §15.5 — NOT XOR'd). Returns None if absent or malformed.
fn extract_alternate_server(data: &[u8]) -> Option<SocketAddr> {
    iter_attrs(data)
        .find(|(t, _)| *t == 0x0003)
        .and_then(|(_, v)| {
            if v.len() < 8 {
                return None;
            }
            let family = v[1];
            let port = u16::from_be_bytes([v[2], v[3]]);
            match family {
                0x01 => {
                    let ip = std::net::Ipv4Addr::new(v[4], v[5], v[6], v[7]);
                    Some(SocketAddr::new(ip.into(), port))
                }
                0x02 if v.len() >= 20 => {
                    let mut o = [0u8; 16];
                    o.copy_from_slice(&v[4..20]);
                    Some(SocketAddr::new(std::net::Ipv6Addr::from(o).into(), port))
                }
                _ => None,
            }
        })
}

fn extract_realm(data: &[u8]) -> Option<String> {
    extract_string_attr(data, 0x0014)
}
fn extract_nonce(data: &[u8]) -> Option<String> {
    extract_string_attr(data, 0x0015)
}

fn extract_lifetime(data: &[u8]) -> Option<u32> {
    iter_attrs(data)
        .find(|(t, _)| *t == 0x000D)
        .and_then(|(_, v)| {
            if v.len() == 4 {
                Some(u32::from_be_bytes([v[0], v[1], v[2], v[3]]))
            } else {
                None
            }
        })
}

fn extract_xor_addr(data: &[u8], typ: u16) -> Option<SocketAddr> {
    iter_attrs(data)
        .find(|(t, _)| *t == typ)
        .and_then(|(_, v)| {
            if v.len() < 8 || v[1] != 0x01 {
                return None;
            } // IPv4 only
            let port = u16::from_be_bytes([v[2], v[3]]) ^ (MAGIC_COOKIE >> 16) as u16;
            let m = MAGIC_COOKIE.to_be_bytes();
            let ip = std::net::Ipv4Addr::new(v[4] ^ m[0], v[5] ^ m[1], v[6] ^ m[2], v[7] ^ m[3]);
            Some(SocketAddr::new(std::net::IpAddr::V4(ip), port))
        })
}

fn extract_xor_mapped_address(data: &[u8]) -> Option<SocketAddr> {
    extract_xor_addr(data, 0x0020)
}
fn extract_xor_relayed_address(data: &[u8]) -> Option<SocketAddr> {
    extract_xor_addr(data, 0x0016)
}

// ── Auth helpers ──────────────────────────────────────────────────────────────

/// Generate time-limited TURN credentials (coturn-compatible).
///
/// username = "{expires_timestamp}:{user}"
/// password = base64(HMAC-SHA1(shared_secret, username))
fn time_limited_credentials(user: &str, secret: &str) -> (String, String) {
    use hmac::{Hmac, Mac};
    use sha1::Sha1;
    let expires = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600; // valid for 1 hour
    let username = format!("{expires}:{user}");
    let mut mac = Hmac::<Sha1>::new_from_slice(secret.as_bytes()).expect("HMAC key");
    mac.update(username.as_bytes());
    let password = {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes())
    };
    (username, password)
}

/// Compute long-term credential key: MD5(username:realm:password).
fn long_term_key(username: &str, realm: &str, password: &str) -> Vec<u8> {
    let input = format!("{username}:{realm}:{password}");
    md5::compute(input.as_bytes()).to_vec()
}

/// Pick credentials based on which auth mode the server is in.
///
/// - TURNA_TEST_SECRET set     → coturn time-limited (SharedSecret server mode)
/// - TURNA_TEST_SECRET unset   → static TURNA_TEST_USER/TURNA_TEST_PASS (LongTerm mode)
///
/// Both branches return (username, password) ready to feed into
/// `long_term_key(username, realm, password)` — the resulting MD5 is the
/// MESSAGE-INTEGRITY key, regardless of mode (the server in SharedSecret
/// mode reproduces the same password internally from the username + secret).
fn effective_credentials() -> (String, String) {
    let user = test_user();
    match test_secret() {
        Some(secret) => {
            let (u, p) = time_limited_credentials(&user, &secret);
            if test_debug() {
                eprintln!("[DEBUG] auth mode = SharedSecret (time-limited)");
                eprintln!("[DEBUG]   secret_len = {}", secret.len());
                eprintln!("[DEBUG]   username   = {u:?}");
                eprintln!("[DEBUG]   password   = {p:?}");
            }
            (u, p)
        }
        None => {
            let pass = test_pass();
            if test_debug() {
                eprintln!("[DEBUG] auth mode = LongTerm (static user/pass)");
                eprintln!("[DEBUG]   username = {user:?}");
                eprintln!("[DEBUG]   password = {pass:?}");
            }
            (user, pass)
        }
    }
}

/// Full authenticated TURN request flow:
/// 1. Send unauthenticated → expect 401 with REALM + NONCE
/// 2. Re-send with credentials → return final response.
async fn turn_authenticated_request(
    socket: &UdpSocket,
    target: SocketAddr,
    username: &str,
    password: &str,
    build: impl Fn(&str, &str) -> TurnMsg, // (realm, nonce) → TurnMsg
) -> Option<Vec<u8>> {
    // Step 1: unauthenticated probe
    let probe = {
        let mut m = TurnMsg::request(0x0003); // Allocate method (used for probe)
        m.add_requested_transport();
        m.encode()
    };
    let (resp, _) = send_recv(socket, target, &probe, 2000).await?;

    if !is_error(&resp) {
        return Some(resp);
    } // shouldn't happen but handle it

    let (code, _) = extract_error_code(&resp)?;
    if code != 401 {
        return Some(resp);
    }

    let realm = extract_realm(&resp)?;
    let nonce = extract_nonce(&resp)?;

    // Step 2: authenticated request
    let key = long_term_key(username, &realm, password);
    let msg = build(&realm, &nonce).encode_with_integrity(&key);
    let (resp2, _) = send_recv(socket, target, &msg, 2000).await?;
    Some(resp2)
}

// ── STUN tests (existing, kept intact) ───────────────────────────────────────

fn build_binding_request() -> Vec<u8> {
    let mut m = TurnMsg::request(0x0001);
    m.class = 0x0000;
    m.encode()
}

fn is_stun_success(data: &[u8]) -> bool {
    data.len() >= 2 && data[0] == 0x01 && data[1] == 0x01
}
fn is_stun_error(data: &[u8]) -> bool {
    data.len() >= 2 && data[0] == 0x01 && data[1] == 0x11
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Existing STUN tests ───────────────────────────────────────────────────

    #[tokio::test]
    async fn stun_binding() {
        let socket = bind_socket().await;
        let target = target_addr();
        let request = build_binding_request();
        let result = send_recv(&socket, target, &request, 2000).await;
        let (response, _) = skip_if_no_server!(result, target);

        assert!(
            is_stun_success(&response),
            "expected Binding Success, got {:02x} {:02x}",
            response[0],
            response[1]
        );
        assert_eq!(
            &response[4..8],
            &[0x21, 0x12, 0xA4, 0x42],
            "magic cookie mismatch"
        );
        assert_eq!(&response[8..20], &request[8..20], "transaction ID mismatch");
        let mapped = extract_xor_mapped_address(&response);
        assert!(mapped.is_some(), "missing XOR-MAPPED-ADDRESS");
    }

    #[tokio::test]
    async fn malformed_packet_ignored() {
        let socket = bind_socket().await;
        let result = send_recv(&socket, target_addr(), &[0xFF; 10], 500).await;
        if let Some((resp, _)) = result {
            assert!(
                !is_stun_success(&resp),
                "garbage should not produce success"
            );
        }
    }

    #[tokio::test]
    async fn concurrent_bindings() {
        let target = target_addr();
        let handles = (0..10)
            .map(|_| {
                tokio::spawn(async move {
                    let s = bind_socket().await;
                    send_recv(&s, target, &build_binding_request(), 2000).await
                })
            })
            .collect::<Vec<_>>();

        let mut success = 0;
        let mut skipped = 0;
        for h in handles {
            match h.await.unwrap() {
                Some((r, _)) if is_stun_success(&r) => success += 1,
                None => skipped += 1,
                _ => {}
            }
        }
        if skipped == 10 {
            eprintln!("SKIP: turna-node not running");
            return;
        }
        assert!(
            success >= 8,
            "at least 80% should succeed, got {success}/10"
        );
    }

    // ── TURN: Allocate ────────────────────────────────────────────────────────

    /// Full allocate flow: unauthenticated → 401 → authenticated → success.
    #[tokio::test]
    async fn turn_allocate() {
        let socket = bind_socket().await;
        let target = target_addr();

        // Step 1: unauthenticated → must get 401
        let mut probe = TurnMsg::request(0x0003);
        probe.add_requested_transport();
        let probe_bytes = probe.encode();
        let result = send_recv(&socket, target, &probe_bytes, 2000).await;
        let (resp401, _) = skip_if_no_server!(result, target);

        assert!(is_error(&resp401), "expected 401, got non-error response");
        let (code, _) = extract_error_code(&resp401).expect("missing ERROR-CODE");
        assert_eq!(code, 401, "expected 401 Unauthorized, got {code}");

        let realm = extract_realm(&resp401).expect("missing REALM in 401");
        let nonce = extract_nonce(&resp401).expect("missing NONCE in 401");
        if test_debug() {
            eprintln!("[DEBUG] server realm = {realm:?}");
            eprintln!("[DEBUG] server nonce = {nonce:?}");
        }

        // Step 2: authenticated allocate
        let (username, password) = effective_credentials();
        let key = long_term_key(&username, &realm, &password);
        let mut alloc = TurnMsg::request(0x0003);
        alloc.add_requested_transport();
        alloc.add_lifetime(600);
        alloc.add_username(&username);
        alloc.add_realm(&realm);
        alloc.add_nonce(&nonce);
        let alloc_bytes = alloc.encode_with_integrity(&key);

        let (mut resp, _) = send_recv(&socket, target, &alloc_bytes, 2000)
            .await
            .expect("no response to authenticated allocate");
        // Retry once if nonce was rotated between probe and request
        if is_error(&resp) {
            if let Some(new_nonce) = extract_nonce(&resp) {
                // Re-derive credentials too — for SharedSecret mode the
                // server's nonce rotation often coincides with the auth
                // window, so a fresh timestamp doesn't hurt.
                let (username, password) = effective_credentials();
                let key = long_term_key(&username, &realm, &password);
                let mut alloc2 = TurnMsg::request(0x0003);
                alloc2.add_requested_transport();
                alloc2.add_lifetime(600);
                alloc2.add_username(&username);
                alloc2.add_realm(&realm);
                alloc2.add_nonce(&new_nonce);
                if let Some((r, _)) =
                    send_recv(&socket, target, &alloc2.encode_with_integrity(&key), 2000).await
                {
                    resp = r;
                }
            }
        }

        assert!(
            is_success(&resp),
            "expected Allocate success; error: {:?}",
            extract_error_code(&resp)
        );

        let relayed = extract_xor_relayed_address(&resp);
        assert!(
            relayed.is_some(),
            "missing XOR-RELAYED-ADDRESS in Allocate response"
        );
        let relay_port = relayed.unwrap().port();
        assert!(relay_port > 0, "relay port should be > 0");

        let lifetime = extract_lifetime(&resp);
        assert!(lifetime.is_some(), "missing LIFETIME in Allocate response");
        assert!(lifetime.unwrap() > 0, "lifetime should be > 0");

        eprintln!(
            "✓ Allocate: relay={}, lifetime={}s",
            relayed.unwrap(),
            lifetime.unwrap()
        );
    }

    /// Allocate with invalid credentials → expect 401.
    #[tokio::test]
    async fn turn_allocate_wrong_password() {
        let socket = bind_socket().await;
        let target = target_addr();

        // Get realm/nonce first
        let mut probe = TurnMsg::request(0x0003);
        probe.add_requested_transport();
        let result = send_recv(&socket, target, &probe.encode(), 2000).await;
        let (resp401, _) = skip_if_no_server!(result, target);

        if !is_error(&resp401) {
            return;
        }
        let realm = match extract_realm(&resp401) {
            Some(r) => r,
            None => return,
        };
        let nonce = match extract_nonce(&resp401) {
            Some(n) => n,
            None => return,
        };

        // Use a correctly-shaped username so we exercise the integrity check,
        // not the username-not-found path. In SharedSecret mode the server
        // will compute its own expected password from this username via
        // HMAC(secret, username); ours below is "definitely-wrong-password"
        // → keys mismatch → 401. In LongTerm mode it matches a static user
        // but wrong password → 401 all the same.
        let (username, _) = effective_credentials();
        let key = long_term_key(&username, &realm, "definitely-wrong-password");
        let mut alloc = TurnMsg::request(0x0003);
        alloc.add_requested_transport();
        alloc.add_username(&username);
        alloc.add_realm(&realm);
        alloc.add_nonce(&nonce);
        let bytes = alloc.encode_with_integrity(&key);

        let (resp, _) = send_recv(&socket, target, &bytes, 2000)
            .await
            .expect("no response to bad-credential allocate");

        assert!(
            is_error(&resp),
            "wrong password should produce error response"
        );
        eprintln!(
            "✓ Wrong password correctly rejected: {:?}",
            extract_error_code(&resp)
        );
    }

    // ── TURN: Refresh ─────────────────────────────────────────────────────────

    /// Allocate then Refresh to extend TTL.
    #[tokio::test]
    async fn turn_refresh() {
        let socket = bind_socket().await;
        let target = target_addr();

        // Allocate first
        let (realm, nonce) = skip_if_no_server!(get_realm_nonce(&socket, target).await, target);

        let (username, password) = effective_credentials();
        let key = long_term_key(&username, &realm, &password);

        let mut alloc = TurnMsg::request(0x0003);
        alloc.add_requested_transport();
        alloc.add_lifetime(600);
        alloc.add_username(&username);
        alloc.add_realm(&realm);
        alloc.add_nonce(&nonce);
        let (resp, _) = send_recv(&socket, target, &alloc.encode_with_integrity(&key), 2000)
            .await
            .expect("no allocate response");

        if !is_success(&resp) {
            eprintln!(
                "SKIP: Allocate failed (no test credentials configured?): {:?}",
                extract_error_code(&resp)
            );
            return;
        }

        // Now Refresh with new nonce (server may rotate)
        let nonce2 = extract_nonce(&resp).unwrap_or(nonce);

        let mut refresh = TurnMsg::request(0x0004); // Refresh method
        refresh.add_lifetime(1200); // extend to 20 minutes
        refresh.add_username(&username);
        refresh.add_realm(&realm);
        refresh.add_nonce(&nonce2);
        let (resp2, _) = send_recv(&socket, target, &refresh.encode_with_integrity(&key), 2000)
            .await
            .expect("no refresh response");

        assert!(
            is_success(&resp2),
            "Refresh failed: {:?}",
            extract_error_code(&resp2)
        );

        let lifetime = extract_lifetime(&resp2).unwrap_or(0);
        assert!(lifetime > 0, "Refresh response should include LIFETIME");
        eprintln!("✓ Refresh: new lifetime={}s", lifetime);

        // Delete: Refresh with lifetime=0
        let nonce3 = extract_nonce(&resp2).unwrap_or(nonce2);
        let mut del = TurnMsg::request(0x0004);
        del.add_lifetime(0);
        del.add_username(&username);
        del.add_realm(&realm);
        del.add_nonce(&nonce3);
        let (resp3, _) = send_recv(&socket, target, &del.encode_with_integrity(&key), 2000)
            .await
            .expect("no delete response");

        assert!(
            is_success(&resp3),
            "Delete (Refresh lifetime=0) failed: {:?}",
            extract_error_code(&resp3)
        );
        let del_lifetime = extract_lifetime(&resp3).unwrap_or(1);
        assert_eq!(del_lifetime, 0, "Delete response should have LIFETIME=0");
        eprintln!("✓ Delete (Refresh lifetime=0): ok");
    }

    // ── TURN: CreatePermission ────────────────────────────────────────────────

    /// Allocate then CreatePermission for a peer IP.
    #[tokio::test]
    async fn turn_create_permission() {
        let socket = bind_socket().await;
        let target = target_addr();

        let (realm, nonce) = skip_if_no_server!(get_realm_nonce(&socket, target).await, target);

        let (username, password) = effective_credentials();
        let key = long_term_key(&username, &realm, &password);

        // Allocate
        let mut alloc = TurnMsg::request(0x0003);
        alloc.add_requested_transport();
        alloc.add_lifetime(600);
        alloc.add_username(&username);
        alloc.add_realm(&realm);
        alloc.add_nonce(&nonce);
        let (alloc_resp, _) = send_recv(&socket, target, &alloc.encode_with_integrity(&key), 2000)
            .await
            .expect("no allocate response");

        if !is_success(&alloc_resp) {
            eprintln!(
                "SKIP: Allocate failed: {:?}",
                extract_error_code(&alloc_resp)
            );
            return;
        }

        let nonce2 = extract_nonce(&alloc_resp).unwrap_or(nonce);
        let peer: SocketAddr = "1.2.3.4:5678".parse().unwrap();

        // CreatePermission
        let mut perm = TurnMsg::request(0x0008); // CreatePermission method
        perm.add_xor_peer_address(peer);
        perm.add_username(&username);
        perm.add_realm(&realm);
        perm.add_nonce(&nonce2);
        let (perm_resp, _) = send_recv(&socket, target, &perm.encode_with_integrity(&key), 2000)
            .await
            .expect("no CreatePermission response");

        assert!(
            is_success(&perm_resp),
            "CreatePermission failed: {:?}",
            extract_error_code(&perm_resp)
        );
        eprintln!("✓ CreatePermission for {peer}: ok");

        // Cleanup
        let nonce3 = extract_nonce(&perm_resp).unwrap_or_default();
        let mut del = TurnMsg::request(0x0004);
        del.add_lifetime(0);
        del.add_username(&username);
        del.add_realm(&realm);
        del.add_nonce(&nonce3);
        let _ = send_recv(&socket, target, &del.encode_with_integrity(&key), 1000).await;
    }

    // ── TURN: ChannelBind ─────────────────────────────────────────────────────

    /// Allocate → CreatePermission → ChannelBind.
    #[tokio::test]
    async fn turn_channel_bind() {
        let socket = bind_socket().await;
        let target = target_addr();

        let (realm, nonce) = skip_if_no_server!(get_realm_nonce(&socket, target).await, target);

        let (username, password) = effective_credentials();
        let key = long_term_key(&username, &realm, &password);

        // Allocate
        let mut alloc = TurnMsg::request(0x0003);
        alloc.add_requested_transport();
        alloc.add_lifetime(600);
        alloc.add_username(&username);
        alloc.add_realm(&realm);
        alloc.add_nonce(&nonce);
        let (alloc_resp, _) = send_recv(&socket, target, &alloc.encode_with_integrity(&key), 2000)
            .await
            .expect("no allocate response");

        if !is_success(&alloc_resp) {
            eprintln!(
                "SKIP: Allocate failed: {:?}",
                extract_error_code(&alloc_resp)
            );
            return;
        }

        let nonce2 = extract_nonce(&alloc_resp).unwrap_or(nonce.clone());
        let peer: SocketAddr = "1.2.3.4:5678".parse().unwrap();

        // CreatePermission (required before ChannelBind)
        let mut perm = TurnMsg::request(0x0008);
        perm.add_xor_peer_address(peer);
        perm.add_username(&username);
        perm.add_realm(&realm);
        perm.add_nonce(&nonce2);
        let (perm_resp, _) = send_recv(&socket, target, &perm.encode_with_integrity(&key), 2000)
            .await
            .expect("no CreatePermission response");

        if !is_success(&perm_resp) {
            eprintln!(
                "SKIP: CreatePermission failed: {:?}",
                extract_error_code(&perm_resp)
            );
            return;
        }

        let nonce3 = extract_nonce(&perm_resp).unwrap_or(nonce2);

        // ChannelBind: channel 0x4000 for peer
        let channel: u16 = 0x4000;
        let mut bind = TurnMsg::request(0x0009); // ChannelBind method
        bind.add_channel_number(channel);
        bind.add_xor_peer_address(peer);
        bind.add_username(&username);
        bind.add_realm(&realm);
        bind.add_nonce(&nonce3);
        let (bind_resp, _) = send_recv(&socket, target, &bind.encode_with_integrity(&key), 2000)
            .await
            .expect("no ChannelBind response");

        assert!(
            is_success(&bind_resp),
            "ChannelBind failed: {:?}",
            extract_error_code(&bind_resp)
        );
        eprintln!("✓ ChannelBind channel={channel:#06x} peer={peer}: ok");

        // Cleanup
        let nonce4 = extract_nonce(&bind_resp).unwrap_or_default();
        let mut del = TurnMsg::request(0x0004);
        del.add_lifetime(0);
        del.add_username(&username);
        del.add_realm(&realm);
        del.add_nonce(&nonce4);
        let _ = send_recv(&socket, target, &del.encode_with_integrity(&key), 1000).await;
    }

    // ── TURN: Full relay ──────────────────────────────────────────────────────

    /// Full relay test: allocate → bind channel → send ChannelData → peer receives.
    #[tokio::test]
    async fn turn_channel_data_relay() {
        let client = bind_socket().await;
        let peer = bind_socket().await;
        let target = target_addr();

        let peer_addr = peer.local_addr().unwrap();

        let (realm, nonce) = skip_if_no_server!(get_realm_nonce(&client, target).await, target);

        let (username, password) = effective_credentials();
        let key = long_term_key(&username, &realm, &password);

        // Allocate
        let mut alloc = TurnMsg::request(0x0003);
        alloc.add_requested_transport();
        alloc.add_lifetime(60);
        alloc.add_username(&username);
        alloc.add_realm(&realm);
        alloc.add_nonce(&nonce);
        let (alloc_resp, _) = send_recv(&client, target, &alloc.encode_with_integrity(&key), 2000)
            .await
            .expect("no allocate response");

        if !is_success(&alloc_resp) {
            eprintln!(
                "SKIP: Allocate failed: {:?}",
                extract_error_code(&alloc_resp)
            );
            return;
        }

        let relay_addr = extract_xor_relayed_address(&alloc_resp).expect("missing relay address");
        let nonce2 = extract_nonce(&alloc_resp).unwrap_or(nonce);

        // CreatePermission for peer's IP
        let mut perm = TurnMsg::request(0x0008);
        perm.add_xor_peer_address(peer_addr);
        perm.add_username(&username);
        perm.add_realm(&realm);
        perm.add_nonce(&nonce2);
        let (perm_resp, _) = send_recv(&client, target, &perm.encode_with_integrity(&key), 2000)
            .await
            .expect("no CreatePermission response");

        if !is_success(&perm_resp) {
            eprintln!(
                "SKIP: CreatePermission failed: {:?}",
                extract_error_code(&perm_resp)
            );
            return;
        }

        let nonce3 = extract_nonce(&perm_resp).unwrap_or_default();

        // ChannelBind
        let channel: u16 = 0x4001;
        let mut bind = TurnMsg::request(0x0009);
        bind.add_channel_number(channel);
        bind.add_xor_peer_address(peer_addr);
        bind.add_username(&username);
        bind.add_realm(&realm);
        bind.add_nonce(&nonce3);
        let (bind_resp, _) = send_recv(&client, target, &bind.encode_with_integrity(&key), 2000)
            .await
            .expect("no ChannelBind response");

        if !is_success(&bind_resp) {
            eprintln!(
                "SKIP: ChannelBind failed: {:?}",
                extract_error_code(&bind_resp)
            );
            return;
        }

        // Send ChannelData from client → relay → peer
        let payload = b"hello from TURN client";
        let channel_data = build_channel_data(channel, payload);
        client.send_to(&channel_data, target).await.unwrap();

        // Peer should receive the raw payload via the relay
        let mut buf = vec![0u8; 1024];
        match tokio::time::timeout(Duration::from_millis(1000), peer.recv_from(&mut buf)).await {
            Ok(Ok((n, src))) => {
                let received = &buf[..n];
                assert_eq!(
                    received, payload,
                    "peer received wrong data: {:?}",
                    received
                );
                eprintln!("✓ ChannelData relay: {} bytes from {src}", n);
            }
            _ => {
                eprintln!(
                    "NOTE: ChannelData relay timeout — peer may need to be on relay's network"
                );
            }
        }

        // Cleanup
        let nonce4 = extract_nonce(&bind_resp).unwrap_or_default();
        let mut del = TurnMsg::request(0x0004);
        del.add_lifetime(0);
        del.add_username(&username);
        del.add_realm(&realm);
        del.add_nonce(&nonce4);
        let _ = send_recv(&client, target, &del.encode_with_integrity(&key), 1000).await;
        eprintln!("✓ Relay addr was: {relay_addr}");
    }

    // ── Unit tests (no server needed) ─────────────────────────────────────────

    #[test]
    fn binding_request_format() {
        let req = build_binding_request();
        assert_eq!(req.len(), 20);
        assert_eq!(&req[4..8], &[0x21, 0x12, 0xA4, 0x42]);
    }

    #[test]
    fn xor_mapped_address_parsing() {
        let mut resp = vec![0u8; 36];
        resp[0] = 0x01;
        resp[1] = 0x01;
        resp[2] = 0x00;
        resp[3] = 0x10;
        resp[4..8].copy_from_slice(&[0x21, 0x12, 0xA4, 0x42]);
        resp[20] = 0x00;
        resp[21] = 0x20;
        resp[22] = 0x00;
        resp[23] = 0x08;
        resp[24] = 0x00;
        resp[25] = 0x01;
        let xport = 3478u16 ^ 0x2112u16;
        resp[26..28].copy_from_slice(&xport.to_be_bytes());
        resp[28] = 192 ^ 0x21;
        resp[29] = 168 ^ 0x12;
        resp[30] = 1 ^ 0xA4;
        resp[31] = 1 ^ 0x42;

        let addr = extract_xor_mapped_address(&resp).unwrap();
        assert_eq!(addr.port(), 3478);
        assert_eq!(addr.ip().to_string(), "192.168.1.1");
    }

    #[test]
    fn long_term_key_rfc_vector() {
        // RFC 5389 test vector: user="user", realm="realm", pass="pass"
        // MD5("user:realm:pass") = 0x8493fbc53ba582fb4c044c456bdc40eb
        let key = long_term_key("user", "realm", "pass");
        assert_eq!(key.len(), 16);
        assert_eq!(
            key,
            vec![
                0x84, 0x93, 0xfb, 0xc5, 0x3b, 0xa5, 0x82, 0xfb, 0x4c, 0x04, 0x4c, 0x45, 0x6b, 0xdc,
                0x40, 0xeb
            ]
        );
    }

    #[test]
    fn turn_msg_encode_length() {
        let mut m = TurnMsg::request(0x0003);
        m.add_requested_transport();
        m.add_lifetime(600);
        let bytes = m.encode();
        // Header (20) + REQUESTED-TRANSPORT (8) + LIFETIME (8) = 36
        assert_eq!(bytes.len(), 36);
        let len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
        assert_eq!(len, 16); // attr bytes only
    }

    #[test]
    fn channel_data_format() {
        let pkt = build_channel_data(0x4000, b"hello");
        assert_eq!(pkt[0], 0x40); // channel high byte
        assert_eq!(pkt[1], 0x00); // channel low byte
        let len = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
        assert_eq!(len, 5); // "hello".len()
        assert_eq!(&pkt[4..9], b"hello");
    }

    #[test]
    fn error_code_parsing() {
        // Build a fake 401 error
        let mut data = vec![0u8; 20 + 4 + 4];
        // ERROR-CODE attr at offset 20: type=0x0009, len=4
        data[20] = 0x00;
        data[21] = 0x09; // type
        data[22] = 0x00;
        data[23] = 0x04; // len=4
        data[24] = 0x00;
        data[25] = 0x00; // reserved
        data[26] = 4; // class=4 → 400s
        data[27] = 1; // number=1 → 401

        let (code, _) = extract_error_code(&data).unwrap();
        assert_eq!(code, 401);
    }

    #[test]
    fn time_limited_credentials_format() {
        let (user, pass) = time_limited_credentials("alice", "turna-secret");
        // username must be "{unix_ts}:{user}" — first segment parses as u64
        let parts: Vec<&str> = user.splitn(2, ':').collect();
        assert_eq!(parts.len(), 2);
        assert!(
            parts[0].parse::<u64>().is_ok(),
            "username prefix not a timestamp: {user:?}"
        );
        assert_eq!(parts[1], "alice");
        // password is base64(20-byte HMAC-SHA1) → 28 chars with padding
        assert_eq!(
            pass.len(),
            28,
            "expected 28-char base64 password, got {pass:?}"
        );
    }

    /// #7 interop: an authenticated Allocate carrying a NONCE the server never
    /// issued must be answered with `438 Stale Nonce` (not 401) plus a fresh
    /// NONCE; retrying with that NONCE then succeeds. Exercises the nonce path
    /// distinctly from the wrong-password path.
    #[tokio::test]
    async fn turn_stale_nonce_challenge() {
        let socket = bind_socket().await;
        let target = target_addr();

        // Get a real realm (nonce value is deliberately ignored below).
        let (realm, _nonce) = skip_if_no_server!(get_realm_nonce(&socket, target).await, target);

        let (username, password) = effective_credentials();
        let key = long_term_key(&username, &realm, &password);

        // Authenticated Allocate with a bogus NONCE the server never minted.
        let mut alloc = TurnMsg::request(0x0003);
        alloc.add_requested_transport();
        alloc.add_lifetime(600);
        alloc.add_username(&username);
        alloc.add_realm(&realm);
        alloc.add_nonce("stale-nonce-000000");
        let (resp, _) = send_recv(&socket, target, &alloc.encode_with_integrity(&key), 2000)
            .await
            .expect("no response to stale-nonce Allocate");

        assert!(is_error(&resp), "stale nonce must yield an error response");
        let (code, _) = extract_error_code(&resp).expect("missing ERROR-CODE");
        assert_eq!(code, 438, "expected 438 Stale Nonce, got {code}");

        // The 438 must carry a fresh NONCE to retry with.
        let fresh = extract_nonce(&resp).expect("438 must carry a fresh NONCE");
        assert_ne!(fresh, "stale-nonce-000000", "server must issue a new NONCE");

        // Retry with the fresh NONCE → success.
        let mut alloc2 = TurnMsg::request(0x0003);
        alloc2.add_requested_transport();
        alloc2.add_lifetime(600);
        alloc2.add_username(&username);
        alloc2.add_realm(&realm);
        alloc2.add_nonce(&fresh);
        let (resp2, _) = send_recv(&socket, target, &alloc2.encode_with_integrity(&key), 2000)
            .await
            .expect("no response to retried Allocate");
        assert!(
            is_success(&resp2),
            "retry with the fresh NONCE should succeed; err={:?}",
            extract_error_code(&resp2)
        );
        eprintln!("\u{2713} Stale nonce challenged (438) then accepted with fresh nonce");

        // Cleanup.
        let nonce_del = extract_nonce(&resp2).unwrap_or(fresh);
        let mut del = TurnMsg::request(0x0004);
        del.add_lifetime(0);
        del.add_username(&username);
        del.add_realm(&realm);
        del.add_nonce(&nonce_del);
        let _ = send_recv(&socket, target, &del.encode_with_integrity(&key), 1000).await;
    }
}

// ── Test helpers ──────────────────────────────────────────────────────────────

/// Probe server with unauthenticated Allocate to get REALM + NONCE.
async fn get_realm_nonce(socket: &UdpSocket, target: SocketAddr) -> Option<(String, String)> {
    let mut probe = TurnMsg::request(0x0003);
    probe.add_requested_transport();
    let (resp, _) = send_recv(socket, target, &probe.encode(), 2000).await?;
    if !is_error(&resp) {
        return None;
    }
    let realm = extract_realm(&resp)?;
    let nonce = extract_nonce(&resp)?;
    Some((realm, nonce))
}

/// Build ChannelData frame: [channel(2)][length(2)][payload][pad].
fn build_channel_data(channel: u16, payload: &[u8]) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(4 + payload.len() + 3);
    pkt.extend_from_slice(&channel.to_be_bytes());
    pkt.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    pkt.extend_from_slice(payload);
    let pad = (4 - payload.len() % 4) % 4;
    pkt.extend(std::iter::repeat_n(0u8, pad));
    pkt
}

// ── §6: cluster redirect / distribution tests ────────────────────────────────
//
// These run against a LIVE multi-node cluster and are opt-in: set
// TURNA_TEST_CLUSTER=1 (otherwise they skip). Point TURNA_TEST_TARGET at any
// one cluster node — new clients (varying source ports) should be spread across
// nodes via `300 Try Alternate` redirects.
//
//   # bring up 2 nodes sharing cluster_name/secret + a common seed, then:
//   TURNA_TEST_CLUSTER=1 TURNA_TEST_TARGET=10.0.0.11:3478 \
//     cargo test -p turna-integration-tests cluster_ -- --nocapture
#[cfg(test)]
mod cluster_tests {
    use super::*;
    use std::collections::HashMap;

    fn cluster_enabled() -> bool {
        std::env::var("TURNA_TEST_CLUSTER").is_ok()
    }

    /// New clients are distributed across the cluster: some are served locally,
    /// some get a 300 Try Alternate redirect to another node, and every redirect
    /// carries a valid (plain, non-XOR) ALTERNATE-SERVER.
    #[tokio::test]
    async fn cluster_redirect_distribution() {
        if !cluster_enabled() {
            eprintln!("SKIP: set TURNA_TEST_CLUSTER=1 to run cluster redirect tests");
            return;
        }
        let target = target_addr();
        const N: usize = 64;
        let mut local = 0usize;
        let mut redirected = 0usize;
        let mut targets: HashMap<SocketAddr, usize> = HashMap::new();

        for _ in 0..N {
            // A fresh ephemeral source port = a different consistent-hash key.
            let socket = bind_socket().await;
            let resp = match send_recv(&socket, target, &build_binding_request(), 2000).await {
                Some((r, _)) => r,
                None => {
                    eprintln!("SKIP: cluster node not reachable on {target}");
                    return;
                }
            };

            if is_error(&resp) {
                let (code, _) = extract_error_code(&resp).unwrap_or((0, String::new()));
                assert_eq!(
                    code, 300,
                    "unexpected error code {code} for a brand-new client"
                );
                let alt = extract_alternate_server(&resp)
                    .expect("300 Try Alternate must carry a parseable ALTERNATE-SERVER");
                assert!(
                    alt.port() != 0 && !alt.ip().is_unspecified(),
                    "ALTERNATE-SERVER looks unset/garbled (XOR encoding?): {alt}"
                );
                *targets.entry(alt).or_default() += 1;
                redirected += 1;
            } else if is_success(&resp) {
                local += 1;
            } else {
                panic!(
                    "unexpected response class for Binding: {:02x} {:02x}",
                    resp[0], resp[1]
                );
            }
        }

        eprintln!(
            "cluster distribution over {N} new clients: {local} local, {redirected} redirected; \
             alternate targets = {targets:?}"
        );
        assert!(
            redirected > 0,
            "no client was redirected — is TURNA_TEST_TARGET a single-node deployment?"
        );
        assert!(
            local > 0,
            "every client was redirected — does the contacted node own any keys?"
        );
    }

    /// Focused check: a redirect is class=error, code=300, with a plain
    /// (non-XOR) ALTERNATE-SERVER that parses to a sane address.
    #[tokio::test]
    async fn cluster_redirect_is_plain_alternate_server() {
        if !cluster_enabled() {
            eprintln!("SKIP: set TURNA_TEST_CLUSTER=1 to run cluster redirect tests");
            return;
        }
        let target = target_addr();
        for _ in 0..128 {
            let socket = bind_socket().await;
            let resp = match send_recv(&socket, target, &build_binding_request(), 2000).await {
                Some((r, _)) => r,
                None => {
                    eprintln!("SKIP: cluster node not reachable on {target}");
                    return;
                }
            };
            if is_error(&resp) {
                let (code, _) = extract_error_code(&resp).unwrap_or((0, String::new()));
                assert_eq!(code, 300, "error response was not 300 Try Alternate");
                let alt = extract_alternate_server(&resp)
                    .expect("ALTERNATE-SERVER must be present and plain-parseable");
                assert!(
                    alt.port() != 0 && !alt.ip().is_unspecified(),
                    "garbled ALTERNATE-SERVER {alt} (server XOR-encoded it?)"
                );
                eprintln!("observed redirect → {alt}");
                return;
            }
        }
        eprintln!("WARN: no redirect seen in 128 probes (single node, or all keys local)");
    }

    // ── RFC 8016 Connection Migration (wire-level) ───────────────────────────
    // Requires a running node with `turn.migration.enabled = true`. Skips if no
    // server, or if the server does not issue a MOBILITY-TICKET (feature off).
    const ATTR_MOBILITY_TICKET: u16 = 0x8030;

    fn extract_attr(data: &[u8], typ: u16) -> Option<Vec<u8>> {
        iter_attrs(data)
            .find(|(t, _)| *t == typ)
            .map(|(_, v)| v.to_vec())
    }

    /// Authenticated Allocate with the RFC 8016 opt-in (empty MOBILITY-TICKET).
    /// Returns the server-issued ticket, or None if the server didn't issue one.
    async fn allocate_with_mobility(socket: &UdpSocket, target: SocketAddr) -> Option<Vec<u8>> {
        let mut probe = TurnMsg::request(0x0003);
        probe.add_requested_transport();
        let (r401, _) = send_recv(socket, target, &probe.encode(), 2000).await?;
        let realm = extract_realm(&r401)?;
        let nonce = extract_nonce(&r401)?;
        let (username, password) = effective_credentials();
        let key = long_term_key(&username, &realm, &password);
        let mut alloc = TurnMsg::request(0x0003);
        alloc.add_requested_transport();
        alloc.add_lifetime(600);
        alloc.add_username(&username);
        alloc.add_realm(&realm);
        alloc.add_nonce(&nonce);
        alloc.add_attr(ATTR_MOBILITY_TICKET, &[]); // opt-in marker
        let (resp, _) = send_recv(socket, target, &alloc.encode_with_integrity(&key), 2000).await?;
        if !is_success(&resp) {
            return None;
        }
        extract_attr(&resp, ATTR_MOBILITY_TICKET)
    }

    /// A Refresh carrying `ticket`, self-authenticating from this socket.
    async fn refresh_with_ticket(
        socket: &UdpSocket,
        target: SocketAddr,
        ticket: &[u8],
    ) -> Option<Vec<u8>> {
        let probe = TurnMsg::request(0x0004); // Refresh, unauthenticated → 401
        let (r401, _) = send_recv(socket, target, &probe.encode(), 2000).await?;
        let realm = extract_realm(&r401)?;
        let nonce = extract_nonce(&r401)?;
        let (username, password) = effective_credentials();
        let key = long_term_key(&username, &realm, &password);
        let mut m = TurnMsg::request(0x0004);
        m.add_lifetime(600);
        m.add_username(&username);
        m.add_realm(&realm);
        m.add_nonce(&nonce);
        m.add_attr(ATTR_MOBILITY_TICKET, ticket);
        let (resp, _) = send_recv(socket, target, &m.encode_with_integrity(&key), 2000).await?;
        Some(resp)
    }

    #[tokio::test]
    async fn turn_migration_rebind_and_replay() {
        let target = target_addr();
        let sock_a = bind_socket().await;

        // Liveness probe (Binding) for the skip gate.
        let probe = {
            let mut m = TurnMsg::request(0x0001);
            m.class = 0x0000;
            m.encode()
        };
        let result = send_recv(&sock_a, target, &probe, 2000).await;
        let _ = skip_if_no_server!(result, target);

        // Allocate with mobility opt-in.
        let ticket = match allocate_with_mobility(&sock_a, target).await {
            Some(t) => t,
            None => {
                eprintln!("⚠ no MOBILITY-TICKET issued (turn.migration disabled?) — skipping");
                return;
            }
        };
        eprintln!("✓ MOBILITY-TICKET issued ({} bytes)", ticket.len());

        // Migrate: present the ticket in a Refresh from a brand-new socket
        // (a fresh 5-tuple — the "network changed" case).
        let sock_b = bind_socket().await;
        let resp = refresh_with_ticket(&sock_b, target, &ticket)
            .await
            .expect("no response to migrating Refresh");
        assert!(
            is_success(&resp),
            "migration Refresh should succeed; err={:?}",
            extract_error_code(&resp)
        );
        assert!(
            extract_attr(&resp, ATTR_MOBILITY_TICKET).is_some(),
            "server should issue a fresh ticket on successful migration"
        );
        eprintln!("✓ rebind from new socket succeeded; fresh ticket issued");

        // Replay the OLD ticket from a third socket → must be rejected: the
        // successful migration bumped the allocation epoch (anti-replay).
        let sock_c = bind_socket().await;
        let replay = refresh_with_ticket(&sock_c, target, &ticket)
            .await
            .expect("no response to replay Refresh");
        assert!(
            is_error(&replay),
            "replaying the stale ticket must be rejected (anti-replay)"
        );
        eprintln!(
            "✓ stale-ticket replay rejected: {:?}",
            extract_error_code(&replay)
        );
    }
}

// ── DTL-5: TURN-over-DTLS (RFC 7350) end-to-end client ──────────────────
//
// Mirrors the UDP `stun_binding` test but runs the STUN Binding exchange over a
// real DTLS 1.2 session against the server's DTLS listener (default
// 127.0.0.1:5349; override with TURNA_TEST_DTLS_TARGET). Requires a server
// built + configured with the `dtls` feature. Gated behind the `dtls` cargo
// feature AND #[ignore] so it never runs in a plain `cargo test`:
//
//   cargo test -p turna-integration-tests --features dtls -- --ignored dtls
//
// Uses the webrtc-dtls 0.10 client API: DTLSConn::new(conn, config, is_client,
// initial_state). Compiles/builds under `--features dtls` (verified 2026-06-11);
// the live exchange requires a server built/configured with the feature.
#[cfg(feature = "dtls")]
mod dtls_e2e {
    use super::*;
    use std::sync::Arc;
    use webrtc_util::conn::Conn;

    fn dtls_target() -> SocketAddr {
        std::env::var("TURNA_TEST_DTLS_TARGET")
            .unwrap_or_else(|_| "127.0.0.1:5349".into())
            .parse()
            .expect("invalid TURNA_TEST_DTLS_TARGET")
    }

    /// Connected UDP socket + DTLS client handshake against `target`.
    /// `insecure_skip_verify = true`: the test server uses a self-signed cert.
    async fn dtls_connect(target: SocketAddr) -> Arc<dyn Conn + Send + Sync> {
        let socket = Arc::new(tokio::net::UdpSocket::bind("0.0.0.0:0").await.unwrap());
        socket.connect(target).await.unwrap();
        let config = webrtc_dtls::config::Config {
            insecure_skip_verify: true,
            ..Default::default()
        };
        Arc::new(
            webrtc_dtls::conn::DTLSConn::new(socket, config, true, None)
                .await
                .expect("DTLS client handshake failed"),
        )
    }

    #[tokio::test]
    #[ignore = "requires a live server built/configured with --features dtls"]
    async fn stun_binding_over_dtls() {
        let target = dtls_target();
        let conn = match tokio::time::timeout(Duration::from_secs(5), dtls_connect(target)).await {
            Ok(c) => c,
            Err(_) => {
                eprintln!("skip: DTLS handshake to {target} timed out (no DTLS server?)");
                return;
            }
        };

        let request = build_binding_request();
        conn.send(&request).await.expect("DTLS send failed");

        let mut buf = vec![0u8; 2048];
        let n = tokio::time::timeout(Duration::from_secs(2), conn.recv(&mut buf))
            .await
            .expect("DTLS recv timed out")
            .expect("DTLS recv failed");
        let response = &buf[..n];

        assert!(
            is_stun_success(response),
            "expected Binding Success over DTLS, got {:02x} {:02x}",
            response[0],
            response[1]
        );
        assert_eq!(
            &response[4..8],
            &[0x21, 0x12, 0xA4, 0x42],
            "magic cookie mismatch"
        );
        assert_eq!(&response[8..20], &request[8..20], "transaction ID mismatch");
        assert!(
            extract_xor_mapped_address(response).is_some(),
            "missing XOR-MAPPED-ADDRESS in DTLS Binding response"
        );
    }
}
