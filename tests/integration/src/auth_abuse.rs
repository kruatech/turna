//! End-to-end tests for the abuse controls and the auth webhook, against the
//! real node binary: `[turn.auto_ban]`, `[turn.relay] max_total_bytes_per_sec`,
//! `[turn.auth] require_binding_auth` and `[turn.auth.webhook]`.
//!
//! Each test boots its own node on ephemeral ports (the settings under test are
//! node-wide, so they cannot share the hermetic node) and kills it on drop.

use super::*;

/// A node started for one test, killed when dropped.
pub(crate) struct Node {
    pub(crate) turn: SocketAddr,
    pub(crate) health: SocketAddr,
    child: std::process::Child,
    dir: std::path::PathBuf,
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Boot a node with `turn_keys` spliced into `[turn]`, `relay_keys` into
/// `[turn.relay]`, and `sections` appended. The base config has one static
/// user, `testuser`/`testpass`, realm `turna`. `None` when the binary is not
/// built (the suite's convention: skip, do not fail).
pub(crate) fn boot(turn_keys: &str, relay_keys: &str, sections: &str) -> Option<Node> {
    boot_with_users(turn_keys, relay_keys, sections, true)
}

pub(crate) fn boot_with_users(
    turn_keys: &str,
    relay_keys: &str,
    sections: &str,
    static_user: bool,
) -> Option<Node> {
    let bin = node_binary();
    if !bin.exists() {
        eprintln!("skipping: node binary not built");
        return None;
    }
    let turn_port = free_port(true);
    let health_port = free_port(false);
    let dir = std::env::temp_dir().join(format!("turna-aa-{}-{turn_port}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let cfg_path = dir.join("turn.toml");
    let users = if static_user {
        "[[turn.auth.static_users]]\nusername = \"testuser\"\npassword = \"testpass\"\n"
    } else {
        ""
    };
    std::fs::write(
        &cfg_path,
        format!(
            "production = false\n\
             [turn]\n\
             listen = \"127.0.0.1:{turn_port}\"\n\
             realm = \"turna\"\n\
             transport = \"tokio\"\n\
             {turn_keys}\n\
             {users}\
             [turn.relay]\n\
             min_port = 49152\n\
             max_port = 49500\n\
             max_allocations = 256\n\
             {relay_keys}\n\
             [turn.peer_filter]\n\
             allow_loopback_peers = true\n\
             [health]\n\
             listen = \"127.0.0.1:{health_port}\"\n\
             {sections}\n"
        ),
    )
    .expect("write config");
    let child = std::process::Command::new(&bin)
        .arg(&cfg_path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn node");
    let node = Node {
        turn: format!("127.0.0.1:{turn_port}").parse().unwrap(),
        health: format!("127.0.0.1:{health_port}").parse().unwrap(),
        child,
        dir,
    };
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    while !http_ready(&node.health) {
        if std::time::Instant::now() > deadline {
            panic!("node did not become ready with config:\n{turn_keys}\n{relay_keys}\n{sections}");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Some(node)
}

/// Fetch REALM and NONCE with an unauthenticated Allocate.
pub(crate) async fn challenge(socket: &UdpSocket, target: SocketAddr) -> Option<(String, String)> {
    let mut probe = TurnMsg::request(0x0003);
    probe.add_requested_transport();
    let (resp, _) = send_recv(socket, target, &probe.encode(), 2000).await?;
    Some((extract_realm(&resp)?, extract_nonce(&resp)?))
}

/// One Allocate with `user`/`pass` after a fresh challenge. Returns the
/// response, or `None` when nothing came back.
pub(crate) async fn allocate_as(
    socket: &UdpSocket,
    target: SocketAddr,
    user: &str,
    pass: &str,
) -> Option<Vec<u8>> {
    let (realm, nonce) = challenge(socket, target).await?;
    let key = long_term_key(user, &realm, pass);
    let mut alloc = TurnMsg::request(0x0003);
    alloc.add_requested_transport();
    alloc.add_lifetime(600);
    alloc.add_username(user);
    alloc.add_realm(&realm);
    alloc.add_nonce(&nonce);
    send_recv(socket, target, &alloc.encode_with_integrity(&key), 2000)
        .await
        .map(|(r, _)| r)
}

fn binding_answered(rt: &tokio::runtime::Runtime, target: SocketAddr) -> bool {
    rt.block_on(async {
        let s = bind_socket().await;
        send_recv(&s, target, &build_binding_request(), 800)
            .await
            .is_some()
    })
}

/// Three wrong passwords behind valid nonces ban the source: afterwards even an
/// unauthenticated Binding gets no answer, and the ban is counted.
#[test]
fn auto_ban_bans_after_repeated_auth_failures() {
    let Some(node) = boot(
        "",
        "",
        "[turn.auto_ban]\nenabled = true\nauth_failures = 3\nwindow_secs = 60\nban_secs = 600\n",
    ) else {
        return;
    };
    let rt = tokio::runtime::Runtime::new().unwrap();
    assert!(
        binding_answered(&rt, node.turn),
        "Binding answered before any failure"
    );

    let wrong = wrong_pw();
    let failures = rt.block_on(async {
        let s = bind_socket().await;
        let mut n = 0;
        for _ in 0..3 {
            if let Some(resp) = allocate_as(&s, node.turn, "testuser", &wrong).await {
                if extract_error_code(&resp).map(|(c, _)| c) == Some(401) {
                    n += 1;
                }
            }
        }
        n
    });
    assert_eq!(
        failures, 3,
        "each wrong password is answered with 401 until the ban"
    );

    assert!(
        !binding_answered(&rt, node.turn),
        "a banned source must get no answer at all, not even to a Binding"
    );
    assert!(metric_value(&node.health, "turna_autoban_bans_total") >= 1.0);
    assert!(metric_value(&node.health, "turna_autoban_dropped_total") >= 1.0);
}

/// Off by default: the same failures on a node without the section ban nobody.
#[test]
fn auto_ban_is_off_by_default() {
    let Some(node) = boot("", "", "") else {
        return;
    };
    let rt = tokio::runtime::Runtime::new().unwrap();
    let wrong = wrong_pw();
    rt.block_on(async {
        let s = bind_socket().await;
        for _ in 0..12 {
            let _ = allocate_as(&s, node.turn, "testuser", &wrong).await;
        }
    });
    assert!(binding_answered(&rt, node.turn));
    assert_eq!(metric_value(&node.health, "turna_autoban_bans_total"), 0.0);
}

/// Allocate as `testuser` and permit `peer`. Returns false on any failure.
pub(crate) async fn allocate_and_permit(
    socket: &UdpSocket,
    target: SocketAddr,
    peer: SocketAddr,
) -> bool {
    let Some((realm, nonce)) = challenge(socket, target).await else {
        return false;
    };
    let key = long_term_key("testuser", &realm, &test_pass());
    let mut alloc = TurnMsg::request(0x0003);
    alloc.add_requested_transport();
    alloc.add_lifetime(600);
    alloc.add_username("testuser");
    alloc.add_realm(&realm);
    alloc.add_nonce(&nonce);
    match send_recv(socket, target, &alloc.encode_with_integrity(&key), 2000).await {
        Some((resp, _)) if !is_error(&resp) => {}
        _ => return false,
    }
    let mut perm = TurnMsg::request(0x0008);
    perm.add_xor_peer_address(peer);
    perm.add_username("testuser");
    perm.add_realm(&realm);
    perm.add_nonce(&nonce);
    matches!(
        send_recv(socket, target, &perm.encode_with_integrity(&key), 2000).await,
        Some((resp, _)) if !is_error(&resp)
    )
}

fn send_indication(peer: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut m = TurnMsg::request(0x0006);
    m.class = 0x0010; // indication
    m.add_xor_peer_address(peer);
    m.add_attr(0x0013, payload);
    m.encode()
}

/// `max_total_bytes_per_sec`: a burst well past the cap reaches the peer only
/// in part, and the node counts what it dropped.
#[test]
fn node_wide_bandwidth_cap_drops_the_excess() {
    let Some(node) = boot("", "max_total_bytes_per_sec = 20000\n", "") else {
        return;
    };
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (sent, received) = rt.block_on(async {
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer.local_addr().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        assert!(
            allocate_and_permit(&client, node.turn, peer_addr).await,
            "allocation and permission must succeed"
        );
        // 100 x 1000 bytes = 100 kB at once against a 20 kB/s cap with a
        // one-second burst: roughly a fifth can pass.
        let payload = [0x5au8; 1000];
        for _ in 0..100 {
            client
                .send_to(&send_indication(peer_addr, &payload), node.turn)
                .await
                .unwrap();
        }
        let mut n = 0usize;
        let mut buf = [0u8; 2048];
        while let Ok(Ok((len, _))) =
            tokio::time::timeout(Duration::from_millis(500), peer.recv_from(&mut buf)).await
        {
            if len == 1000 {
                n += 1;
            }
        }
        (100usize, n)
    });
    assert!(received > 0, "the cap must not block everything");
    assert!(
        received < sent / 2,
        "{received} of {sent} packets passed a 20 kB/s cap in one burst"
    );
    assert!(metric_value(&node.health, "turna_relay_capacity_dropped_packets_total") >= 1.0);
    assert_eq!(
        metric_value(&node.health, "turna_relay_capacity_bytes_per_sec"),
        20000.0
    );
}

/// `require_binding_auth`: an anonymous Binding gets a 401, not an address.
#[test]
fn require_binding_auth_challenges_anonymous_binding() {
    let Some(node) = boot("[turn.auth]\nrequire_binding_auth = true\n", "", "") else {
        return;
    };
    let rt = tokio::runtime::Runtime::new().unwrap();
    let resp = rt.block_on(async {
        let s = bind_socket().await;
        send_recv(&s, node.turn, &build_binding_request(), 2000).await
    });
    let (resp, _) = resp.expect("a challenge, not silence");
    assert!(is_error(&resp));
    assert_eq!(extract_error_code(&resp).map(|(c, _)| c), Some(401));
    assert!(extract_xor_mapped_address(&resp).is_none());
}

/// And the default is unchanged: anonymous Binding is answered.
#[test]
fn binding_stays_anonymous_by_default() {
    let Some(node) = boot("", "", "") else {
        return;
    };
    let rt = tokio::runtime::Runtime::new().unwrap();
    let resp = rt.block_on(async {
        let s = bind_socket().await;
        send_recv(&s, node.turn, &build_binding_request(), 2000).await
    });
    let (resp, _) = resp.expect("a Binding response");
    assert!(is_success(&resp));
    assert!(extract_xor_mapped_address(&resp).is_some());
}

/// A minimal credential endpoint for `[turn.auth.webhook]`: `hookuser` is
/// found (by password), every other name is 404. Counts the requests it served.
fn webhook_stub(password: String) -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
    webhook_stub_delayed(password, Duration::ZERO)
}

/// As [`webhook_stub`], answering every name that starts with `hookuser` and
/// holding each answer for `delay` (a slow endpoint).
fn webhook_stub_delayed(
    password: String,
    delay: Duration,
) -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
    use std::io::{Read, Write};
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind stub");
    let url = format!("http://{}/turn/credentials", l.local_addr().unwrap());
    let hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let hits_out = hits.clone();
    std::thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { continue };
            let password = password.clone();
            let hits = hits.clone();
            std::thread::spawn(move || {
                let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                // Read headers, then the declared body.
                loop {
                    let n = s.read(&mut chunk).unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    let text = String::from_utf8_lossy(&buf).to_string();
                    if let Some(h) = text.find("\r\n\r\n") {
                        let cl = text
                            .lines()
                            .find_map(|l| {
                                l.to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                    .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                            })
                            .unwrap_or(0);
                        if buf.len() >= h + 4 + cl {
                            break;
                        }
                    }
                }
                hits.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let req = String::from_utf8_lossy(&buf);
                std::thread::sleep(delay);
                let (status, body) = if req.contains("\"username\":\"hookuser") {
                    ("200 OK", format!("{{\"password\":\"{password}\"}}"))
                } else {
                    ("404 Not Found", "{}".to_string())
                };
                let resp = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
                 Connection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = s.write_all(resp.as_bytes());
            });
        }
    });
    (url, hits_out)
}

/// Send `req` the way a STUN client does over UDP — retransmitting until an
/// answer arrives — and return the answer.
async fn with_retransmission(
    socket: &UdpSocket,
    target: SocketAddr,
    req: &[u8],
) -> Option<Vec<u8>> {
    for _ in 0..6 {
        if let Some((resp, _)) = send_recv(socket, target, req, 500).await {
            return Some(resp);
        }
    }
    None
}

/// `[turn.auth.webhook]` end to end: a user the node has never heard of is
/// looked up on the endpoint and allocates; an unknown one gets a 401; the
/// endpoint is asked once per user thanks to the cache.
#[test]
fn auth_webhook_resolves_unknown_users_through_the_endpoint() {
    let password = std::env::var("TURNA_TEST_PW_V1").expect("source .env.test");
    let (url, hits) = webhook_stub(password.clone());
    let Some(node) = boot_with_users(
        &format!("[turn.auth.webhook]\nenabled = true\nurl = \"{url}\"\ntimeout_ms = 1000\n"),
        "",
        "",
        false,
    ) else {
        return;
    };
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (ok, ghost, again) = rt.block_on(async {
        let s = bind_socket().await;
        let (realm, nonce) = challenge(&s, node.turn).await.expect("challenge");
        let build = |user: &str, pass: &str| {
            let key = long_term_key(user, &realm, pass);
            let mut m = TurnMsg::request(0x0003);
            m.add_requested_transport();
            m.add_lifetime(600);
            m.add_username(user);
            m.add_realm(&realm);
            m.add_nonce(&nonce);
            m.encode_with_integrity(&key)
        };
        let ok = with_retransmission(&s, node.turn, &build("hookuser", &password)).await;
        let ghost_sock = bind_socket().await;
        let (realm2, nonce2) = challenge(&ghost_sock, node.turn).await.expect("challenge");
        let key = long_term_key("ghost", &realm2, &password);
        let mut g = TurnMsg::request(0x0003);
        g.add_requested_transport();
        g.add_username("ghost");
        g.add_realm(&realm2);
        g.add_nonce(&nonce2);
        let ghost =
            with_retransmission(&ghost_sock, node.turn, &g.encode_with_integrity(&key)).await;
        // A second allocation for the same user from another socket is served
        // from the cache: no new request to the endpoint.
        let other = bind_socket().await;
        let (realm3, nonce3) = challenge(&other, node.turn).await.expect("challenge");
        let key = long_term_key("hookuser", &realm3, &password);
        let mut a = TurnMsg::request(0x0003);
        a.add_requested_transport();
        a.add_username("hookuser");
        a.add_realm(&realm3);
        a.add_nonce(&nonce3);
        let again = send_recv(&other, node.turn, &a.encode_with_integrity(&key), 2000)
            .await
            .map(|(r, _)| r);
        (ok, ghost, again)
    });
    let ok = ok.expect("the webhook user must be answered after at most a retransmission");
    assert!(is_success(&ok), "allocation for a webhook-resolved user");
    let ghost = ghost.expect("an unknown user is answered");
    assert_eq!(extract_error_code(&ghost).map(|(c, _)| c), Some(401));
    let again = again.expect("the cached user is answered on the first try");
    assert!(is_success(&again));
    assert_eq!(
        hits.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "one endpoint request per user: hookuser and ghost"
    );
    std::thread::sleep(Duration::from_millis(5_500)); // cache counters mirror every 5 s
    assert!(metric_value(&node.health, "turna_auth_webhook_requests_total") >= 2.0);
    assert!(metric_value(&node.health, "turna_auth_webhook_cache_hits_total") >= 1.0);
    assert!(metric_value(&node.health, "turna_auth_webhook_not_found_total") >= 1.0);
}

/// Fail closed: an endpoint that is down refuses the user (500), it does not
/// let them in and it does not pretend they are unknown.
#[test]
fn auth_webhook_fails_closed_when_the_endpoint_is_down() {
    let dead = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let Some(node) = boot_with_users(
        &format!(
            "[turn.auth.webhook]\nenabled = true\nurl = \"http://127.0.0.1:{dead}/x\"\n\
             timeout_ms = 300\nerror_ttl_secs = 30\n"
        ),
        "",
        "",
        false,
    ) else {
        return;
    };
    let password = std::env::var("TURNA_TEST_PW_V1").expect("source .env.test");
    let rt = tokio::runtime::Runtime::new().unwrap();
    let resp = rt.block_on(async {
        let s = bind_socket().await;
        let (realm, nonce) = challenge(&s, node.turn).await.expect("challenge");
        let key = long_term_key("hookuser", &realm, &password);
        let mut m = TurnMsg::request(0x0003);
        m.add_requested_transport();
        m.add_username("hookuser");
        m.add_realm(&realm);
        m.add_nonce(&nonce);
        with_retransmission(&s, node.turn, &m.encode_with_integrity(&key)).await
    });
    let resp = resp.expect("a refusal, not silence");
    assert_eq!(extract_error_code(&resp).map(|(c, _)| c), Some(500));
    assert!(metric_value(&node.health, "turna_auth_webhook_unavailable_total") >= 1.0);
}

/// The OAuth verification kit against a node with `[turn.auth.oauth]`
/// (production = false): tokens it mints are accepted through Allocate,
/// Refresh, CreatePermission and release, responses are signed with the
/// token's mac_key, and tampered, wrong-key, expired and other-server tokens
/// are refused. This is the kit's `selftest`; it proves the plumbing, not
/// interop with a real authorization server (docs/runbooks/oauth-verification.md).
#[test]
fn oauth_verification_kit_selftest_passes_against_the_node() {
    use turna_oauth_verify::{exercise, expect_refused, mint, now_secs, to_hex, ExerciseOptions};
    let as_rs: [u8; 32] = rand::random();
    let Some(node) = boot_with_users(
        &format!(
            "[turn.auth.oauth]\nenabled = true\nserver_name = \"turn.test\"\n\
             as_rs_keys = [\"{}\"]\n",
            to_hex(&as_rs)
        ),
        "",
        "",
        false,
    ) else {
        return;
    };
    let timeout = Duration::from_millis(1000);
    for (mac_len, sha256) in [(20usize, false), (32, true)] {
        let m = mint(&as_rs, "turn.test", mac_len, now_secs(), 600).unwrap();
        let steps = exercise(&ExerciseOptions {
            server: node.turn,
            token: m.token,
            mac_key: m.mac_key,
            kid: None,
            sha256,
            peer: "8.8.8.8".parse().unwrap(),
            timeout,
            negative: true,
        });
        let failed: Vec<String> = steps
            .iter()
            .filter(|s| !s.ok)
            .map(|s| s.to_string())
            .collect();
        assert!(
            failed.is_empty() && steps.len() >= 7,
            "kit steps failed:\n{}",
            failed.join("\n")
        );
    }
    let expired = mint(&as_rs, "turn.test", 20, now_secs() - 7_200, 60).unwrap();
    let s = expect_refused(
        node.turn,
        timeout,
        &expired.token,
        &expired.mac_key,
        "expired",
    );
    assert!(s.ok, "{s}");
    let other = mint(&as_rs, "elsewhere.test", 20, now_secs(), 600).unwrap();
    let s = expect_refused(
        node.turn,
        timeout,
        &other.token,
        &other.mac_key,
        "other server",
    );
    assert!(s.ok, "{s}");
}

/// A TURNS client driven through `openssl s_client`: STUN messages in, STUN
/// messages out. `None` when openssl is not installed.
struct TlsClient {
    child: std::process::Child,
    stdin: std::process::ChildStdin,
    rx: std::sync::mpsc::Receiver<Vec<u8>>,
}

impl TlsClient {
    fn connect(addr: SocketAddr) -> Option<Self> {
        use std::io::Read;
        let mut child = std::process::Command::new("openssl")
            .args([
                "s_client",
                "-connect",
                &addr.to_string(),
                "-quiet",
                "-nocommands",
                "-verify_quiet",
            ])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .ok()?;
        let stdin = child.stdin.take()?;
        let mut stdout = child.stdout.take()?;
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || loop {
            // STUN framing: 20-byte header whose bytes 2..4 are the body length.
            let mut h = [0u8; 20];
            if stdout.read_exact(&mut h).is_err() {
                return;
            }
            let len = u16::from_be_bytes([h[2], h[3]]) as usize;
            let mut body = vec![0u8; len];
            if stdout.read_exact(&mut body).is_err() {
                return;
            }
            let mut msg = h.to_vec();
            msg.extend(body);
            if tx.send(msg).is_err() {
                return;
            }
        });
        Some(Self { child, stdin, rx })
    }

    fn transact(&mut self, msg: &[u8], timeout: Duration) -> Option<Vec<u8>> {
        use std::io::Write;
        self.stdin.write_all(msg).ok()?;
        self.stdin.flush().ok()?;
        self.rx.recv_timeout(timeout).ok()
    }

    fn send(&mut self, msg: &[u8]) {
        use std::io::Write;
        let _ = self.stdin.write_all(msg);
        let _ = self.stdin.flush();
    }
}

impl Drop for TlsClient {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// TURNS with a slow credential endpoint: a parked Allocate is answered once
/// the lookup completes (a TCP client never retransmits), and one whose
/// connection closes while it is parked leaves no allocation behind.
#[test]
fn auth_webhook_over_turns_answers_parked_requests_and_forgets_closed_ones() {
    let password = std::env::var("TURNA_TEST_PW_V1").expect("source .env.test");
    let (url, hits) = webhook_stub_delayed(password.clone(), Duration::from_millis(1500));
    let dir = std::env::temp_dir().join(format!("turna-aa-tls-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cert = dir.join("cert.pem");
    let key = dir.join("key.pem");
    let ok = std::process::Command::new("openssl")
        .args([
            "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-keyout",
        ])
        .arg(&key)
        .arg("-out")
        .arg(&cert)
        .args(["-subj", "/CN=localhost"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !ok {
        eprintln!("skipping: openssl not available");
        return;
    }
    let tls_port = free_port(false);
    let Some(node) = boot_with_users(
        &format!("[turn.auth.webhook]\nenabled = true\nurl = \"{url}\"\ntimeout_ms = 5000\n"),
        "",
        &format!(
            "[tls]\nenabled = true\nlisten = \"127.0.0.1:{tls_port}\"\ncert_path = \"{}\"\n\
             key_path = \"{}\"\n",
            cert.display(),
            key.display()
        ),
        false,
    ) else {
        return;
    };
    let tls: SocketAddr = format!("127.0.0.1:{tls_port}").parse().unwrap();
    let t = Duration::from_secs(3);

    let authed = |c: &mut TlsClient, user: &str| -> Option<Vec<u8>> {
        let mut probe = TurnMsg::request(0x0003);
        probe.add_requested_transport();
        let r = c.transact(&probe.encode(), t)?;
        let (realm, nonce) = (extract_realm(&r)?, extract_nonce(&r)?);
        let k = long_term_key(user, &realm, &password);
        let mut m = TurnMsg::request(0x0003);
        m.add_requested_transport();
        m.add_lifetime(600);
        m.add_username(user);
        m.add_realm(&realm);
        m.add_nonce(&nonce);
        Some(m.encode_with_integrity(&k))
    };

    // B: parked, then its connection closes before the endpoint answers.
    let Some(mut b) = TlsClient::connect(tls) else {
        eprintln!("skipping: openssl s_client unavailable");
        return;
    };
    let req_b = authed(&mut b, "hookuser-b").expect("challenge over TURNS");
    b.send(&req_b);
    std::thread::sleep(Duration::from_millis(300));
    drop(b);

    // A: parked, connection kept, answered when the lookup lands.
    let mut a = TlsClient::connect(tls).expect("second TLS client");
    let req_a = authed(&mut a, "hookuser-a").expect("challenge over TURNS");
    let resp = a
        .transact(&req_a, Duration::from_secs(5))
        .expect("the parked Allocate is answered without a retransmission");
    assert!(
        is_success(&resp),
        "allocation for the webhook user over TURNS"
    );

    // Past B's lookup completing: its re-injected request must have been dropped.
    std::thread::sleep(Duration::from_millis(2500));
    assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 2);
    assert_eq!(
        metric_value(&node.health, "turna_active_allocations"),
        1.0,
        "only the open connection holds an allocation"
    );
    drop(a);
    let _ = std::fs::remove_dir_all(&dir);
}
