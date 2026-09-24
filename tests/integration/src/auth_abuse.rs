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
