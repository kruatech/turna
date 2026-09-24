//! RFC 7635 OAuth verification kit — the library behind `turna-oauth-verify`.
//!
//! turna implements third-party authorization (RFC 7635) and refuses it under
//! `production = true` until it has been verified against a real authorization
//! server (`docs/PRODUCTION_READINESS.md` R9, `docs/OPEN-DECISIONS.md`
//! "OAuth"). This kit makes that verification mechanical; the procedure is
//! `docs/runbooks/oauth-verification.md`.
//!
//! - [`mint`] seals a self-contained token exactly as an AS does
//!   (`turna_auth::oauth_token`), for a self-test of the node's OAuth path.
//! - [`inspect`] opens a token *your* AS minted with turna's own decoder, so a
//!   format disagreement shows up before any packet is sent.
//! - [`exercise`] runs the full client flow against a live node over UDP:
//!   the 401 with THIRD-PARTY-AUTHORIZATION, an Allocate carrying
//!   ACCESS-TOKEN and MESSAGE-INTEGRITY keyed with the token's `mac_key`, a
//!   response signed with that key (RFC 7635 §9), Refresh (capped at the token's
//!   remaining lifetime, §6.1), CreatePermission, the negative cases, and the
//!   release.
//!
//! Evidence for lifting the gate is `exercise` passing with a token and
//! `mac_key` issued by the real AS. `mint` + `exercise` (the `selftest`
//! subcommand) proves only that the node and this kit agree with each other.

use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use turna_auth::oauth_token::{encode_access_token, inspect_access_token, TokenContents};
use turna_proto_stun::attribute::Attribute;
use turna_proto_stun::header::MessageClass;
use turna_proto_stun::message::StunMessage;
use turna_proto_stun::method::Method;

/// Seconds since the Unix epoch.
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A token as an AS would hand it to a client (RFC 7635 §4.1): the token and
/// the session key the client signs with.
#[derive(Debug, Clone)]
pub struct Minted {
    pub token: Vec<u8>,
    pub mac_key: Vec<u8>,
    pub timestamp_secs: u64,
    pub lifetime: u32,
}

/// Mint a token under `as_rs_key` for `server_name`, with a fresh random
/// `mac_key` of `mac_key_len` bytes (20 for HMAC-SHA-1, 32 for HMAC-SHA-256)
/// and a fresh GCM nonce.
pub fn mint(
    as_rs_key: &[u8],
    server_name: &str,
    mac_key_len: usize,
    timestamp_secs: u64,
    lifetime: u32,
) -> Result<Minted, String> {
    if !(1..=32).contains(&mac_key_len) {
        return Err("mac key length must be 1..=32 bytes".into());
    }
    let mac_key = turna_crypto::random_key_32()[..mac_key_len].to_vec();
    let nonce: [u8; 12] = turna_crypto::random_key_32()[..12]
        .try_into()
        .expect("12 of 32 bytes");
    let token = encode_access_token(
        as_rs_key,
        server_name,
        &nonce,
        &TokenContents {
            mac_key: mac_key.clone(),
            timestamp_secs,
            lifetime,
        },
    )
    .map_err(|e| format!("cannot mint: {e} (AS-RS key must be 16 or 32 bytes)"))?;
    Ok(Minted {
        token,
        mac_key,
        timestamp_secs,
        lifetime,
    })
}

/// Open `token` with turna's decoder and describe it. `Err` carries the
/// reason turna would refuse it.
pub fn inspect(token: &[u8], as_rs_keys: &[Vec<u8>], server_name: &str) -> Result<String, String> {
    let c = inspect_access_token(token, as_rs_keys, server_name).map_err(|_| {
        "turna cannot open this token: wrong AS-RS key, wrong server_name (it is \
         the AEAD associated data), or a layout other than RFC 7635 §6.2 \
         (u16 nonce_len | nonce | AES-GCM{ u16 key_len | mac_key | u64 timestamp \
         | u32 lifetime } | tag)"
            .to_string()
    })?;
    let now = now_secs();
    let end = c.timestamp_secs.saturating_add(c.lifetime as u64);
    let skew = now as i64 - c.timestamp_secs as i64;
    let mut out = format!(
        "mac_key: {} bytes ({})\ntimestamp: {} (issued {}s {} this host's clock)\nlifetime: {}s\n",
        c.mac_key.len(),
        match c.mac_key.len() {
            20 => "HMAC-SHA-1 size",
            32 => "HMAC-SHA-256 size",
            _ => "unusual size",
        },
        c.timestamp_secs,
        skew.unsigned_abs(),
        if skew >= 0 { "before" } else { "AFTER" },
        c.lifetime,
    );
    if now >= end.saturating_add(5) {
        out.push_str(&format!(
            "status: EXPIRED {}s ago — turna would answer 401\n",
            now - end
        ));
    } else if skew < -5 {
        out.push_str(
            "status: dated in the future beyond the 5 s skew allowance — check the AS clock\n",
        );
    } else {
        out.push_str(&format!(
            "status: valid for another {}s\n",
            end.saturating_sub(now)
        ));
    }
    Ok(out)
}

/// USERNAME sent when no `--kid` is given.
pub const NO_KID: &str = "turna-oauth-verify";

/// What [`exercise`] needs.
#[derive(Debug, Clone)]
pub struct ExerciseOptions {
    pub server: SocketAddr,
    pub token: Vec<u8>,
    pub mac_key: Vec<u8>,
    /// Sent as USERNAME for RFC 7635 §6.1 key selection
    /// (`[[turn.auth.oauth.keys]]`). `None` sends [`NO_KID`].
    pub kid: Option<String>,
    /// Sign with MESSAGE-INTEGRITY-SHA256 instead of the RFC 5389 SHA-1 variant.
    pub sha256: bool,
    /// Peer for the CreatePermission step. Nothing is sent to it.
    pub peer: IpAddr,
    /// Per-transaction timeout (three attempts each).
    pub timeout: Duration,
    /// Also run the cases that must be refused.
    pub negative: bool,
}

/// One step's outcome.
#[derive(Debug, Clone)]
pub struct Step {
    pub name: &'static str,
    pub ok: bool,
    pub detail: String,
}

impl std::fmt::Display for Step {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "  {}  {:<32} {}",
            if self.ok { "PASS" } else { "FAIL" },
            self.name,
            self.detail
        )
    }
}

fn step(name: &'static str, ok: bool, detail: impl Into<String>) -> Step {
    Step {
        name,
        ok,
        detail: detail.into(),
    }
}

/// One UDP client with STUN retransmission.
struct Client {
    sock: UdpSocket,
    server: SocketAddr,
    timeout: Duration,
}

impl Client {
    fn new(server: SocketAddr, timeout: Duration) -> Result<Self, String> {
        let bind: SocketAddr = if server.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };
        let sock = UdpSocket::bind(bind).map_err(|e| format!("bind: {e}"))?;
        sock.set_read_timeout(Some(timeout))
            .map_err(|e| format!("socket: {e}"))?;
        Ok(Self {
            sock,
            server,
            timeout,
        })
    }

    /// Send and wait for the response with the same transaction id; three
    /// attempts. Returns the raw bytes.
    fn transact(&self, raw: &[u8], tid: [u8; 12]) -> Option<Vec<u8>> {
        let mut buf = [0u8; 2048];
        for _ in 0..3 {
            self.sock.send_to(raw, self.server).ok()?;
            let deadline = std::time::Instant::now() + self.timeout;
            while std::time::Instant::now() < deadline {
                match self.sock.recv_from(&mut buf) {
                    Ok((n, from)) if from == self.server => {
                        if n >= 20 && buf[8..20] == tid {
                            return Some(buf[..n].to_vec());
                        }
                    }
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
        }
        None
    }
}

fn error_code(m: &StunMessage) -> Option<u16> {
    m.attributes.iter().find_map(|a| match a {
        Attribute::ErrorCode { code, .. } => Some(*code),
        _ => None,
    })
}

fn lifetime_of(m: &StunMessage) -> Option<u32> {
    m.attributes.iter().find_map(|a| match a {
        Attribute::Lifetime(l) => Some(*l),
        _ => None,
    })
}

fn relayed(m: &StunMessage) -> Option<SocketAddr> {
    m.attributes.iter().find_map(|a| match a {
        Attribute::XorRelayedAddress(x) => Some(*x),
        _ => None,
    })
}

fn describe(m: &StunMessage) -> String {
    match m.class {
        MessageClass::SuccessResponse => "success".into(),
        MessageClass::ErrorResponse => match error_code(m) {
            Some(c) => format!("error {c}"),
            None => "error (no code)".into(),
        },
        _ => "unexpected class".into(),
    }
}

/// Everything the authenticated requests share.
struct Session<'a> {
    opts: &'a ExerciseOptions,
    realm: String,
    nonce: String,
}

impl Session<'_> {
    /// Build and sign `m` with the OAuth credentials, send it, and return the
    /// decoded response plus whether its MESSAGE-INTEGRITY verified with
    /// `mac_key`. A 438 is retried once with the fresh nonce.
    fn send(
        &mut self,
        client: &Client,
        method: Method,
        extra: &[Attribute],
        token: &[u8],
        key: &[u8],
    ) -> Result<(StunMessage, bool), String> {
        for _ in 0..2 {
            let mut m = StunMessage::new(method, MessageClass::Request);
            for a in extra {
                m.add(a.clone());
            }
            // RFC 7635 §6.1: the client carries the token's `kid` in USERNAME.
            // turna's processor challenges any request without a USERNAME, so
            // one is always sent; without a kid the node trial-decrypts across
            // its keyring (unless `strict_kid` is on, which then refuses it).
            m.add(Attribute::Username(
                self.opts.kid.clone().unwrap_or_else(|| NO_KID.to_string()),
            ));
            m.add(Attribute::Realm(self.realm.clone()));
            m.add(Attribute::Nonce(self.nonce.clone()));
            m.add(Attribute::AccessToken(token.to_vec()));
            let mut buf = [0u8; 2048];
            let n = if self.opts.sha256 {
                m.encode_with_integrity_sha256(&mut buf, key)
            } else {
                m.encode_with_integrity(&mut buf, key)
            }
            .map_err(|e| format!("encode: {e}"))?;
            let raw = client
                .transact(&buf[..n], m.transaction_id)
                .ok_or("no response (timeout)")?;
            let resp = StunMessage::decode(&raw).map_err(|e| format!("decode: {e}"))?;
            if error_code(&resp) == Some(438) {
                if let Some(n) = resp.get_nonce() {
                    self.nonce = n.to_string();
                    continue;
                }
            }
            let signed = if resp.get_message_integrity_sha256().is_some() {
                resp.verify_integrity_sha256(&raw, &self.opts.mac_key)
            } else if resp.get_message_integrity().is_some() {
                resp.verify_integrity(&raw, &self.opts.mac_key)
            } else {
                false
            };
            return Ok((resp, signed));
        }
        Err("stale nonce twice".into())
    }
}

/// Unauthenticated Allocate: the 401 challenge with REALM, NONCE and
/// THIRD-PARTY-AUTHORIZATION.
fn challenge(client: &Client) -> Result<(String, String, Option<String>), String> {
    let mut m = StunMessage::new(Method::Allocate, MessageClass::Request);
    m.add(Attribute::RequestedTransport(17));
    let mut buf = [0u8; 256];
    let n = m.encode(&mut buf).map_err(|e| format!("encode: {e}"))?;
    let raw = client
        .transact(&buf[..n], m.transaction_id)
        .ok_or("no response to an unauthenticated Allocate (is the node listening?)")?;
    let r = StunMessage::decode(&raw).map_err(|e| format!("decode: {e}"))?;
    if error_code(&r) != Some(401) {
        return Err(format!("expected 401, got {}", describe(&r)));
    }
    let realm = r.get_realm().ok_or("401 without REALM")?.to_string();
    let nonce = r.get_nonce().ok_or("401 without NONCE")?.to_string();
    let tpa = r
        .get_third_party_authorization()
        .map(|v| String::from_utf8_lossy(v).into_owned());
    Ok((realm, nonce, tpa))
}

/// Run the full client flow against a live node. Every step is reported; the
/// run passed when every step has `ok`.
pub fn exercise(opts: &ExerciseOptions) -> Vec<Step> {
    let mut steps = Vec::new();
    let client = match Client::new(opts.server, opts.timeout) {
        Ok(c) => c,
        Err(e) => {
            steps.push(step("socket", false, e));
            return steps;
        }
    };

    // 1. The challenge.
    let (realm, nonce) = match challenge(&client) {
        Ok((realm, nonce, tpa)) => {
            let ok = tpa.is_some();
            steps.push(step(
                "401 THIRD-PARTY-AUTHORIZATION",
                ok,
                match tpa {
                    Some(t) => format!("realm {realm:?}, authorization server {t:?}"),
                    None => format!(
                        "realm {realm:?} but no THIRD-PARTY-AUTHORIZATION: the base realm \
                         is not in OAuth mode ([turn.auth.oauth] enabled = true?)"
                    ),
                },
            ));
            (realm, nonce)
        }
        Err(e) => {
            steps.push(step("401 THIRD-PARTY-AUTHORIZATION", false, e));
            return steps;
        }
    };
    let mut s = Session { opts, realm, nonce };

    // 2. Allocate with the token.
    let alloc = s.send(
        &client,
        Method::Allocate,
        &[Attribute::RequestedTransport(17), Attribute::Lifetime(600)],
        &opts.token,
        &opts.mac_key,
    );
    let allocated = match alloc {
        Ok((r, signed)) if matches!(r.class, MessageClass::SuccessResponse) => {
            steps.push(step(
                "Allocate with ACCESS-TOKEN",
                relayed(&r).is_some(),
                format!(
                    "relayed {:?}, lifetime {:?}s (capped by the token's remaining life, §6.1)",
                    relayed(&r),
                    lifetime_of(&r)
                ),
            ));
            steps.push(step(
                "response signed with mac_key",
                signed,
                if signed {
                    "MESSAGE-INTEGRITY verifies with the token's mac_key (§9)"
                } else {
                    "the success response is not signed with mac_key"
                },
            ));
            true
        }
        Ok((r, _)) => {
            steps.push(step(
                "Allocate with ACCESS-TOKEN",
                false,
                format!(
                    "{} — 401 means the node could not open or validate the token: \
                     run `inspect` with the node's AS-RS key and server_name",
                    describe(&r)
                ),
            ));
            false
        }
        Err(e) => {
            steps.push(step("Allocate with ACCESS-TOKEN", false, e));
            false
        }
    };
    if !allocated {
        return steps;
    }

    // 3. Refresh.
    match s.send(
        &client,
        Method::Refresh,
        &[Attribute::Lifetime(600)],
        &opts.token,
        &opts.mac_key,
    ) {
        Ok((r, signed)) => steps.push(step(
            "Refresh",
            matches!(r.class, MessageClass::SuccessResponse) && signed,
            format!("{}, lifetime {:?}s", describe(&r), lifetime_of(&r)),
        )),
        Err(e) => steps.push(step("Refresh", false, e)),
    }

    // 4. CreatePermission.
    match s.send(
        &client,
        Method::CreatePermission,
        &[Attribute::XorPeerAddress(SocketAddr::new(opts.peer, 9))],
        &opts.token,
        &opts.mac_key,
    ) {
        Ok((r, signed)) => steps.push(step(
            "CreatePermission",
            matches!(r.class, MessageClass::SuccessResponse) && signed,
            format!(
                "{} for {} (403 here is the peer filter, not OAuth — pass --peer)",
                describe(&r),
                opts.peer
            ),
        )),
        Err(e) => steps.push(step("CreatePermission", false, e)),
    }

    // 5. What must be refused.
    if opts.negative {
        let mut tampered = opts.token.clone();
        if let Some(last) = tampered.last_mut() {
            *last ^= 0x01;
        }
        match s.send(
            &client,
            Method::Refresh,
            &[Attribute::Lifetime(600)],
            &tampered,
            &opts.mac_key,
        ) {
            Ok((r, _)) => steps.push(step(
                "tampered token refused",
                error_code(&r) == Some(401),
                describe(&r),
            )),
            Err(e) => steps.push(step("tampered token refused", false, e)),
        }
        let wrong_key: Vec<u8> = opts.mac_key.iter().map(|b| b ^ 0x5a).collect();
        match s.send(
            &client,
            Method::Refresh,
            &[Attribute::Lifetime(600)],
            &opts.token,
            &wrong_key,
        ) {
            Ok((r, _)) => steps.push(step(
                "wrong mac_key refused",
                error_code(&r) == Some(401),
                describe(&r),
            )),
            Err(e) => steps.push(step("wrong mac_key refused", false, e)),
        }
    }

    // 6. Release.
    match s.send(
        &client,
        Method::Refresh,
        &[Attribute::Lifetime(0)],
        &opts.token,
        &opts.mac_key,
    ) {
        Ok((r, _)) => steps.push(step(
            "release (Refresh 0)",
            matches!(r.class, MessageClass::SuccessResponse),
            describe(&r),
        )),
        Err(e) => steps.push(step("release (Refresh 0)", false, e)),
    }
    steps
}

/// A token the node must refuse on its own terms: an Allocate with it should
/// get a 401. Used by `selftest` for expired and wrong-server tokens.
pub fn expect_refused(
    server: SocketAddr,
    timeout: Duration,
    token: &[u8],
    mac_key: &[u8],
    name: &'static str,
) -> Step {
    let client = match Client::new(server, timeout) {
        Ok(c) => c,
        Err(e) => return step(name, false, e),
    };
    let (realm, nonce) = match challenge(&client) {
        Ok((r, n, _)) => (r, n),
        Err(e) => return step(name, false, e),
    };
    let opts = ExerciseOptions {
        server,
        token: token.to_vec(),
        mac_key: mac_key.to_vec(),
        kid: None,
        sha256: false,
        peer: "8.8.8.8".parse().unwrap(),
        timeout,
        negative: false,
    };
    let mut s = Session {
        opts: &opts,
        realm,
        nonce,
    };
    match s.send(
        &client,
        Method::Allocate,
        &[Attribute::RequestedTransport(17)],
        token,
        mac_key,
    ) {
        Ok((r, _)) => step(name, error_code(&r) == Some(401), describe(&r)),
        Err(e) => step(name, false, e),
    }
}

/// Parse hex (whitespace ignored).
pub fn parse_hex(s: &str) -> Result<Vec<u8>, String> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if !s.len().is_multiple_of(2) || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("not hex".into());
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

/// Parse base64, standard or URL-safe, padded or not — ASes differ.
pub fn parse_b64(s: &str) -> Result<Vec<u8>, String> {
    use base64::Engine;
    let s = s.trim();
    let engines = [
        &base64::engine::general_purpose::STANDARD,
        &base64::engine::general_purpose::STANDARD_NO_PAD,
        &base64::engine::general_purpose::URL_SAFE,
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
    ];
    engines
        .iter()
        .find_map(|e| e.decode(s).ok())
        .ok_or_else(|| "not base64".to_string())
}

pub fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn to_b64(b: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minted_token_inspects_as_valid() {
        let as_rs = turna_crypto::random_key_32().to_vec();
        let m = mint(&as_rs, "turn.example", 20, now_secs(), 600).unwrap();
        let report = inspect(&m.token, std::slice::from_ref(&as_rs), "turn.example").unwrap();
        assert!(report.contains("mac_key: 20 bytes"), "{report}");
        assert!(report.contains("status: valid"), "{report}");
        assert!(inspect(&m.token, &[as_rs], "wrong.example").is_err());
    }

    #[test]
    fn expired_tokens_are_reported_as_such() {
        let as_rs = turna_crypto::random_key_32()[..16].to_vec();
        let m = mint(&as_rs, "s", 32, now_secs() - 3_600, 60).unwrap();
        let report = inspect(&m.token, &[as_rs], "s").unwrap();
        assert!(report.contains("EXPIRED"), "{report}");
    }

    #[test]
    fn encodings_parse() {
        assert_eq!(parse_hex("0a ff").unwrap(), vec![0x0a, 0xff]);
        assert!(parse_hex("0g").is_err());
        let raw = vec![0xfb, 0xff, 0x01];
        assert_eq!(parse_b64(&to_b64(&raw)).unwrap(), raw);
        assert_eq!(parse_b64("-_8B").unwrap(), raw, "url-safe, no padding");
    }
}
