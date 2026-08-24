//! Peer-address normalization and filtering (the coturn CVE class).
//!
//! Two responsibilities, applied at every point where a peer address enters
//! the relay (CreatePermission, ChannelBind, Send indication, and relay
//! recv):
//!
//! 1. **Normalize** `::ffff:a.b.c.d` (IPv4-mapped IPv6) down to a plain IPv4
//!    address so that a single representation is stored and checked. Without
//!    this, a deny rule on `127.0.0.0/8` is trivially bypassed with
//!    `::ffff:127.0.0.1` — the exact bypass coturn fixed in CVE-2026-27624.
//!
//! 2. **Filter** the (normalized) peer address through a [`PeerPolicy`].
//!    Special-use ranges (RFC 6890) — loopback, link-local incl. the cloud
//!    metadata endpoint `169.254.169.254`, multicast, unspecified, IPv4
//!    broadcast, `0.0.0.0/8` — are **always** denied: they are never a valid
//!    relay peer. On top of that the policy decides what to do with private
//!    (RFC 1918 / ULA) ranges and any operator-supplied allow/deny CIDR lists.
//!
//! ## Policy (M1)
//!
//! The active policy is installed once at startup with [`init_peer_policy`]
//! from `[turn.peer_filter]` config. Until then (and in unit tests) the
//! **secure default** applies: profile `internet-facing`, which denies
//! RFC 1918 / ULA peers. LAN relaying is an explicit opt-in
//! (`profile = "lan"`). This is a deliberate change from the previous
//! "private allowed by default" behaviour — see `docs/security/peer-filter.md`.
//!
//! Loopback relaying stays gated behind an explicit opt-in
//! (`allow_loopback_peers = true`, or `TURNA_ALLOW_LOOPBACK_PEERS=1`) for
//! local development and test rigs. The allow-list **cannot** re-enable the
//! hardcoded special-use denies above (loopback excepted, via its own flag).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::OnceLock;

use tracing::warn;

/// Collapse an IPv4-mapped IPv6 address to its canonical IPv4 form.
/// Everything else is returned unchanged.
#[inline]
pub fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

/// Normalize the IP portion of a socket address, keeping the port.
#[inline]
pub fn normalize_addr(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(normalize_ip(addr.ip()), addr.port())
}

// ---------------------------------------------------------------------------
// CIDR matching (no external dependency)
// ---------------------------------------------------------------------------

/// A parsed CIDR range, e.g. `10.0.0.0/8` or `fc00::/7`.
#[derive(Debug, Clone)]
struct Cidr {
    addr: IpAddr,
    prefix: u8,
}

impl Cidr {
    /// Parse `"<ip>/<prefix>"`. Returns `None` on a malformed range or an
    /// out-of-bounds prefix (so callers can warn-and-skip).
    fn parse(s: &str) -> Option<Cidr> {
        let (ip_str, pfx_str) = s.trim().split_once('/')?;
        let addr: IpAddr = ip_str.trim().parse().ok()?;
        let prefix: u8 = pfx_str.trim().parse().ok()?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        if prefix > max {
            return None;
        }
        Some(Cidr { addr, prefix })
    }

    fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => masked_eq_v4(net, ip, self.prefix),
            (IpAddr::V6(net), IpAddr::V6(ip)) => masked_eq_v6(net, ip, self.prefix),
            // Family mismatch never matches (peer is already normalized).
            _ => false,
        }
    }
}

fn masked_eq_v4(net: Ipv4Addr, ip: Ipv4Addr, prefix: u8) -> bool {
    if prefix == 0 {
        return true;
    }
    let mask: u32 = u32::MAX << (32 - prefix as u32);
    (u32::from(net) & mask) == (u32::from(ip) & mask)
}

fn masked_eq_v6(net: Ipv6Addr, ip: Ipv6Addr, prefix: u8) -> bool {
    if prefix == 0 {
        return true;
    }
    let mask: u128 = u128::MAX << (128 - prefix as u32);
    (u128::from(net) & mask) == (u128::from(ip) & mask)
}

// ---------------------------------------------------------------------------
// Peer policy
// ---------------------------------------------------------------------------

/// Decides whether a (normalized) peer address may be relayed to.
#[derive(Debug, Clone)]
pub struct PeerPolicy {
    /// Deny RFC 1918 / ULA peers (the `internet-facing` profile).
    deny_private: bool,
    /// Allow loopback peers (dev/test only).
    allow_loopback: bool,
    /// Operator deny list, applied on top of the profile.
    denied: Vec<Cidr>,
    /// Operator allow list. Takes precedence over `deny_private` and the deny
    /// list, but NOT over the hardcoded special-use denies.
    allowed: Vec<Cidr>,
}

impl Default for PeerPolicy {
    /// Secure default used before [`init_peer_policy`] runs and in tests:
    /// internet-facing (private ranges denied).
    fn default() -> Self {
        Self::internet_facing()
    }
}

impl PeerPolicy {
    /// Internet-facing: deny RFC 1918 / ULA peers (secure default).
    pub fn internet_facing() -> Self {
        Self {
            deny_private: true,
            allow_loopback: env_allow_loopback(),
            denied: Vec::new(),
            allowed: Vec::new(),
        }
    }

    /// LAN / trusted perimeter: allow private peers (explicit opt-in).
    pub fn lan() -> Self {
        Self {
            deny_private: false,
            allow_loopback: env_allow_loopback(),
            denied: Vec::new(),
            allowed: Vec::new(),
        }
    }

    /// Build a policy from `[turn.peer_filter]` config primitives. Unknown
    /// profiles fall back to the secure `internet-facing` behaviour.
    /// Unparseable CIDRs are skipped with a warning (config validation should
    /// have rejected them already).
    pub fn from_config(
        profile: &str,
        allow_loopback_peers: bool,
        denied_peer_ranges: &[String],
        allowed_peer_ranges: &[String],
    ) -> Self {
        let deny_private = match profile.trim().to_ascii_lowercase().as_str() {
            "lan" | "trusted" => false,
            // "internet-facing" and anything unrecognised → secure default.
            _ => true,
        };
        Self {
            deny_private,
            allow_loopback: allow_loopback_peers || env_allow_loopback(),
            denied: parse_ranges(denied_peer_ranges, "denied_peer_ranges"),
            allowed: parse_ranges(allowed_peer_ranges, "allowed_peer_ranges"),
        }
    }

    /// Returns true if relaying to/from this **normalized** peer is refused.
    pub fn is_forbidden(&self, ip: IpAddr) -> bool {
        // Hardcoded special-use denies — never valid relay peers, and the
        // allow-list cannot override them (loopback has its own flag).
        if ip.is_loopback() {
            return !self.allow_loopback;
        }
        if ip.is_unspecified() || ip.is_multicast() {
            return true;
        }
        match ip {
            IpAddr::V4(v4) if is_special_v4(v4) => return true,
            IpAddr::V6(v6) if is_special_v6(v6) => return true,
            _ => {}
        }

        // Explicit allow wins over deny_private and the deny list.
        if self.allowed.iter().any(|c| c.contains(ip)) {
            return false;
        }
        if self.denied.iter().any(|c| c.contains(ip)) {
            return true;
        }
        if self.deny_private && is_private(ip) {
            return true;
        }
        false
    }
}

fn parse_ranges(ranges: &[String], label: &str) -> Vec<Cidr> {
    ranges
        .iter()
        .filter_map(|s| match Cidr::parse(s) {
            Some(c) => Some(c),
            None => {
                warn!(range = %s, list = %label, "ignoring unparseable peer CIDR");
                None
            }
        })
        .collect()
}

fn env_allow_loopback() -> bool {
    matches!(
        std::env::var("TURNA_ALLOW_LOOPBACK_PEERS").as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    )
}

fn is_special_v4(v4: Ipv4Addr) -> bool {
    // Link-local 169.254.0.0/16 — includes the cloud metadata endpoint
    // 169.254.169.254. is_link_local() is stable since Rust 1.0.
    if v4.is_link_local() {
        return true;
    }
    // Limited broadcast.
    if v4 == Ipv4Addr::BROADCAST {
        return true;
    }
    // "This host on this network" 0.0.0.0/8 (0.x is not is_unspecified).
    v4.octets()[0] == 0
}

fn is_special_v6(v6: Ipv6Addr) -> bool {
    let s = v6.segments();

    // Link-local unicast fe80::/10 (Ipv6Addr::is_unicast_link_local is still
    // unstable, so test the prefix directly).
    if (s[0] & 0xffc0) == 0xfe80 {
        return true;
    }
    // Deprecated site-local fec0::/10 (RFC 3879). Still routed by some stacks.
    if (s[0] & 0xffc0) == 0xfec0 {
        return true;
    }

    // ── v4-embedding transition ranges ──────────────────────────────────────
    // These matter because they carry an arbitrary IPv4 address inside a v6
    // literal. Without them, every v4 rule above (link-local 169.254.169.254,
    // RFC 1918, the operator deny list) is bypassable simply by asking for the
    // v6 form of the same target — which became reachable the moment IPv6
    // relaying was added. Denying the prefixes outright is the only safe answer:
    // resolving them to a v4 address and re-running the v4 policy would still
    // leave the operator's own allow/deny CIDRs written in the wrong family.
    //
    // NAT64 well-known prefix 64:ff9b::/96 (RFC 6052).
    if s[0] == 0x0064 && s[1] == 0xff9b && s[2] == 0 && s[3] == 0 && s[4] == 0 && s[5] == 0 {
        return true;
    }
    // 6to4 2002::/16 (RFC 3056) — the next 32 bits are a v4 address.
    if s[0] == 0x2002 {
        return true;
    }
    // Teredo 2001::/32 (RFC 4380) — embeds a v4 server and client address.
    if s[0] == 0x2001 && s[1] == 0x0000 {
        return true;
    }
    // IPv4-compatible ::/96 (deprecated, RFC 4291 §2.5.5.1), e.g. ::203.0.113.1.
    // `to_ipv4_mapped()` does NOT normalise this form, so it would otherwise
    // reach the datapath as a v6 peer. `::` itself is caught by is_unspecified
    // and `::1` by is_loopback before we get here.
    if s[0] == 0 && s[1] == 0 && s[2] == 0 && s[3] == 0 && s[4] == 0 && s[5] == 0 {
        return true;
    }

    // ── non-routable / reserved ─────────────────────────────────────────────
    // Discard-only 100::/64 (RFC 6666).
    if s[0] == 0x0100 && s[1] == 0 && s[2] == 0 && s[3] == 0 {
        return true;
    }
    // Benchmarking 2001:2::/48 (RFC 5180) and ORCHIDv2 2001:20::/28 (RFC 7343).
    if s[0] == 0x2001 && (s[1] == 0x0002 || (s[1] & 0xfff0) == 0x0020) {
        return true;
    }
    // NOT denied: documentation 2001:db8::/32 (RFC 3849). It embeds no IPv4
    // address, so it is not a bypass of the v4 rules, and it is the canonical
    // stand-in for "a routable public v6 address" in test suites and examples —
    // including this crate's own `internet_facing_default_denies_private_allows_public`.
    // Denying it would buy nothing and surprise anyone writing a test.
    false
}

/// RFC 1918 (v4) / ULA fc00::/7 (v6).
fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private(),
        IpAddr::V6(v6) => (v6.segments()[0] & 0xfe00) == 0xfc00,
    }
}

// ---------------------------------------------------------------------------
// Global policy (installed once at startup)
// ---------------------------------------------------------------------------

static POLICY: OnceLock<PeerPolicy> = OnceLock::new();

/// Install the process-wide peer-filter policy. Call once at startup, before
/// serving traffic. A second call is ignored (the first one wins).
pub fn init_peer_policy(policy: PeerPolicy) {
    if POLICY.set(policy).is_err() {
        warn!("peer-filter policy already initialised; ignoring re-init");
    }
}

fn policy() -> &'static PeerPolicy {
    // If startup never installed one (e.g. unit tests), fall back to the
    // secure default rather than fail-open.
    POLICY.get_or_init(PeerPolicy::default)
}

/// Returns true if relaying to/from this peer must be refused under the active
/// policy. Call this on the **normalized** address.
pub fn is_forbidden_peer(ip: IpAddr) -> bool {
    policy().is_forbidden(ip)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn normalizes_mapped_v4() {
        assert_eq!(normalize_ip(ip("::ffff:127.0.0.1")), ip("127.0.0.1"));
        assert_eq!(normalize_ip(ip("::ffff:10.0.0.1")), ip("10.0.0.1"));
        assert_eq!(normalize_ip(ip("10.0.0.1")), ip("10.0.0.1"));
        assert_eq!(normalize_ip(ip("2001:db8::1")), ip("2001:db8::1"));
    }

    #[test]
    fn denies_special_use_by_default() {
        // The CVE-2026-27624 case: mapped loopback must be caught after normalize.
        assert!(is_forbidden_peer(normalize_ip(ip("::ffff:127.0.0.1"))));
        assert!(is_forbidden_peer(ip("127.0.0.1")));
        assert!(is_forbidden_peer(ip("::1")));
        assert!(is_forbidden_peer(ip("169.254.169.254"))); // cloud metadata
        assert!(is_forbidden_peer(ip("0.0.0.0")));
        assert!(is_forbidden_peer(ip("255.255.255.255")));
        assert!(is_forbidden_peer(ip("224.0.0.1"))); // multicast
        assert!(is_forbidden_peer(ip("fe80::1"))); // link-local v6
        assert!(is_forbidden_peer(ip("fec0::1"))); // deprecated site-local
                                                   // v4-embedding transition ranges: without these, every v4 rule is
                                                   // bypassable by asking for the v6 spelling of the same target.
        assert!(
            is_forbidden_peer(ip("64:ff9b::a9fe:a9fe")),
            "NAT64 form of 169.254.169.254 must be denied"
        );
        assert!(is_forbidden_peer(ip("2002:c000:0204::1")), "6to4");
        assert!(is_forbidden_peer(ip("2001::1")), "Teredo");
        assert!(
            is_forbidden_peer(ip("::203.0.113.1")),
            "deprecated IPv4-compatible form is not normalised by to_ipv4_mapped"
        );
        assert!(is_forbidden_peer(ip("100::1")), "discard-only");
        assert!(is_forbidden_peer(ip("2001:2::1")), "benchmarking");
        assert!(is_forbidden_peer(ip("2001:20::1")), "ORCHIDv2");
        // 2001:db8::/32 is deliberately NOT denied — see is_special_v6.
        assert!(
            !is_forbidden_peer(ip("2001:db8::1")),
            "the documentation prefix must stay allowed: it embeds no IPv4 address \
             and is the canonical example address in tests"
        );
        // A normal global v6 address stays allowed — the point is to deny the
        // transition/reserved prefixes, not IPv6 itself.
        assert!(
            !is_forbidden_peer(ip("2606:4700::1111")),
            "a routable global v6 peer must remain allowed"
        );
        assert!(is_forbidden_peer(ip("::"))); // unspecified
    }

    #[test]
    fn internet_facing_default_denies_private_allows_public() {
        // Secure default (no init_peer_policy in tests) = internet-facing.
        assert!(!is_forbidden_peer(ip("8.8.8.8")));
        assert!(!is_forbidden_peer(ip("2001:db8::1")));
        // RFC 1918 / ULA now denied by default (M1).
        assert!(is_forbidden_peer(ip("10.0.0.5")));
        assert!(is_forbidden_peer(ip("172.16.0.1")));
        assert!(is_forbidden_peer(ip("192.168.1.1")));
        assert!(is_forbidden_peer(ip("fc00::1")));
        assert!(is_forbidden_peer(ip("fd12:3456::1")));
    }

    #[test]
    fn lan_profile_allows_private() {
        let p = PeerPolicy::lan();
        assert!(!p.is_forbidden(ip("10.0.0.5")));
        assert!(!p.is_forbidden(ip("192.168.1.1")));
        assert!(!p.is_forbidden(ip("fc00::1")));
        // …but special-use is still denied even in LAN mode.
        assert!(p.is_forbidden(ip("169.254.169.254")));
        assert!(p.is_forbidden(ip("127.0.0.1")));
    }

    #[test]
    fn allow_list_overrides_internet_facing_deny() {
        let p =
            PeerPolicy::from_config("internet-facing", false, &[], &["10.10.0.0/16".to_string()]);
        assert!(!p.is_forbidden(ip("10.10.5.6"))); // explicitly allowed subnet
        assert!(p.is_forbidden(ip("10.20.5.6"))); // other private still denied
                                                  // Allow-list cannot resurrect special-use.
        let meta = PeerPolicy::from_config(
            "internet-facing",
            false,
            &[],
            &["169.254.0.0/16".to_string()],
        );
        assert!(meta.is_forbidden(ip("169.254.169.254")));
    }

    #[test]
    fn deny_list_blocks_public_range() {
        let p = PeerPolicy::from_config("lan", false, &["8.8.8.0/24".to_string()], &[]);
        assert!(p.is_forbidden(ip("8.8.8.8")));
        assert!(!p.is_forbidden(ip("8.8.4.4")));
    }

    #[test]
    fn cidr_parse_and_contains() {
        let c = Cidr::parse("192.168.0.0/16").unwrap();
        assert!(c.contains(ip("192.168.5.5")));
        assert!(!c.contains(ip("192.169.0.1")));
        let c6 = Cidr::parse("fc00::/7").unwrap();
        assert!(c6.contains(ip("fd00::1")));
        assert!(!c6.contains(ip("2001:db8::1")));
        assert!(Cidr::parse("10.0.0.0/33").is_none()); // bad prefix
        assert!(Cidr::parse("nonsense").is_none());
    }
}
