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
//! 2. **Deny special-use ranges by default** (RFC 6890): loopback,
//!    link-local (incl. the cloud metadata endpoint 169.254.169.254),
//!    multicast, unspecified, and IPv4 broadcast. This stops the relay from
//!    being used as an SSRF gateway into the host's own loopback / private
//!    control plane.
//!
//! Private RFC 1918 / ULA ranges are **allowed** by default because LAN
//! relays are a legitimate use case; deny them explicitly via config if your
//! deployment is internet-only.
//!
//! The loopback opt-in exists for local development and test rigs:
//! set `TURNA_ALLOW_LOOPBACK_PEERS=1`.
//!
//! TODO(config): move the allow/deny decision into `turna-config`
//! (`denied_peer_ranges` / `allowed_peer_ranges` / `allow_loopback_peers`)
//! so it is set per-profile instead of via env. Tracked as a follow-up.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::OnceLock;

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

fn allow_loopback() -> bool {
    static FLAG: OnceLock<bool> = OnceLock::new();
    *FLAG.get_or_init(|| {
        matches!(
            std::env::var("TURNA_ALLOW_LOOPBACK_PEERS").as_deref(),
            Ok("1") | Ok("true") | Ok("yes")
        )
    })
}

/// Returns true if relaying to/from this peer must be refused by default.
///
/// Call this on the **normalized** address.
pub fn is_forbidden_peer(ip: IpAddr) -> bool {
    // Loopback is the highest-value SSRF target; gated behind an explicit
    // opt-in for local development only.
    if ip.is_loopback() {
        return !allow_loopback();
    }
    if ip.is_unspecified() || ip.is_multicast() {
        return true;
    }
    match ip {
        IpAddr::V4(v4) => is_forbidden_v4(v4),
        IpAddr::V6(v6) => is_forbidden_v6(v6),
    }
}

fn is_forbidden_v4(v4: Ipv4Addr) -> bool {
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
    if v4.octets()[0] == 0 {
        return true;
    }
    false
}

fn is_forbidden_v6(v6: Ipv6Addr) -> bool {
    // Link-local unicast fe80::/10 (Ipv6Addr::is_unicast_link_local is still
    // unstable, so test the prefix directly).
    let seg0 = v6.segments()[0];
    if (seg0 & 0xffc0) == 0xfe80 {
        return true;
    }
    false
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
        assert!(is_forbidden_peer(ip("::"))); // unspecified
    }

    #[test]
    fn allows_normal_peers() {
        assert!(!is_forbidden_peer(ip("8.8.8.8")));
        assert!(!is_forbidden_peer(ip("10.0.0.5"))); // private LAN: allowed
        assert!(!is_forbidden_peer(ip("2001:db8::1")));
    }
}
