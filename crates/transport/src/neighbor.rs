//! Per-destination next-hop MAC resolution via netlink (`rtnetlink`).
//!
//! AF_XDP Phase 2. The sync datapath (`af_xdp::xsk`) builds Ethernet frames and
//! needs the next-hop MAC for each target. Phase 1 used a single static
//! `dst_mac` (the gateway). This module resolves per-destination:
//!   target IP --(routing table, kernel LPM)--> next-hop IP
//!   next-hop IP --(neighbour table)--> MAC
//! It runs as an async task maintaining a shared cache that the (blocking)
//! datapath reads without awaiting. netlink wire-format is intricate, so this
//! is grounded against rtnetlink 0.21 / netlink-packet-route 0.30 and exercised
//! on a lab via the `neigh_probe` example before being wired into the hot path.
#![cfg(all(target_os = "linux", feature = "af-xdp"))]

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use futures_util::stream::TryStreamExt;
use netlink_packet_route::neighbour::{NeighbourAddress, NeighbourAttribute, NeighbourState};
use netlink_packet_route::route::{RouteAddress, RouteAttribute};
use rtnetlink::sys::AsyncSocket;
use rtnetlink::{new_connection, Handle, IpVersion, RouteMessageBuilder};

pub type Mac = [u8; 6];

/// Shared, cheaply-cloneable cache of resolved next-hop MACs keyed by the
/// *target* address (so the datapath looks up by the address it is sending to).
#[derive(Clone, Default)]
pub struct NeighborCache {
    inner: Arc<RwLock<HashMap<IpAddr, (Mac, Instant)>>>,
}

impl NeighborCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Fresh MAC for `target`, or `None` if absent or older than `ttl`.
    pub fn get(&self, target: IpAddr, ttl: Duration) -> Option<Mac> {
        let g = self.inner.read().ok()?;
        let (mac, learned) = g.get(&target)?;
        if learned.elapsed() <= ttl {
            Some(*mac)
        } else {
            None
        }
    }

    pub fn put(&self, target: IpAddr, mac: Mac) {
        if let Ok(mut g) = self.inner.write() {
            g.insert(target, (mac, Instant::now()));
        }
    }

    pub fn len(&self) -> usize {
        self.inner.read().map(|g| g.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Last-known MAC for `target` regardless of age. Lets the datapath keep
    /// sending during a TTL refresh instead of reverting to the static
    /// next-hop.
    pub fn get_stale(&self, target: IpAddr) -> Option<Mac> {
        let g = self.inner.read().ok()?;
        g.get(&target).map(|(mac, _)| *mac)
    }

    /// Evict entries older than `age`; returns how many were removed. Keeps
    /// the cache bounded under churny peer sets (TTL alone only gates reads).
    pub fn evict_older_than(&self, age: Duration) -> usize {
        if let Ok(mut g) = self.inner.write() {
            let before = g.len();
            g.retain(|_, (_, learned)| learned.elapsed() <= age);
            before - g.len()
        } else {
            0
        }
    }
}

fn na_ip(a: &NeighbourAddress) -> Option<IpAddr> {
    match a {
        NeighbourAddress::Inet(v) => Some(IpAddr::V4(*v)),
        NeighbourAddress::Inet6(v) => Some(IpAddr::V6(*v)),
        _ => None,
    }
}

fn ra_ip(a: &RouteAddress) -> Option<IpAddr> {
    match a {
        RouteAddress::Inet(v) => Some(IpAddr::V4(*v)),
        RouteAddress::Inet6(v) => Some(IpAddr::V6(*v)),
        _ => None,
    }
}

/// Open a netlink connection with strict get-checking (so the kernel resolves
/// the route for an exact destination) and spawn its driver task.
fn connect() -> std::io::Result<Handle> {
    let (mut conn, handle, _) = new_connection()?;
    // Strict checking makes RTM_GETROUTE with a destination return the route the
    // kernel would actually use (longest-prefix match done kernel-side).
    conn.socket_mut().socket_mut().set_netlink_get_strict_chk(true)?;
    tokio::spawn(conn);
    Ok(handle)
}

/// Ask the kernel for the route to `target`; return its next hop: the route's
/// gateway if present (off-link), otherwise `target` itself (on-link).
async fn next_hop(handle: &Handle, target: IpAddr) -> Option<IpAddr> {
    let req = match target {
        IpAddr::V4(v4) => RouteMessageBuilder::<Ipv4Addr>::new()
            .destination_prefix(v4, 32)
            .build(),
        IpAddr::V6(v6) => RouteMessageBuilder::<Ipv6Addr>::new()
            .destination_prefix(v6, 128)
            .build(),
    };
    let mut routes = handle.route().get(req).execute();
    if let Ok(Some(msg)) = routes.try_next().await {
        for a in &msg.attributes {
            if let RouteAttribute::Gateway(g) = a {
                if let Some(ip) = ra_ip(g) {
                    return Some(ip);
                }
            }
        }
        // Route exists but has no gateway → destination is on-link.
        return Some(target);
    }
    None
}

/// Look up the MAC of `next_hop` in the neighbour table. Skips entries that
/// cannot have a usable address (INCOMPLETE / FAILED / NOARP).
async fn neigh_mac(handle: &Handle, next_hop: IpAddr) -> Option<Mac> {
    let family = match next_hop {
        IpAddr::V4(_) => IpVersion::V4,
        IpAddr::V6(_) => IpVersion::V6,
    };
    let mut ns = handle.neighbours().get().set_family(family).execute();
    while let Ok(Some(msg)) = ns.try_next().await {
        if matches!(
            msg.header.state,
            NeighbourState::Incomplete | NeighbourState::Failed | NeighbourState::Noarp
        ) {
            continue;
        }
        let mut dst: Option<IpAddr> = None;
        let mut mac: Option<Mac> = None;
        for a in &msg.attributes {
            match a {
                NeighbourAttribute::Destination(d) => dst = na_ip(d),
                NeighbourAttribute::LinkLayerAddress(ll) if ll.len() == 6 => {
                    let mut m = [0u8; 6];
                    m.copy_from_slice(ll);
                    mac = Some(m);
                }
                _ => {}
            }
        }
        if dst == Some(next_hop) {
            if let Some(m) = mac {
                return Some(m);
            }
        }
    }
    None
}

/// One-shot resolution: target → next-hop → MAC. Opens its own short-lived
/// netlink connection. Used by the `neigh_probe` example and tests; the hot
/// path uses [`run_resolver`] + [`NeighborCache`] instead.
pub async fn resolve_mac(target: IpAddr) -> std::io::Result<Option<Mac>> {
    let handle = connect()?;
    let nh = next_hop(&handle, target).await.unwrap_or(target);
    Ok(neigh_mac(&handle, nh).await)
}

/// Discard port (RFC 863) for the inert kick datagram.
const KICK_PORT: u16 = 9;
/// After kicking, poll the neighbour table this many times…
const RETRY_POLLS: usize = 5;
/// …spaced this far apart (first-packet resolution latency budget).
const RETRY_DELAY: Duration = Duration::from_millis(100);
/// Don't re-attempt the same target within this window (dedups a burst of
/// cache-miss sends to one peer).
const RESOLVE_SUPPRESS: Duration = Duration::from_secs(2);
/// How often to sweep stale cache entries.
const EVICT_INTERVAL: Duration = Duration::from_secs(60);
/// Drop cache entries older than this (bounds memory).
const EVICT_MAX_AGE: Duration = Duration::from_secs(300);

/// Provoke kernel neighbour resolution (ARP for IPv4, Neighbour
/// Solicitation for IPv6) for `next_hop` by sending a zero-byte datagram to
/// it on the discard port. The kernel performs the actual ARP/NS; the
/// datagram is inert (and dropped even if it arrives).
fn kick(next_hop: IpAddr) {
    let bind: &str = if next_hop.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    if let Ok(sock) = std::net::UdpSocket::bind(bind) {
        let _ = sock.set_nonblocking(true);
        let _ = sock.send_to(&[], (next_hop, KICK_PORT));
    }
}

/// Resolve one target: route → next-hop → neighbour MAC. On a table miss,
/// actively kick ARP/NDP and poll until the entry appears or the retry
/// budget runs out. Caches on success (keyed by target).
async fn resolve_one(handle: &Handle, cache: &NeighborCache, target: IpAddr) {
    let nh = next_hop(handle, target).await.unwrap_or(target);
    if let Some(mac) = neigh_mac(handle, nh).await {
        cache.put(target, mac);
        return;
    }
    kick(nh);
    for _ in 0..RETRY_POLLS {
        tokio::time::sleep(RETRY_DELAY).await;
        if let Some(mac) = neigh_mac(handle, nh).await {
            cache.put(target, mac);
            return;
        }
    }
}

/// Background resolver: drains target addresses from `rx`, resolves each
/// (actively triggering ARP/NDP on a miss), and stores the result in `cache`.
/// One netlink connection for the task's lifetime. Periodically evicts stale
/// cache entries. Returns when the request channel closes.
pub async fn run_resolver(
    cache: NeighborCache,
    mut rx: tokio::sync::mpsc::UnboundedReceiver<IpAddr>,
) -> std::io::Result<()> {
    let handle = connect()?;
    let mut last_attempt: HashMap<IpAddr, Instant> = HashMap::new();
    loop {
        match tokio::time::timeout(EVICT_INTERVAL, rx.recv()).await {
            Ok(Some(target)) => {
                // Suppress duplicate work for a target we just tried.
                if let Some(t) = last_attempt.get(&target) {
                    if t.elapsed() < RESOLVE_SUPPRESS {
                        continue;
                    }
                }
                last_attempt.insert(target, Instant::now());
                resolve_one(&handle, &cache, target).await;
            }
            Ok(None) => return Ok(()),
            Err(_) => {
                cache.evict_older_than(EVICT_MAX_AGE);
                last_attempt.retain(|_, t| t.elapsed() < EVICT_MAX_AGE);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_put_get_ttl() {
        let c = NeighborCache::new();
        let ip: IpAddr = "10.0.0.2".parse().unwrap();
        assert!(c.get(ip, Duration::from_secs(1)).is_none());
        c.put(ip, [1, 2, 3, 4, 5, 6]);
        assert_eq!(c.get(ip, Duration::from_secs(60)), Some([1, 2, 3, 4, 5, 6]));
        // Zero TTL → always considered stale.
        assert!(c.get(ip, Duration::from_secs(0)).is_none());
    }
}
