//! RFC 5780 NAT behaviour discovery — the four-socket responder.
//!
//! A client learns what kind of NAT it is behind by asking a STUN server to
//! answer from a *different* address or port than the one it sent to, and
//! watching which answers arrive (§3). That needs two IP addresses of the same
//! family and two ports, with every combination bound: A1:P1, A1:P2, A2:P1 and
//! A2:P2 (§6). One address cannot implement it, which is why this is opt-in
//! (`[turn.nat_discovery]`, off by default) and why config validation refuses
//! it without both addresses — coturn refuses the same way.
//!
//! # Why separate sockets rather than the TURN listener
//!
//! The TURN listener may be io_uring, AF_XDP or a reuseport group, none of
//! which can send a reply from a socket other than the one the request arrived
//! on. Reaching into every datapath to add three more egress sockets would
//! touch the hot path of every deployment for a feature almost none enable.
//! So the discovery service runs on its own four UDP sockets, answers Binding
//! only, and the TURN listener keeps refusing CHANGE-REQUEST with 420, which
//! is what §6 requires of a server that cannot honour it there. RFC 5780 §9.2
//! allows the usage on its own port, found through the `stun-behavior` SRV
//! name.
//!
//! UDP only. §6 says a server SHOULD also do TCP and TLS; this one does not.
//!
//! # Abuse
//!
//! Each response is an unauthenticated reply, and a spoofed request can aim
//! it — or, with CHANGE-REQUEST, three different sources — at a victim. The
//! processor applies the configured ingress tiers and the unauthenticated-reply
//! budget to every request here exactly as on the TURN listener, and refuses
//! PADDING and RESPONSE-PORT (the two attributes the RFC's own security section
//! discusses) with 420. The limiter instances belong to the processor handed to
//! [`run`]; the node builds a dedicated one, so the budget is per service, with
//! the same tiers.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use tracing::{info, warn};

use crate::processor::PacketProcessor;

/// The two addresses and two ports of an RFC 5780 server (§6: A1, A2, P1, P2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NatDiscoveryTopology {
    pub primary_ip: IpAddr,
    pub alternate_ip: IpAddr,
    pub primary_port: u16,
    pub alternate_port: u16,
}

impl NatDiscoveryTopology {
    /// Build a topology, refusing the shapes §6 cannot work with: the two
    /// addresses must differ and share a family, the two ports must differ,
    /// and nothing may be a wildcard — a reply's source must be a concrete
    /// address, and RESPONSE-ORIGIN has to name it.
    pub fn new(
        primary_ip: IpAddr,
        alternate_ip: IpAddr,
        primary_port: u16,
        alternate_port: u16,
    ) -> Result<Self, String> {
        if primary_ip == alternate_ip {
            return Err("primary_ip and alternate_ip must be different addresses".into());
        }
        if primary_ip.is_ipv4() != alternate_ip.is_ipv4() {
            return Err("primary_ip and alternate_ip must be the same address family".into());
        }
        if primary_ip.is_unspecified() || alternate_ip.is_unspecified() {
            return Err("primary_ip and alternate_ip must be concrete, not wildcard".into());
        }
        if primary_port == 0 || alternate_port == 0 || primary_port == alternate_port {
            return Err("primary_port and alternate_port must be non-zero and different".into());
        }
        Ok(Self {
            primary_ip,
            alternate_ip,
            primary_port,
            alternate_port,
        })
    }

    /// The four socket addresses, A1:P1 first.
    pub fn sockets(&self) -> [SocketAddr; 4] {
        [
            SocketAddr::new(self.primary_ip, self.primary_port),
            SocketAddr::new(self.primary_ip, self.alternate_port),
            SocketAddr::new(self.alternate_ip, self.primary_port),
            SocketAddr::new(self.alternate_ip, self.alternate_port),
        ]
    }

    fn other_ip(&self, ip: IpAddr) -> Option<IpAddr> {
        if ip == self.primary_ip {
            Some(self.alternate_ip)
        } else if ip == self.alternate_ip {
            Some(self.primary_ip)
        } else {
            None
        }
    }

    fn other_port(&self, port: u16) -> Option<u16> {
        if port == self.primary_port {
            Some(self.alternate_port)
        } else if port == self.alternate_port {
            Some(self.primary_port)
        } else {
            None
        }
    }

    /// RFC 5780 §6.1 Table 1: the source of the response to a request received
    /// on `local` (Da:Dp) with the given CHANGE-REQUEST flags. `None` if
    /// `local` is not one of this topology's sockets.
    pub fn response_source(
        &self,
        local: SocketAddr,
        change_ip: bool,
        change_port: bool,
    ) -> Option<SocketAddr> {
        let ip = if change_ip {
            self.other_ip(local.ip())?
        } else {
            // Membership check even when unchanged, so a stray `local` is
            // refused rather than echoed.
            self.other_ip(local.ip()).map(|_| local.ip())?
        };
        let port = if change_port {
            self.other_port(local.port())?
        } else {
            self.other_port(local.port()).map(|_| local.port())?
        };
        Some(SocketAddr::new(ip, port))
    }

    /// RFC 5780 §6.1: OTHER-ADDRESS is Ca:Cp "regardless of the value of the
    /// CHANGE-REQUEST flags".
    pub fn other_address(&self, local: SocketAddr) -> Option<SocketAddr> {
        Some(SocketAddr::new(
            self.other_ip(local.ip())?,
            self.other_port(local.port())?,
        ))
    }
}

/// Bind the four discovery sockets. Binding happens before `run` so a missing
/// address fails node startup instead of leaving a half-built service — a
/// discovery server that answers from three of its four addresses reports a
/// NAT type that is wrong, which is worse than reporting none.
pub async fn bind(topology: &NatDiscoveryTopology) -> std::io::Result<Vec<tokio::net::UdpSocket>> {
    let mut out = Vec::with_capacity(4);
    for addr in topology.sockets() {
        let sock = tokio::net::UdpSocket::bind(addr).await.map_err(|e| {
            std::io::Error::new(
                e.kind(),
                format!(
                    "RFC 5780 NAT discovery: cannot bind {addr}: {e}. Both \
                     [turn.nat_discovery] addresses must be assigned to this host"
                ),
            )
        })?;
        out.push(sock);
    }
    Ok(out)
}

/// Serve RFC 5780 Binding requests on `sockets` (as returned by [`bind`], in
/// [`NatDiscoveryTopology::sockets`] order) until `shutdown` flips.
pub async fn run(
    processor: Arc<PacketProcessor>,
    topology: NatDiscoveryTopology,
    sockets: Vec<tokio::net::UdpSocket>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let sockets: Arc<Vec<(SocketAddr, tokio::net::UdpSocket)>> = Arc::new(
        topology
            .sockets()
            .into_iter()
            .zip(sockets)
            .collect::<Vec<_>>(),
    );
    info!(
        primary = %SocketAddr::new(topology.primary_ip, topology.primary_port),
        alternate = %SocketAddr::new(topology.alternate_ip, topology.alternate_port),
        "RFC 5780 NAT behaviour discovery listening (UDP, 4 sockets)"
    );
    let mut tasks = Vec::with_capacity(4);
    for idx in 0..sockets.len() {
        let sockets = sockets.clone();
        let processor = processor.clone();
        tasks.push(tokio::spawn(async move {
            let (local, sock) = &sockets[idx];
            let mut buf = vec![0u8; 2048];
            loop {
                let (n, src) = match sock.recv_from(&mut buf).await {
                    Ok(v) => v,
                    Err(e) => {
                        // ICMP-induced errors (ECONNREFUSED from an earlier
                        // send) surface here on Linux; they are about a past
                        // reply, not this socket.
                        tracing::debug!(%local, error = %e, "nat discovery recv error");
                        continue;
                    }
                };
                let Some((reply, from)) =
                    processor.handle_nat_discovery(&buf[..n], src, *local, &topology)
                else {
                    continue;
                };
                match sockets.iter().find(|(a, _)| *a == from) {
                    Some((_, out)) => {
                        if let Err(e) = out.send_to(&reply, src).await {
                            tracing::debug!(%from, error = %e, "nat discovery send failed");
                        }
                    }
                    // Unreachable: `response_source` only returns members of
                    // the topology, and all four are bound.
                    None => warn!(%from, "nat discovery: no socket for response source"),
                }
            }
        }));
    }
    let _ = shutdown.changed().await;
    for t in tasks {
        t.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn topo() -> NatDiscoveryTopology {
        NatDiscoveryTopology::new(
            "192.0.2.1".parse().unwrap(),
            "192.0.2.2".parse().unwrap(),
            3478,
            3479,
        )
        .unwrap()
    }

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    /// RFC 5780 §6.1 Table 1, row by row, from each of the four sockets.
    #[test]
    fn table_1_from_every_socket() {
        let t = topo();
        for (da, ca) in [("192.0.2.1", "192.0.2.2"), ("192.0.2.2", "192.0.2.1")] {
            for (dp, cp) in [(3478u16, 3479u16), (3479, 3478)] {
                let local = sa(&format!("{da}:{dp}"));
                let cases = [
                    ((false, false), format!("{da}:{dp}")),
                    ((true, false), format!("{ca}:{dp}")),
                    ((false, true), format!("{da}:{cp}")),
                    ((true, true), format!("{ca}:{cp}")),
                ];
                for ((ip, port), want) in cases {
                    assert_eq!(
                        t.response_source(local, ip, port),
                        Some(sa(&want)),
                        "local {local}, change_ip={ip}, change_port={port}"
                    );
                }
                // OTHER-ADDRESS is Ca:Cp whatever the flags.
                assert_eq!(t.other_address(local), Some(sa(&format!("{ca}:{cp}"))));
            }
        }
    }

    #[test]
    fn a_socket_outside_the_topology_gets_nothing() {
        let t = topo();
        assert_eq!(t.response_source(sa("192.0.2.9:3478"), false, false), None);
        assert_eq!(t.response_source(sa("192.0.2.1:9999"), false, false), None);
        assert_eq!(t.other_address(sa("192.0.2.9:3478")), None);
    }

    #[test]
    fn topology_refuses_what_section_6_cannot_serve() {
        let v4a: IpAddr = "192.0.2.1".parse().unwrap();
        let v4b: IpAddr = "192.0.2.2".parse().unwrap();
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        let any: IpAddr = "0.0.0.0".parse().unwrap();
        assert!(NatDiscoveryTopology::new(v4a, v4a, 3478, 3479).is_err());
        assert!(NatDiscoveryTopology::new(v4a, v6, 3478, 3479).is_err());
        assert!(NatDiscoveryTopology::new(any, v4b, 3478, 3479).is_err());
        assert!(NatDiscoveryTopology::new(v4a, v4b, 3478, 3478).is_err());
        assert!(NatDiscoveryTopology::new(v4a, v4b, 0, 3479).is_err());
        assert!(NatDiscoveryTopology::new(v4a, v4b, 3478, 3479).is_ok());
        let v6b: IpAddr = "2001:db8::2".parse().unwrap();
        assert!(NatDiscoveryTopology::new(v6, v6b, 3478, 3479).is_ok());
    }
}

#[cfg(test)]
mod socket_tests {
    //! The four real sockets on 127.0.0.1 and 127.0.0.2 — both loopback, so
    //! this runs on any Linux host, and a reply from the "other" address is
    //! observable exactly as it would be from a public one.
    use super::*;
    use std::time::Duration;
    use turna_auth::{AuthMode, AuthRegistry};
    use turna_health::Metrics;
    use turna_proto_stun::attribute::Attribute;
    use turna_proto_stun::header::MessageClass;
    use turna_proto_stun::message::StunMessage;
    use turna_proto_stun::method::Method;
    use turna_session::AllocationStore;

    /// Two ports free on both loopback addresses. Retries rather than
    /// assuming, because the pair has to be free on both.
    async fn topology() -> Option<(NatDiscoveryTopology, Vec<tokio::net::UdpSocket>)> {
        for _ in 0..20 {
            let p1 = std::net::UdpSocket::bind("127.0.0.1:0")
                .ok()?
                .local_addr()
                .ok()?
                .port();
            let p2 = std::net::UdpSocket::bind("127.0.0.1:0")
                .ok()?
                .local_addr()
                .ok()?
                .port();
            let Ok(t) = NatDiscoveryTopology::new(
                "127.0.0.1".parse().unwrap(),
                "127.0.0.2".parse().unwrap(),
                p1,
                p2,
            ) else {
                continue;
            };
            if let Ok(socks) = bind(&t).await {
                return Some((t, socks));
            }
        }
        None
    }

    #[tokio::test]
    async fn change_request_is_answered_from_the_other_address_and_port() {
        let Some((t, socks)) = topology().await else {
            eprintln!("skipping: could not bind 127.0.0.1 and 127.0.0.2 with a shared port pair");
            return;
        };
        let p = Arc::new(PacketProcessor::new(
            Arc::new(AllocationStore::new(28000, 28099, 4)),
            Arc::new(AuthRegistry::new(AuthMode::long_term("nat", [("u", "p")]))),
            "127.0.0.1".parse().unwrap(),
            Arc::new(Metrics::new()),
        ));
        let (tx, rx) = tokio::sync::watch::channel(false);
        let server = tokio::spawn(run(p, t, socks, rx));

        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let a1p1 = t.sockets()[0];
        for (flags, want) in [
            (None, t.sockets()[0]),
            (Some((true, true)), t.sockets()[3]),
            (Some((true, false)), t.sockets()[2]),
            (Some((false, true)), t.sockets()[1]),
        ] {
            let mut m = StunMessage::new(Method::Binding, MessageClass::Request);
            if let Some((change_ip, change_port)) = flags {
                m.add(Attribute::ChangeRequest {
                    change_ip,
                    change_port,
                });
            }
            let mut buf = [0u8; 128];
            let n = m.encode(&mut buf).unwrap();
            client.send_to(&buf[..n], a1p1).await.unwrap();
            let mut rbuf = [0u8; 512];
            let (rn, from) =
                tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut rbuf))
                    .await
                    .expect("reply within 2s")
                    .unwrap();
            assert_eq!(from, want, "flags {flags:?}: wrong source");
            let r = StunMessage::decode(&rbuf[..rn]).unwrap();
            assert_eq!(r.transaction_id, m.transaction_id);
            assert_eq!(r.get_response_origin(), Some(want));
            assert_eq!(r.get_other_address(), Some(t.sockets()[3]));
        }
        let _ = tx.send(true);
        let _ = server.await;
    }
}
