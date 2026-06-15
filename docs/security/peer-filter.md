# Peer filtering & SSRF hardening (`[turn.peer_filter]`)

A TURN server relays a client's traffic to whatever peer address the client
asks for. Without restrictions that turns the relay into an SSRF gateway into
the operator's own network (internal APIs, databases, cloud metadata).

`turna` normalizes every peer address before policy checks. In particular,
IPv4-mapped IPv6 addresses such as `::ffff:127.0.0.1` are collapsed to IPv4
before allow/deny decisions, so an IPv4 deny rule cannot be bypassed through an
IPv6 representation.

## Always denied (cannot be re-enabled by config)

Loopback (see opt-in below), unspecified (`0.0.0.0`, `::`), multicast, IPv4
broadcast, `0.0.0.0/8`, link-local `169.254.0.0/16` (including the cloud
metadata endpoint `169.254.169.254`) and `fe80::/10`. The allow-list cannot
resurrect these — they are never a valid relay peer.

## Profiles

```toml
[turn.peer_filter]
# "internet-facing" (default) | "lan"  ("trusted" is an alias for "lan")
profile = "internet-facing"

# Dev/test only. Also: TURNA_ALLOW_LOOPBACK_PEERS=1
allow_loopback_peers = false

# Refinements (CIDR). "allow" wins over "deny" and over the profile.
denied_peer_ranges  = []   # e.g. ["100.64.0.0/10"]
allowed_peer_ranges = []   # e.g. ["10.20.0.0/16"]  (permit one internal subnet)
```

* **`internet-facing`** (default): denies RFC 1918 (`10/8`, `172.16/12`,
  `192.168/16`) and ULA (`fc00::/7`) peers. Use this for any node reachable
  from the internet.
* **`lan`**: allows private peers. Use only when the node sits inside a trusted
  perimeter and LAN relaying is intended.

## ⚠️ Breaking change

Previous builds **allowed** RFC 1918 / ULA peers by default. As of this
release the default profile is `internet-facing`, so private peers are
**denied** unless you either set `profile = "lan"` or add the specific
subnets to `allowed_peer_ranges`. Deployments that legitimately relay to a LAN
must update their config on upgrade.

Defense in depth: this filter is not a substitute for an egress firewall on the
relay ports. Keep both.
