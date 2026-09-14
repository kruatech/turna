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

## Self-hosted with an SFU: keep `internet-facing`

This is the most common deployment shape for this project, and the tempting
setting is the wrong one.

The reasoning that leads to `profile = "lan"` goes: the node is ours, the SFU is
ours, both are on our own network, so private peers are fine. What it misses is
that the node is reachable from the internet and its clients are authenticated,
not trusted — they are whoever obtained a credential from your signalling
service, which for a conferencing product includes every guest who was sent a
meeting link.

`lan` opens relaying to **all** of RFC 1918. A client who can allocate can then
point a peer address at any host in your private network and use the TURN server
as a proxy into it: your SFU, but also the Prometheus you bound to a private
address, the Tarantool backend, the hypervisor management interface, the
printer. That is the SSRF vector this filter exists to close, and `lan` is the
switch that reopens it.

The correct shape is to keep the deny and allow-list exactly what needs relaying:

```toml
[turn.peer_filter]
profile = "internet-facing"
allowed_peer_ranges = ["192.0.2.20/32"]   # the SFU, and nothing else
allow_loopback_peers = false
```

A `/32` per host, not the subnet the host happens to live in. `allowed` wins
over both `denied` and the profile, so the list is precisely the exception you
are making and nothing more.

**If the SFU is on the same box**, the instinct is
`allow_loopback_peers = true`. Prefer giving the SFU a private address and
listing that instead: loopback is not one service, it is every service on the
host, including the ones you did not think of. `allow_loopback_peers` is a
dev/test switch.

**Watch `turna_peer_rejected_total` after deploying.** A steady non-zero rate
usually means the SFU's address is missing from `allowed_peer_ranges` — and note
that CreatePermission is atomic, so one forbidden peer in a request returns 403
for the whole request, not just for that peer. The symptom is a call that
connects and carries no media.

## ⚠️ Breaking change

Previous builds **allowed** RFC 1918 / ULA peers by default. As of this
release the default profile is `internet-facing`, so private peers are
**denied** unless you either set `profile = "lan"` or add the specific
subnets to `allowed_peer_ranges`. Deployments that legitimately relay to a LAN
must update their config on upgrade.

Defense in depth: this filter is not a substitute for an egress firewall on the
relay ports. Keep both.
