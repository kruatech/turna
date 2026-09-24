# Self-hosted turna

One node, your own hardware, serving a conferencing product whose media goes
through an SFU. Start to finish, in order.

This page exists because the settings that decide whether the deployment works
are spread across a config file, a sysctl file, a certificate and the client's
ICE configuration, and getting five of six right produces a node that looks
healthy and fails for a subset of users.

Reference config: [`deploy/examples/selfhosted.toml`](../deploy/examples/selfhosted.toml).
Every key in it carries the reason it is set.

## 1. What the host needs

- Linux. The datapath is portable, but the tuning below and the AF_XDP/io_uring
  options are not.
- A public IPv4 address. If the node is behind NAT you need a static 1:1
  mapping — TURN cannot work through a NAT that rewrites ports.
- Open inbound: **3478/udp**, **5349/tcp**, and the relay range
  **49152-65535/udp**. The relay range is not optional; blocking it produces
  allocations that succeed and media that never arrives.
- CPU sized against a measurement, not a guess. The one figure this project has
  is 112 000 relayed packets/second on a 16-core Threadripper, over loopback —
  an upper bound on the software path, not on your NIC. See
  [`docs/capacity/threadripper-1950x-2026-08-26.md`](capacity/threadripper-1950x-2026-08-26.md).

Two interfaces (public for clients, private to the SFU) is the common shape and
is what `bind_ip` in the reference config is for.

## 2. Host tuning

```sh
sudo install -m 0644 deploy/sysctl.d/99-turna.conf /etc/sysctl.d/99-turna.conf
sudo sysctl --system
```

Read the file first. Two of its settings are load-bearing:

**The ephemeral port range must not overlap the relay range.** The defaults do
overlap on most hosts, and a peer socket landing inside the relay range makes
the relay forward to itself.

```sh
cat /proc/sys/net/ipv4/ip_local_port_range
```

**`net.core.rmem_max` caps the socket buffer.** `socket_recv_buffer_bytes` in
the config is a *request*; the kernel clamps it silently. This matters because a
receive-buffer overflow is dropped **in the kernel**, before turna sees the
packet — every turna metric reads clean while users watch the picture break up.
The node logs the size it actually got and warns when it was clamped.

## 3. Certificates

TURNS is not optional: turna has no plain TURN-over-TCP listener, so it is the
only way in for a client on a network that blocks UDP. Corporate guests are
exactly that population.

Two workable paths:

**Public domain + Let's Encrypt.** Works even though the deployment is private —
the certificate is public, the key stays on your machine. Point `cert_path` and
`key_path` at the live files; `cert_reload_secs = 300` picks up a renewal
without a restart, which matters with 90-day certificates.

**Corporate CA.** rustls serves a privately-signed chain without complaint. The
catch is entirely client-side: a browser that does not trust your root **fails
the TURNS handshake silently** and the user reports "TURN is broken". Distribute
the root through GPO or MDM to every client population *before* switching, and
remember that a personal phone on the guest wifi is a client population.

If your users sit behind filters that only allow well-known ports, put `[tls]
listen` on 443 instead of 5349. Nothing else changes.

## 4. Config

```sh
sudo mkdir -p /etc/turna/tls
sudo cp deploy/examples/selfhosted.toml /etc/turna/turn.toml
sudo chown -R turna:turna /etc/turna
```

Then edit, in this order:

1. `external_ip` — the address clients send media to.
2. `[turn.auth] shared_secret` — `openssl rand -hex 32`. Keep it out of the
   file with `${TURNA_SHARED_SECRET}` or `file:///run/secrets/...` if you have
   somewhere better to put it.
3. `[turn.peer_filter] allowed_peer_ranges` — the SFU's address, as a /32, and
   nothing else. **Do not set `profile = "lan"`.** It is the tempting setting
   and the wrong one: it lets any authenticated client relay to any host in your
   private network.
4. `[turn.rate_limit] trusted_prefixes` — the offices and VPN pools where
   hundreds of users share one NAT address. Without this, a 300-person meeting
   starting at 10:00 hits the Allocate ceiling and a chunk of the attendees
   spend 30 seconds failing before they join.
5. `[turn.relay] bind_ip` — the public interface, on a two-NIC host.

Check it before starting anything:

```sh
turna-node --dump-config /etc/turna/turn.toml
```

## 5. Run it

**systemd**, which is the simpler path on bare metal: no NAT layer, and sysctl
and capabilities behave normally.

```sh
sudo cp deploy/systemd/turna-node.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now turna-node
```

**Docker**, if you would rather:

```sh
docker run --rm --network host \
  -v /etc/turna:/etc/turna:ro \
  turna:local /etc/turna/turn.toml
```

`--network host` is not a shortcut. Publishing 16 384 UDP ports through the
bridge creates a rule per port and an extra NAT hop on the media path, and the
node then sees the gateway's address instead of the client's — which quietly
collapses per-IP rate limiting into one shared bucket.

## 6. Client ICE configuration

```js
iceServers: [
  { urls: "turn:turn.example.net:3478?transport=udp", username, credential },
  { urls: "turns:turn.example.net:5349?transport=tcp", username, credential },
]
```

`turn:...?transport=tcp` is **not** served, by design. Leaving it in the client
config costs part of the ICE gathering budget on a connection refused before the
client reaches the URL that works.

Credentials are TURN REST, coturn-compatible: your signalling service derives
them from the same `shared_secret` and hands them to the client per session.
The secret itself never reaches a browser.

## 7. Verify

```sh
# Listeners where you expect them, and nowhere else.
ss -ulnp | grep turna-node
ss -tlnp | grep turna-node

# A real allocation.
turnutils_uclient -v -u <user> -w <credential> -p 3478 turn.example.net

# TURNS specifically — this is the one people forget until a user reports it.
turnutils_uclient -v -S -u <user> -w <credential> -p 5349 turn.example.net
```

`tools/browser-probes/connectivity-check.html` exercises the browser path,
including whether your certificate chain is trusted, which the CLI cannot tell
you.

## 8. What to watch

| Signal | Means |
|---|---|
| `turna_send_queue_dropped_total` | The node is shedding media. The one counter that sees egress loss a client-side measurement cannot. |
| `turna_quota_exceeded_total` | Per-allocation bandwidth cap hit. Over it, packets are **dropped**, not throttled — the user sees frame loss. |
| `turna_peer_rejected_total` | Peer filter refusing a relay target. A steady rate usually means the SFU's address is missing from `allowed_peer_ranges`. |
| `turna_auth_previous_secret_total` | Clients still using the old shared secret. Must reach zero before you drop it. |
| `turna_recv_workers_alive` | Receive workers still running, against the count at startup. A fall is permanent and means the clients the kernel hashes to that socket are unserved **while the node still reports Ready**. Alert on any decrease. |
| `turna_unauth_replies_suppressed_total` | Binding responses and 401 challenges withheld because a source used up its reflection budget. A real client needs single digits of these in its whole life, so a sustained rate means spoofed requests naming a victim as the source. |
| `turna_dtls_pending_handshakes` | DTLS handshakes in flight, i.e. state allocated before the source address was proved real. Read it against `turna_dtls_accepted_total`: near the cap with flat accepts is an attack, not load. Only if DTLS is enabled. |
| `turna_quic_retries_sent_total` | Initials answered with a Retry. Should track new connections roughly one-for-one; far above that is spoofed traffic that cost a datagram instead of a signature. Only if QUIC is enabled. |
| `nstat -az UdpRcvbufErrors` | Kernel-side buffer overflow. **Not a turna metric** — nothing in turna can see it, which is why it is on this list. |

Alert rules: [`docs/alerts/turna.yml`](alerts/turna.yml) for capacity and
correctness, [`docs/alerts/turna-abuse.yml`](alerts/turna-abuse.yml) for the
signals above. Read the thresholds before loading them — the numbers that fit a
node serving three hundred people are not the numbers for thirty thousand, and a
rule that cries wolf is worse than no rule.

## 9. Rotating the shared secret

No restart, no dropped calls:

```sh
# 1. New secret in shared_secret, old one in previous_shared_secret.
sudo systemctl reload turna-node
# 2. Wait for turna_auth_previous_secret_total to stop increasing.
# 3. Remove previous_shared_secret.
sudo systemctl reload turna-node
```

The realm cannot change this way and a reload that tries is refused — a realm
change invalidates every credential in flight.

## Upgrading from 0.4.x

Five things change behaviour without you touching the config. None of them is
a knob you are expected to find in the CHANGELOG afterwards.

**Configs with `[sfu]`, `[signaling]` or `[recording]` will not load.** The
schema is strict, so a leftover section is a hard failure — with a message
naming the section and telling you to delete it. Nothing else is needed; those
sections were parsed and read by nothing.

**`max_per_user` now counts people, not credentials.** It used to key on the raw
TURN REST username, which carries an expiry prefix and therefore changed every
time your signalling service minted a credential — so the cap bounded one pair
of credentials and reset whenever a client asked for a fresh one. It now keys on
the userid. **Existing values are too low**: one person legitimately holds
several allocations at once — two ICE transports, a second device, a reconnect
whose old allocation has not yet expired. Raise it before upgrading, not after
the support tickets. The reference config uses 12.

`set_user_limits` changes with it: the subject is now `alice`, not
`1758012345:alice`. Any override you set before was silently matching nothing.

**Per-source caps switched on.** `[tls] max_connections_per_ip` goes from
unlimited to 64, and the DTLS and QUIC `max_sessions_per_ip` from unlimited to
16. If a known NAT egress point carries more than that from one address, raise
it explicitly — the number is now a decision either way.

**A `[turn.dtls] demux = false` config will refuse to start.**
`max_handshakes_per_sec_per_ip` also defaults to 8 now, and it cannot be
enforced on the stock listener, where the handshake runs below `accept()`.
Validation refuses the combination rather than accepting a limit that would do
nothing. Add `max_handshakes_per_sec_per_ip = 0` to keep the stock listener, or
drop `demux = false` — it has been the default since 0.5.0, and the stock path
has neither handshake rate limiting nor certificate hot-reload.

The default is not made to depend on `demux`, deliberately: a setting whose
meaning changes with a neighbouring key is one nobody can read off the config
file, and it would silently drop the limit for anyone who later switched
`demux` off.

**QUIC clients pay one extra round trip on their first connection.** Unvalidated
Initials are answered with a Retry instead of a handshake, which is what stops a
spoofed Initial from costing a TLS signature. `turna_quic_retries_sent_total`
should track new connections roughly one-for-one; far more than that means
spoofed traffic.

**The Tarantool bootstrap requires a password.** It used to generate one and
print it to STDOUT for you to copy out of the log — which is journald, docker
logs and whatever collects them. Supply `TURNA_PASSWORD` or
`TURNA_PASSWORD_FILE`; a rerun with a new value is now how you rotate the
credential. Only relevant if you use the Tarantool backend; a single node on
`memory` is unaffected.

Two more worth knowing, though they need no action: `[tls]` is now built into
the release image by default and the node refuses to start if `[tls]` is enabled
on a binary without it, and core dumps are disabled unless you set
`[turn] allow_core_dumps = true`.

## Things that will bite you

**Logs contain client IP addresses.** Every 403 and every rate-limit rejection
logs a source address at warn level. For a node serving your own staff that is
personal data with whatever retention your log collector has.

Two independent switches, because the sinks are independent:
`syslog_redact_addresses = true` covers the syslog layer, and
`log_allocation_addresses = false` covers stdout — what `journalctl` and
`docker logs` show, and what a shipper collects. With the second one off,
addresses become `ip-<12 hex>` under a per-process salt: a host keeps one label
across every line about it, and the address is not recoverable from the log
afterwards. Set a retention period on the stream anyway.

**The health port serves the full metric surface.** Hundreds of series,
including per-tenant detail. It binds 127.0.0.1 by default; if you move it for
a remote Prometheus, move it to a private address, not to 0.0.0.0.

**Quota is abuse protection, not QoS.** Over the limit packets are dropped, so a
value set close to real usage produces frame loss that looks like a network
problem. Set it well above what a legitimate participant uses.
