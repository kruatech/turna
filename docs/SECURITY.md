# Security model

## What `turna` protects

- **Bandwidth abuse.** TURN credentials are required to allocate a
  relay. Without valid credentials, no allocation is created and no
  packets are forwarded.
- **Replay & forgery of STUN messages.** Message integrity is checked
  per RFC 8489 (HMAC-SHA1 with a key derived from
  `MD5(username:realm:password)`).
- **Cross-tenant interference.** Allocations are scoped to a `(client
  IP, port)` 5-tuple; permissions and channel bindings are per
  allocation; one client cannot read or write another's relay.

## What `turna` does NOT protect

- **The content of relayed packets.** TURN is a relay, not a tunnel.
  If a client sends plaintext UDP, anyone observing the relay path
  sees plaintext UDP. For WebRTC clients this is moot — they use
  DTLS-SRTP end-to-end. For non-WebRTC clients, use DTLS/your own
  app-level encryption.
- **DDoS at the network layer.** Sustained volumetric attacks need
  upstream mitigation (CloudFlare, AWS Shield, etc.). `turna` does
  have an in-process BPF filter for STUN format validation (planned —
  see TODO.md), but that doesn't help against pure traffic floods.
- **Compromise of the host.** If an attacker gets shell on the
  `turna-node` machine, they can read secrets from memory and from
  `/etc/turna/`. Standard server hardening applies.

## Threat model: what's the worst that can happen?

| Attacker | What they can try | What stops them |
|---|---|---|
| Random Internet host with no credentials | Allocate a relay | HMAC check fails → no allocation |
| Random Internet host that guessed/leaked `shared_secret` | Allocate a relay, burn your bandwidth | Rotate `shared_secret`; restrict credential lifetime via `token_ttl` |
| User with valid credentials | Allocate many relays to exhaust ports | `[turn.relay] max_allocations` + per-user quota in `BandwidthQuota` (planned wire-through to config — see TODO.md) |
| Operator on the same private network as Tarantool | Read/modify allocation records | Network-level access control + (planned) Tarantool user/password — see TODO.md |
| Operator who got a valid client cert for the gRPC API | Drain nodes, list allocations | mTLS reduces blast radius to known operators; rotate CA if a cert leaks |

## Production checklist

Before exposing to the Internet:

- [ ] `production = true` in config or `TURNA_PRODUCTION=true`.
- [ ] `shared_secret` set to a strong random value (`openssl rand -hex 32`).
      Not committed to git. Not in shell history (`unset HISTFILE` or use
      a secret store).
- [ ] `external_ip` set to your actual public IP.
- [ ] `/etc/turna/secrets.env` (or equivalent) is `chmod 0600` and owned
      by `root` or the `turna` user — not world-readable.
- [ ] Health/metrics port 9090 is **not** open to the public Internet.
      Firewall rules limit it to your monitoring host.
- [ ] gRPC management port 5350 is **not** open to the public Internet.
      Either bind to `127.0.0.1` or limit by firewall.
- [ ] gRPC management TLS: `mTLS` if reachable from anywhere off-host;
      `disabled` (with 127.0.0.1 binding) only for single-machine ops.
- [ ] Run the server as a non-root user (`turna`).
- [ ] systemd hardening directives applied (see [DEPLOY.md](DEPLOY.md)).
- [ ] You know how to rotate the `shared_secret` (see below).

## Rotating `shared_secret`

The shared secret is used for HMAC validation. Rotating it invalidates
all currently issued time-limited credentials.

In single-node mode:

1. Generate the new secret: `openssl rand -hex 32`.
2. Update the env var / file / config.
3. `systemctl restart turna-node`.
4. All currently active sessions die at restart in single-node mode.
   With cluster persistence enabled, sessions resume — but new
   credentials must be issued through your credential service.

For zero-downtime rotation you'd need to support two simultaneous
secrets and have clients migrate. That's not built in. **Workaround**:
schedule rotations during low-traffic windows.

## Reporting vulnerabilities

If you find a security issue, please report it privately first rather
than opening a public issue: use GitHub's private vulnerability reporting
("Security" tab → "Report a vulnerability") at
<https://github.com/kruatech/turna/security/advisories/new>.
Please include a minimal reproduction and the commit/tag you tested.

## What gets logged

By default `turna-node` logs at INFO level: client IPs, usernames,
allocation lifecycle events. Secrets (passwords, HMAC keys, the
shared secret itself) are **never** logged.

If you enable JSON logs (`json_logs = true`) and ship them to a
central log store, treat that store as containing personally
identifiable network metadata. Configure retention accordingly.
