# Security profile

One document, because the material was spread across a dozen files in
`docs/security/` and an operator hardening a deployment had to find them all.
This is the checklist; the linked documents are the reasoning.

Each item says what to set, what it costs, and what breaks if you skip it. An
item with no cost is usually one nobody thought about.

## Non-negotiable

| setting | why | cost of skipping |
|---|---|---|
| `production = true` | Refuses placeholder secrets, missing TLS in cluster mode, unlimited per-allocation bandwidth, and three experimental transports. | The node starts with defaults that are convenient for development. |
| `[turn.auth] shared_secret` from env or file | `${TURNA_SHARED_SECRET}` or `file:///run/secrets/...`. Never a literal. | The credential that mints TURN sessions sits in a file that gets copied into tickets. |
| `[management] require_client_cert = true` | The management plane mints users and shuts down nodes. | Anyone who reaches the port is an administrator. |
| `[turn.peer_filter] profile` set deliberately | Default denies RFC 1918 and ULA. `lan` relays to private ranges. | An internet-facing relay becomes an SSRF proxy into the deployment's own network. |
| Relay port range disjoint from the ephemeral range | `cat /proc/sys/net/ipv4/ip_local_port_range` and stay clear of it. | A peer socket lands inside the relay range and the relay forwards to itself. This has happened here. |

## Strongly recommended

| setting | why |
|---|---|
| `[management.rbac] enabled = true` | Without it every management client is an administrator. Note it is default-deny: enabling on a running deployment locks out every client until bound. |
| `[turn.relay.quota] max_per_user` | A single credential can otherwise consume the whole port range. |
| Per-IP caps on every enabled transport | `max_connections_per_ip` on TURNS, DTLS, QUIC, SCTP. One source can otherwise hold every slot. |
| Handshake rate limits | TURNS, QUIC and SCTP support them. DTLS only on the demux path — see below. |
| `[observability] syslog_endpoint` | Security events to a SIEM. Absent, an investigation reads the absence of events as the absence of attacks. |
| `[turn.relay] drain_timeout_secs` tuned | Default 30. A node whose clients vanished pays it in full, which is five minutes across a ten-node rolling upgrade. |

## Where the defaults are weaker than they look

**DTLS on the stock path has no certificate hot-reload and no handshake rate
limit.** Both exist on the demux path (`[turn.dtls] demux = true`), which is off
by default because the stock path is the one with recorded verification. Two
requirements are therefore structurally unavailable on the current default. This
is a known open decision, not an oversight — `docs/OPEN-DECISIONS.md`.

**MESSAGE-INTEGRITY is HMAC-SHA1 and the credential key is MD5.** Both are fixed
by RFC 5389 and required by every deployed TURN client. RFC 8489's
MESSAGE-INTEGRITY-SHA256 is implemented and preferred when the client offers it.
No configuration changes this; it is the protocol.

**There is no certificate revocation.** Revoking a management client means
rotating the CA. Deliberate, documented in `docs/security/mtls-revocation.md`,
and the thing a customer asks about first.

**AF_XDP accepts five configuration keys it does not apply.** They are now
refused at startup rather than ignored, but the underlying limitation stands: ring
sizes come from the library.

## Verifying rather than assuming

| check | what it establishes |
|---|---|
| `scripts/verify/mtls.sh` | The management plane accepts a certificate *and refuses a request without one*. The refusal is the half that carries it. |
| `scripts/verify/air-gap.sh` | The node relays with no route off the host and opens no outbound socket. Needs root. |
| `bash scripts/check-doc-claims.sh` | Documented claims still match the code — including that the production refusals named here still exist. |
| `scripts/verify/reproducible-build.sh` | The published binary corresponds to the published source. Linux only. |
| `scripts/support-bundle.sh` | Produces a shareable bundle. Read its MANIFEST before sending — that habit is what makes the redaction trustworthy rather than assumed. |

## Accepted risks

Recorded in `docs/security/accepted-risks.md` rather than here, so that a risk
somebody decided to accept cannot be mistaken for one nobody noticed. Read it
before concluding something was missed.
