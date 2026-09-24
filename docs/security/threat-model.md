# Threat Model — turna

**Date:** 2026-06-11  
**Version:** 1.1  
**Status:** current for the present TURN-only workspace

## 1. Scope

This threat model describes the current Turna workspace: TURN/STUN relay,
optional encrypted transports, gRPC management/control plane, cluster gossip and
Tarantool-backed allocation persistence.

The current repository has no standalone `turna-signaling`, bundled browser demo or
SFU service. Platform JWT/user-store components exist as crate-level
primitives, but are not a public HTTP auth service in this workspace.

## 2. Protected assets

| Asset | Description | Criticality |
|---|---|---|
| TURN credentials | Shared-secret, static long-term users, derived HMAC keys | Critical |
| TURN allocations | Relay ports, permissions, channel bindings, allocation TTL | High |
| Relay traffic metadata | Client/peer/relay addresses, username/realm, counters | High |
| Management API | gRPC management interface and `turnactl` operations | High |
| Cluster gossip | Node membership, redirect ownership, drain/leaving messages | High |
| Persistence backend | Tarantool allocation/node state | High |
| TLS/DTLS/QUIC key material | Certificate/private-key files for optional transports | Critical |
| Observability data | Metrics/logs/traces with network metadata | Medium/High |

## 3. Attacker classes

### 3.1 Unauthenticated Internet client

- **Capabilities:** sends arbitrary UDP/TCP packets to the public TURN edge.
- **Goals:** obtain a relay without credentials, trigger a parser panic, exhaust CPU.
- **Mitigations:** STUN parser limits, MESSAGE-INTEGRITY before state mutation,
  auth challenge path, malformed packet counters, optional Linux BPF pre-filter.

### 3.2 Malicious authenticated TURN client

- **Capabilities:** has valid credentials.
- **Goals:** exhaust allocations/relay ports/bandwidth, scan the private
  network via TURN permissions, attempt to read other clients' traffic.
- **Mitigations:** per-allocation isolation, permission/channel enforcement,
  `[turn.relay].max_allocations`, `[turn.relay.quota]`, peer filter default
  `internet-facing`.

### 3.3 Replay attacker

- **Capabilities:** interception and replay of TURN/STUN requests or a mobility ticket.
- **Goals:** reuse stale credentials/tickets.
- **Mitigations:** credential expiry in username for shared-secret mode, nonce handling,
  MESSAGE-INTEGRITY, migration ticket TTL and HMAC key.

### 3.4 Peer-address abuse / SSRF attacker

- **Capabilities:** an authenticated client tries to create a permission/channel/send
  toward loopback, link-local, cloud metadata, RFC1918/ULA, multicast, etc.
- **Goals:** use TURN as a port scanner or SSRF relay.
- **Mitigations:** peer filter normalizes addresses before decision, denies special-use
  ranges, and defaults to `internet-facing`.

### 3.5 Malformed packet sender

- **Capabilities:** sends deliberately malformed STUN/ChannelData/RTP/RTCP packets.
- **Goals:** OOB read/write, panic, infinite loop, high parser CPU.
- **Mitigations:** parser limits, fuzzing, property tests, counters
  `turna_parser_rejections_total` and `turna_malformed_packets_total`.

### 3.6 Management-plane attacker

- **Capabilities:** reaches the gRPC management port.
- **Goals:** drain node, kill allocation, read operational state, call future admin
  RPCs.
- **Mitigations:** loopback bind by default in `deploy/turn.toml`, production validation
  requiring mTLS for non-loopback exposure, firewall/VPN requirement.

### 3.7 Cluster-network attacker

- **Capabilities:** reaches the UDP gossip port or Tarantool port on the private network.
- **Goals:** inject node membership, redirect clients, corrupt persisted
  allocation state.
- **Mitigations:** `cluster_secret` for gossip HMAC, private firewall rules, Tarantool
  dedicated user/password, least-privilege schema grants.

### 3.8 Compromised node

- **Capabilities:** full shell on one Turna host.
- **Goals:** read local secrets, alter config, publish bad cluster state, observe
  metadata.
- **Mitigations:** OS hardening, non-root service user, least-privilege secret files,
  mTLS/control-plane cert rotation, cluster credential rotation, backend audit.

## 4. Trust boundaries

```text
PUBLIC INTERNET
  │ UDP/TCP 3478, optional TLS/DTLS/QUIC listener
  ▼
PUBLIC TURN EDGE
  - parser limits
  - auth challenge
  - optional BPF pre-filter
  │ verified MESSAGE-INTEGRITY
  ▼
RELAY CORE
  - allocation store
  - permissions/channels
  - peer filter
  - quota/accounting
  │ internal state writes / metrics
  ▼
CLUSTER + PERSISTENCE NETWORK
  - UDP gossip with shared secret
  - Tarantool with user/password
  │ operator-only access
  ▼
MANAGEMENT PLANE
  - gRPC + turnactl
  - mTLS when exposed off-host
  │ read-only scrape
  ▼
OBSERVABILITY
  - /health, /status, /metrics
  - logs/traces containing network metadata
```

## 5. Attack surfaces

### 5.1 STUN/TURN parser

- **Vector:** any UDP/TCP packet on the TURN listener.
- **Risk:** malformed attribute lengths, ambiguous STUN/ChannelData framing,
  parser panic.
- **Controls:** strict parser, fuzzing, hard limits, parse error counters.

### 5.2 Allocation lifecycle

- **Vector:** Allocate, Refresh, CreatePermission, ChannelBind, Send Indication,
  ChannelData.
- **Risk:** unauthenticated state mutation, permission bypass, stale allocation
  reuse.
- **Controls:** auth before mutation, allocation/session indexes, permission TTL,
  channel binding validation.

### 5.3 Peer filtering

- **Vector:** authenticated requests targeting denied IP ranges.
- **Risk:** SSRF / private network scanning.
- **Controls:** address normalization, default private/special-use denial,
  explicit LAN opt-in.

### 5.4 Optional encrypted transports

- **Vector:** TLS/DTLS/QUIC handshakes and framed TURN payloads.
- **Risk:** handshake flood, cert/key misconfiguration, less-exercised code path.
- **Controls:** feature gates, config validation, max connections/sessions,
  mTLS guidance for management plane.

### 5.5 gRPC management

- **Vector:** management listener.
- **Risk:** unauthorized admin action or operational data exposure.
- **Controls:** loopback default, production mTLS validation, firewall, client CA
  rotation.

### 5.6 Cluster gossip

- **Vector:** UDP gossip endpoint.
- **Risk:** fake node injection, malicious redirects, false liveness.
- **Controls:** cluster name, `cluster_secret`, private network firewall,
  gossip timeout and leaving/drain handling.

### 5.7 Tarantool backend

- **Vector:** iproto port / backend credentials.
- **Risk:** persisted allocation modification, failover corruption.
- **Controls:** dedicated user/password, minimum privileges from
  `deploy/tarantool/init.lua`, private network, monitoring writer errors/drops.

### 5.8 Config loading and secrets

- **Vector:** `turn.toml`, `${VAR}`, `file:///path`, mounted secrets.
- **Risk:** placeholder secret in production, bad external IP, secret leakage.
- **Controls:** strict schema, production validation, file-secret support,
  masked `--dump-config`.

## 6. Security invariants

- No allocation or relay state is created before credentials validate.
- A permission/channel binding is scoped to exactly one allocation.
- Peer filtering normalizes addresses before policy checks.
- Special-use addresses are denied by default for Internet-facing deployments.
- Cluster node ids are unique in a healthy cluster.
- Tarantool write drops are observable and must alert in HA deployments.
- gRPC management must be loopback-only or mTLS-protected in production.

## 7. Accepted risk: global rotating NONCE

`NonceManager` keeps a server-wide current/previous NONCE rather than a
per-client nonce. A captured NONCE is therefore valid for another client within
the grace window.

This is accepted because MESSAGE-INTEGRITY is still mandatory on authenticated
requests: a stolen NONCE alone grants nothing without the client's long-term key.
The reuse window is bounded by rotation/grace timing. Revisit this only if
per-client replay accounting becomes a strict requirement.
