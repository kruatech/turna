# Threat model

A high-level threat model for turna as a TURN/STUN relay and its control
plane. It is intentionally concise and is meant to be read alongside
`docs/security/` (audit, unsafe inventory, accepted risks). Mitigations are
tagged **[implemented]** or **[planned]** so the document does not overstate
the current posture.

## Assets

- TURN shared secret and long-term user credentials.
- Allocation / session state (5-tuples, permissions, channel bindings).
- Relay traffic and its metadata.
- Control-plane credentials and gRPC surface.
- mTLS / TLS private keys and certificates.
- Persisted state in the backend (e.g. Tarantool).

## Trust boundaries

- The node process (data plane) and the untrusted network edge.
- The control plane and the nodes it manages.
- The state backend (separate process / host).
- The Kubernetes secret store and the container boundary.
- Operator-supplied configuration and certificate files.

## Threats and mitigations

- **Credential leakage / weak auth.** Long-term credentials (HMAC-SHA1) and
  shared-secret auth; passwords hashed with Argon2; JWT for management tokens.
  **[implemented]** Secrets injected via Kubernetes `Secret` (env), never
  baked into the ConfigMap or image. **[implemented]**
- **Open-relay abuse / unauthorized relaying.** TURN permission and
  channel-binding authorization gate which peers a client may reach.
  **[implemented]** Rate limiting / QoS via the token-bucket limiter
  (`turna-qos`). **[implemented]**
- **Control-plane takeover.** gRPC control surface separated from the public
  TURN listener; TLS/mTLS available for the control channel (feature-gated,
  experimental). **[implemented, experimental]** A real client-certificate
  CRL is **[planned]**.
- **Metrics / control endpoint exposure.** Health/metrics moved to an internal
  ClusterIP service, split from the public TURN load balancer.
  **[implemented]** Cluster-level `NetworkPolicy` (opt-in via
  `networkPolicy.enabled`) keeps health/metrics cluster-internal while
  leaving TURN/STUN and the relay UDP range public. **[implemented]**
- **Malicious packet input (parser).** STUN/TURN/RTP parsers fuzzed in CI
  (`cargo fuzz`, smoke run per target); pure-memory `unsafe` checked under
  Miri; lock-free primitives checked under Loom. **[implemented]**
- **Memory-safety bugs in `unsafe`.** All `unsafe` blocks inventoried and
  audited (`docs/security/unsafe-inventory.json`, `docs/unsafe-audit.md`); a
  CI script fails on new `unsafe` outside the audited set. **[implemented]**
- **Dependency / supply-chain compromise.** `cargo deny` (licenses +
  advisories) in CI; release images cosign-signed (keyless) with SLSA
  provenance + SBOM attestations; GitHub Actions pinned by commit SHA
  (`pinact`) and maintained by Dependabot; OpenSSF Scorecard workflow.
  **[implemented]**
- **Container escape / privilege escalation.** Containers run as a fixed
  non-root UID/GID with all capabilities dropped, read-only root filesystem,
  no privilege escalation, and the default seccomp profile. **[implemented]**
- **Configuration mistakes.** Config is parsed and validated by
  `turna-config`; the rendered Helm config is parsed by the same code in CI.
  **[implemented]**

## Out of scope (for now)

- Runtime user CRUD over the management API (not implemented / partial — see
  `docs/PRODUCTION_READINESS.md`).
- DDoS protection at the network edge (deploy-time concern; left to the
  operator's infrastructure).
