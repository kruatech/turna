# turna documentation

Where to start, by what you are trying to do. Dated files (`*-2026-08-19.md`,
`v0.3.0-rc.1.md`) are evidence records: they describe a run on a given day and
are not updated afterwards. Undated files are maintained and describe the
current tree.

## Start here

| Document | For |
|---|---|
| [QUICKSTART.md](QUICKSTART.md) | First run on a laptop |
| [SELFHOSTED.md](SELFHOSTED.md) | One node on your own hardware, start to finish |
| [why-turna.md](why-turna.md) | Design rationale and comparison |
| [migrating-from-coturn.md](migrating-from-coturn.md) | Moving an existing coturn deployment |

## What is supported

| Document | For |
|---|---|
| [feature-support.md](feature-support.md) | Feature and RFC support matrix |
| [PRODUCTION_READINESS.md](PRODUCTION_READINESS.md) | Maturity per area and known limitations |
| [protocol-gap.md](protocol-gap.md) | Protocol features not implemented, and why |
| [COMPLIANCE.md](COMPLIANCE.md) | Protocol compliance and deliberate constraints |
| [OPEN-DECISIONS.md](OPEN-DECISIONS.md) | Decisions not yet taken |

## Configure and deploy

| Document | For |
|---|---|
| [CONFIGURATION.md](CONFIGURATION.md) | Every configuration key |
| [DEPLOY.md](DEPLOY.md) | Production deployment (Docker, Helm, systemd) |
| [deployment/host-tuning.md](deployment/host-tuning.md) | Kernel and host tuning |
| [deployment/enterprise-network-profile.md](deployment/enterprise-network-profile.md) | Corporate network profile |
| [CLUSTER.md](CLUSTER.md) | Cluster mode (experimental) |
| [transport-backends.md](transport-backends.md) | tokio / io_uring / AF_XDP datapaths |
| [compatibility/transport-backends.md](compatibility/transport-backends.md) | Datapath compatibility and support tiers |

## Operate

| Document | For |
|---|---|
| [operations-overview.md](operations-overview.md) | Operations overview |
| [OBSERVABILITY.md](OBSERVABILITY.md) | Metrics, tracing, logs |
| [slo-and-capacity.md](slo-and-capacity.md) | SLOs and capacity planning |
| [runbooks.md](runbooks.md) | Incident runbooks (§23) |
| [runbooks/](runbooks/) | Per-area runbooks: Tarantool, Kubernetes, io_uring, AF_XDP, encrypted transports, disaster recovery |
| [operator-todo.md](operator-todo.md) | Decisions and measurements left to the operator |
| [admin/README.md](admin/README.md) | Admin console |
| [MANAGEMENT_API.md](MANAGEMENT_API.md) | gRPC management API contract |
| [MTLS.md](MTLS.md) | mTLS for the management API |

## Security

| Document | For |
|---|---|
| [../SECURITY.md](../SECURITY.md) | Supported versions and how to report a vulnerability |
| [SECURITY.md](SECURITY.md) | Security model |
| [SECURITY_OPS.md](SECURITY_OPS.md) | Hardening and operational notes |
| [THREAT_MODEL.md](THREAT_MODEL.md) | Threat model (summary) |
| [security/threat-model.md](security/threat-model.md) | Threat model (full) |
| [security/](security/) | Invariants, peer filter, management surface, accepted risks, audit records |
| [unsafe-audit.md](unsafe-audit.md) | `unsafe` code audit |
| [REPRODUCIBLE_BUILDS.md](REPRODUCIBLE_BUILDS.md) | Reproducible builds |

## Release and project policy

| Document | For |
|---|---|
| [../RELEASE.md](../RELEASE.md) | Release gates and procedure |
| [RELEASE-POLICY.md](RELEASE-POLICY.md) | Branching, tagging and release guarantees |
| [SUPPORT-POLICY-OPTIONS.md](SUPPORT-POLICY-OPTIONS.md) | Support/LTS options and their cost |
| [BENCHMARKING.md](BENCHMARKING.md) | How benchmarks are run |

## Design notes

[design/](design/) — AF_XDP datapath, QUIC/WebTransport, DTLS, RFC 6062 TCP
allocations, allocation persistence, capacity API, `ADDITIONAL-ADDRESS-FAMILY`.

## Evidence records

Dated; each supports a status claim in the matrices above.

- [verification/](verification/) — per-feature support records and GA verification
- [interop/](interop/) — interoperability runs (browsers, coturn, OpenSSL)
- [soak/](soak/) — endurance and soak runs
- [capacity/](capacity/), [scale/](scale/), [failover/](failover/), [dtls/](dtls/) — capacity, scale, failover and DTLS runs
- [roadmap/](roadmap/) — implementation status and gap analyses
