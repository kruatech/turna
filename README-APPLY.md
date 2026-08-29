# Applying this archive

Nothing here has been compiled or run. Every file was checked for what could be
checked without a toolchain — brace balance, shell syntax, python syntax, JSON
validity, the arithmetic inside the logic — and that is a different thing from
working.

Two of the items in the last session needed a compiler round to find a mistake I
had made. Expect the same here.

## Order

    # 1. new modules — need module declarations added
    #    crates/control/src/lib.rs      : pub mod rbac;
    #    crates/observability/src/lib.rs: pub mod syslog;

    # 2. the RBAC wiring patch
    python3 patches/rbac_wiring.py

    # 3. build and let the compiler list what is left
    cargo clippy --workspace --all-targets \
      --features "tls,dtls,quic,web-transport,sctp" -- -D warnings

## What the compiler will ask for

**`rbac` threaded into the service builder.** The wiring patch adds the field and
the constructor argument; where the policy comes from — config — is the part it
cannot guess.

**`_req` renamed to `req`** in methods that ignored their request and now need it
for the permission check.

**Config sections** for `[management.rbac]` and the syslog endpoint. Both modules
take their configuration as plain structs, so the config crate needs the sections
and the node needs to pass them.

**`turna_crypto::sha256`** in syslog.rs — if the observability crate does not
already depend on turna-crypto, either add it or swap that call for whatever hash
is nearer to hand. It is used only for optional address hashing.

## What is in here

| file | what it is |
|---|---|
| `crates/control/src/rbac.rs` | Roles, permissions, bindings. 11 tests. Roles come from config, so a new one needs no release. |
| `crates/observability/src/syslog.rs` | RFC 5424 export for SIEM. 8 tests. UDP and TCP with octet framing. |
| `deploy/grafana/turna-overview.json` | 24 panels, schema 39 (Grafana 10 and 11). Every metric checked to exist in turna-health; no panel overlaps. |
| `tools/sdk/python/turna_sdk.py` | Python client. mTLS is required by the constructor rather than optional. |
| `tools/browser-probes/connectivity-check.html` | Client-side diagnosis, single file, no dependencies. |
| `scripts/verify/capacity-profile.sh` | Finds the packet-rate ceiling. Already run: 112k pps on 32 threads. |
| `scripts/verify/deployment-compliance.sh` | Checks a deployment against the security profile. Tested against a good and a bad config. |
| `scripts/verify/rotation-under-load.sh` | Certificate and secret rotation with traffic flowing. |
| `scripts/verify/upgrade-rollback.sh` | Drain, swap the binary, roll back — against the *new* config, which is what an operator would have. |
| `docs/security/security-profile.md` | One checklist instead of a dozen scattered documents. |
| `docs/deployment/enterprise-network-profile.md` | Ports, the proxy matrix, conntrack sizing. |
| `docs/capacity/threadripper-1950x-2026-08-26.md` | The measured ceiling, and the three wrong numbers before it. |

## Not in here

**RFC 5780 NAT discovery** — deferred, it needs a second address on the node.

**Infrastructure audit beyond RPCs** — `AuditEntry` already covers privileged
management operations with a hash chain. Extending it to non-RPC events needs a
decision about what counts, and inventing that list would have produced
categories nobody asked for.

## Two things worth reading before the code

`docs/security/security-profile.md` has a section called "Where the defaults are
weaker than they look". Three of those are open decisions rather than bugs, and
one — DTLS on the stock path having neither certificate reload nor handshake rate
limiting — blocks two P0 requirements structurally.

`docs/capacity/` records that the failure above the ceiling is a cliff, not a
slope: 7 % over, and a million frames go in two minutes. That is the argument for
admission control acting on a fraction of the measured figure, and it is more
useful than the figure.
