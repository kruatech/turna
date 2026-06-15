# Backend e2e / differential tests (Stage 3 / Milestone 3)

These scripts exercise the **real** TURN lifecycle against a live `turna-node`
on each transport backend and compare the results, instead of duplicating
assertions per backend. They reuse the existing live-server suite in
`tests/integration` (Binding → Allocate 401→auth → Refresh → CreatePermission →
ChannelBind → ChannelData → delete).

## `backend_diff.sh` — Tokio vs io_uring differential (roadmap §7.1)

Builds one node binary (`--features io-uring`), then boots it once per backend
by flipping `[turn].transport` in a copy of a base config, runs the integration
suite against each, and reports **parity** (identical results) or **divergence**.

```bash
# defaults: base config deploy/turn.toml, target 127.0.0.1:3478,
# health http://127.0.0.1:9090/health, backends "tokio io_uring"
scripts/e2e/backend_diff.sh deploy/turn.toml

# shared-secret (coturn lt-cred) auth, single test:
TURNA_TEST_SECRET=turna-secret TEST_FILTER=turn_allocate \
  scripts/e2e/backend_diff.sh deploy/turn.toml

# static-users auth:
TURNA_TEST_USER=user TURNA_TEST_PASS=pass \
  scripts/e2e/backend_diff.sh deploy/turn.toml
```

Env knobs: `BACKENDS`, `TARGET`, `HEALTH_URL`, `TEST_FILTER`, `START_TIMEOUT`,
and the suite's `TURNA_TEST_SECRET` / `TURNA_TEST_USER` / `TURNA_TEST_PASS`
(forwarded as-is; they must match the base config's `[turn.auth]`).

Exit code: `0` = all backends agree, `1` = divergence or a backend failed to
start. Per-backend node and test logs are printed in the failure summary.

## Coverage matrix

| Backend  | Covered here | How |
|----------|--------------|-----|
| Tokio    | yes          | `transport = "tokio"`, live suite |
| io_uring | yes          | `transport = "io_uring"`, same suite, result diffed vs tokio |
| DTLS     | no (DTL-5)   | needs a DTLS-wrapped client; the UDP suite cannot speak DTLS |
| AF_XDP   | no (AFX-7)   | needs a privileged veth + XDP lab harness |
| coturn   | no (§7.2)    | external reference; separate differential |

## Notes / limitations

- This is a **suite-level** differential: it compares pass/fail of the whole
  integration run per backend. Response-byte-level comparison (per §7.1) is a
  finer follow-up.
- io_uring requires Linux 5.6+; on other platforms the io_uring run will fail
  to start and the script reports divergence (expected — run it on Linux).
- DTLS (DTL-5) and AF_XDP (AFX-7) get their own harnesses; this script
  deliberately scopes to the two UDP backends the existing client supports.
