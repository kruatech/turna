# Backend end-to-end checks

## `backend_diff.sh` — tokio and io_uring acceptance

From the repository root on Linux:

```bash
OUT=backend-diff-$(date +%Y%m%d-%H%M%S) bash scripts/e2e/backend_diff.sh
```

Builds the release node with `--locked --features io-uring`, then runs ten named
STUN/TURN tests per backend. Each test must execute exactly once without SKIP.
Both backends must pass and exit cleanly after SIGTERM. Matching failures are
failures, not parity. This is suite-level testing, not a byte-level comparison.

Defaults: loopback UDP 13478, HTTP `/ready` on 19098, relay ports 23000..23255,
static test credentials, loopback peers allowed and `production = false`.
Ports must be free. Output is a new private directory containing `summary.tsv`,
configurations, build logs and individual test/node logs. Do not publish credentials.

An optional base config must match `TARGET` and `HEALTH_URL` and use IPv4
loopback endpoints. Supply matching `TURNA_TEST_USER`/`TURNA_TEST_PASS` or
`TURNA_TEST_SECRET` for that config. `START_TIMEOUT` controls startup waiting;
shutdown waits up to 60 seconds, then fails and kills the process. `TEST_FILTER`
can select a subset, but a subset is not full-suite evidence. `BACKENDS` must
remain `tokio io_uring`.

Exit 0 means every selected check and both shutdowns passed; any failure returns
nonzero. The earlier ten-second shutdown budget could kill a healthy draining
node and has been corrected; successful reruns are recorded in
[verification](../../docs/verification/io-uring-supported-2026-09-19.md).

```bash
python3 -m unittest discover -s scripts/e2e -p test_backend_diff.py
```

These runner unit tests use fake processes. They do not validate a real kernel.
Live backend tests require Linux with io_uring permitted; no sudo is needed on
an unrestricted test host. DTLS, QUIC, WebTransport, SCTP, AF_XDP and independent
coturn interoperability require their own verification procedures.
