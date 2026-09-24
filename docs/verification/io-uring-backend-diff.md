# Short tokio / io_uring live comparison

Run `bash scripts/e2e/backend_diff.sh` on Linux from the repository checkout.
The runner builds the release node with `--locked --features io-uring` and runs
10 explicitly named STUN/TURN tests sequentially against each backend. It is a
suite-level functional comparison, not a byte-level differential or soak.

The default stand uses loopback UDP 13478, TCP health 19098, and relay ports
23000..23255. The test identity is testuser/testpass, production=false, with
loopback peers allowed. It refuses occupied TURN/health ports before building.
No external traffic, sudo, firewall changes or background service is required.
An optional base config must match TARGET and HEALTH_URL; custom configurations
must provide matching test credentials through the existing environment.

OUT defaults to a timestamped directory, created exclusively with private
permissions. Build, node and individual test logs and summary.tsv are retained.
Do not publish custom configs containing real credentials.

PASS requires both backends to start, every selected test to execute exactly once
and succeed without SKIP, the node to remain alive, and graceful process exit.
Equal failures, zero selected tests, reachability skips and startup failures fail.
The relay test requires media in both directions and successful allocation deletion;
a relay timeout no longer merely prints a note and returns success.

Runner regression tests (fake processes; not a datapath validation):

```sh
python3 -m unittest discover -s scripts/e2e -p test_backend_diff.py
```

The previous recovery patch was operator-verified on cloud: 68 transport unit tests
and one worker drain test passed. On Linux 6.14.0-33, run
`uring-backend-614-drainfix-20260920-021750` passed all ten tests per backend,
with `node shutdown: exit=0` for both. The initial run passed the functional
checks but failed the runner's ten-second shutdown deadline. The corrected
runner waits up to 60 seconds and still fails on forced kill or nonzero exit.
See the [support record](io-uring-supported-2026-09-19.md) for the evidence matrix.
