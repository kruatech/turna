# What the logs contain — audit, 2026-08-27

Every logging macro in the relay, session and node paths, read rather than
sampled. §6's data-minimisation item.

## Negative results, which are half the audit

**Usernames never reach a log.** Seventeen mentions of `username` in
`processor.rs`, none inside a logging macro. A username is the credential half an
operator can act on, and it is not written down.

**Secrets never reach a log.** No `shared_secret`, key material, nonce or token
in any macro. `--dump-config` masks them, and `--dump-config-raw` is the one that
does not — the help says so.

**No relayed payload is logged**, at any level. The datapath counts; it does not
narrate.

Worth stating rather than omitting: an audit that only lists findings reads as if
nothing was checked beyond them.

## The finding

**Three INFO lines carry the client's IP address**, all per-allocation:

```
info!(%src, %relay_addr, lifetime, "allocation created")
info!(%src, %relay_addr, lifetime, "TCP allocation created (RFC 6062)")
info!(%src, %old_addr, %relay_addr, "allocation migrated (RFC 8016)")
```

INFO is on by default. So a production node writes one line containing a client
address for every allocation it grants. This project's own 3-hour soak made 13.7
million allocations — 13.7 million lines of personal data, retained as long as
the log is.

Two problems in one:

**Privacy.** An IP address is personal data under GDPR and its equivalents.
Logging it is often legitimate and sometimes required; doing it by default with no
way to stop leaves the decision to whoever did not think about it.

**Volume.** One line per allocation at 10 800 allocations/second — a rate this
project has measured — is a log nobody keeps and a disk somebody fills.

## What was done, and the default that was not changed

`[observability] log_client_addresses`, **default true**: existing behaviour.

Defaulting to false would be the privacy-forward choice and it was not taken.
`src` on the allocation line is the field an operator correlates a complaint
against, and removing it silently in an upgrade breaks what logs are used for —
discovered, inevitably, during an incident.

So the behaviour stays, the switch exists, this document says what is being
logged, and `deployment-compliance.sh` reports the setting so an operator is told
rather than left to inherit a default.

Set false and addresses log as `ip-<12 hex>` under a per-process salt: an incident
stays traceable across one node's lifetime, and the address is not recoverable
from the log afterwards. The salt is never written down.

One function does the formatting for all three sites, not a conditional at each.
A log where two lines carry an address and the third carries a hash is worse than
either choice made consistently — somebody correlating them gets nothing and
cannot tell why.

## What this audit does not cover

**The transport crates.** TURNS, DTLS, QUIC and SCTP log their own connection
events and were not read line by line. They are likelier to carry addresses than
not, and the same switch does not reach them.

**Third-party crates.** `rustls`, `quinn` and `webrtc-dtls` log under their own
targets. What they say at INFO has not been examined.

Both are follow-up work, and naming them is the point: an audit that implies it
covered everything is worse than one that says where it stopped.
