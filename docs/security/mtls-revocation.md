# mTLS client-certificate revocation (management plane)

Audit-2 §9.2 #9: "No CRL for mTLS — a compromised client certificate cannot be
revoked without rotating the whole CA."

This document records the current posture, why a code-level CRL is not a quick
fix on the present stack, and the mitigations available today.

## Current mTLS posture

The management gRPC server (`crates/control/src/grpc.rs`) builds TLS with tonic's
high-level `ServerTlsConfig`:

- server identity: `server_cert` + `server_key`;
- client trust anchor: `client_ca_root` = `client_ca_cert`.

When TLS is configured, mTLS is enforced (a client must present a certificate
that chains to the configured CA — see the M4 management-TLS hardening). There is
no per-certificate revocation: **any** client cert chaining to the CA is accepted
for the life of that cert.

## The gap

There is no CRL or OCSP check. If a single client certificate is compromised, the
only way to invalidate it today is to rotate the CA — which re-issues every client
certificate, not just the leaked one.

## Why this is not a one-line fix

tonic 0.12's `ServerTlsConfig` is a thin wrapper over tokio-rustls and exposes no
CRL hook (no `with_crls` / custom-verifier injection). Real revocation requires a
custom rustls `WebPkiClientVerifier::builder(roots).with_crls(crls).build()` (and
optionally OCSP), which means either:

1. upgrading to a tonic version that lets a custom rustls `ServerConfig` be
   supplied (ties into the `tonic 0.12 → 0.14` migration tracked with the RUSTSEC
   advisories), or
2. terminating TLS in a custom `tokio-rustls` accept loop and feeding the accepted
   streams to tonic via `serve_with_incoming`.

Both are real work that must be built and tested on a branch with the build
available. To avoid the "misleading config" trap, **no CRL config field has been
added** until the verifier behind it actually enforces it.

## What now exists (2026-08-27)

`[grpc] revocation_list` — a file of client-certificate fingerprints that may not
be used.

```toml
[grpc]
revocation_list = "/etc/turna/revoked-certs.txt"
```

```text
# laptop lost 2026-08-14, ticket OPS-4471
3fa1c9...  # alice@example.com, issued 2026-06-01
7bd204...
```

Colons and upper case are accepted, because that is what
`openssl x509 -fingerprint -sha256` emits and an operator pasting its output
should not have to know otherwise.

### Be precise about what this is

**It is not RFC 5280 CRL validation.** No CA-signed list, no `nextUpdate`
freshness rule, no distribution point. If a compliance regime names CRL or OCSP
specifically, this does not satisfy it and the work described below is what does.

**It is a deny-list checked when an RPC arrives**, at the application layer, using
the same certificate fingerprint the audit log already derives. A revoked client
completes the TLS handshake and is refused on its first call.

### Why this shape, given the analysis below still holds

Everything the next section says about `ServerTlsConfig` remains true — there is
no CRL hook, and TLS-level revocation still needs a custom verifier behind either
a tonic version accepting a custom `ServerConfig` or an accept loop feeding
`serve_with_incoming`.

The operational goal, though, does not require TLS-level integration: a leaked
certificate stops working and the other twenty are not reissued. That was
reachable in a hundred lines because the pieces existed — `actor_of` already
derives the fingerprint, RBAC already maps fingerprints to meaning.

Three things this has that a CRL would not, here:

**It works with no route off the host.** A CRL has to reach the node from the CA.
The deployments that most need revocation are the air-gapped ones — the case
`scripts/verify/air-gap.sh` exists to prove — and a CRL distribution point is
exactly what they cannot have.

**The operator revokes directly.** One line and a reload, not a CA operation.

**One notion of identity.** The fingerprint means the same thing to the audit log,
to RBAC, and to this.

Two things it lacks:

**Refusal is post-handshake.** It costs a TLS handshake, and the refusal appears
in the audit log rather than as a TLS alert in a packet capture.

**It is per-node.** Ten nodes need the file ten times — a configuration-management
problem where a CRL would have been a fetch.

### Fail-closed

A configured path that cannot be read **stops the node from starting**, and a
malformed line is an error naming the line.

Both are deliberate and both are the loud direction. A list that is configured and
silently empty looks like protection and is not, and the first person to discover
that is whoever used the leaked certificate. A mistyped fingerprint is a
revocation that does not apply, which is the same failure one line smaller.

The error message says how to produce a correct fingerprint, because the person
reading it is mid-incident.

### Checked before RBAC, deliberately

Both refusals return `permission_denied`, so the order looks cosmetic. It is not.

A revoked certificate that *also* lacks the permission would be audited as
`rbac_denied` if RBAC ran first. An operator reading that entry would grant the
role — and the revoked certificate would then work. The audit entry has to name
the reason that applies, and revocation is the stronger claim: it is about the
credential, not the capability.

### What the caller is told

"permission denied", the same as any other refusal. Not "your certificate is
revoked" — that would confirm the certificate was once valid and that the operator
knows it leaked. The detail is in the audit log under the action `cert_revoked`,
read by somebody already inside.

### Still future work

Real TLS-level CRL and OCSP stapling, for deployments where a compliance regime
names them or where a CA already publishes lists that should be honoured. The
analysis below is unchanged and is still the map.

Note for whoever does it: **OCSP is the wrong default for this product.** It needs
a reachable responder, and the air-gapped case has none — configuring it there
means either failing every handshake or setting soft-fail, which is the absence of
revocation with the appearance of it. CRL first, OCSP as an option for connected
deployments.

## Mitigations available now

Until code-level CRL lands, bound the exposure with operational controls:

- **Short-lived client certificates** (hours/days). A leaked cert self-expires
  quickly — this is the standard substitute for CRL and the recommended default.
- **Per-client intermediate CAs.** Issue client certs from per-client (or
  per-team) intermediates so a compromise is contained to one intermediate, which
  can be dropped from the trust bundle without reissuing every client cert.
- **Network allowlist on the management port** in addition to mTLS, so a leaked
  cert is only usable from approved source networks.
- **Monitor and rotate.** Alert on management-plane cert usage; on suspected
  compromise, rotate the CA (full) or the affected intermediate (scoped).

## Future work (the real fix)

Custom rustls client verifier with CRL support (and optional OCSP stapling),
gated on the tonic upgrade or a custom accept loop. Track alongside the
`tonic 0.12.3 → 0.14.x` migration in `docs/security/remediation-2026-06.md`.
