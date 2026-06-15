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
