# Runbook — verifying RFC 7635 OAuth against your authorization server

turna implements third-party authorization (RFC 7635): self-contained
ACCESS-TOKENs sealed with AES-GCM under a key shared with an authorization server
(AS), `kid` key selection, the §6.1 lifetime cap, and the 401
THIRD-PARTY-AUTHORIZATION challenge. It still **refuses `[turn.auth.oauth]
enabled = true` under `production = true`** (`docs/PRODUCTION_READINESS.md` R9),
because every test so far used tokens minted next to the validator — one reading
of the RFC checked against itself (`docs/OPEN-DECISIONS.md`, "OAuth").

This runbook is how an operator with a real AS produces the missing evidence. The
kit is `turna-oauth-verify` (`tools/oauth-verify`), wrapped by
`scripts/verify/oauth-verification.sh`. **Running it does not lift the gate**; it
produces the record that justifies doing so (last section).

## What you need

- Your AS, configured to issue RFC 7635 **self-contained** tokens (§6.2) with an
  AEAD algorithm turna supports: **AES-128-GCM** (16-byte AS-RS key) or
  **AES-256-GCM** (32-byte key). Other token formats (JWT, introspection-based
  tokens) are not RFC 7635 self-contained tokens and are out of scope.
- The AS-RS key(s) the AS seals with, in hex, and the `kid` for each.
- The **server name** the AS uses as the AEAD associated data for this TURN
  server. It must equal `[turn.auth.oauth] server_name` byte for byte.
- A staging node (`production = false`) with UDP reachable from where you run
  the kit, and a way to obtain one token plus its session key (`key`, the
  `mac_key`) from the AS the way your client application does (RFC 7635 §4).
- A Rust toolchain on the machine that builds the kit, or a prebuilt
  `turna-oauth-verify`.

Treat the token and `mac_key` as credentials: short lifetimes, and delete the
shell history afterwards.

## Step 0 — prove the plumbing (no AS)

```sh
scripts/verify/oauth-verification.sh selftest
```

Starts a throwaway loopback node with OAuth on and a random key, mints tokens
the way an AS does (`turna_auth::oauth_token`), and runs every step below,
including expired, wrong-server, tampered and wrong-key tokens, with both
MESSAGE-INTEGRITY variants. `RESULT: PASS (18 steps)` means this build and the
kit agree. It says nothing about your AS.

## Step 1 — configure the staging node

```toml
production = false

[turn]
realm = "example.com"

[turn.auth.oauth]
enabled = true
server_name = "turn.example.com"         # the AEAD associated data, exactly as the AS uses it
as_identity = "https://as.example.com"   # advertised in the 401 THIRD-PARTY-AUTHORIZATION
# One entry per kid the AS may use. A kid in USERNAME selects its key directly.
[[turn.auth.oauth.keys]]
kid = "turn-2026-09"
key = "${TURNA_OAUTH_KEY_2026_09}"       # hex, 32 or 64 characters
# strict_kid = true                      # also verify the strict profile (step 5)
```

## Step 2 — does turna read your AS's token? (no packets)

Get one token and its key from the AS, then:

```sh
scripts/verify/oauth-verification.sh inspect \
  --server-name turn.example.com \
  --as-rs-key-hex "$TURNA_OAUTH_KEY_2026_09" \
  --token '<access_token, base64>'
```

`RESULT: PASS` prints the enclosed `mac_key` length, issue time and lifetime as
turna decodes them, and the clock difference between the AS and this host.

| result | meaning |
|---|---|
| `FAIL — turna cannot open this token` | wrong key, a different `server_name` (AAD), or a layout other than §6.2 as turna reads it: `u16 nonce_len | nonce | AES-GCM{ u16 key_len | mac_key | u64 timestamp | u32 lifetime } | tag`. Compare with the AS's documentation before changing anything. |
| `mac_key` length not 20 or 32 | unusual; HMAC-SHA-1 (RFC 5389) needs 20, HMAC-SHA-256 (RFC 8489) 32. |
| `timestamp` hours away from now | the AS encodes the timestamp differently. RFC 7635 §6.2 is 64-bit fixed point, **seconds in the top 48 bits**; a raw Unix time in all 64 bits reads as a date near 1970. Record it — this is exactly the class of disagreement this exercise exists to find. |
| `EXPIRED` or `in the future` | clock skew; turna allows 5 s (§6.1 Delta). Fix NTP on either side. |

## Step 3 — exercise the node with the AS's token

```sh
scripts/verify/oauth-verification.sh exercise \
  --server 203.0.113.10:3478 \
  --token '<access_token>' \
  --mac-key-b64 '<key from the AS response>' \
  --kid turn-2026-09
```

Add `--sha256` if the AS issued a 32-byte key and your clients sign with
MESSAGE-INTEGRITY-SHA256; run once with each variant your clients use. `--peer`
changes the CreatePermission target (default `8.8.8.8`; nothing is sent to it).

Every step must `PASS`:

1. `401 THIRD-PARTY-AUTHORIZATION` — the node challenges with REALM, NONCE and
   your `as_identity`.
2. `Allocate with ACCESS-TOKEN` — accepted; the granted LIFETIME never exceeds
   the token's remaining life (§6.1).
3. `response signed with mac_key` — the success response carries
   MESSAGE-INTEGRITY keyed with the token's `mac_key` (§9).
4. `Refresh`, `CreatePermission` — authenticated with the same token.
5. `tampered token refused`, `wrong mac_key refused` — 401.
6. `release (Refresh 0)`.

A 401 at step 2 after a clean `inspect` usually means the node's `server_name`
or key differs from what you passed to `inspect`, or `strict_kid` is on and the
kid is not configured.

## Step 4 — expiry, rotation and kid selection

- Request a token with a short lifetime (60 s), wait for it to lapse, and run
  `exercise` again: step 2 must now fail with 401 (`inspect` shows `EXPIRED`).
- Rotate: add a second `[[turn.auth.oauth.keys]]` entry, have the AS issue with
  the new kid, restart the node, and `exercise` tokens from **both** kids.
- With `strict_kid = true`, a token presented under an unknown kid must be
  refused; without it, turna trial-decrypts across the keyring.

## Step 5 — a real client, if you have one

Most WebRTC stacks do not implement RFC 7635. If your client does, run a call
through the staging node with OAuth credentials and note the client and version.
This is the strongest evidence; the kit is a stand-in for it, not a replacement.

## What to record

Create `docs/interop/oauth-<as-name>-<YYYY-MM-DD>.md` with:

- the AS product and version, the AEAD algorithm, key sizes, and how the token
  was obtained;
- the node's commit (`git rev-parse HEAD` of the build) and its `[turn.auth.oauth]` section
  with keys removed;
- the full `inspect` and `exercise` outputs (they contain no key material — the
  token and key are only on your command line), for SHA-1 and SHA-256 as used;
- the expiry, rotation and `strict_kid` results;
- anything that disagreed, and how it was resolved.

## Lifting the gate (a separate change, after review)

Only once the record above exists and has been reviewed:

1. Remove the `turn.auth.oauth.enabled = true in production` refusal from
   `validate()` in `crates/config/src/lib.rs`, and the integration test
   `refuses_to_start_when_oauth_is_enabled_in_production`.
2. In `scripts/check-doc-claims.sh`, move `turn.auth.oauth.enabled` from the
   required-gate loop to `LIFTED_GATES`, so a later revert is caught.
3. Update R9 in `docs/PRODUCTION_READINESS.md`, the OAuth rows in
   `docs/feature-support.md`, `docs/protocol-gap.md`, `docs/migrating-from-coturn.md`
   and `README.md`, and the "OAuth" entry in `docs/OPEN-DECISIONS.md`, each linking
   the interop record.

This runbook and the kit ship with the gate **in place**.
