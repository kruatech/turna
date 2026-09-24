# Auth webhook — `[turn.auth.webhook]`

turna can ask your signalling service for a long-term user's credentials instead
of holding every user in its config or its state backend. When a request names a
USERNAME that is not in `[[turn.auth.static_users]]`, turna POSTs the name to an
HTTPS endpoint you run, caches the answer, and validates MESSAGE-INTEGRITY
against it. coturn gets the same effect with a SQL or Redis user database; here
the source of truth stays in the service that already knows your users.

**Off by default.** Enabling it switches the base realm to long-term
credentials (static users first, then the webhook); the TURN REST
`shared_secret` path is not used for the base realm while it is on. Tenants
(`[[tenants]]`) are unaffected. It cannot be combined with `[turn.auth.oauth]`.

## Configuration

```toml
[turn.auth.webhook]
enabled = true
url = "https://signalling.internal/turn/credentials"
bearer_token = "${TURNA_WEBHOOK_TOKEN}"            # or file:///run/secrets/...
signing_secret = "file:///run/secrets/turna_webhook_hmac"
# ca_file = "/etc/turna/signalling-ca.pem"         # private CA; replaces system roots
timeout_ms = 2000
max_concurrency = 32
queue_depth = 1024
positive_ttl_secs = 300
negative_ttl_secs = 30
error_ttl_secs = 2
max_entries = 100000
```

Every key, with defaults, is in [CONFIGURATION.md](CONFIGURATION.md#turnauthwebhook).
Under `production = true`, `url` must be `https://` and at least one of
`bearer_token` / `signing_secret` must be set. Webhook settings are read at
startup; SIGHUP does not reload them.

## The contract

### Request

```
POST <url>
Content-Type: application/json
Accept: application/json
User-Agent: turna/<version>
Authorization: Bearer <bearer_token>             (if configured)
X-Turna-Timestamp: <unix seconds>                (if signing_secret is configured)
X-Turna-Signature: v1=<hex HMAC-SHA256>          (if signing_secret is configured)

{"realm":"<realm>","username":"<USERNAME as sent by the client>"}
```

- `username` is the STUN USERNAME exactly as received (UTF-8, under 513 bytes;
  longer ones are refused without a request). Treat it as untrusted input.
- `realm` is the node's `[turn] realm`. The keys you return must be for it.
- The signature is `v1=` followed by the lower-case hex HMAC-SHA256, keyed with
  `signing_secret`, over the ASCII bytes `"<X-Turna-Timestamp>.<raw body>"`.
  Verify it over the raw body before parsing, compare in constant time, and
  reject a timestamp outside your window (±60 s is reasonable) to stop replays.
  Reference implementation: `turna_auth::webhook::sign_request`.
- turna does not follow redirects and ignores `HTTP(S)_PROXY`.

### Responses

| status | body | turna does |
|---|---|---|
| `200` | `{"password": "<plaintext>"}` | derives both long-term keys (`MD5(user:realm:password)` for RFC 5389 and `SHA-256(user:realm:password)` for RFC 8489), then zeroizes the password. Caches the keys. |
| `200` | `{"key_md5": "<32 hex>", "key_sha256": "<64 hex>"}` | uses the keys as given. Either may be omitted; a client using the missing variant is then treated as an unknown user. Prefer this form: the password never leaves your service. |
| `200` | either of the above plus `"ttl_secs": N` | caches for `min(N, positive_ttl_secs)` — you can shorten the cache per user, never lengthen it. |
| `404` | anything | the user does not exist: 401 to the client, cached for `negative_ttl_secs`. |
| anything else, a timeout, a transport error, a body over 16 KiB, a body that is none of the above (including `password` together with a key) | — | **failure**: the client gets `500 Server Error`, cached for `error_ttl_secs`. |

`401` and `403` from your endpoint are failures too, logged as
`endpoint_rejected_turna`: they mean turna's own credential was refused, not the
user's.

`key_md5` is exactly what coturn calls the user's HMAC key (`turnadmin -k`), so
a user table already holding those can be served as-is.

## What happens to the client's request

The lookup never runs on the packet path. The datapath is synchronous and shared
by every transport, and an HTTP round trip there would stall a receive worker
and every client hashed to it. So:

1. **Cache hit** (found, not found, or failed and still within its TTL): answered
   at once.
2. **Miss**: one fetch is queued for that USERNAME — concurrent requests for the
   same user share it — and the request is **parked, not answered**.
   - **UDP, DTLS, QUIC datagrams**: dropped. The client retransmits (RFC 8489
     §6.2.1: first retransmission after 500 ms; browsers use less), the answer
     is in the cache by then, and the retransmission is served. The cost is one
     retransmission interval on a user's first allocation after a cache miss.
   - **TURNS, SCTP, and QUIC/WebTransport stream messages**: clients on a
     reliable transport do not retransmit, so the bridge parks the request and
     re-processes it as soon as the lookup completes. Bounded: 4096 parked
     requests per bridge, 8 per connection, 12 s each; requests waiting on the
     same lookup share one waiting task. A request whose connection (or QUIC
     session) closes meanwhile is discarded, and the TURNS bridge drops any
     packet for a connection it no longer knows, so no allocation is created
     for a client that is gone.
3. **Failure** — timeout, error status, malformed body, or no room to queue the
   fetch (`queue_depth` full, or the cache full of in-flight lookups): `500
   Server Error`. **Fail closed**: nobody is admitted on a lookup that did not
   succeed.

Cache TTLs are never below one second, whatever the configuration or the
endpoint's `ttl_secs` says: an answer that expired as it was stored would turn
every retransmission into another HTTP request and never answer the client.

### Lookup floods

Only a request that has completed a NONCE round trip can start a lookup, but
such a client can still name a different random user in every Allocate or
Refresh. Unbounded, one host would fill `queue_depth` and every uncached user on
the node would get 500 until it drained. Three controls stop that:

- **A per-source lookup budget**: `lookups_per_ip_burst` / `lookups_per_ip_rps`
  and `lookups_per_prefix_burst` / `lookups_per_prefix_rps` (per /24 or /48).
  Charged only when a request would *start* a fetch — cache hits and requests
  joining a lookup already in flight cost nothing. Over budget, that source gets
  `500` (`turna_auth_webhook_throttled_total`); nobody else is affected.
- **Auto-ban evidence**: with `[turn.auto_ban]` on, every lookup a source starts
  and every one it is refused counts toward `credential_lookups` (default 20 per
  window). A 404 answer followed by the client's credentials is an ordinary auth
  failure and counts toward `auth_failures`.
- **Refresh is rate-limited** with the Allocate tier, like Allocate itself.

A lookup that is merely pending for a legitimate user, and an endpoint outage
(`Unavailable`), are not auth failures: they are not in `turna_auth_failures`
and an outage never feeds auto-ban.

A STUN Binding carrying MESSAGE-INTEGRITY needs no NONCE, so its source address
may be forged. It is validated against the cache only and **never starts a
lookup** — otherwise anyone could make the node send HTTP requests to your
service by spoofing Binding requests. (With `require_binding_auth = true` the
Binding does carry a verified NONCE and may start one.) Every other request that
reaches the webhook has already completed a NONCE round trip from its source.

## Operating it

**Sizing.** `max_concurrency` bounds requests in flight; `queue_depth` bounds
lookups waiting for a slot; the per-source budget bounds how much of that one
source can use. An office where hundreds of users sign in at once behind one NAT
address will need a larger `lookups_per_ip_*` than the defaults (16 burst, 2/s). With the defaults, a cold cache after a restart
fetches 32 users at a time. The cache holds `max_entries` users; beyond it the
entry expiring soonest is evicted (never one in flight).

**Revocation lag.** A user removed from your service keeps working for up to
`positive_ttl_secs` from the last lookup, and an allocation already granted runs
to its own lifetime. Lower the TTL, or have your service return a short
`ttl_secs`, if that matters more than request volume.

**Metrics.** `turna_auth_webhook_requests_total`, `_errors_total`,
`_not_found_total`, `_cache_hits_total`, `_cache_negative_hits_total`,
`_cache_misses_total`, `_rejected_total`, `_cache_entries`, `_deferred_total`,
`_unavailable_total` and the `turna_auth_webhook_duration_seconds` histogram —
see [OBSERVABILITY.md](OBSERVABILITY.md). Alert rules in
`docs/alerts/turna-abuse.yml`.

**Logs.** A failed lookup logs its kind (`timeout`, `connect`, `status`,
`endpoint_rejected_turna`, `malformed_body`, …) and latency, once per power of two
failures. The USERNAME, the password, returned keys, the bearer token and the
signature are never logged, and `--dump-config` masks the two secrets.

**Threat model and accepted risks.** `docs/security/threat-model.md` §5.8a and
RISK-008 in `docs/security/accepted-risks.md`.
