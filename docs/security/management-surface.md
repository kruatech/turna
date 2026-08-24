# Management surface

What the management plane is made of, and which vulnerability classes that
composition rules out. This is about *structure*, not about patch discipline —
see [threat-model.md](threat-model.md) §3.6 / §5.5 for the "attacker reaches the
port" analysis and [management-tls.md](management-tls.md) for mTLS.

## What the surface actually is

| Component | Process | Language | Can mutate state? |
|---|---|---|---|
| `turna-node` | dataplane | Rust | via its own gRPC management listener |
| `turna-control-plane` | separate | Rust | yes, over authenticated gRPC |
| `turnactl` | CLI, off-host | Rust | only by calling gRPC |
| `turna-admin` | separate | Rust (axum) + JS frontend | only by calling gRPC |

Two properties follow from that table and are worth stating explicitly, because
they are what the rest of this document rests on:

* **`turna-admin` reads over HTTP and writes only over gRPC.** Its HTTP client is
  scoped to the node's read-only endpoints (`/status`, `/metrics`, `/health`,
  `/ready`, `/cluster`); every mutation goes through the same authenticated gRPC
  API that `turnactl` uses. A compromise of the panel therefore grants exactly
  the set of RPCs the caller was authorised for — each of which lands in the
  tamper-evident audit log — and not file or config access.
* **There is no SQL anywhere in the workspace.** No `sqlx`, `rusqlite`,
  `tokio-postgres` or `mysql` dependency, and no query construction. Durable
  state lives in Tarantool, reached over iproto with stored procedures.

## Classes that are absent by construction

Not "we have not had one of these yet" — absent because the ingredient is
missing.

**SQL injection.** Requires SQL. There is none. For calibration on why this class
is worth calling out at all rather than assumed away: the reference TURN
implementation has shipped at least two, one of them CVSS 9.8 in 2018 and another
in 2026 in the delete operations of its HTTPS admin panel.

**Arbitrary file write from an admin command.** The gRPC surface is a fixed set of
RPCs defined in a `.proto`; none of them takes a filesystem path. There is no
generic "run this admin command" entry point, no telnet CLI, and no scripting
console. coturn's CLI `psd` command was a 2026 CVE for exactly this, and in the
published 8x8 relay-abuse report the same CLI was what turned relay access into
writing files on the server.

**Admin authentication bypass in the node.** The node does not authenticate admin
users at all — it authorises gRPC peers by client certificate (mTLS). There is no
password comparison in the dataplane process to get backwards. coturn shipped an
inverted password check that accepted any wrong password.

**Memory-safety bugs in a database driver or embedded HTTP server.** Neither is
linked into the dataplane. coturn has had buffer overflows in its MySQL driver
and HTTP server.

## What is *not* claimed

* `turna-admin` is still a web application with a JS frontend. Ordinary web
  vulnerability classes — XSS, CSRF, session handling — remain possible there. The
  claim above is narrow: the panel cannot escalate beyond the gRPC API it is
  allowed to call.
* The gRPC surface is not small. It can drain a node, delete allocations, change
  limits and add or remove users. Reaching it authenticated is a serious
  compromise; the argument here is only that it is *bounded and audited*.
* Rust removes memory-safety classes from safe code, not from the audited
  `unsafe` inventory in the transport and relay datapaths — see
  [../unsafe-audit.md](../unsafe-audit.md).
* None of this is a substitute for keeping the management port off the public
  internet.

## The chain that mattered in practice

The published 8x8 finding did not exploit one bug. It chained two:

1. the TURN relay would forward to `127.0.0.1`, because peer addresses were not
   restricted; then
2. an admin CLI was listening there, and it could write files and edit the
   configuration.

Both legs are closed by default here — loopback is a tier-1 peer deny (see
[peer-filter.md](peer-filter.md)) and no admin listener runs inside the node
process — but they are closed *independently*, and one configuration couples them
back together:

> **Warning.** Setting `allow_loopback_peers = true` (or
> `TURNA_ALLOW_LOOPBACK_PEERS=1`) re-opens leg 1. If the management gRPC listener
> is on loopback at the same time — which is the default in `deploy/turn.toml` —
> an authenticated TURN client can then relay traffic to it. That combination
> reconstructs the 8x8 chain up to the point of needing a valid client
> certificate.
>
> These flags exist for local test rigs, and the 12-hour soak and endurance runs
> in `docs/soak/` used them deliberately. Never combine them with a reachable
> management port on a host that serves untrusted clients.

## Verifying rather than trusting this page

* Peer-filter wiring and the loopback deny: [relay-abuse-testing.md](relay-abuse-testing.md).
* mTLS enforcement on the management listener: [management-tls.md](management-tls.md).
* The claim "no SQL in the workspace" is one grep away and should be re-checked
  whenever a dependency is added:

```
git grep -Ei 'sqlx|rusqlite|tokio-postgres|mysql' -- '*.toml' || echo "no SQL dependency"
```
