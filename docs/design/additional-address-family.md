# `ADDITIONAL-ADDRESS-FAMILY` (RFC 8656 §7.2) — design

**Status:** not started. Blocked on one decision (§3) — and, since the RFC re-read of
2026-09-24 (§8), on a correction to that decision: RFC 8656 gives each family of a
dual allocation its **own** lifetime and permissions, and answers a half-successful
Allocate with **success plus ADDRESS-ERROR-CODE**, not a failure. Both change the
storage shape. The §7 prerequisite is **largely satisfied** and no longer the reason
to defer — see §7, which was written before the IPv6 path had been exercised and has
since been overtaken.

One Allocate asks for a relayed address in **both** families and gets two, in a
single allocation. This is what a dual-stack WebRTC client wants, and it is the
largest remaining standards gap in the relayed transport. The protocol work is
small. The state work is not, and that is what this document is about.

---

## 1. What the RFC requires

- `ADDITIONAL-ADDRESS-FAMILY` (type `0x8000`, comprehension-optional) carries a
  family value, and **only IPv6 is legal** in it. An Allocate carrying IPv4 there
  is answered `400`.
- It is **mutually exclusive with `REQUESTED-ADDRESS-FAMILY`**; both present →
  `400`. (We already enforce the analogous exclusion with `RESERVATION-TOKEN`.)
- On success the response carries **two** `XOR-RELAYED-ADDRESS` attributes, one per
  family.
- On partial failure — one family available, the other not — **the allocation
  succeeds with the family that could be allocated, and the success response carries
  ADDRESS-ERROR-CODE (0x8001)** naming the missing family with 440 or 508 (RFC 8656
  §7.2 step 9, client side §7.3). Only when neither can be allocated is the answer a
  508. *This bullet used to say the allocation fails; that was wrong — see §8.* What
  it was guarding against is still right: the server must never return one family
  **silently**, because a client that asked for dual-stack and received one family
  without ADDRESS-ERROR-CODE will believe it has both.

Codec side, today: `Attribute::RequestedAddressFamily` exists,
`ADDITIONAL-ADDRESS-FAMILY` does not (`attribute.rs` has no `0x8000` entry). Because
it is comprehension-optional, a client sending it today is **silently ignored** — no
`420`, no `400`. So the current behaviour is already wrong in the mildest way: we
answer as if the attribute were absent.

## 2. What already exists to build on

The per-family machinery from the IPv6 pass is reusable as-is:

- `session::RelayFamily` and the three `*_family` bind helpers.
- `bind_relay_socket` with `IPV6_V6ONLY` on the v6 side.
- Family enforcement: `443 Peer Address Family Mismatch` on CreatePermission and
  ChannelBind, counted drop on Send indication.
- `processor::external_ip6` and the per-family advertised address.

What does **not** generalise is the assumption baked into every layer below the
processor: **one allocation owns exactly one relay port**.

## 3. The decision: where the second port lives

`turna_allocations` (defined once, in `deploy/tarantool/init.lua`; the Rust
`INIT_SCRIPT` this used to name no longer exists, so a migration touches one file
and not two) is:

```
relay_port    unsigned   ← PRIMARY KEY
user_id       string     ← by_user
node_id       string     ← by_node
expires_at_ms unsigned   ← by_expiry
data          string     ← StoredAllocation as JSON
```

A second relay port has to go somewhere. Three options, with the concrete cost of
each.

### Option 1 — second port inside `data`

`StoredAllocation` gains `relay_port6: Option<u16>` and `relay_addr6:
Option<String>`, both `#[serde(default)]`.

- **Schema change: none.** And there is precedent: `allocation_id` and
  `migration_epoch` were both added to `StoredAllocation` exactly this way, with
  `#[serde(default)]` so pre-existing rows keep decoding. A rollback reads new rows
  fine too — it just ignores the v6 half.
- **Cost:** the v6 port has **no index**. Two guarantees become half-guarantees:
  `pool_states` (used for rehydrate accounting) and port-collision detection. There
  is an existing test, `rehydrate_double_port_conflict`, asserting the latter — it
  would keep passing while covering only the v4 half, which is the dangerous kind of
  green.
- **Mitigation if chosen:** on rehydrate, walk every row's `data` and reserve
  `relay_port6` in the in-memory pool explicitly. That restores collision
  detection at the cost of a full scan on startup, which rehydrate already does.
  Write that down as the reason the scan cannot be optimised away later.

### Option 2 — two tuples per allocation

One tuple per relay port, linked by `allocation_id`.

- Both ports indexed; no schema change to the *format*, only to the invariant
  "one tuple = one allocation".
- **Cost:** `by_user` quota counting double-counts every dual-stack allocation, so
  per-user allocation limits silently halve. `refresh` and `remove` become
  transactional across two tuples — and a partial failure leaves a half-allocation
  that nothing owns. That is a new class of bug in the persistence layer, which is
  the last place worth introducing one.
- **Assessment:** cheapest-looking, worst-behaving. Not recommended.

### Option 3 — composite primary key

Primary key becomes `(relay_port, family)` or the allocation gains a synthetic key
with `relay_port` demoted to a secondary unique index.

- Correct model: both ports indexed, one tuple per allocation, quota counting
  unaffected.
- **Cost:** a schema migration on live data, in `deploy/tarantool/init.lua` alone
  (this used to say "plus the Rust `INIT_SCRIPT`" — that constant does not exist,
  so this option is cheaper than it was costed at). Migration itself is mechanical
  (`create_index` with a new name, backfill family = v4 for existing rows, drop the
  old index), but it needs a documented procedure and a rollback that does not
  strand rows.

### Recommendation

**Option 3 if a schema migration is acceptable in this release; Option 1 otherwise**,
with the halved guarantee and the rehydrate mitigation written down at the call site
rather than discovered later.

Not Option 2 — double-counted quotas and non-atomic refresh are worse than an
unindexed column.

## 4. Pre-existing constraint worth knowing before deciding

The primary key is `relay_port` **alone**, with `by_node` as a separate secondary
index. That means the space assumes relay ports are unique *across the whole
cluster*, not per node — two nodes cannot both hold port 50000. Whatever partitioning
makes that true today, AAF doubles the port consumption of every dual-stack
allocation, so it interacts directly with that assumption. Confirm how ports are
partitioned before choosing, because Option 3's composite key is also the natural
place to fix it if the answer is unsatisfying.

## 5. Edit list (independent of which option is chosen)

- `proto-stun/attribute.rs`: `ATTR_ADDITIONAL_ADDRESS_FAMILY = 0x8000`,
  `Attribute::AdditionalAddressFamily(AddressFamily)`, encode/decode.
- `proto-stun/message.rs`: `get_additional_address_family()` alongside the existing
  `get_requested_address_family()`.
- `processor::handle_allocate`: the two `400` cases (both attributes present; IPv4
  in the additional one); bind two sockets; **release the first if the second
  fails**, and answer per §1 rather than degrading to one family; two
  `XOR-RELAYED-ADDRESS` attributes in the response.
- `session::Allocation`: second relay address. This is the field whose ripple is the
  subject of §3.
- `session::write_op::WriteOp::Create`: carry the second port/address.
- `relay::server`: register both relay sockets in the egress registry (already keyed
  by port, so this part is mechanical).
- Port release: `pool_for_port` on both ports, and the `PortReservationGuard` must
  cover both or a mid-Allocate failure leaks one.
- `state-backend`: `memory.rs` and `tarantool.rs` per the chosen option.
- Permissions and channels: `peer_family_mismatch` currently compares against *the*
  relay address. With two, the rule becomes "the peer must match **one** of them",
  and the permission must record which — otherwise a v4 permission would authorise
  the v6 socket.

That last point is the one to design carefully: it is a security check, and widening
it from "matches the family" to "matches one of two families" is exactly where an
over-permissive shortcut would hide.

## 6. Tests this needs (write them with the feature, not after)

- Both attributes present → `400`; IPv4 in the additional attribute → `400`.
- Success returns two `XOR-RELAYED-ADDRESS` attributes, families distinct, ports
  distinct.
- Second bind fails → success with the first family **and ADDRESS-ERROR-CODE (508)**
  for the second, whose port is released (assert the pool: one port held, not two).
  Both binds fail → `508` and the pool is back to its prior state. *(Corrected
  2026-09-24; this line used to require the whole Allocate to fail.)*
- EVEN-PORT with R=1 plus ADDITIONAL-ADDRESS-FAMILY → `400`; RESERVATION-TOKEN plus
  ADDITIONAL-ADDRESS-FAMILY → `400` (§7.2 steps 8 and 5).
- A v4 peer permission does not authorise traffic on the v6 socket, and vice versa.
- Restart with a dual-stack allocation live: rehydrate restores both ports and both
  are marked used in the pool.
- Refresh **without** REQUESTED-ADDRESS-FAMILY affects both halves atomically; a
  Refresh **with** it touches only that family, and LIFETIME = 0 there deletes one half
  and leaves the other half's permissions and channels intact (§8.1).

## 7. Prerequisite: verify plain IPv6 first — LARGELY SATISFIED

> **Corrected.** As written below, this section said the v6 path "shipped without
> any runtime verification — no allocation has ever relayed media over IPv6". That
> stopped being true on 2026-08-19 and this document was not updated, so the
> prerequisite has been reading as a hard blocker on evidence that already exists.
> The original reasoning is kept because it is still the right reasoning; only its
> premise was stale.

The argument stands: AAF is a layer on the single-family v6 path, and building it
on an unverified base makes the first failure ambiguous — base v6, or the pairing?
What has changed is that the base is now largely verified.

**Done**, against Tier 2 of `docs/verification/interop-plan.md`:

- **Relayed media on routable global addresses** —
  `docs/interop/relayed-media-2026-08-19.md` §"Routable IPv6, 2026-08-23": node on
  `2a0c:db40:0:82fe::3`, peer on `::2`, 6 010 of 6 010 frames returned, zero loss,
  p99 0.5 ms, peer filter in `lan` profile with **no** `allow_loopback_peers`. An
  earlier loopback run (20 000 of 20 000) is the weaker one it replaced.
- **`443` in both directions** — `docs/interop/conformance-2026-08-18.md`: a v6
  peer on a v4 allocation and a v4 peer on a v6 allocation both refused.

**Still open**, and neither is a reason to hold AAF:

- **Routing between different hosts.** Both addresses in the 08-23 run belong to
  one machine, so the frames cross the v6 stack and the v6 relay socket but not a
  router. A genuinely off-host test needs a second machine with its own v6. This
  bounds what the run proves about MTU and forwarding, not about the allocation
  logic AAF builds on.
- **`EVEN-PORT` on v6.** No recorded run. Worth doing, and independent of AAF:
  EVEN-PORT is refused outright on a TCP allocation and is orthogonal to carrying
  two families.

So the order is no longer "verify, then this". It is: **decide §3**, which is the
one thing genuinely outstanding, and treat the two items above as parallel work.

## 8. RFC re-read, 2026-09-24 — what the design above gets wrong

Done while implementing the rest of the protocol-parity PR (USERHASH, RFC 5780, IPv6
for RFC 6062). AAF was **not** implemented in that PR; these findings are why.

1. **Partial success is a success.** RFC 8656 §7.2 step 9: if the server can allocate
   only one family, it returns an Allocate *success* with ADDRESS-ERROR-CODE (0x8001,
   §18.12: family, class/number 440 or 508, reason phrase) for the other; §7.3 tells
   the client not to retry a 440 family and to wait a minute after a 508. §1 and §6
   above said the reverse and are corrected in place.

2. **Each family has its own lifetime.** §8.1: a Refresh of a dual allocation may carry
   REQUESTED-ADDRESS-FAMILY to refresh — or, with LIFETIME = 0, delete — one family
   only, and "Deleting a single allocation destroys any permissions or channels
   associated with that particular allocation; it MUST NOT affect any permissions or
   channels associated with allocations for the other address family." So a dual
   allocation is two halves with independent expiry and independent permission and
   channel sets, sharing one 5-tuple and one quota unit. None of the three options in
   §3 models that:
   - option 1 has one `expires_at_ms` (and the only `by_expiry` index) for both;
   - option 3 as costed ("one tuple per allocation, both ports indexed") needs a
     second expiry field **and** a second expiry index, or the sweep cannot find an
     expired v6 half whose v4 half is alive;
   - a half-deleted allocation (v6 gone, v4 alive, or the reverse) must be a legal
     stored state, so the "primary" port can disappear while the allocation lives —
     which is awkward when `relay_port` is the primary key and the write-behind
     coalescing key (`WriteOp::relay_port`).
   The shape this points at is a synthetic primary key (`allocation_id`, already in
   `StoredAllocation`) with `relay_port4` / `relay_port6` as **nullable unique**
   secondary indexes and per-family expiry fields, each indexed. Tarantool cannot
   enforce uniqueness *across* the two port indexes (a port is family-agnostic in the
   pool), so the store function must check both before insert — write that check and
   its test first.

3. **"Composite primary key `(relay_port, family)`" is option 2 in disguise.** A key of
   (port, family) means one tuple per port, which is exactly the double-counted
   `by_user` quota §3 rejects. Option 3 only works in its "synthetic key" reading.

4. **CreatePermission and ChannelBind.** §10.1: for a dual allocation the client MAY mix
   families in one CreatePermission. The 443 rule becomes "the peer's family must match
   a *live* half", evaluated per peer, and the permission belongs to that half (point 2).

5. **Surfaces that assume one port per allocation** (all need the second port, and all
   emit or consume `CloseRelay { port }`): `relay::server` (tokio egress registry and
   expiry sweep), `relay::handler` + `transport::worker` (io_uring), the AF_XDP
   listener, the TLS / QUIC / SCTP bridges and the DTLS listener, `session`'s
   `by_relay` index and `release`/`refresh`, the port selection in
   `channel_data_decision`, `handle_send_indication` and `process_relay_recv` (the
   relay port must follow the peer's family), `node::writer` coalescing, failover
   `turna_claim_allocation`, `bulk_load`, and the control-plane allocation listing
   (whose proto would need an additive field). The io_uring and AF_XDP datapaths need
   their feature builds to test.

6. **Test environment, as found.** Tarantool *is* runnable in the development container
   (Ubuntu's `tarantool` 2.6 runs all three `deploy/tarantool/tests/*_test.lua` suites
   green when `box.cfg` is called before `init.lua`; CI uses the `tarantool/tarantool:2`
   image). IPv6 is **not**: binds fail with EAFNOSUPPORT, so every success path of a
   dual allocation — which binds a v6 socket by definition — would only ever run as a
   skipped test there. The migration could be tested; the feature could not.

**Next step:** decide §3 again with points 2–3 in hand (a per-family expiry index is
the new cost), then implement on a host with IPv6.
