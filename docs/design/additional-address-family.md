# `ADDITIONAL-ADDRESS-FAMILY` (RFC 8656 §7.2) — design

**Status:** not started. Blocked on one decision (§3) and one prerequisite (§7).

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
- On partial failure — one family available, the other not — the RFC's position is
  that the allocation fails; the server does not silently return one family when
  two were requested. Getting this wrong is worse than not implementing the
  feature, because a client that asked for dual-stack and received one family will
  believe it has both.

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

`turna_allocations` (both `deploy/tarantool/init.lua` and the Rust `INIT_SCRIPT` —
they carry an explicit "change one place, change both" comment) is:

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
- **Cost:** a schema migration on live data, and `init.lua` plus the Rust
  `INIT_SCRIPT` must move together. Migration itself is mechanical (`create_index`
  with a new name, backfill family = v4 for existing rows, drop the old index), but
  it needs a documented procedure and a rollback that does not strand rows.

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
- Second bind fails → the whole Allocate fails **and the first port is released**
  (assert the pool is back to its prior state, not just that a `508` was returned).
- A v4 peer permission does not authorise traffic on the v6 socket, and vice versa.
- Restart with a dual-stack allocation live: rehydrate restores both ports and both
  are marked used in the pool.
- Refresh and remove affect both ports atomically.

## 7. Prerequisite: verify plain IPv6 first

The single-family v6 path shipped without any runtime verification — no allocation
has ever relayed media over IPv6. AAF is a layer on top of it. Building it now
doubles the unverified surface and makes the first failure ambiguous: base v6 or the
pairing?

So the order is: Tier 2 of `docs/verification/interop-plan.md` (bidirectional media
to a real external v6 peer, `443` in both directions, `EVEN-PORT` on v6), **then**
this. On a verified base this is one focused change; on an unverified one it is two
overlapping investigations.
