# Support and LTS: the options, and what each costs

§11 asks for an LTS release channel. This document does not choose one — the
choice is a promise to customers, not a technical decision, and the cost falls on
whoever has to keep it.

What it does is name the options, price them in work that is already visible in
this repository, and point out the decision that has to come first.

## The decision before the decision

**turna is 0.4.0.** Under semver, a 0.x version declares that anything may change
— and this release uses that latitude: shutdown behaviour changed and twenty-three
configuration keys were added.
An LTS channel promises the opposite.

Offering LTS on 0.3 is not impossible — plenty of projects do it — but it means
the version number says one thing and the support policy says another, and the
customer reads whichever suits their argument later. So:

**Either commit to 1.0 first, or say plainly that the support promise is
independent of the version number.** The second is a real option and some
projects take it deliberately; it just has to be written down rather than left to
be discovered.

What 1.0 would require here, from what this repository already tracks:

| | state |
|---|---|
| Management API stable and versioned | **yes** — `turna.management.v1`, with a compatibility gate that fails on a field-number change |
| Config schema stable | **yes** in effect — `deny_unknown_fields` on 38 structs, stricter than a version field |
| Wire protocol conformance | **yes** — RFC 5389/8489/5766/8656, three browser engines, coturn on five paths |
| Reproducible builds and signed artifacts | **yes** — all three binaries reproduce byte-for-byte on Linux |
| Capacity characterised | **partial** — one machine, and the figure is uncertain by 2× |
| Cluster behaviour under failure | **no** — needs three nodes |
| Six open design decisions | **no** — `docs/OPEN-DECISIONS.md` |

The last two are the honest blockers. A 1.0 whose clustering has never had a node
killed under load is a 1.0 that will have a 1.0.1 within a fortnight.

## Option A — no LTS. Latest minor only.

What most infrastructure projects do before 1.0, and what turna does today by
omission.

**Promise:** the current minor gets fixes. Upgrading is the support path.

**Cost:** near zero. It is the status quo.

**What it forecloses:** enterprise sales where a procurement process asks for a
supported-until date. Some will not proceed without one, and finding that out
during a deal is expensive.

**Honest about:** it is a policy, not an absence of one, and saying so is worth
more than leaving the question blank. A customer who reads "no LTS" plans around
it; one who finds nothing assumes and is disappointed.

## Option B — N-1 minor supported

**Promise:** the current minor and the one before it get security fixes. Roughly
6–12 months of runway depending on release cadence.

**Cost, concretely:**

- A maintenance branch per supported minor, and backports onto it.
- CI on both branches. The workflows here run on push and PR to `main`; a second
  branch means a matrix or a duplicate.
- The mutation run and the capacity job would want to cover both, and the capacity
  job needs a self-hosted runner per branch or a queue.
- Every security fix becomes two changes, two reviews, two releases.

**Rough size:** the second branch costs a day to set up and then a tax on every
fix. Call it 20–30 % on top of security work.

**Fits:** a product sold to customers who upgrade yearly.

## Option C — a named LTS minor, 2 years

**Promise:** one minor designated LTS, supported 24 months from release. Security
fixes and severe-bug fixes; no features.

This is what an enterprise procurement process usually expects for infrastructure.

**Cost, concretely:**

- Everything in Option B, plus the branch lives long enough to diverge
  meaningfully. Backporting to a two-year-old branch is not the same work as
  backporting to last quarter's.
- **Dependency drift is the real cost.** `cargo deny` is clean today. In eighteen
  months a transitive dependency will have an advisory, and the fix will require a
  major bump the LTS branch cannot take. Then it is either a patch carried
  locally, or a vendored fork, or an exception documented to the customer. All
  three are ongoing work.
- The MSRV becomes a commitment. It is not pinned anywhere today — a `rust-version`
  in `Cargo.toml` and a CI job on that toolchain would be needed, or the LTS
  branch stops building on the compilers customers have.
- Reproducible builds have to keep working on the LTS branch. They work today
  because the toolchain is pinned to 1.95.0; two years on, reproducing a build
  means keeping that toolchain available.

**Rough size:** a week to establish, then a standing commitment measured in days
per quarter, rising as the branch ages.

**Fits:** what you are apparently being asked for. The 123-requirement
specification is an enterprise document.

## Option D — 5 years, Ubuntu-style

**Cost:** all of the above, plus the near-certainty of carrying patched
dependencies for years and a real chance of maintaining a fork of something.

**Rough size:** this is a role, not a task. Do not choose it without someone whose
job it is.

**Fits:** a customer paying for it explicitly, with the price reflecting a
person's time.

## What comparable projects promise

Offered as calibration, not as a recommendation — each of these has a team behind
the number.

| project | per-release support | note |
|---|---|---|
| Kubernetes | 14 months per minor | three minors supported at a time; a large dedicated release team |
| Node.js | 30 months LTS | even-numbered majors only |
| Ubuntu | 5 years LTS | a company's business model |
| PostgreSQL | 5 years per major | very slow-moving on-disk format |
| coturn | none formal | the nearest comparable, and it offers nothing |

**coturn is the informative row.** The closest project to this one, widely deployed
in production, offers no formal LTS at all. That is evidence that the market
tolerates its absence in this category — and also that offering one is a
differentiator.

## What has to exist before any of B, C or D

These are not optional extras; without them the promise cannot be kept.

**A pinned MSRV.** `rust-version` in `Cargo.toml`, and a CI job building on it.
Absent today. Without it, "supported" quietly means "on whatever compiler we
happen to use", and an LTS customer on an older toolchain discovers otherwise.

**A branch protection and backport process.** Which fixes qualify, who decides,
how a backport is verified. `scripts/verify/upgrade-rollback.sh` tests an upgrade
between two refs and is most of the verification machinery already.

**A security-fix classification.** Which advisories force a release. `cargo deny`
runs in CI; what it means for a supported branch is a policy, not a tool.

**A documented end-of-life date per release.** In the release notes, at release
time. Added afterwards it reads as retroactive.

**Capacity figures per supported version.** `scripts/verify/capacity-regression.sh`
compares a build against a per-machine baseline. An LTS branch needs its own
baseline, or a regression on it is invisible.

## A recommendation about the process, not the answer

Whatever is chosen, **write the end-of-life date into the release notes at release
time.** That single habit costs nothing and prevents the failure mode all four
options share: a customer running a version nobody remembers agreeing to support,
discovering it during an incident.

And: **do not announce a longer window than the smallest team that will ever
maintain it can keep.** A missed LTS commitment costs more trust than never having
offered one, because the second was honest and the first was not.
