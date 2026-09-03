# Code scanning: what the alerts mean

CodeQL moved from 3.37.3 to 4.37.9, and its Rust analysis is much fuller in 4.x.
Seventy-one alerts appeared on code that had not changed.

All of them were read. This records what was fixed, what was not, and why — so
that the open ones are a decision rather than a backlog nobody looked at.

**Nothing was dismissed.** Every alert that could be closed by changing the code
was closed that way. The ones still open are open on purpose, and each has a
reason below.

## Three were real

**`capacity.yml` had no `permissions` block**, so its token got the repository
default. The workflow checks out, runs a benchmark and writes a file; `contents:
read` covers it.

**Test output printed a working TURN password in full** — in debug output and
again in an assertion message, both of which land in a CI log. The line above the
first already printed `secret_len` rather than the secret, so the intent was
there and the derived password had been missed. Now length only.

**`--dump-config` printed the backend URI whole.** A Tarantool URI is
`user:password@host:port`, so the password was disclosed — on the line directly
above one that carefully masks the password field. Credentials in the URI are now
masked.

That last one is the pattern worth noticing: the masking existed and one field was
overlooked. A scanner that flags forty false positives is still worth reading if
it finds that.

## What the code changes were

**Test credentials come from the environment.** Fifty literals across five files
now read from `.env.test` (mirrored in the workflow) rather than appearing inline.
No defaults: `unwrap_or("pass12345")` puts the literal straight back, which was one
of the misses on the first pass.

Wrapping them in a helper was tried first and did not work — CodeQL follows the
value through the function. Worth recording so nobody tries it again.

**Upstream URLs are assembled from parsed parts.** The admin proxy took a `String`
into `client.get()`. A prefix check did not satisfy the request-forgery rule, and
rightly: a check is something you can forget to call. The address is now parsed
once at startup into scheme, host and port, and every request is built from those
plus a path that is a literal in this crate.

Better independently of the scanner — a malformed address stops startup with a
clear message instead of failing on the first request.

**`[turn.auth] require_sha256`.** SHA-256 was already preferred when a client
advertises it, but the fallback to MD5 was silent. An operator can now close that
path and know it is closed. Off by default, because most deployed TURN clients
predate RFC 8489 and turning it on where they exist locks them out.

## What is still open, and why

### Test inputs that have to be literals — several

`"short"`, `"garbage"`, `"not-a-nonce"`, `"zz:zz"`, `""`, `"pass"`.

These are the *bad inputs* a test asserts are rejected. A test that a short
password is refused needs a short password; one that a malformed nonce is refused
needs a malformed nonce. Moving them out of the source would make the test depend
on configuration in order to check that garbage stays garbage.

The rule sees a string flowing into a function that also takes a key, and cannot
tell a fixture from a credential.

### Usernames in output — 5

`turnactl` prints `User 'alice' added`; `--dump-config` lists configured users.

The operator typed that name in the command they just ran, and the whole point of
`--dump-config` is to show what is configured. Removing the name leaves a message
that says something happened to someone.

A username in TURN is an identifier, not a secret. The passwords beside them are
masked.

### MD5 in `long_term_key` — 3

RFC 5389 §15.4 defines the long-term key as `MD5(username:realm:password)`. Every
TURN client computes it that way. Removing MD5 means turna cannot authenticate
clients at all.

RFC 8489 added SHA-256 and turna prefers it whenever the client advertises
`PASSWORD-ALGORITHMS`, which most do not — the RFC is from 2020 and client
deployments lag. `require_sha256` lets a deployment that knows its clients close
the weak path.

The alert stays because the code stays. There is no version of this that satisfies
the rule and speaks the protocol.

### Scorecard findings — 5

Not CodeQL. These are repository settings.

**Branch-Protection.** Six sub-findings, and four require a second person: required
approvers, codeowners review, stale review dismissal, last-push approval. A
single-maintainer repository cannot satisfy them, and pretending otherwise by
approving one's own pull requests would be worse than the finding.

Two were actionable and are done: up-to-date branches is now required, and the
ruleset applies status checks. Administrator bypass is kept deliberately — when the
CI workflow itself is broken, as happened during this work, the bypass is how the
fix gets in.

**Code-Review** and **Maintained** measure the same thing from the outside: how
many commits arrive through reviewed pull requests, and how recently. Both improve
on their own as the project accumulates history.

**Pinned-Dependencies.** `runs-on: self-hosted` cannot be pinned to a digest — the
runner is a specific machine. `curl` to `127.0.0.1` is the node's own health
endpoint, not a fetched dependency.

## Two things about the tooling itself

**A scanner upgrade is a code change in effect.** Seventy-one alerts appeared with
no commit to the source. Reviewing them cost most of a day, and three real
findings came out of it — which is a good trade, but it is a cost that arrives
without warning and should be planned for rather than absorbed.

**Alerts do not close by themselves when the code moves.** Fixing a line shifts
everything below it, and the scanner may read the shifted alerts as new while the
old ones stay open. When the count does not fall as expected after a fix, check
whether the numbers are the same alerts before concluding the fix failed.
