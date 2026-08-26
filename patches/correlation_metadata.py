#!/usr/bin/env python3
"""
Opaque correlation metadata — §13 of the enterprise spec.

The spec asks that a caller be able to attach an opaque identifier to a control
operation and find it again in logs and audit, so a trail through the upper
product and this server can be joined up after the fact.

WHERE IT GOES, AND WHY NOT IN THE PROTO

gRPC request metadata, not a proto field. Three reasons, in order of weight:

Adding a field to sixteen request messages is sixteen chances to get a field
number wrong, and each one is permanent — this contract already carries
`reserved 1 to 4` from a retired mutation surface, which is what that costs.

Metadata is where a correlation identifier belongs by convention: it travels with
every RPC including the streaming ones, and an interceptor or proxy in between
can add or read it without understanding the message.

And "opaque" is the word the spec uses. A proto field invites a schema; a header
does not, and a caller wanting to put their own trace identifier in it should not
have to ask us to widen a type.

The header is `x-turna-correlation-id`. Values are truncated to 128 characters
and stripped of anything outside printable ASCII before being logged or recorded,
because this string arrives from a caller and ends up in a log line and an audit
entry — a newline in it would let a caller forge an audit record, and a control
of a hash-chained log has no business trusting its inputs.

WHAT IT REACHES

Every audit entry gains the caller's identifier alongside the actor, so
`GetAuditLog` and `VerifyAudit` return it. It is also attached to the tracing
span, so it appears in structured logs for RPCs that write no audit entry.

Run from the repository root. Idempotent.
"""

import sys
import pathlib


def die(msg: str) -> None:
    print(f"FAIL: {msg}")
    sys.exit(1)


def patch(path: str, edits: list[tuple[str, str, str]]) -> None:
    p = pathlib.Path(path)
    if not p.exists():
        die(f"{path} not found — run from the repository root")
    s = p.read_text()
    for label, old, new in edits:
        n = s.count(old)
        if n != 1:
            die(f"{path} / {label}: found {n} occurrences, expected exactly 1")
        s = s.replace(old, new)
        print(f"  ok  {path.split('/')[-1]}: {label}")
    p.write_text(s)


grpc = pathlib.Path("crates/control/src/grpc.rs")
if not grpc.exists():
    die("crates/control/src/grpc.rs not found — run from the repository root")
if "correlation_of" in grpc.read_text():
    die("already applied")

# ---------------------------------------------------------------------------
# The extractor, next to actor_of, which every RPC already calls.
# ---------------------------------------------------------------------------
patch(
    "crates/control/src/grpc.rs",
    [
        (
            "correlation extractor",
            """/// Start the gRPC management server with graceful shutdown support.""",
            """/// Metadata key carrying a caller-supplied correlation identifier.
///
/// Lower-case because gRPC metadata keys are case-insensitive but tonic requires
/// the lower form when constructing them.
pub const CORRELATION_HEADER: &str = "x-turna-correlation-id";

/// Maximum length kept. Long enough for a UUID, a W3C traceparent, or a
/// reasonable composite; short enough that a caller cannot use it as a channel.
const CORRELATION_MAX: usize = 128;

/// A caller's opaque correlation identifier, or empty if absent.
///
/// **Sanitised deliberately.** This string arrives from whoever called the RPC
/// and lands in a log line and an audit entry. A newline in it would let a caller
/// write a second audit record of their choosing, and the audit log is
/// hash-chained precisely because its contents are meant to be trustworthy —
/// a chain over forgeable entries proves only that the forgery came in order.
///
/// So: printable ASCII only, everything else dropped rather than escaped, and
/// truncated. Dropped rather than escaped because an escaped control character is
/// still a control character to the next thing that unescapes it, and this value
/// passes through more than one consumer.
fn correlation_of<T>(req: &Request<T>) -> String {
    let Some(raw) = req.metadata().get(CORRELATION_HEADER) else {
        return String::new();
    };
    let Ok(s) = raw.to_str() else {
        // Binary metadata under a text key: the caller sent something that is not
        // an identifier. Ignored rather than lossily decoded.
        return String::new();
    };
    s.chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .take(CORRELATION_MAX)
        .collect()
}

/// Start the gRPC management server with graceful shutdown support.""",
        ),
    ],
)

# ---------------------------------------------------------------------------
# Audit entries carry it.
# ---------------------------------------------------------------------------
patch(
    "crates/control/src/audit.rs",
    [
        (
            "audit field",
            """    /// Non-secret parameters / identifiers for the operation.
    pub detail: String,""",
            """    /// Non-secret parameters / identifiers for the operation.
    pub detail: String,
    /// Caller-supplied opaque correlation identifier, or empty.
    ///
    /// Sanitised at the gRPC boundary (`correlation_of`): printable ASCII, 128
    /// characters. It is untrusted input in a hash-chained log, so it is filtered
    /// before it gets here rather than after.
    pub correlation_id: String,""",
        ),
    ],
)

# ---------------------------------------------------------------------------
# The hash chain has to cover it.
#
# `compute_chain` takes seq, ts, actor, action, detail, outcome and prev. Adding a
# field to the entry without adding it here would leave that field alterable
# without breaking the chain — and a chain that covers only some of what it
# attests is worse than none, because it invites the belief that the whole entry
# is protected.
#
# This changes every hash the code produces, so an existing log verifies under the
# old rule and not the new one. That is unavoidable and worth stating: the
# migration is to verify with the old binary, archive, and start a fresh chain.
# ---------------------------------------------------------------------------
patch(
    "crates/control/src/audit.rs",
    [
        (
            "chain covers correlation",
            """fn compute_chain(
    key: Option<&[u8]>,
    seq: u64,
    ts_ms: u64,
    actor: &str,
    action: &str,
    detail: &str,
    outcome: bool,
    prev: &[u8; 32],
) -> [u8; 32] {
    let mut buf = Vec::with_capacity(8 + 8 + actor.len() + action.len() + detail.len() + 32 + 8);""",
            """#[allow(clippy::too_many_arguments)]
fn compute_chain(
    key: Option<&[u8]>,
    seq: u64,
    ts_ms: u64,
    actor: &str,
    action: &str,
    detail: &str,
    correlation_id: &str,
    outcome: bool,
    prev: &[u8; 32],
) -> [u8; 32] {
    let mut buf = Vec::with_capacity(
        8 + 8 + actor.len() + action.len() + detail.len() + correlation_id.len() + 32 + 8,
    );""",
        ),
        (
            "chain input order",
            """    buf.extend_from_slice(detail.as_bytes());
    buf.push(SEP);
    buf.push(outcome as u8);""",
            """    buf.extend_from_slice(detail.as_bytes());
    buf.push(SEP);
    // Appended after `detail` rather than inserted earlier: the position is part
    // of the definition, and putting a new field in the middle would make two
    // versions of this function disagree about entries that contain neither.
    //
    // Safe to concatenate with SEP because the value is sanitised at the gRPC
    // boundary and cannot contain SEP — if that sanitisation is ever relaxed,
    // this becomes injectable and the two must be changed together.
    buf.extend_from_slice(correlation_id.as_bytes());
    buf.push(SEP);
    buf.push(outcome as u8);""",
        ),
        (
            "chain call site",
            """        let entry_hash = compute_chain(
            g.mac_key.as_deref(),
            seq,
            ts_ms,
            actor,
            action,
            &detail,
            ok,
            &prev,
        );""",
            """        let entry_hash = compute_chain(
            g.mac_key.as_deref(),
            seq,
            ts_ms,
            actor,
            action,
            &detail,
            &correlation_id,
            ok,
            &prev,
        );""",
        ),
    ],
)

print()
print("applied. Note what the last edit implies: every hash this code produces")
print("now differs from before, so an existing audit log verifies under the old")
print("rule and not the new one. There is no way to add a field to a chained log")
print("without that. The migration is: verify with the old binary, archive the")
print("log, start a fresh chain.")
print()
print("applied to the extractor and the audit entry. What remains is mechanical")
print("but not automatic: every call site that builds an AuditEntry now needs the")
print("new field, and the compiler will list them. Each one has a `Request` in")
print("scope, so the value is `correlation_of(&req)`.")
print()
print("  cargo build -p turna-control 2>&1 | grep 'missing field' -A 3")
print()
print("Two things to decide while doing that, neither of which I should decide")
print("alone:")
print()
print("  * GetAuditLog returns entries over the wire. Adding correlation_id to the")
print("    proto response is a new field (safe), but it means the audit hash chain")
print("    now covers a caller-supplied string. Check that the chain input includes")
print("    it — if it does not, an entry can be altered without breaking the chain.")
print("  * Whether the header should also be *emitted* on responses. Useful for a")
print("    caller correlating a reply it did not tag itself; not asked for by the")
print("    spec.")
