#!/usr/bin/env python3
"""
Stop the AF_XDP section from accepting settings it does not apply.

Five keys are read from TOML, pass validation, and change nothing. The transport
says so itself:

    // xsk-rs 0.6 gates frame/queue sizes behind FrameSize/QueueSize newtypes
    // whose constructors are version-sensitive. For first-light use library
    // defaults (frame 4096, rings 2048) and honour only frame_count.
    let umem_config = UmemConfig::default();

So `frame_size`, `fill_ring_size`, `comp_ring_size`, `rx_ring_size` and
`tx_ring_size` are inert. Worse, `frame_size`'s default in the config is 2048
while the library uses 4096 — the default itself is wrong, so an operator who
reads the config and believes it is misled twice.

And one of them is not merely inert. The fill ring is fixed at 2048 frames, so a
`frame_count` above roughly twice that leaves more free frames than the ring can
hold and **reception silently stops**: at frame_count = 16384 we measured
umem_free_frames = 8160 against a 2048-entry fill ring and zero packets received,
with no error anywhere. That is the same shape as the two receive leaks already
fixed in this datapath — a hard stop at a resource boundary, invisible to every
check.

This adds:

  * constants in af_xdp.rs naming what the library actually provides, so the
    numbers have one home rather than being scattered literals
  * validation that rejects the five inert keys when set to anything other than
    what is really used, naming the reason
  * a frame_count bound, so the silent-RX-death case fails at startup instead
  * a corrected frame_size default

Rejecting rather than silently honouring is the deliberate choice. Making the
keys work needs version-sensitive xsk-rs newtype constructors and a NIC to
verify against; until then, refusing a setting is honest and accepting one is
not.

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


axdp = pathlib.Path("crates/transport/src/af_xdp.rs")
if not axdp.exists():
    die("crates/transport/src/af_xdp.rs not found — run from the repository root")
if "LIB_RING_SIZE" in axdp.read_text():
    die("already applied (LIB_RING_SIZE exists)")

# ---------------------------------------------------------------------------
# 1. Name the library's real geometry, next to the code that relies on it.
# ---------------------------------------------------------------------------
s = axdp.read_text()
anchor = "#[derive(Debug, Clone)]\npub struct AfXdpConfig {"
if s.count(anchor) != 1:
    # fall back to inserting before the config struct by a looser anchor
    anchor = "pub struct AfXdpConfig {"
    if s.count(anchor) != 1:
        die("could not find AfXdpConfig to anchor the constants")

consts = """/// Ring and frame geometry the UMEM is actually created with.
///
/// `UmemConfig::default()` is used because xsk-rs 0.6 gates `FrameSize` and
/// `QueueSize` behind newtype constructors whose signatures move between
/// versions. The consequence is that five `[turn.af_xdp]` keys are inert, and
/// these constants exist so config validation can say so with the real numbers
/// rather than repeating literals that drift.
///
/// If the sizes ever become configurable, these constants and the validation in
/// `turna-config` are the two places to change together.
pub const LIB_FRAME_SIZE: u32 = 4096;
/// Fill, completion, RX and TX rings are all this size.
pub const LIB_RING_SIZE: u32 = 2048;
/// Upper bound on `frame_count`.
///
/// Above roughly twice the fill-ring size, more frames are free than the ring
/// can hold and reception stops with no error: measured at frame_count = 16384,
/// where `umem_free_frames` reached 8160 against a 2048-entry fill ring and RX
/// went to zero. Rejecting at startup turns a silent dead datapath into a
/// message.
pub const MAX_FRAME_COUNT: u32 = LIB_RING_SIZE * 2;

"""

axdp.write_text(s.replace(anchor, consts + anchor, 1))
print("  ok  af_xdp.rs: geometry constants")

# ---------------------------------------------------------------------------
# 2. Correct the frame_size default, which claimed 2048 against a real 4096.
# ---------------------------------------------------------------------------
patch(
    "crates/transport/src/af_xdp.rs",
    [
        (
            "transport default frame_size",
            """            frame_count: 4096,
            frame_size: 2048,""",
            """            frame_count: 4096,
            // 4096, not 2048: this is what UmemConfig::default() uses, and the
            // old value described a geometry the code never created.
            frame_size: LIB_FRAME_SIZE,""",
        ),
    ],
)

# ---------------------------------------------------------------------------
# 3. Config: correct the default, and reject settings that do nothing.
#
# The constants are repeated here as literals rather than imported: turna-config
# is a leaf crate and depending on turna-transport would invert the dependency
# direction for the sake of three numbers. The comment names the source of truth
# so the two cannot drift silently.
# ---------------------------------------------------------------------------
patch(
    "crates/config/src/lib.rs",
    [
        (
            "af_xdp validation",
            """        // Check port conflicts
        let all_ports = [""",
            """        // AF_XDP: five keys in this section are read and then ignored, because
        // the UMEM is created with `UmemConfig::default()` (see the comment at
        // the call site in crates/transport/src/af_xdp.rs). Accepting a value
        // that changes nothing is the config lying to the operator, so they are
        // refused instead — with the real number, so the message is actionable.
        //
        // Numbers duplicated from af_xdp.rs's LIB_* constants rather than
        // imported: this is a leaf crate and inverting the dependency for three
        // integers is a worse trade. If the transport starts honouring the keys,
        // both places change together.
        if matches!(self.turn.transport, TransportSelection::AfXdp) {
            const LIB_FRAME_SIZE: u32 = 4096;
            const LIB_RING_SIZE: u32 = 2048;
            const MAX_FRAME_COUNT: u32 = LIB_RING_SIZE * 2;

            let a = &self.turn.af_xdp;
            if a.frame_size != LIB_FRAME_SIZE {
                errors.push(format!(
                    "turn.af_xdp.frame_size = {} is not applied: the UMEM is built with \
                     the library default of {LIB_FRAME_SIZE}. Set it to {LIB_FRAME_SIZE} \
                     or remove the key.",
                    a.frame_size
                ));
            }
            for (name, value) in [
                ("fill_ring_size", a.fill_ring_size),
                ("comp_ring_size", a.comp_ring_size),
                ("rx_ring_size", a.rx_ring_size),
                ("tx_ring_size", a.tx_ring_size),
            ] {
                if value != LIB_RING_SIZE {
                    errors.push(format!(
                        "turn.af_xdp.{name} = {value} is not applied: all four rings are \
                         built at the library default of {LIB_RING_SIZE}. Set it to \
                         {LIB_RING_SIZE} or remove the key."
                    ));
                }
            }
            // Not merely inert: above roughly twice the fill-ring size, more
            // frames end up free than the ring can hold and reception stops with
            // no error at all. Measured at frame_count = 16384 — 8160 free frames
            // against a 2048-entry fill ring, zero packets received. Failing at
            // startup turns a dead datapath into a message.
            if a.frame_count > MAX_FRAME_COUNT {
                errors.push(format!(
                    "turn.af_xdp.frame_count = {} exceeds {MAX_FRAME_COUNT}: with a \
                     {LIB_RING_SIZE}-entry fill ring, a larger UMEM leaves more free \
                     frames than the ring can hold and reception stops silently. Use \
                     {MAX_FRAME_COUNT} or fewer.",
                    a.frame_count
                ));
            }
            if a.frame_count == 0 {
                errors.push("turn.af_xdp.frame_count must be > 0".into());
            }
        }

        // Check port conflicts
        let all_ports = [""",
        ),
        (
            "config default frame_size",
            """            frame_count: 4096,
            frame_size: 2048,""",
            """            frame_count: 4096,
            // 4096, not 2048: this is the size the UMEM is actually created
            // with. The old default described a geometry that never existed.
            frame_size: 4096,""",
        ),
    ],
)

print()
print("applied. Verify:")
print()
print("  cargo clippy -p turna-config -p turna-transport --all-targets -- -D warnings")
print("  cargo test -p turna-config")
print()
print("One existing test asserts rx_ring_size parses as 2048, which still holds.")
print("If a test sets frame_size = 2048 it will now fail validation — that is the")
print("point, but check whether the expectation or the value should change.")
print()
print("Checked against your tree: the variant is TransportSelection::AfXdp.")
