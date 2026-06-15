# turna fuzzing

Fuzz tests for the STUN/TURN parsers. The targets are declared in
`fuzz/Cargo.toml`; the crate depends only on `turna-proto-stun` and
`turna-proto-turn`.

| Target | What it exercises |
|---|---|
| `fuzz_stun` | `turna-proto-stun`: `StunMessage::decode`, attribute parsing, `MessageHeader::decode`, ChannelData decode, integrity verify |
| `fuzz_turn` | `turna-proto-turn` + `turna-proto-stun`: ChannelData decode, TURN control messages, channel-number validation |
| `fuzz_stun_semantic` | `turna-proto-stun`: builds valid STUN frames and applies semantic mutations (duplicate attributes, bit-flipped MESSAGE-INTEGRITY, wrong FINGERPRINT, INTEGRITY-before-USERNAME ordering, boundary/oversized attribute lengths, zero/max transaction IDs, unknown address family, repeated XOR-PEER-ADDRESS, empty DATA), then decodes and `verify_integrity` — contract: no panic/hang/OOM |
| `fuzz_turn_lifecycle` | `turna-proto-turn` + `turna-proto-stun`: stateful — builds semantically valid TURN sequences (Allocate → CreatePermission → ChannelBind → Send → Refresh → RefreshZero → ChannelData) with attribute mutations (missing/zero lifetime, wrong transport, invalid channel number, multicast peer, duplicate username, long nonce, missing peer) plus a trailing ChannelData frame; targets state-machine paths random-byte fuzzing can't reach past auth |
| `fuzz_encode` | `turna-proto-stun`: fuzzes the encode paths (`StunMessage::encode` / `encode_value`, `encode_channel_data`) with adversarial output-buffer sizes; asserts a reported length never exceeds its buffer and encoding never panics or writes out of bounds (ASan catches stray writes), and re-decodes the output |

> There is no `fuzz_rtcp` target and no `turna-proto-rtcp` crate in this
> workspace; earlier versions of this README listed one in error.

Corpus directories currently present in the tree: `fuzz/corpus/fuzz_stun`,
`fuzz/corpus/fuzz_turn`, `fuzz/corpus/fuzz_encode`. The other targets start from
an empty corpus (cargo-fuzz creates the directory on first run).

## Prerequisites

```bash
# Rust nightly (required by cargo-fuzz / libFuzzer)
rustup install nightly

# cargo-fuzz
cargo install cargo-fuzz
```

## Quick smoke run (CI / local sanity check)

Each command runs the target for 60 seconds and stops. Run from the repo root.

```bash
cargo +nightly fuzz run fuzz_stun           -- -max_total_time=60
cargo +nightly fuzz run fuzz_turn           -- -max_total_time=60
cargo +nightly fuzz run fuzz_stun_semantic  -- -max_total_time=60
cargo +nightly fuzz run fuzz_turn_lifecycle -- -max_total_time=60
cargo +nightly fuzz run fuzz_encode         -- -max_total_time=60
```

## Short campaign (CI, ~5 min per target)

```bash
cargo +nightly fuzz run fuzz_stun           -- -max_total_time=300
cargo +nightly fuzz run fuzz_turn           -- -max_total_time=300
cargo +nightly fuzz run fuzz_stun_semantic  -- -max_total_time=300
cargo +nightly fuzz run fuzz_turn_lifecycle -- -max_total_time=300
cargo +nightly fuzz run fuzz_encode         -- -max_total_time=300
```

## Long-running campaign (24+ hours, separate machine / tmux)

Run the targets in parallel, each in its own window. For targets that have a
corpus directory, pass it so runs resume from accumulated coverage:

```bash
# window 1
cargo +nightly fuzz run fuzz_stun \
    fuzz/corpus/fuzz_stun        \
    -- -max_total_time=86400 -jobs=4 -workers=4

# window 2
cargo +nightly fuzz run fuzz_turn \
    fuzz/corpus/fuzz_turn        \
    -- -max_total_time=86400 -jobs=4 -workers=4

# window 3
cargo +nightly fuzz run fuzz_encode \
    fuzz/corpus/fuzz_encode        \
    -- -max_total_time=86400 -jobs=4 -workers=4

# window 4 / 5 (no corpus dir yet — cargo-fuzz creates one)
cargo +nightly fuzz run fuzz_stun_semantic  -- -max_total_time=86400 -jobs=4 -workers=4
cargo +nightly fuzz run fuzz_turn_lifecycle -- -max_total_time=86400 -jobs=4 -workers=4
```

Adjust `-jobs` and `-workers` to match available CPU cores. On a Linux machine
with 8+ cores run each target with `-jobs=8 -workers=8`.

## Sanitizers

AddressSanitizer is enabled by cargo-fuzz by default on Linux (`-Z sanitizer=address`).
On macOS ASan works but is less complete; for serious campaigns prefer Linux or Docker.

To add UndefinedBehaviorSanitizer on top of ASan:

```bash
RUSTFLAGS="-Z sanitizer=address,undefined" \
    cargo +nightly fuzz run fuzz_stun -- -max_total_time=3600
```

## Crash triage

Crashes land in `fuzz/artifacts/<target>/`. To reproduce a specific crash:

```bash
cargo +nightly fuzz run fuzz_stun fuzz/artifacts/fuzz_stun/crash-<hash>
```

To minimise a crash to the smallest reproducing input:

```bash
cargo +nightly fuzz tmin fuzz_stun fuzz/artifacts/fuzz_stun/crash-<hash>
```

## Coverage report

```bash
cargo +nightly fuzz coverage fuzz_stun
# HTML report at: fuzz/coverage/fuzz_stun/html/index.html
```

## Corpus management

After a long campaign, deduplicate and minimise the corpus:

```bash
cargo +nightly fuzz cmin fuzz_stun
```

This rewrites `fuzz/corpus/fuzz_stun/` with only the inputs that provide unique
coverage, making subsequent runs start faster.

## Docker (recommended for long campaigns on macOS hosts)

```dockerfile
FROM rust:latest
RUN rustup install nightly && cargo install cargo-fuzz
WORKDIR /src
COPY . .
CMD ["cargo", "+nightly", "fuzz", "run", "fuzz_stun", "--", "-max_total_time=86400"]
```

```bash
docker build -t turna-fuzz .
docker run --rm -v "$PWD/fuzz/artifacts:/src/fuzz/artifacts" turna-fuzz
```
