# turna_server fuzzing

Fuzz tests for the STUN/TURN/RTCP parsers. Three targets:

| Target | Crate(s) | What it exercises |
|---|---|---|
| `fuzz_stun` | `turna-proto-stun` | `StunMessage::decode`, `parse_attributes`, `MessageHeader::decode`, `decode_channel_data`, `verify_integrity` |
| `fuzz_turn` | `turna-proto-turn` + `turna-proto-stun` | ChannelData decode, TURN control messages, `is_valid_channel` |
| `fuzz_rtcp` | `turna-proto-rtcp` | `parse_compound`, individual RTCP parsers (SR, RR, NACK, PLI, FIR, REMB), RTP one-byte extensions |

## Prerequisites

```bash
# Rust nightly (required by cargo-fuzz / libFuzzer)
rustup install nightly

# cargo-fuzz
cargo install cargo-fuzz
```

## Quick smoke run (CI / local sanity check)

Each command runs the target for 60 seconds and stops.

```bash
cd /path/to/turna_server

cargo +nightly fuzz run fuzz_stun  -- -max_total_time=60
cargo +nightly fuzz run fuzz_turn  -- -max_total_time=60
cargo +nightly fuzz run fuzz_rtcp  -- -max_total_time=60
```

## Short campaign (CI, ~5 min per target)

```bash
cargo +nightly fuzz run fuzz_stun  -- -max_total_time=300
cargo +nightly fuzz run fuzz_turn  -- -max_total_time=300
cargo +nightly fuzz run fuzz_rtcp  -- -max_total_time=300
```

## Long-running campaign (24+ hours, separate machine / tmux)

Run all three targets in parallel, each in its own window:

```bash
# window 1
cargo +nightly fuzz run fuzz_stun  \
    fuzz/corpus/fuzz_stun          \
    -- -max_total_time=86400 -jobs=4 -workers=4

# window 2
cargo +nightly fuzz run fuzz_turn  \
    fuzz/corpus/fuzz_turn          \
    -- -max_total_time=86400 -jobs=4 -workers=4

# window 3
cargo +nightly fuzz run fuzz_rtcp  \
    fuzz/corpus/fuzz_rtcp          \
    -- -max_total_time=86400 -jobs=4 -workers=4
```

Adjust `-jobs` and `-workers` to match available CPU cores.
On a Linux machine with 8+ cores run each target with `-jobs=8 -workers=8`.

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

This rewrites `fuzz/corpus/fuzz_stun/` with only the inputs that provide unique coverage, making subsequent runs start faster.

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
