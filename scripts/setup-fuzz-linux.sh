#!/usr/bin/env bash
# scripts/setup-fuzz-linux.sh
#
# Prepares Ubuntu 22.04 / 24.04 for running a 24-hour fuzz campaign.
# Run once on a clean machine or in a Docker image.
#
# Usage:
#   bash scripts/setup-fuzz-linux.sh
#   bash scripts/setup-fuzz-linux.sh --dry-run   # only shows what it would do
#
# After completion:
#   cargo +nightly fuzz run fuzz_stun fuzz/corpus/fuzz_stun -- -max_total_time=86400

set -euo pipefail

DRY=0
[[ "${1:-}" == "--dry-run" ]] && DRY=1

run() {
    echo "  >> $*"
    [[ $DRY -eq 1 ]] || "$@"
}

echo "━━━ [1/4] System dependencies ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
run sudo apt-get update -qq
run sudo apt-get install -y --no-install-recommends \
    build-essential pkg-config curl git \
    clang llvm libclang-dev \
    libelf-dev libbpf-dev \
    libssl-dev libsodium-dev \
    libpcap-dev libnuma-dev \
    protobuf-compiler \
    dpdk-dev \
    screen                  # for background sessions without tmux

echo ""
echo "━━━ [2/4] Rust (stable + nightly) ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
if command -v rustup &>/dev/null; then
    echo "  rustup already installed ($(rustup --version 2>&1 | head -1))"
    run rustup update stable
    run rustup update nightly
else
    run curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --default-toolchain stable --no-modify-path
    # shellcheck source=/dev/null
    [[ $DRY -eq 1 ]] || source "$HOME/.cargo/env"
fi
run rustup toolchain install nightly --component rust-src

echo ""
echo "━━━ [3/4] cargo-fuzz ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
if cargo fuzz --version &>/dev/null 2>&1; then
    echo "  cargo-fuzz already installed ($(cargo fuzz --version))"
else
    run cargo install --locked cargo-fuzz
fi

echo ""
echo "━━━ [4/4] Smoke-run (60 seconds on fuzz_stun) ━━━━━━━━━━━━━━━━━━━━━━━━━━"
if [[ $DRY -eq 1 ]]; then
    echo "  (skipped in --dry-run)"
else
    cd "$(git rev-parse --show-toplevel)"
    cargo +nightly fuzz run fuzz_stun fuzz/corpus/fuzz_stun \
        -- -max_total_time=60 -print_final_stats=1
    echo ""
    echo "  Smoke-run passed — the full campaign can be started."
fi

echo ""
echo "━━━ Done ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
cat <<'EOF'

Running the 24-hour campaign (three screen or tmux windows):

  screen -S fuzz_stun
  cargo +nightly fuzz run fuzz_stun fuzz/corpus/fuzz_stun -- -max_total_time=86400
  Ctrl-A D  ← detach

  screen -S fuzz_turn
  cargo +nightly fuzz run fuzz_turn fuzz/corpus/fuzz_turn -- -max_total_time=86400
  Ctrl-A D

  screen -S fuzz_rtcp
  cargo +nightly fuzz run fuzz_rtcp fuzz/corpus/fuzz_rtcp -- -max_total_time=86400
  Ctrl-A D

View the results:
  screen -r fuzz_stun

Crashes will be in:
  fuzz/artifacts/fuzz_stun/
  fuzz/artifacts/fuzz_turn/
  fuzz/artifacts/fuzz_rtcp/
EOF
