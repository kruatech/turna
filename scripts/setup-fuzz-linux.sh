#!/usr/bin/env bash
# scripts/setup-fuzz-linux.sh
#
# Готовит Ubuntu 22.04 / 24.04 к запуску 24-часовой fuzz-кампании.
# Запускать один раз на чистой машине или в Docker-образе.
#
# Использование:
#   bash scripts/setup-fuzz-linux.sh
#   bash scripts/setup-fuzz-linux.sh --dry-run   # только покажет что будет делать
#
# После завершения:
#   cargo +nightly fuzz run fuzz_stun fuzz/corpus/fuzz_stun -- -max_total_time=86400

set -euo pipefail

DRY=0
[[ "${1:-}" == "--dry-run" ]] && DRY=1

run() {
    echo "  >> $*"
    [[ $DRY -eq 1 ]] || "$@"
}

echo "━━━ [1/4] Системные зависимости ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
run sudo apt-get update -qq
run sudo apt-get install -y --no-install-recommends \
    build-essential pkg-config curl git \
    clang llvm libclang-dev \
    libelf-dev libbpf-dev \
    libssl-dev libsodium-dev \
    libpcap-dev libnuma-dev \
    protobuf-compiler \
    dpdk-dev \
    screen                  # для фоновых сессий без tmux

echo ""
echo "━━━ [2/4] Rust (stable + nightly) ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
if command -v rustup &>/dev/null; then
    echo "  rustup уже установлен ($(rustup --version 2>&1 | head -1))"
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
    echo "  cargo-fuzz уже установлен ($(cargo fuzz --version))"
else
    run cargo install --locked cargo-fuzz
fi

echo ""
echo "━━━ [4/4] Smoke-run (60 секунд на fuzz_stun) ━━━━━━━━━━━━━━━━━━━━━━━━━━━"
if [[ $DRY -eq 1 ]]; then
    echo "  (пропущен в --dry-run)"
else
    cd "$(git rev-parse --show-toplevel)"
    cargo +nightly fuzz run fuzz_stun fuzz/corpus/fuzz_stun \
        -- -max_total_time=60 -print_final_stats=1
    echo ""
    echo "  Smoke-run прошёл — можно запускать полную кампанию."
fi

echo ""
echo "━━━ Готово ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
cat <<'EOF'

Запуск 24-часовой кампании (три окна screen или tmux):

  screen -S fuzz_stun
  cargo +nightly fuzz run fuzz_stun fuzz/corpus/fuzz_stun -- -max_total_time=86400
  Ctrl-A D  ← отцепиться

  screen -S fuzz_turn
  cargo +nightly fuzz run fuzz_turn fuzz/corpus/fuzz_turn -- -max_total_time=86400
  Ctrl-A D

  screen -S fuzz_rtcp
  cargo +nightly fuzz run fuzz_rtcp fuzz/corpus/fuzz_rtcp -- -max_total_time=86400
  Ctrl-A D

Посмотреть результат:
  screen -r fuzz_stun

Крэши будут в:
  fuzz/artifacts/fuzz_stun/
  fuzz/artifacts/fuzz_turn/
  fuzz/artifacts/fuzz_rtcp/
EOF
