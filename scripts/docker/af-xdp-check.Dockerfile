# Compile-check image for `--features af-xdp`.
#
# WHY A SEPARATE IMAGE
#
# `af-xdp` is the only Cargo feature in this workspace that has never been
# compiled during the current change set. It cannot be: `build.rs` refuses to
# build off Linux by design, and the plain `rust:1` image lacks the C toolchain
# that `libxdp-sys` / `libbpf-sys` need to build their vendored libraries. So a
# `cargo clippy --features af-xdp` on a dev mac or in `rust:1` proves nothing.
#
# The package list mirrors `docs/compatibility/transport-backends.md`. If that
# table changes, change this file in the same commit.
#
# SCOPE: this checks that the feature *compiles and lints*. It does not and cannot
# run the datapath — AF_XDP needs a real NIC queue, CAP_NET_RAW, and an external
# XDP program attached. Runtime validation belongs on the lab host
# (`scripts/lab/af_xdp_veth_setup.sh`, `af_xdp_smoke.sh`), not here.
#
# USAGE (from the repository root):
#
#   docker build -f scripts/docker/af-xdp-check.Dockerfile -t turna-afxdp-check .
#   docker run --rm \
#     -v "$PWD":/w -w /w \
#     -v turna-cargo:/usr/local/cargo/registry \
#     -v turna-target-afxdp:/tmp/t \
#     -e CARGO_TARGET_DIR=/tmp/t \
#     turna-afxdp-check
#
# A separate target volume from the other checks on purpose: this build produces
# native objects for the vendored C libraries and sharing a target dir with the
# plain-Rust checks only causes rebuild churn.

# Pinned by digest, not by tag. `rust:1` moves whenever a new 1.x lands, so an
# image that built yesterday can fail today for reasons unrelated to this repo —
# and a mutable tag is also a place someone else's change enters the build, which
# is what Scorecard flags as Pinned-Dependencies.
# Refresh deliberately:
#   docker pull rust:1 && docker inspect --format='{{index .RepoDigests 0}}' rust:1
FROM rust:1@sha256:7f7a53a25a0319dd8284e279d529d45759cb384d59b14cc6806132910f45522e

# libxdp-sys builds vendored libxdp + libbpf, which need clang (for BPF
# compilation), llvm, libelf and zlib headers. pkg-config and libbpf-dev let the
# -sys crates find a system libbpf when they prefer it over the vendored copy.
# protobuf-compiler is unrelated to af-xdp but `cargo clippy --workspace` pulls
# turna-control, whose build script needs protoc — without it the run fails on a
# crate that has nothing to do with what is being checked.
RUN apt-get update -qq \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
        clang \
        llvm \
        libelf-dev \
        zlib1g-dev \
        libbpf-dev \
        pkg-config \
        protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

# clippy is not in the base image and `rust-toolchain.toml` pins a version, so the
# component has to be added for that pinned toolchain. If the network cannot reach
# static.rust-lang.org the entrypoint degrades to `cargo check`, which still catches
# compile errors — it just stops gating on warnings, and says so.
RUN rustup component add clippy || true

# TERM keeps apt/debconf from complaining about a missing tty in nested runs.
ENV TERM=dumb

WORKDIR /w

RUN printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -uo pipefail' \
    'echo "### $(rustc --version)"' \
    'if cargo clippy --version >/dev/null 2>&1; then' \
    '  LINT="clippy"; ARGS="-- -D warnings"' \
    'else' \
    '  LINT="check"; ARGS=""' \
    '  echo "!!! clippy unavailable; using cargo check (compile errors only, no warning gate)"' \
    'fi' \
    'FAIL=0' \
    'echo; echo "########## turna-transport --features af-xdp ##########"' \
    'cargo $LINT -p turna-transport --features af-xdp --all-targets $ARGS 2>&1 \' \
    '  | grep -vE "^\s+(Compiling|Checking|Downloaded|Updating|Finished|Locking)" | tail -30' \
    '[ ${PIPESTATUS[0]} -eq 0 ] || FAIL=1' \
    'echo; echo "########## turna-node --features af-xdp ##########"' \
    'cargo $LINT -p turna-node --features af-xdp --all-targets $ARGS 2>&1 \' \
    '  | grep -vE "^\s+(Compiling|Checking|Downloaded|Updating|Finished|Locking)" | tail -30' \
    '[ ${PIPESTATUS[0]} -eq 0 ] || FAIL=1' \
    'echo; echo "########## af_xdp frame unit tests (pure L2-L4, no NIC needed) ##########"' \
    'cargo test -p turna-transport --features af-xdp frame 2>&1 | tail -15' \
    '[ ${PIPESTATUS[0]} -eq 0 ] || FAIL=1' \
    'echo; if [ "$FAIL" = 0 ]; then echo "af-xdp-check: OK"; else echo "af-xdp-check: FAILED (see above)"; fi' \
    'exit $FAIL' \
    > /usr/local/bin/af-xdp-check \
    && chmod +x /usr/local/bin/af-xdp-check

ENTRYPOINT ["/usr/local/bin/af-xdp-check"]
