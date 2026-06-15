# syntax=docker/dockerfile:1
#
# Turna TURN/STUN server image.
#
# Build from repository root:
#   docker build -f deploy/Dockerfile -t turna:local .
#
# Run:
#   docker run --rm \
#     -p 3478:3478/udp -p 3478:3478/tcp -p 9090:9090/tcp \
#     -v "$PWD/deploy/turn.toml:/etc/turna/turn.toml:ro" \
#     turna:local

# =============================================================================
# Stage 1: Build
# =============================================================================
FROM rust:1.95.0-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    cmake \
    libclang-dev \
    pkg-config \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy the full workspace. This intentionally avoids stale per-crate COPY lists:
# the workspace is the source of truth and the image must not reference removed
# crates/binaries that are no longer members of the current workspace.
COPY . .

# Build only binaries that exist in the current workspace.
RUN cargo build --locked --release \
    --bin turna-node \
    --bin turna-control-plane \
    --bin turnactl

# =============================================================================
# Stage 2: Runtime
# =============================================================================
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -r turna \
    && useradd -r -g turna -d /etc/turna -s /usr/sbin/nologin turna

COPY --from=builder /build/target/release/turna-node /usr/local/bin/
COPY --from=builder /build/target/release/turna-control-plane /usr/local/bin/
COPY --from=builder /build/target/release/turnactl /usr/local/bin/
COPY deploy/turn.toml /etc/turna/turn.toml

RUN mkdir -p /etc/turna/tls /etc/turna/ebpf /var/run/turna \
    && chown -R turna:turna /etc/turna /var/run/turna

# Ports:
#   3478/udp  - TURN/STUN
#   3478/tcp  - TURN over TCP
#   5349/tcp  - TURNS (TLS), when enabled in config
#   5350/tcp  - gRPC management API, when enabled/bound externally
#   9090/tcp  - health + Prometheus metrics
EXPOSE 3478/udp 3478/tcp 5349/tcp 5350/tcp 9090/tcp

# Relay UDP ports. Publish a narrower range in compose/dev when needed.
EXPOSE 49152-65535/udp

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -fsS http://127.0.0.1:9090/health >/dev/null || exit 1

USER turna

ENV RUST_LOG=info,turna=debug
ENV TURNA_WORKERS=0

ENTRYPOINT ["turna-node"]
CMD ["/etc/turna/turn.toml"]
