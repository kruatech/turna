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
FROM rust:1.98.0-bookworm@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922 AS builder
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
FROM debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171 AS runtime

# Pinned non-root UID/GID so the Helm chart can set
# runAsUser/runAsGroup/fsGroup to a known value (65532, the conventional
# "nonroot" id) that matches the ownership of /etc/turna and /var/run/turna.
# Changing these here without updating deploy/helm/turna/values.yaml will break
# readOnlyRootFilesystem writes under Kubernetes.
ARG TURNA_UID=65532
ARG TURNA_GID=65532

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*
RUN groupadd -r -g ${TURNA_GID} turna \
    && useradd -r -u ${TURNA_UID} -g turna -d /etc/turna -s /usr/sbin/nologin turna
COPY --from=builder /build/target/release/turna-node /usr/local/bin/
COPY --from=builder /build/target/release/turna-control-plane /usr/local/bin/
COPY --from=builder /build/target/release/turnactl /usr/local/bin/
COPY deploy/turn.toml /etc/turna/turn.toml
RUN mkdir -p /etc/turna/tls /etc/turna/ebpf /var/run/turna \
    && chown -R turna:turna /etc/turna /var/run/turna

# OCI image metadata. VERSION is passed by the release workflow
# (--build-arg VERSION=<tag>); the default tracks the current chart/appVersion.
ARG VERSION=0.4.0
LABEL org.opencontainers.image.title="turna" \
      org.opencontainers.image.description="High-performance TURN/STUN server in Rust" \
      org.opencontainers.image.source="https://github.com/kruatech/turna" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}"

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
