# syntax=docker/dockerfile:1
#
# Turna TURN/STUN server image.
#
# Build from repository root:
#   docker build -f deploy/Dockerfile -t turna:local .
#
# Run:
#   docker run --rm \
#     -p 3478:3478/udp -p 5349:5349/tcp \
#     -v "$PWD/deploy/turn.toml:/etc/turna/turn.toml:ro" \
#     turna:local
# =============================================================================
# Stage 1: Build
# =============================================================================
# Pinned to the same toolchain as rust-toolchain.toml and every CI job (1.95.0).
# It was 1.98.0 here: rustup inside the container saw the pin, downloaded 1.95.0
# on every build, and the image and CI compiled with different compilers. Lowered
# rather than raising the pin because the version appears in eight places in
# .github/workflows/ci.yml plus the msrv job's name.
FROM rust:1.95.0-bookworm@sha256:6258907abe69656e41cd992e0b705cdcfabcbbe3db374f92ed2d47121282d4a1 AS builder
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
# `--features tls` is spelled out even though `tls` is a default feature of
# turna-node: if somebody later moves it out of `default`, this image must keep
# serving TURNS rather than start dropping port 5349 silently.
RUN cargo build --locked --release --features tls \
    --bin turna-node \
    --bin turna-control-plane \
    --bin turnactl
# =============================================================================
# Stage 2: Runtime
# =============================================================================
FROM debian:bookworm-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251 AS runtime

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
ARG VERSION=0.5.0
LABEL org.opencontainers.image.title="turna" \
      org.opencontainers.image.description="High-performance TURN/STUN server in Rust" \
      org.opencontainers.image.source="https://github.com/kruatech/turna" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}"

# Ports:
#   3478/udp  - TURN/STUN
#   5349/tcp  - TURNS (TLS), when enabled in config
#   5350/tcp  - gRPC management API, when enabled/bound externally
#
# 3478/tcp is deliberately absent: turna has no plain TURN-over-TCP listener.
# The supported client URLs are turn:<host>:3478?transport=udp and
# turns:<host>:5349?transport=tcp. See "Client ICE configuration" in README.md.
#
# 9090/tcp is absent too: health and the full Prometheus surface bind
# 127.0.0.1 in deploy/turn.toml, so EXPOSE would advertise a port that is
# deliberately not reachable from outside the network namespace. Scrape it over
# host networking (deploy/docker-compose.yml) or point TURNA_HEALTH_ADDR at a
# private address.
EXPOSE 3478/udp 5349/tcp 5350/tcp
# Relay UDP ports. Publish a narrower range in compose/dev when needed.
EXPOSE 49152-65535/udp
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -fsS http://127.0.0.1:9090/health >/dev/null || exit 1
USER turna
ENV RUST_LOG=info,turna=debug
ENV TURNA_WORKERS=0
ENTRYPOINT ["turna-node"]
CMD ["/etc/turna/turn.toml"]
