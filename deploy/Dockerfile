# syntax=docker/dockerfile:1
#
# Turna TURN — Multi-arch Docker image (amd64 + arm64)
#
# Build:
#   docker buildx build --platform linux/amd64,linux/arm64 -t turna .
#
# Run:
#   docker run -p 3478:3478/udp -p 8080:8080 -p 9090:9090 turna

# ============================================================================
# Stage 1: Build
# ============================================================================
FROM rust:1.82-bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    cmake \
    pkg-config \
    libclang-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Cache dependencies: copy only Cargo files first
COPY Cargo.toml Cargo.lock ./
COPY crates/protocol/proto-stun/Cargo.toml crates/protocol/proto-stun/
COPY crates/protocol/proto-turn/Cargo.toml crates/protocol/proto-turn/
COPY crates/protocol/proto-ice/Cargo.toml crates/protocol/proto-ice/
COPY crates/protocol/proto-rtp/Cargo.toml crates/protocol/proto-rtp/
COPY crates/transport/Cargo.toml crates/transport/
COPY crates/packet/Cargo.toml crates/packet/
COPY crates/relay/Cargo.toml crates/relay/
COPY crates/session/Cargo.toml crates/session/
COPY crates/auth/Cargo.toml crates/auth/
COPY crates/crypto/Cargo.toml crates/crypto/
COPY crates/qos/Cargo.toml crates/qos/
COPY crates/discovery/Cargo.toml crates/discovery/
COPY crates/control/Cargo.toml crates/control/
COPY crates/config/Cargo.toml crates/config/
COPY crates/observability/Cargo.toml crates/observability/
COPY crates/health/Cargo.toml crates/health/
COPY crates/sfu/Cargo.toml crates/sfu/
COPY crates/rtp-analyzer/Cargo.toml crates/rtp-analyzer/
COPY crates/rest-api/Cargo.toml crates/rest-api/
COPY services/node/Cargo.toml services/node/
COPY services/signaling/Cargo.toml services/signaling/
COPY services/control-plane/Cargo.toml services/control-plane/
COPY tools/load-test/Cargo.toml tools/load-test/

# Create dummy src files for dependency caching
RUN find . -name "Cargo.toml" -path "*/crates/*" -exec sh -c \
    'dir=$(dirname {})/src && mkdir -p $dir && echo "// dummy" > $dir/lib.rs' \;
RUN find . -name "Cargo.toml" -path "*/services/*" -exec sh -c \
    'dir=$(dirname {})/src && mkdir -p $dir && echo "fn main(){}" > $dir/main.rs' \;
RUN find . -name "Cargo.toml" -path "*/tools/*" -exec sh -c \
    'dir=$(dirname {})/src && mkdir -p $dir && echo "fn main(){}" > $dir/main.rs' \;

# Build dependencies only (cached layer)
RUN cargo build --release --workspace 2>/dev/null || true

# Copy actual source
COPY . .

# Touch all source files to invalidate build cache
RUN find . -name "*.rs" -exec touch {} +

# Build release binaries
RUN cargo build --release --bin turna-node --bin turna-signaling

# ============================================================================
# Stage 2: Runtime
# ============================================================================
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r turna && useradd -r -g turna -d /etc/turna -s /sbin/nologin turna

# Copy binaries
COPY --from=builder /build/target/release/turna-node /usr/local/bin/
COPY --from=builder /build/target/release/turna-signaling /usr/local/bin/

# Default config
COPY deploy/turn.toml /etc/turna/turn.toml

# Create directories
RUN mkdir -p /etc/turna/tls /etc/turna/ebpf /var/run/turna \
    && chown -R turna:turna /etc/turna /var/run/turna

# Ports:
#   3478/udp  - TURN/STUN
#   3478/tcp  - TURN over TCP
#   5349/tcp  - TURNS (TLS)
#   8080/tcp  - Signaling (WebSocket)
#   9090/tcp  - Health + REST API + Metrics
EXPOSE 3478/udp 3478/tcp 5349/tcp 8080/tcp 9090/tcp

# Relay port range
EXPOSE 49152-65535/udp

# Health check
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:9090/health || exit 1

USER turna

# Environment
ENV RUST_LOG=info,turna=debug
ENV VOX_WORKERS=0

ENTRYPOINT ["turna-node"]
CMD ["/etc/turna/turn.toml"]
