#!/bin/bash
# Turna TURN/STUN — local quick start script

set -euo pipefail

TURN_PID=""
cleanup() {
  if [ -n "$TURN_PID" ]; then
    kill "$TURN_PID" 2>/dev/null || true
  fi
}
trap cleanup INT TERM EXIT

echo "=== Building Turna TURN/STUN ==="
cargo build --workspace

echo ""
echo "=== Starting TURN/STUN server (UDP/TCP 3478, health 9090) ==="
cargo run --bin turna-node -- deploy/turn.toml &
TURN_PID=$!

sleep 1

echo ""
echo "========================================"
echo "  Turna is running"
echo "  TURN/STUN:       udp/tcp://0.0.0.0:3478"
echo "  Health:          http://127.0.0.1:9090/health"
echo "  Metrics:         http://127.0.0.1:9090/metrics"
echo "========================================"
echo ""
echo "Press Ctrl+C to stop."

wait "$TURN_PID"
