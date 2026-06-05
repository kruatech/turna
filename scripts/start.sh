#!/bin/bash
# Turna TURN — quick start script

set -e

echo "=== Building Turna TURN ==="
cargo build --workspace

echo ""
echo "=== Starting TURN server (port 3478) ==="
cargo run --bin turna-node -- deploy/turn.toml &
TURN_PID=$!
sleep 1

echo "=== Starting Signaling server (port 8080) ==="
cargo run --bin turna-signaling &
SIG_PID=$!
sleep 1

echo ""
echo "========================================"
echo "  Turna TURN is running!"
echo "  TURN server:     udp://0.0.0.0:3478"
echo "  Signaling:       ws://0.0.0.0:8080"
echo "  Web client:      open services/web-client/index.html"
echo "========================================"
echo ""
echo "Open index.html in two browser tabs,"
echo "enter the same room name, and click Join."
echo ""
echo "Press Ctrl+C to stop."

trap "kill $TURN_PID $SIG_PID 2>/dev/null; exit" INT TERM
wait
