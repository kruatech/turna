#!/usr/bin/env bash
# AFX-7 lab: create a veth pair for AF_XDP smoke testing (Linux, root).
#
# Sets up `turna-veth0` <-> `turna-veth1` in the host namespace, assigns IPs,
# brings them up, and disables features that break AF_XDP on veth (TX/RX
# checksum offload, generic-XDP fallbacks differ per kernel). The node binds its
# AF_XDP socket to `turna-veth0` queue 0; a test client drives traffic from
# `turna-veth1`.
#
# Idempotent: re-running tears down a previous pair first.
set -euo pipefail

DEV0="${DEV0:-turna-veth0}"
DEV1="${DEV1:-turna-veth1}"
IP0="${IP0:-10.123.0.1}"
IP1="${IP1:-10.123.0.2}"
PREFIX="${PREFIX:-24}"

[ "$(id -u)" -eq 0 ] || { echo "must run as root (needs CAP_NET_ADMIN)"; exit 1; }
command -v ip >/dev/null || { echo "iproute2 'ip' not found"; exit 1; }

echo "==> removing any existing pair"
ip link del "$DEV0" 2>/dev/null || true   # deleting one end removes the peer

echo "==> creating veth pair $DEV0 <-> $DEV1"
ip link add "$DEV0" type veth peer name "$DEV1"

for d in "$DEV0" "$DEV1"; do
  # AF_XDP on veth is sensitive to offloads; disable the common culprits.
  ethtool -K "$d" tx off rx off tso off gso off gro off 2>/dev/null || true
done

ip addr add "${IP0}/${PREFIX}" dev "$DEV0"
ip addr add "${IP1}/${PREFIX}" dev "$DEV1"
ip link set "$DEV0" up
ip link set "$DEV1" up

echo "==> ready:"
echo "    node side : $DEV0  $IP0/$PREFIX  (bind AF_XDP here, queue 0)"
echo "    client    : $DEV1  $IP1/$PREFIX"
echo
echo "Suggested [turn.af_xdp] in the node config:"
echo "    interface = \"$DEV0\""
echo "    queue_id  = 0"
echo "    src_mac   = \"$(cat /sys/class/net/$DEV0/address)\""
echo "    dst_mac   = \"$(cat /sys/class/net/$DEV1/address)\""
