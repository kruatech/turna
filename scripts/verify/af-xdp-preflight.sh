#!/usr/bin/env bash
# Read-only inventory. Does not attach XDP or alter NIC/RSS/offload settings.
set -euo pipefail
IFACE=${1:?Usage: bash scripts/verify/af-xdp-preflight.sh ens3}
[[ "$IFACE" =~ ^[a-zA-Z0-9_.:-]+$ ]] || { echo 'Invalid interface name'; exit 1; }
[[ -d /sys/class/net/$IFACE ]] || { echo "No interface: $IFACE"; exit 1; }
uname -sr
ip -details link show dev "$IFACE"
ip -br address show dev "$IFACE"
ethtool -i "$IFACE"
ethtool -l "$IFACE"
python3 - "$IFACE" <<'PY'
import pathlib, sys
root = pathlib.Path('/sys/class/net') / sys.argv[1]
queues = sorted(int(p.name[3:]) for p in (root / 'queues').glob('rx-*'))
if not queues or any(q >= 64 for q in queues):
    raise SystemExit('Unsupported/missing RX queue IDs')
print('queue_ids = ' + str(queues))
print('MTU:', (root / 'mtu').read_text().strip())
print('Inventory only: native XDP and zero-copy require a successful bind/attach test.')
PY
