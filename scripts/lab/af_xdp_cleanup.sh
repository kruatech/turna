#!/usr/bin/env bash
# AFX-7 lab: tear down the veth pair created by af_xdp_veth_setup.sh.
set -euo pipefail
DEV0="${DEV0:-turna-veth0}"
[ "$(id -u)" -eq 0 ] || { echo "must run as root"; exit 1; }
# Deleting one end of a veth pair removes its peer too.
ip link del "$DEV0" 2>/dev/null && echo "removed $DEV0 (+peer)" || echo "$DEV0 not present"
