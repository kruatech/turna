# turna-node %postun. Reload unit files; on upgrade ($1 >= 1) restart the
# service if it was running, so the new binary takes over.
systemctl daemon-reload >/dev/null 2>&1 || :
if [ "$1" -ge 1 ]; then
    systemctl try-restart turna-node.service >/dev/null 2>&1 || :
fi
exit 0
