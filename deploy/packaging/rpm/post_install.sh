# turna-node %post. Reload unit files; the service is not enabled or started:
# the shipped config uses a placeholder shared secret, and a TURN server that
# mints credentials from a public placeholder must not come up by itself.
systemctl daemon-reload >/dev/null 2>&1 || :
exit 0
