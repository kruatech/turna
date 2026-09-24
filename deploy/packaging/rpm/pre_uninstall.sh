# turna-node %preun. On full removal ($1 = 0) stop and disable the unit; on
# upgrade ($1 >= 1) leave it running.
if [ "$1" -eq 0 ]; then
    systemctl --no-reload disable --now turna-node.service >/dev/null 2>&1 || :
fi
exit 0
