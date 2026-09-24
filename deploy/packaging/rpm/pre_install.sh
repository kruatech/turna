# turna-node %pre: create the service user before the files owned by its group
# are laid down. Mirrors deploy/packaging/sysusers.d/turna-node.conf, which is
# also installed, for systems that manage users through systemd-sysusers.
getent group turna >/dev/null || groupadd -r turna
getent passwd turna >/dev/null || \
    useradd -r -g turna -d /nonexistent -M -s /sbin/nologin \
        -c "turna TURN/STUN server" turna
exit 0
