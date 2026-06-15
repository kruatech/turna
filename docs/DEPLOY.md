# Production deployment

This guide assumes a single-node deployment on a Linux server with a
public IP. For multi-node clusters, read this first, then
[CLUSTER.md](CLUSTER.md).

## Pre-flight checklist

- [ ] Linux server with a public, NAT-free IP (or a 1:1 NAT mapping).
- [ ] At minimum 1 vCPU, 1 GB RAM, 2 GB disk. More if you expect
      >1000 concurrent sessions.
- [ ] `turna-node` binary in place (`cargo build --release` on a build
      host, or download from a release artifact).
- [ ] Inbound UDP allowed on port 3478 and on the relay range
      (default 49152–65535). TCP 3478 if you plan to use TCP TURN.
- [ ] Inbound TCP **blocked** on 9090 (metrics) and 5350 (gRPC management)
      from the public Internet. Expose only to your monitoring host.

## 1. Generate secrets

```sh
# 32-byte random secret (recommended)
openssl rand -hex 32
# → e.g.  c1f3...a82b  (use your own output, not this one)
```

Store this somewhere the server can read it. Two common patterns:

**Pattern A: env var via systemd `EnvironmentFile`.**
```sh
sudo install -d -m 0700 /etc/turna
sudo tee /etc/turna/secrets.env <<'EOF'
TURNA_PRODUCTION=true
TURNA_SHARED_SECRET=<paste-your-secret-here>
EOF
sudo chmod 0600 /etc/turna/secrets.env
sudo chown root:root /etc/turna/secrets.env
```

**Pattern B: secret file referenced from `turn.toml`.**
```sh
sudo install -d -m 0700 /etc/turna/secrets
echo -n '<paste-your-secret-here>' | sudo tee /etc/turna/secrets/shared_secret >/dev/null
sudo chmod 0600 /etc/turna/secrets/shared_secret
```

Then in `turn.toml`:
```toml
[turn.auth]
shared_secret = "file:///etc/turna/secrets/shared_secret"
```

Either pattern works. Pattern A integrates better with systemd /
container secrets; pattern B is closer to what Kubernetes' mounted
secret volumes give you.

## 2. Place the config

```sh
sudo install -d -m 0755 /etc/turna
sudo cp deploy/turn.toml /etc/turna/turn.toml
sudo chmod 0644 /etc/turna/turn.toml
```

Edit `/etc/turna/turn.toml`:

```toml
production = true
[turn]
external_ip = "203.0.113.10"   # your public IP
```

(Both can be supplied via env vars instead — `TURNA_PRODUCTION=true`
and `TURNA_EXTERNAL_IP=203.0.113.10`. Whichever way you prefer.)

## 3. Create a system user

Running TURN as root is unnecessary. Bind to ports > 1024 (the defaults
are 3478 and 49152–65535) and run unprivileged:

```sh
sudo useradd --system --no-create-home --shell /usr/sbin/nologin turna
sudo install -o turna -g turna -m 0755 target/release/turna-node /usr/local/bin/turna-node
sudo chown -R turna:turna /etc/turna
```

If you want to use port 3478 (which is below 1024 only for `0` and
`< 1024`, so 3478 is actually fine without root), no capabilities needed.
If you ever move to port 80/443, see `man capabilities` and grant
`CAP_NET_BIND_SERVICE`.

## 4. systemd unit

```sh
sudo tee /etc/systemd/system/turna-node.service <<'EOF'
[Unit]
Description=turna TURN/STUN server
After=network-online.target
Wants=network-online.target

[Service]
Type=exec
User=turna
Group=turna
EnvironmentFile=/etc/turna/secrets.env
ExecStart=/usr/local/bin/turna-node /etc/turna/turn.toml
Restart=always
RestartSec=5

# Hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadOnlyPaths=/etc/turna
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6
RestrictNamespaces=true
LockPersonality=true
SystemCallArchitectures=native

# Logging
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now turna-node.service
```

## 5. Verify

```sh
# Service is healthy
systemctl status turna-node

# Logs
journalctl -u turna-node -f

# From a remote host that can reach the server's public IP
curl -sS http://203.0.113.10:9090/health     # → ok  (only if you allowed 9090)
stunclient 203.0.113.10 -p 3478
```

## 6. Firewall

The rules below assume `ufw`. Adapt to your tool.

```sh
# TURN listener
sudo ufw allow 3478/udp comment 'turna STUN/TURN'
sudo ufw allow 3478/tcp comment 'turna TCP (optional)'

# Relay range — clients send/receive media on these
sudo ufw allow 49152:65535/udp comment 'turna relay range'

# Metrics: only your monitoring host, NOT the public Internet
sudo ufw allow from 10.20.30.40 to any port 9090 proto tcp comment 'prometheus scrape'

# gRPC management: only operators / control plane peers
sudo ufw allow from 10.20.30.0/24 to any port 5350 proto tcp comment 'turna-control-plane'
```

## 7. Health & metrics

Once running, the server exposes:

- `GET /health` — `200 ok` or `503 draining` (use for load-balancer
  liveness probes).
- `GET /status` — JSON snapshot of uptime, allocations, traffic.
- `GET /metrics` — Prometheus text format.

See [OBSERVABILITY.md](OBSERVABILITY.md) for the full metric list and
recommended alerts.

## Updating the server

`turna-node` shuts down gracefully on `SIGTERM`. systemd's
`Restart=always` plus `turna-node`'s graceful drain means a simple
binary swap + restart looks like this:

```sh
sudo install -o turna -g turna -m 0755 target/release/turna-node /usr/local/bin/turna-node
sudo systemctl restart turna-node
```

In single-node mode this still costs every client a re-Allocate
(roughly 1–2 seconds of glitchy audio per ongoing call). In cluster
mode with persistence enabled, active sessions are restored from the
backend on startup — see [CLUSTER.md](CLUSTER.md).

## Container-based deployment (sketch)

```yaml
# docker-compose.yml
services:
  turna:
    image: turna:latest          # build it yourself, no public image yet
    restart: unless-stopped
    network_mode: host              # required for TURN — relay ports
    environment:
      TURNA_PRODUCTION: "true"
      TURNA_EXTERNAL_IP: "203.0.113.10"
      TURNA_SHARED_SECRET: "${TURNA_SHARED_SECRET}"   # from .env or secrets mgr
    volumes:
      - ./turn.toml:/etc/turna/turn.toml:ro
    command: ["/etc/turna/turn.toml"]
```

Notes:

- **Host networking is effectively required.** TURN allocates relay
  ports dynamically in the 49152–65535 range; Docker bridge networking
  can't forward them efficiently.
- **Don't put PEM contents in env.** Mount them as files instead.

## Common pitfalls

**"validation: turn.external_ip must be set in production".**
You enabled production mode but didn't set `external_ip`. Without it,
TURN clients get `0.0.0.0` as their relay address, which they can't
use. Set the actual public IP of the server.

**Clients connect but can't reach each other through TURN.**
The relay port range (49152–65535) is not open in your firewall.

**Metrics scrape returns nothing.** Check that
`TURNA_HEALTH_ADDR` is not `127.0.0.1:9090` (only localhost); for
Prometheus on a separate host you need `0.0.0.0:9090` plus a firewall
rule that only allows Prometheus.

**Process restart took > 10s and clients dropped.**
`Restart=always` plus the default `RestartSec=5` gives a ~5s window
where the server is down. For single-node this means brief client
re-connects. For zero-gap upgrades, see [CLUSTER.md](CLUSTER.md).
