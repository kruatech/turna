# Quickstart

Get Turna running locally in about 5 minutes.

**Prerequisites:** Rust toolchain ≥ 1.74 (`cargo --version`), a modern browser.

## Build

```sh
cargo build --release
```

Key binaries:

- `target/release/turna-node` — TURN/STUN server (media relay)
- `target/release/turna-signaling` — WebSocket signaling server
- `target/release/turna-control-plane` — gRPC ops API (optional)

---

## Option A — Video call in the browser (full stack)

This is the fastest way to see everything working together.

**Terminal 1 — TURN server:**
```sh
./target/release/turna-node deploy/turn.toml
```

You'll see expected dev warnings about `shared_secret` and `external_ip`.
That's fine for local use.

**Terminal 2 — Signaling server:**
```sh
./target/release/turna-signaling deploy/turn.toml
```

Listens on `ws://localhost:9001` by default.

**Browser — Web client:**

Open `services/web-client/index.html` in your browser (just drag the file
into a browser tab, or `open services/web-client/index.html` on macOS).

Open it in **two tabs**. In each tab:
- Enter different names
- Use the same room (e.g. `test-room`)
- Signaling server: `ws://localhost:9001`
- Click **Join call →**

Allow camera and microphone when prompted. The two tabs will connect and you'll
see each other's video.

---

## Option B — TURN server only (verify relay works)

If you just want to verify STUN/TURN without the video call UI:

```sh
./target/release/turna-node deploy/turn.toml
```

```sh
# Health check
curl -sS http://127.0.0.1:9090/health
# → ok

# Prometheus metrics
curl -sS http://127.0.0.1:9090/metrics | head -20

# STUN binding test (requires coturn-utils or similar)
stunclient 127.0.0.1 -p 3478
# → Binding test: success
```

---

## Configuration

All defaults are safe for local development. For reference:

| What | Default | Override |
|---|---|---|
| TURN/STUN port | `0.0.0.0:3478` | `TURNA_LISTEN_ADDR` |
| Health/metrics port | `0.0.0.0:9090` | `TURNA_HEALTH_ADDR` |
| Signaling WebSocket | `0.0.0.0:9001` | `TURNA_SIGNALING_ADDR` |
| Shared secret | `change-me-in-production` | `TURNA_SHARED_SECRET` |
| External IP | _(empty, warns)_ | `TURNA_EXTERNAL_IP` |
| Persistence | disabled | `[cluster.persistence] mode = "write_behind"` |

The annotated config template is at `deploy/turn.toml`.

---

## What's next

- **Deploy to a server** → [DEPLOY.md](DEPLOY.md)
- **Every config knob** → [CONFIGURATION.md](CONFIGURATION.md)
- **Metrics and alerts** → [OBSERVABILITY.md](OBSERVABILITY.md)
- **Multi-node cluster** → [CLUSTER.md](CLUSTER.md)

---

## Troubleshooting

**"address already in use" on port 3478.**
Another TURN server (coturn?) is running.
`sudo lsof -i :3478` to find it; stop it, or override with
`TURNA_LISTEN_ADDR=0.0.0.0:3479`.

**"address already in use" on port 9090.**
Set `TURNA_HEALTH_ADDR=0.0.0.0:9091` and retry.

**"address already in use" on port 9001.**
Set `TURNA_SIGNALING_ADDR=0.0.0.0:9002` and update the WS URL in the browser.

**Browser says "Camera denied".**
Allow camera/microphone in the browser permission prompt. On macOS,
check System Settings → Privacy → Camera/Microphone.

**WebSocket connection failed in browser.**
Check the signaling server is running and the WS URL matches the port.
The default is `ws://localhost:9001` — not 8080.

**Call connects but no video/audio.**
ICE negotiation likely failed. On localhost this usually works with just
STUN. If testing across different machines, make sure `TURNA_EXTERNAL_IP`
is set to the public IP of the machine running turna-node.

**"validation: turn.auth.shared_secret is empty".**
You set `TURNA_SHARED_SECRET` to an empty string. Either unset it or set
a real value.

**Process exits with "validation" error.**
You set `TURNA_PRODUCTION=true` without real secrets. Either generate them
(`openssl rand -hex 32`) or remove `TURNA_PRODUCTION` for dev.
