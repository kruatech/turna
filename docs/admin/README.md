# turna-admin — management console

Web console for the turna TURN server: read-only monitoring (stage 1) and
mutating operations via the gRPC control plane (stage 2).

## Stages

- Stage 1 (read-only): GET proxying of the node's /status /metrics /health
  /ready /cluster; dashboard (Overview, Allocations, Users, Nodes, Cluster,
  Events, Metrics, Config, Diagnostics).
- Stage 2 (mutations): POST /api/manage to the control plane over gRPC (:5350).
  Verified live: node.drain/node.undrain (SetDraining), failover.status and
  allocations.count (GetServerStats), allocations.list (ListAllocations),
  allocations.kill (DeleteAllocation), users.* (AddUser/RemoveUser/SetUserLimits),
  config.get/update. Gated by X-Admin-Token.

## Running (Node not required at runtime)

    cargo build -p turna-admin --release
    ./target/release/turna-admin \
        --turna-addr http://127.0.0.1:9090 \
        --grpc-addr  http://127.0.0.1:5350 \
        --static-dir services/admin/dist \
        --auth-token "$(openssl rand -hex 32)" \
        --listen 127.0.0.1:8080

## Flags / env

- --listen / TURNA_ADMIN_LISTEN (default 127.0.0.1:8080): console listen address.
- --turna-addr / TURNA_ADMIN_TURNA_ADDR (default http://127.0.0.1:9090): node health plane (read).
- --grpc-addr / TURNA_ADMIN_GRPC_ADDR (default http://127.0.0.1:5350): control-plane gRPC (mutations).
- --auth-token / TURNA_ADMIN_AUTH_TOKEN (unset): operator token for mutations (X-Admin-Token).
- --static-dir / TURNA_ADMIN_STATIC_DIR (default ./dist): frontend static dir.
- --upstream-timeout / TURNA_ADMIN_UPSTREAM_TIMEOUT (default 5s): timeout to the node.
- --tls-ca / TURNA_ADMIN_TLS_CA (unset): CA to verify CP server cert / mTLS.
- --tls-cert / TURNA_ADMIN_TLS_CERT (unset): client cert (mTLS).
- --tls-key / TURNA_ADMIN_TLS_KEY (unset): client key (mTLS).

## Transport to the control plane (stage 2) — three modes

1. http://  → plaintext gRPC. Loopback only (dev). Non-loopback with http:// is
   fail-closed (start refused).
2. https:// without --tls-* → TLS with system roots (trusted cert, e.g. Let's
   Encrypt). admin verifies the CP server cert, presents none. Enough for
   loopback / trusted network plus --auth-token.
3. https:// with all of --tls-ca/cert/key → mTLS: admin presents a client cert,
   the CP verifies it against the client CA. For exposure beyond a trusted network.

SNI override for tunnels: --grpc-domain lets admin dial https://127.0.0.1:5350
while validating the name turna.krutilin.pro (SSH tunnel to a CP with a trusted cert).

## Topology and security

- Loopback by default: admin :8080, node health :9090, control plane :5350 are
  loopback by design. Only admin is exposed outward (reverse proxy / VPN / SSH
  tunnel), never :9090/:5350 directly.
- Mutations require --auth-token. Without a token POST /api/manage returns 401.
  If no token is configured, mutations pass unauthenticated (safe only on
  loopback); a WARN is logged at startup.
- Fail-closed: a plaintext (http://) gRPC address that is not loopback refuses to start.
- Recommended topology: run admin on the same host as the control plane, dialing
  the CP over loopback. For loopback, mTLS is unnecessary — TLS plus --auth-token
  is enough. mTLS is needed only when admin and CP traverse a network.
- The node's read-only management plane (:9090) is loopback-only by design.
- Symmetric fail-closed is enforced: a non-loopback admin listener without
  `--auth-token` / `TURNA_ADMIN_AUTH_TOKEN` is rejected at startup.

## Development (Node required)

    cd services/admin/frontend
    npm install
    npm run dev

## Building the static bundle (Node required, one-off)

    cd services/admin/frontend
    npm run build

## Bridge API

Read (stage 1):
- GET /api/status  → node /status (JSON). Node unreachable → 503 node_unreachable.
- GET /api/metrics → /metrics → normalized JSON (counters, gauges, labeled).
- GET /api/health  → /health (200 live / 503 draining).
- GET /api/ready   → /ready (200 ready / 503 not-ready or draining).
- GET /api/cluster → /cluster ([] when clustering is disabled).

Mutate (stage 2):
- POST /api/manage → command dispatcher → gRPC RPC to the control plane.
  Requires X-Admin-Token. Body: {"command": "...", "params": {...}}.
  Commands and their proto RPCs: see crates/control/proto/management.proto.
- POST|GET /api/actions/* → 501 (reserved).
- GET /* → static from --static-dir (SPA fallback to index.html).

## Verified live (stage 2)

Local test admin → gRPC → control plane (plaintext loopback + token):
node.drain/node.undrain returned ok with draining toggling; failover.status
returned a valid GetServerStats; a request without the token returned 401. The
full admin→gRPC→CP chain executes mutations, not a stub.

## Known limitations

- Chart history is in-session memory (ring buffer ~120 points), reset on reload.
  For long-term history use Prometheus + Grafana.
- Panel metric names are verbatim from node code; if they change in turna, sync
  the frontend (src/lib/series.ts, panels).
- tarantool_connection_state: 0=connected, 1=reconnecting, 2=failed
  (per crates/health/src/lib.rs).
- The mTLS mode is implemented in code; live testing used plaintext-loopback +
  token. Production deployment (mTLS, exposed) has not been exercised.

## GA management behavior

The admin image is a release artifact. `/healthz` reports bridge process health
without requiring the control plane to be available at container startup;
actual API calls return an explicit upstream error while it is unavailable.
Static frontend assets are required at startup and are checked by CI container
smoke.

For non-loopback admin listeners, `TURNA_ADMIN_AUTH_TOKEN` is mandatory. The
frontend sends it in `x-admin-token`, never in the URL, and keeps a manually
entered token only in `sessionStorage` (not localStorage or persistent config).
Mutation without the token is rejected. Read endpoints follow the bridge's
explicit route policy; deployment networking must still keep admin private.

Config and Users pages operate on target-node desired/observed state. A retry
following a lost response reuses the same idempotency key; a new user intent
creates a new key. Version conflicts are displayed separately and refresh the
observed version rather than reporting false success.
