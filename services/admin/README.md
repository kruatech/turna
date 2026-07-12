# turna-admin

Management console for turna (Rust/axum bridge + React/Vite frontend).

- Backend bridge (this crate): proxies the node read-only management plane
  (:9090) and routes mutations to the control plane (:5350) over gRPC; serves
  the built frontend from one origin.
- Frontend: services/admin/frontend (React + TypeScript + Vite + Tailwind).
  Node is only needed to build; the runtime serves the prebuilt dist/.

Full documentation — running, flags/env, the two stages (read-only + gRPC
mutations), TLS modes, topology and security — is in docs/admin/README.md.

Quick start:

    cargo build -p turna-admin --release
    (cd services/admin/frontend && npm install && npm run build)
    ./target/release/turna-admin \
        --turna-addr http://127.0.0.1:9090 \
        --grpc-addr  http://127.0.0.1:5350 \
        --static-dir services/admin/dist \
        --auth-token "$(openssl rand -hex 32)" \
        --listen 127.0.0.1:8080
