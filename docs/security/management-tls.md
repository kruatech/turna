# Management plane authentication (`[grpc]`)

The management gRPC API exposes node control — `shutdown`, `set_draining`,
`add_user`, `remove_user`, `delete_allocation`, `update_config`. Anyone who can
call it controls the node.

`tls_mode` options:

| mode         | channel encrypted | client authenticated | allowed in prod on non-loopback |
| ------------ | ----------------- | -------------------- | ------------------------------- |
| `disabled`   | no                | no                   | **no** (rejected)               |
| `tls`        | yes               | **no**               | **no** (rejected — M4)          |
| `mtls`       | yes               | yes (client cert)    | yes                             |

`tls` (server-only) encrypts the channel but does **not** verify the caller —
anyone who can reach the port and speak TLS can issue admin RPCs. As of M4,
config validation refuses both `disabled` and `tls` on a **non-loopback**
`management.listen` when `production = true`. Use:

```toml
[grpc]
tls_mode = "mtls"
tls_cert = "/etc/turna/mgmt-server.pem"
tls_key  = "/etc/turna/mgmt-server-key.pem"
tls_ca   = "/etc/turna/mgmt-client-ca.pem"   # required for mtls
```

`tls` (server-only) remains valid only behind a trusted perimeter (loopback or
a private network you control). Bind `management.listen` to `127.0.0.1` / `::1`
if you do not need remote management.

Note: `set_user_limits` returns `UNIMPLEMENTED` — the per-user rate limiter it
was meant to drive was dead code and has been removed (M3).
