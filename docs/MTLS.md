# mTLS for the gRPC management API

The `turna-control-plane` gRPC interface can be served in three modes:

| Mode | Server cert | Client cert verified | Use when |
|---|---|---|---|
| `disabled` | none | no | Bound to `127.0.0.1` and reachable only by local processes (e.g. `turnactl` on the same host). |
| `tls`      | yes  | no | Inside a trusted network where you want confidentiality but trust every client. Rare. |
| `mtls`     | yes  | yes | Anything else — recommended whenever the control plane is reachable from outside the host. |

mTLS rejects connections from clients that don't present a certificate
signed by the configured CA. This means a leaked control-plane address
isn't enough: an attacker also needs a valid client cert your CA signed.

This guide walks through setting up mTLS end-to-end with `openssl` and
a simple self-managed CA. If you already use `cfssl`, Vault PKI, or
your cloud provider's certificate manager, adapt accordingly — the
contents of the PEM files are what matter, not which tool generated
them.

## 1. Create a CA

Once per cluster. Keep the CA key offline if possible.

```sh
sudo install -d -m 0700 /etc/turna/pki/ca
cd /etc/turna/pki/ca

# CA private key (4096-bit RSA; ECDSA P-256 is fine too)
sudo openssl genrsa -out ca.key 4096
sudo chmod 0600 ca.key

# Self-signed CA cert, 10-year validity
sudo openssl req -x509 -new -key ca.key -days 3650 -sha256 \
    -subj "/CN=turna CA" \
    -out ca.crt
```

`ca.crt` is what every server and every client in your cluster will
need to verify each other. Distribute it freely; treat `ca.key` like a
root password.

## 2. Issue a server certificate

Once per `turna-control-plane` host.

```sh
cd /etc/turna/pki

# Server key
sudo openssl genrsa -out server.key 4096
sudo chmod 0600 server.key

# CSR — Common Name (CN) and SubjectAltName (SAN) must match how
# clients address this server. Clients verify the cert's SAN against
# the hostname/IP they connect to.
sudo tee /etc/turna/pki/server.cnf <<'EOF'
[req]
default_bits       = 4096
distinguished_name = req_distinguished_name
req_extensions     = v3_req
prompt             = no

[req_distinguished_name]
CN = turna-cp-1.internal

[v3_req]
keyUsage         = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName   = @alt_names

[alt_names]
DNS.1 = turna-cp-1.internal
DNS.2 = localhost
IP.1  = 10.20.30.40
IP.2  = 127.0.0.1
EOF

sudo openssl req -new -key server.key -config server.cnf -out server.csr

# Sign with the CA. Validity 1 year; rotate before expiry.
sudo openssl x509 -req -in server.csr \
    -CA ca/ca.crt -CAkey ca/ca.key -CAcreateserial \
    -days 365 -sha256 \
    -extfile server.cnf -extensions v3_req \
    -out server.crt

# Cleanup: the CSR is no longer needed
sudo rm server.csr

# Quick sanity check
sudo openssl x509 -in server.crt -noout -text | grep -E 'CN|DNS|IP'
```

## 3. Issue a client certificate

Once per operator, host, or service that needs to call the gRPC API.

```sh
cd /etc/turna/pki

# Per-client key (this one is for `turnactl` running on the ops host)
sudo openssl genrsa -out client-ops1.key 4096

# CSR — clientAuth, no SAN required (clients identify by CN)
sudo tee /etc/turna/pki/client-ops1.cnf <<'EOF'
[req]
default_bits       = 4096
distinguished_name = req_distinguished_name
req_extensions     = v3_req
prompt             = no

[req_distinguished_name]
CN = ops-1

[v3_req]
keyUsage         = digitalSignature
extendedKeyUsage = clientAuth
EOF

sudo openssl req -new -key client-ops1.key -config client-ops1.cnf -out client-ops1.csr

sudo openssl x509 -req -in client-ops1.csr \
    -CA ca/ca.crt -CAkey ca/ca.key -CAcreateserial \
    -days 365 -sha256 \
    -extfile client-ops1.cnf -extensions v3_req \
    -out client-ops1.crt

sudo rm client-ops1.csr
```

Distribute `client-ops1.crt` + `client-ops1.key` + `ca.crt` to the
operator. The CA cert is needed so the client can verify the server.

## 4. Configure the server

Either in `/etc/turna/turn.toml`:

```toml
[grpc]
tls_mode = "mtls"
tls_cert = "/etc/turna/pki/server.crt"
tls_key  = "/etc/turna/pki/server.key"
tls_ca   = "/etc/turna/pki/ca/ca.crt"
```

Or via env (overrides the file):

```sh
TURNA_GRPC_TLS_MODE=mtls
TURNA_GRPC_TLS_CERT=/etc/turna/pki/server.crt
TURNA_GRPC_TLS_KEY=/etc/turna/pki/server.key
TURNA_GRPC_TLS_CA=/etc/turna/pki/ca/ca.crt
```

Permissions matter:

```sh
sudo chown -R turna:turna /etc/turna/pki/server.{crt,key}
sudo chown root:turna   /etc/turna/pki/ca/ca.crt
sudo chmod 0640 /etc/turna/pki/server.key
sudo chmod 0644 /etc/turna/pki/server.crt /etc/turna/pki/ca/ca.crt
```

The control-plane process needs read access to all three; nobody else
needs the server key.

Restart the control plane:

```sh
sudo systemctl restart turna-control-plane
sudo journalctl -u turna-control-plane -n 20
# Expect: "gRPC TLS enabled mode=mtls ..."
```

## 5. Connect with a client

For `turnactl` (or any tonic-based client), supply the three files:

```sh
turnactl --tls-cert /etc/turna/client-ops1.crt \
       --tls-key  /etc/turna/client-ops1.key \
       --tls-ca   /etc/turna/ca.crt \
       --server   turna-cp-1.internal:5350 \
       status
```

For `grpcurl`:

```sh
grpcurl \
    -cacert /etc/turna/ca.crt \
    -cert   /etc/turna/client-ops1.crt \
    -key    /etc/turna/client-ops1.key \
    turna-cp-1.internal:5350 \
    list
```

## Rotation

Server certs expire (365 days in the recipe above). To rotate without
breaking active connections:

1. Generate a new server cert, sign with the same CA.
2. Replace `server.crt` and `server.key` on disk.
3. **Restart** the control plane. Hot reload is not implemented yet.
4. Existing clients keep working because they verify against the CA,
   which hasn't changed.

To rotate the CA itself is more involved — you need to bridge old and
new CA trust for the duration of the rollover. Pragmatic approach:

- Generate a new CA and new server cert signed by it.
- Concatenate `cat old-ca.crt new-ca.crt > combined-ca.crt` and use
  `combined-ca.crt` as the trust bundle on clients during the
  transition.
- Issue new client certs from the new CA, distribute them.
- Once all clients are on new certs, drop the old CA from
  `combined-ca.crt` (now just `new-ca.crt`).

## Revocation

This setup does not implement CRL or OCSP in code, and that is a
deliberate choice.

### Why not in turna itself

Implementing CRL or OCSP correctly in a tonic/rustls stack adds
significant complexity: CRL download and caching, OCSP stapling,
handling of soft-fail vs hard-fail policies, clock skew, and revoked
intermediate CAs. The blast radius of getting it wrong (silently
accepting revoked certs, or incorrectly rejecting valid ones) is high.

More importantly: revocation is solved better at the infrastructure
layer. Vault PKI handles CRL distribution and OCSP automatically.
Kubernetes cert-manager does the same. Your cloud provider's ACM or
Cloud CA does too. Building a bespoke revocation path inside turna would
duplicate that work, badly.

### Immediate workaround (no Vault)

If a client cert is compromised and you don't have Vault:

1. Generate a **new CA key and cert**.
2. Issue a new server cert signed by the new CA.
3. Issue new client certs signed by the new CA for all legitimate operators.
4. Deploy new server cert + new CA trust bundle to the control plane; restart.
5. Distribute new client certs to operators.

The compromised cert can no longer connect — the server now trusts only
the new CA. This is a full CA rotation, which is more work than revoking
one cert, but it is correct and requires no new code.

### Recommended: Vault PKI

For production deployments that need per-cert revocation, use
[Vault PKI](https://developer.hashicorp.com/vault/docs/secrets/pki).

Minimal setup:

```sh
# 1. Enable the PKI secrets engine
vault secrets enable pki
vault secrets tune -max-lease-ttl=8760h pki   # 1 year

# 2. Generate an internal CA
vault write pki/root/generate/internal \
    common_name="turna CA" ttl=87600h

# 3. Create a role for turna control-plane certs
vault write pki/roles/turna-control \
    allowed_domains="internal" \
    allow_subdomains=true \
    max_ttl=720h          # 30 days — short-lived, rotate often

# 4. Issue a server cert
vault write pki/issue/turna-control \
    common_name="turna-cp-1.internal" \
    alt_names="localhost" \
    ip_sans="127.0.0.1,10.20.30.40" \
    ttl=720h

# 5. Issue a client cert
vault write pki/issue/turna-control \
    common_name="ops-1" \
    ttl=168h   # 7 days — shorter for clients
```

Vault writes the cert, key, and CA chain to its response. Extract them
and write to the paths configured in `turn.toml`.

To revoke a client cert:

```sh
vault write pki/revoke serial_number=<serial>
```

Vault updates its CRL automatically. To have turna honour it, configure
tonic to fetch and cache the CRL — out of scope here, but straightforward
with the `rustls` CRL API once Vault is in place.

**Short-lived certs as an alternative to revocation:** with `max_ttl=168h`
(7 days) a compromised cert is useless within a week without any explicit
revocation. This is often simpler to operate than CRL infrastructure.

## Troubleshooting

**"transport error: invalid peer certificate"** on the client side.
Server cert's SAN doesn't include the hostname the client is using.
Re-issue the server cert with the right `subjectAltName`.

**"transport error: failed to load certificate"** at startup.
Wrong file path, or the cert and key don't match. Verify:

```sh
openssl x509 -noout -modulus -in server.crt | openssl md5
openssl rsa  -noout -modulus -in server.key | openssl md5
# Two outputs must match exactly.
```

**Server starts but rejects every client with "no client cert".**
Either `tls_mode` is `tls` not `mtls` (server isn't asking for a
client cert), or the client isn't sending one, or the client cert
isn't signed by the configured CA.

**"certificate has expired".**
Server or client cert is past `not_after`. Rotate (see above).
`openssl x509 -in <file> -noout -dates` to check.

**"X509_NAME error" / mysterious validation failures.**
Try `openssl verify -CAfile ca.crt server.crt` outside turna. If openssl
itself can't verify, turna can't either — fix the cert chain first.

## Disabling mTLS for local dev

Just set `tls_mode = "disabled"` (or `TURNA_GRPC_TLS_MODE=disabled`).
The control plane binds to `127.0.0.1:5350` by default, so plaintext
is acceptable — nothing off-host can connect anyway.

The production validator in `turna-config` will refuse this combination
(`production = true` + `disabled` + non-loopback bind), so it's
explicitly safe in dev and explicitly impossible to ship by accident
in prod.
