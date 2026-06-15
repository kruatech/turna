# Release policy

How turna releases are produced and what guarantees ship with them. If the
repository already has a `RELEASE.md`, merge this section into it.

## Branch & tagging

- `main` is the protected integration branch; enable branch protection
  (required CI, no force-push, review required) in repository settings.
- Releases are cut from `main` by pushing a version tag `vX.Y.Z`
  (e.g. `v0.2.0-alpha.1`).
- The tag push triggers `.github/workflows/release.yml`; release artifacts are
  built by GitHub Actions, not locally.

## Artifacts & supply-chain guarantees

- A multi-arch container image (`linux/amd64`, `linux/arm64`) is published to
  GHCR.
- The image is **cosign-signed (keyless)** and carries SLSA provenance + an
  SBOM attestation.
- Standalone `linux/amd64` binary tarballs ship with `.sha256` checksums, an
  SPDX SBOM, and a GitHub build-provenance attestation.
- Workflow `permissions` follow least privilege (read-only by default; jobs
  elevate only what they need); third-party Actions are pinned by commit SHA.

## Verifying a release

```
cosign verify ghcr.io/kruatech/turna:vX.Y.Z \
  --certificate-identity-regexp '^https://github.com/kruatech/turna/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Binary tarballs can be checked against their `.sha256` files, and the SPDX
SBOM (`*.spdx.json`) enumerates the components in each artifact.
