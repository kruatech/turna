# Support

Thanks for using `turna`. Here is where to go depending on what you need.

## Documentation first

Most questions are answered in the docs:

- [QUICKSTART](docs/QUICKSTART.md) — run a server locally.
- [CONFIGURATION](docs/CONFIGURATION.md) — all config keys.
- [DEPLOY](docs/DEPLOY.md) — systemd / Docker / Kubernetes.
- [PRODUCTION_READINESS](docs/PRODUCTION_READINESS.md) — what is supported vs
  experimental before you go to production.
- [OBSERVABILITY](docs/OBSERVABILITY.md), [MTLS](docs/MTLS.md),
  [SECURITY](docs/SECURITY.md).

The [status matrix](README.md#status) tells you which features are supported and
which are experimental.

## Questions and help

- **Usage questions / "how do I…?"** — open a GitHub Discussion if enabled,
  otherwise a GitHub issue using the question/feature template.
- **Bugs** — open a GitHub issue with the bug report template. Include the
  version/commit, how you deployed (binary/Docker/Helm), the datapath
  (tokio/io_uring/af_xdp), a minimal config, and relevant logs.
- **Feature requests** — open a GitHub issue with the feature request template.

## Security issues

Do **not** open a public issue for a security vulnerability. Follow
[SECURITY.md](SECURITY.md) (private GitHub advisory).

## Expectations

`turna` is alpha, maintained on a best-effort basis. There is no commercial
support or SLA. Clear, reproducible reports get help fastest.
