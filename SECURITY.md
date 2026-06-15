# Security Policy

## Supported Versions

`turna` is pre-1.0 and is currently published as alpha pre-releases. Only the
latest released version receives security fixes.

| Version         | Supported                |
|-----------------|--------------------------|
| `0.2.0-alpha.x` | ✅ (current pre-release)  |
| `< 0.2.0`       | ❌                       |

Once a stable line is released, this table will track the supported minor
versions.

## Reporting a Vulnerability

Please report security issues **privately** — do not open a public issue.

Use GitHub's private vulnerability reporting (**Security → Report a
vulnerability**), or go directly to:

<https://github.com/kruatech/turna/security/advisories/new>

Include a minimal reproduction and the commit or tag you tested. We aim to
acknowledge reports within a few business days and will coordinate a fix and
disclosure timeline with you.

## Scope and threat model

The full security model — what `turna` does and does not protect, the threat
table, the production hardening checklist, and `shared_secret` rotation — lives
in [docs/SECURITY.md](docs/SECURITY.md). Please read it before exposing a
deployment to the Internet.
