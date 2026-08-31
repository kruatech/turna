# Security Policy

## Supported Versions

`turna` runs in production and is pre-1.0: interfaces may change in any minor
release — 0.4.0 added twenty-three config keys — and only the latest released
version receives security fixes.

| Version         | Supported                |
|-----------------|--------------------------|
| `0.4.0`         | ✅ current                |
| `< 0.4.0`       | ❌ superseded            |

Only the newest release is supported: there is no LTS line, and adding one is a
commitment rather than a table entry — the options are priced in
`docs/SUPPORT-POLICY-OPTIONS.md`.

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
