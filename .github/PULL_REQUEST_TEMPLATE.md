# Description

<!-- What does this PR do and why? -->

Fixes # <!-- issue number, if any -->

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Docs / chore / CI

## Checklist

- [ ] `cargo fmt --all --check` passes
- [ ] `cargo clippy --workspace --all-targets --locked -- -D warnings` passes
- [ ] `cargo test --workspace --locked` passes
- [ ] `cargo deny check` passes (if dependencies changed)
- [ ] `CHANGELOG.md` updated under `## [Unreleased]` (for user-facing changes)
- [ ] Docs updated (config → `docs/CONFIGURATION.md`, deploy → `docs/DEPLOY.md`, etc.)
- [ ] If `unsafe` added/changed in `crates/transport` or `crates/relay`:
      `scripts/unsafe-inventory.sh` re-run and `docs/unsafe-audit.md` updated
- [ ] Commits are signed off (`git commit -s`, DCO — see CONTRIBUTING.md)

## Notes for reviewers

<!-- Anything reviewers should pay attention to: trade-offs, follow-ups, etc. -->
