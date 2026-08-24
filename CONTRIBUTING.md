# Contributing to turna

Thanks for your interest in contributing! `turna` is a high-performance
TURN/STUN server written in Rust. This guide covers how to build, test, and
submit changes.

> **Status:** `turna` is alpha. APIs, config keys, and crate boundaries may
> still change between pre-releases. See the
> [status matrix](README.md#status) for what is supported vs experimental.

## Reporting security issues

**Do not open public issues for security vulnerabilities.** Follow
[SECURITY.md](SECURITY.md) (private GitHub advisory).

## Getting started

The workspace pins its toolchain in `rust-toolchain.toml` (Rust **1.95.0**), so
`rustup` will fetch the right version automatically.

System build dependencies (Debian/Ubuntu names): `cmake`, `libclang-dev`,
`pkg-config`, `protobuf-compiler`. The AF_XDP datapath additionally needs
`clang`/`llvm`, `libelf`, and `zlib` headers.

```bash
git clone https://github.com/kruatech/turna
cd turna
cargo build --workspace --locked
```

## Before you open a pull request

Run the same gates CI runs:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo deny check
```

If your change touches dependencies, also check for a clean tree:

```bash
cargo deny check
cargo tree -d
```

If your change adds or modifies `unsafe` in `crates/transport` or
`crates/relay`, regenerate the inventory and document the block in
`docs/unsafe-audit.md`:

```bash
bash scripts/unsafe-inventory.sh > /tmp/unsafe-inventory.md
```

New `unsafe` outside the audited set will show up under "New unsafe outside the
audited set" — review it, add a `// SAFETY:` (or `// NEEDS-REVIEW:`) comment,
update `docs/unsafe-audit.md` / `docs/security/unsafe-inventory.json`, and add
the file to `AUDITED_PATHS` in the script.

Fuzz targets (nightly) live under `fuzz/`:

```bash
cd fuzz && cargo +nightly fuzz build
```

### Tests come with the change

New functionality is expected to arrive with tests, and a fix is expected to
arrive with a test that fails without it. Reviews ask for this.

Assert on observable behaviour rather than on the constant or the call you just
wrote. `ATTR_ALTERNATE_SERVER` held the wrong value across three releases while a
unit test asserted that the constant equalled itself; the test that caught it
checks the bytes on the wire. Where a getter or an encoder is involved, include a
decoy — a second attribute of the same shape — so a test cannot pass by matching
whatever happens to be first.

Mutation testing runs on a schedule (`cargo mutants`) and reports code a test
executes without detecting a change to it. A surviving mutant is a real gap, not
a false positive: it means the behaviour could be replaced and nothing would
notice.

## Commit and PR conventions

- Keep commits focused; write a clear message explaining the *why*.
  Conventional-commit prefixes (`feat:`, `fix:`, `ci:`, `docs:`) are used in
  history and appreciated but not enforced.
- Update `CHANGELOG.md` under `## [Unreleased]` for any user-facing change.
- Update docs alongside behavior changes (config keys → `docs/CONFIGURATION.md`,
  deployment → `docs/DEPLOY.md`, etc.).
- Fill in the pull request template.

## Developer Certificate of Origin (DCO)

Contributions are accepted under the project's license (see below). We use the
[DCO](https://developercertificate.org/): sign off every commit to certify you
have the right to submit it.

```bash
git commit -s -m "your message"
```

This appends a `Signed-off-by: Your Name <you@example.com>` trailer.

## License of contributions

This project is licensed under the **Apache License 2.0** (see
[LICENSE](LICENSE)). By submitting a contribution, you agree that it is
licensed under the same terms, per section 5 of the Apache-2.0 license.

## Code of conduct

This project follows the [Code of Conduct](CODE_OF_CONDUCT.md). By
participating you are expected to uphold it.
