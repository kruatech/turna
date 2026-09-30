# Local shortcuts for the checks CI runs (.github/workflows/ci.yml).
# Requires the pinned toolchain (rust-toolchain.toml) and `protoc`
# (Debian/Ubuntu: apt-get install protobuf-compiler; macOS: brew install protobuf).

FRONTEND := services/admin/frontend

.PHONY: help build fmt fmt-check clippy test test-dtls doc-claims deploy-check \
        frontend frontend-lint check

help: ## List targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-14s %s\n", $$1, $$2}'

build: ## Release build of the workspace
	cargo build --release --workspace --locked

fmt: ## Format all Rust code
	cargo fmt --all

fmt-check: ## Fail if Rust code is not formatted
	cargo fmt --all --check

clippy: ## Lint the workspace, warnings as errors
	cargo clippy --workspace --all-targets --locked -- -D warnings

test: test-dtls ## Workspace tests, as CI runs them
	cargo test --workspace --locked --exclude turna-dtls

test-dtls: ## turna-dtls tests, single-threaded (they share UDP sockets and a crypto provider)
	cargo test -p turna-dtls --locked -- --test-threads=1

doc-claims: ## Documented claims agree with the code
	bash scripts/check-doc-claims.sh

deploy-check: ## Versions agree across Cargo, Helm, Dockerfiles and README
	bash scripts/check-deploy-consistency.sh

frontend: ## Install, lint and build the admin frontend
	cd $(FRONTEND) && npm ci && npm run lint && npm run build

frontend-lint: ## Lint the admin frontend
	cd $(FRONTEND) && npm run lint

check: fmt-check clippy doc-claims deploy-check test ## What the CI `check` and `msrv` jobs run
