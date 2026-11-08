# SealedBounty root tasks. Requires: Node >= 23, pnpm, Rust (rustup picks 1.95 from
# contracts/sealed-bounty/rust-toolchain.toml), cargo-near (only for `make build`).
# None of these targets need NEARAI_API_KEY or a NEAR account.

CONTRACT := contracts/sealed-bounty
NODE_DIRS := shared cli web $(CONTRACT)/tests/fixtures
# rpc.testnet.near.org is deprecated and answers -429; override with `make live RPC=...`
RPC ?= https://test.rpc.fastnear.com

.PHONY: setup test test-contract test-cli test-web demo verify-offline live web build clean

setup: ## pnpm install in every JS package (lockfiles are committed)
	@for d in $(NODE_DIRS); do echo "==> pnpm install ($$d)"; (cd $$d && pnpm install --frozen-lockfile) || exit 1; done

test: test-contract test-cli test-web ## all test suites

test-contract: ## unit tests + near-sandbox E2E with real TEE fixtures (first run downloads near-sandbox)
	cd $(CONTRACT) && cargo test

test-cli:
	cd cli && pnpm build && pnpm test

test-web:
	cd web && pnpm test

demo: ## re-verify every recorded TEE judgement offline (no key, no network)
	cd shared && pnpm demo:offline

verify-offline: ## CLI: verify a live TEE fixture + offline dry-run of submit_claim
	cd cli && pnpm sb verify-fixture ../fixtures/live.ed25519.json
	cd cli && pnpm sb submit --program 0 --fixture ../fixtures/demo.sqli.json --dry-run

live: ## read-only views of the testnet deployment (no account needed)
	cd cli && NEAR_RPC_URL=$(RPC) pnpm -s sb programs
	cd cli && NEAR_RPC_URL=$(RPC) pnpm -s sb claims 0
	cd cli && NEAR_RPC_URL=$(RPC) pnpm -s sb verify-claim --claim 0

web: ## web dev server on http://localhost:5173 (live testnet data, demo mode via the selector)
	cd web && VITE_NEAR_RPC=$(RPC) pnpm dev

build: ## contract wasm + CLI dist + static web bundle
	cd $(CONTRACT) && cargo near build non-reproducible-wasm
	cd cli && pnpm build
	cd web && pnpm build

clean:
	rm -rf cli/dist web/dist
	@for d in $(NODE_DIRS); do rm -rf $$d/node_modules; done
