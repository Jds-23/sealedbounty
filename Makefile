# SealedBounty root tasks. Requires: Node >= 23, pnpm 10.27.0 via `corepack enable` (pinned in the root
# package.json), Rust (rustup picks 1.95 from contracts/sealed-bounty/rust-toolchain.toml), cargo-near (only for
# `make build`). None of these targets need NEARAI_API_KEY or a NEAR account.

CONTRACT := contracts/sealed-bounty
NODE_DIRS := shared cli web $(CONTRACT)/tests/fixtures
# v3 escrow (params pinning, decryption challenge, per-program signers, bond). History: v2 sealedbounty-v2.testnet
# (`make live-v2`), v1 escrow.baldingsucks7993.testnet (`make live-v1`).
ESCROW ?= sealedbounty-v3.testnet
# The CLI and web already default to https://test.rpc.fastnear.com; set RPC=... only to override it.
RPC ?=
SB_ENV := ESCROW_CONTRACT_ID=$(ESCROW) $(if $(RPC),NEAR_RPC_URL=$(RPC))
# Live v3 demo: program 1 (program 0 was created with a wrong repo_url, then closed and refunded), claim 0 = Paid.
PROGRAM ?= 1
CLAIM ?= 0
RPC_URL := $(if $(RPC),$(RPC),https://test.rpc.fastnear.com)

.PHONY: setup test test-contract test-cli test-web demo verify-offline attest live live-v2 live-v1 signers web build clean

setup: ## pnpm install in every JS package (lockfiles are committed)
	@for d in $(NODE_DIRS); do echo "==> pnpm install ($$d)"; (cd $$d && pnpm install --frozen-lockfile) || exit 1; done

test: test-contract test-cli test-web test-helper ## all test suites

test-contract: ## unit tests + near-sandbox E2E with real TEE fixtures (first run downloads near-sandbox)
	cd $(CONTRACT) && cargo test

test-cli:
	cd cli && pnpm build && pnpm test

test-web:
	cd web && pnpm test

test-helper: ## demo-helper unit tests (node --test, no deps, no network)
	cd demo-helper && pnpm test

demo: ## re-verify every recorded TEE judgement offline (no key, no network)
	cd shared && pnpm demo:offline

verify-offline: ## CLI: verify a live TEE fixture + offline dry-run of submit_claim
	cd cli && pnpm sb verify-fixture ../fixtures/live.ed25519.json
	cd cli && pnpm sb submit --program 0 --fixture ../fixtures/demo.sqli.json --dry-run

attest: ## live Intel TDX (DCAP) + NVIDIA NRAS attestation of the NEAR AI model signers (network, no key)
	cd cli && $(SB_ENV) pnpm -s sb attest

signers: ## onchain signer allowlist (get_signers) of the escrow, via a plain RPC view
	@node -e 'fetch("$(RPC_URL)",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({jsonrpc:"2.0",id:1,method:"query",params:{request_type:"call_function",finality:"final",account_id:"$(ESCROW)",method_name:"get_signers",args_base64:Buffer.from("{}").toString("base64")}})}).then(r=>r.json()).then(j=>{if(j.error)throw new Error(JSON.stringify(j.error));console.log("get_signers on $(ESCROW):");for(const [s,m] of JSON.parse(Buffer.from(j.result.result).toString()))console.log("  "+s+"  "+m.kind+"  "+m.model)})'

live: ## read-only views of the v3 testnet deployment, program 1 (no account needed)
	cd cli && $(SB_ENV) pnpm -s sb programs
	cd cli && $(SB_ENV) pnpm -s sb program $(PROGRAM)
	cd cli && $(SB_ENV) pnpm -s sb claims $(PROGRAM)
	cd cli && $(SB_ENV) pnpm -s sb verify-claim --claim $(CLAIM)
	@$(MAKE) -s signers ESCROW=$(ESCROW) RPC=$(RPC)

live-v2: ## read-only views of the v2 escrow (history; no params_hash, bond or program signers)
	@$(MAKE) -s live ESCROW=sealedbounty-v2.testnet RPC=$(RPC) PROGRAM=0 CLAIM=1

live-v1: ## read-only views of the v1 escrow (history; it has no code_hash)
	@$(MAKE) -s live ESCROW=escrow.baldingsucks7993.testnet RPC=$(RPC) PROGRAM=0 CLAIM=0

web: ## web dev server on http://localhost:5173 (live v3 testnet data; demo mode via the selector)
	cd web && $(if $(RPC),VITE_NEAR_RPC=$(RPC)) VITE_ESCROW_CONTRACT_ID=$(ESCROW) pnpm dev

build: ## contract wasm + CLI dist + static web bundle
	cd $(CONTRACT) && cargo near build non-reproducible-wasm
	cd cli && pnpm build
	cd web && pnpm build

clean:
	rm -rf cli/dist web/dist
	@for d in $(NODE_DIRS); do rm -rf $$d/node_modules; done
