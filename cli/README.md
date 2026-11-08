# sealedbounty CLI

Command-line client for the SealedBounty escrow (`contracts/sealed-bounty`). A NEAR AI TEE model
judges each exploit report and signs the verdict. The contract checks that signature onchain. The
full report is encrypted so that only the program owner can read it.

All judge, crypto and prompt logic comes from `../shared/judge.mjs`, through the typed facade in
`src/shared.ts`, so the CLI and the web app hash and encrypt the same bytes.

## Setup

```sh
cd shared && pnpm install    # shared/judge.mjs needs tweetnacl + ethers
cd ../cli && pnpm install && pnpm build
pnpm sb --help               # dev (tsx); or: node dist/index.js --help
```

Config is read from the repo-root `.env`:

| var | default | used for |
|---|---|---|
| `ESCROW_CONTRACT_ID` | `escrow.baldingsucks7993.testnet` | escrow contract (`--contract` overrides it). `CONTRACT_ID` is ignored because it points at the Phase 0 spike. |
| `NEAR_NETWORK` / `NEAR_RPC_URL` | `testnet` / `https://rpc.testnet.near.org` | RPC |
| `NEAR_TESTNET_ACCOUNT_ID` | none | default signer (`--account` overrides it) |
| `NEAR_CREDENTIALS_PATH` | `~/.near-credentials/<network>/<account>.json` | signing key (near-cli JSON format) |
| `NEARAI_API_KEY`, `NEARAI_BASE_URL`, `NEARAI_MODEL`, `NEARAI_SIGNING_ALGO` | none, `https://cloud-api.near.ai/v1`, `Qwen/Qwen3.8-27B`, `ed25519` | judging (`submit` without `--fixture`) |

Every transaction prints `https://testnet.nearblocks.io/txns/<hash>`. Commands that send a transaction accept `--dry-run`.

## Commands

### Admin: allowlist TEE signers
```sh
pnpm sb attest                       # ed25519 + ecdsa: TDX (DCAP) + NVIDIA NRAS + report_data binding
pnpm sb attest --algo ed25519 --out-dir /tmp/att    # also save the evidence JSON
pnpm sb attest --register --account <admin>.testnet # add_signer for each VERIFIED model signer (skips existing ones)
```
This prints a PASS/FAIL table for each attestation entry and the exact `add_signer` args for each verified model signer.

### Program owner
```sh
pnpm sb create-program --name "vuln-app" --repo https://github.com/sealedbounty/vuln-app \
  --commit demo-commit-0001 --payout-low 0.1 --payout-medium 0.5 --payout-high 1 --payout-critical 2 \
  --fund 5 --dispute-secs 300 --min-confidence 70 [--dry-run]
```
This generates an x25519 keypair and registers `system_prompt_hash = sha256(shared/system-prompt.txt)`.
It attaches `fund + 0.05 NEAR` (the storage allowance; the contract adds whatever is left of it to the
pool). The secret key is written to `~/.sealedbounty/owner-pending-*.json` **before** the transaction is
sent and renamed to `~/.sealedbounty/owner-<programId>.json` (chmod 600) after it succeeds. Back this
file up: without it you cannot read the reports.

```sh
pnpm sb inbox --program 0 [--status Pending]   # decrypt each report, check sha256(body)==req_hash + prompt/model binding
pnpm sb dispute --claim 3 [--dry-run]          # reveal the body on-chain to reject a tampered claim
```
`dispute` stops before sending if the request matches the program's prompt and model, because the
contract would panic with `dispute invalid: prompt matches`. `--force` sends it anyway.

### Hunter
```sh
pnpm sb submit --program 0 --code server.ts --report sqli.md [--dry-run]   # live NEAR AI judgement
pnpm sb submit --program 0 --fixture ../fixtures/demo.sqli.json            # pre-recorded, no API key
pnpm sb submit --program 0 --fixture ../fixtures/demo.sqli.json --dry-run  # fully offline, no network
```
The flow is: judge (or load the fixture), then `verifyFixture` (hashes, signed text, signature, verdict,
prompt hash), then contract pre-checks (open, valid, severity, `min_confidence`, pool balance, signer
allowlist), then `encryptForOwner(request_body, program.owner_enc_pubkey)`, then `submit_claim` with a
storage deposit of `(ciphertext bytes + 1500) × 1e19 + 0.01 NEAR`. The contract refunds the unused part.
If a pre-check fails, nothing is sent unless you pass `--force`. An offline dry-run encrypts to
`--owner-pubkey`, or to the local owner key, or else to a throwaway key; the ciphertext size is exact
in every case. `--full` prints the args without elision.

### Anyone
```sh
pnpm sb programs | pnpm sb program 0 | pnpm sb claims 0
pnpm sb finalize --claim 3            # after finalize_after
pnpm sb verify-claim --claim 3        # offline sig check of model:req_hash:resp_hash from on-chain fields
pnpm sb verify-fixture ../fixtures/live.ed25519.json
```

## Tests
```sh
pnpm build && pnpm test
```
The tests cover the args builders, the fixture → `submit_claim` mapping (`live.ed25519.json`,
`live.ecdsa.json`, `demo.sqli.json`), the storage-deposit estimate, the encrypt/decrypt roundtrip and
ciphertext layout, the owner-key file handling, and `verify-claim` on simulated on-chain fields.
