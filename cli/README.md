# sealedbounty CLI

Command-line client for the SealedBounty escrow (`contracts/sealed-bounty`). A NEAR AI TEE model
judges each exploit report and signs the verdict. The contract checks that signature onchain. The
full report is encrypted so that only the program owner can read it.

This is the **v2** CLI (docs/INTERFACE.md "v2"). Each program is bound to a published **code bundle**
(`code_hash`). Each judge request is bound to that bundle and to the **hunter** account that submits
it. A hunter therefore can't invent vulnerable code, and nobody can front-run a pending claim.

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
| `ESCROW_CONTRACT_ID` | `sealedbounty-v2.testnet` | escrow contract (`--contract` overrides it). `CONTRACT_ID` is ignored because it points at the Phase 0 spike. The v1 escrow `escrow.baldingsucks7993.testnet` has no `code_hash`. |
| `NEAR_NETWORK` / `NEAR_RPC_URL` | `testnet` / `https://test.rpc.fastnear.com` | RPC |
| `NEAR_TESTNET_ACCOUNT_ID` | none | default signer (`--account` overrides it). For `submit` this account is also the `HUNTER` bound into the request. |
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
# publish an existing bundle file ...
pnpm sb create-program --name "vuln-app" \
  --repo https://github.com/sealedbounty/sealedbounty/tree/main/fixtures/vuln-app --commit demo-commit-0001 \
  --code ../fixtures/vuln-app/bundle.txt \
  --payout-low 0.1 --payout-medium 0.5 --payout-high 1 --payout-critical 2 \
  --fund 5 --dispute-secs 300 --min-confidence 70 [--dry-run]
# ... or build it from source files (paths/globs relative to --code-root; writes <root>/bundle.txt + bundle.sha256)
pnpm sb create-program ... --code-root ../fixtures/vuln-app --code-files 'src/**/*.ts'
```
You pass exactly one of `--code` or `--code-files`. `code_hash = sha256(bundle)` goes into
`create_program` right after `system_prompt_hash`. The demo bundle hashes to `82faf3a0…285abd`. Bundle
format (`shared/judge.mjs` `buildCodeBundle`): files sorted by path, each one written as
`// file: <path>\n<content>` with a trailing `\n` added if missing. `--code-files` takes literal files,
directories (recursive) or globs (`*`, `**`, `?`, `{a,b}`), and skips `node_modules`, `.git` and its
own `bundle.txt`/`bundle.sha256`. Publish `bundle.txt` with the program, because hunters must judge
against it byte for byte.

The command also generates an x25519 keypair and registers `system_prompt_hash =
sha256(shared/system-prompt.txt)`. It attaches `fund + 0.05 NEAR` (the storage allowance; the contract
adds whatever is left of it to the pool). The secret key is written to
`~/.sealedbounty/owner-pending-*.json` **before** the transaction is sent and renamed to
`~/.sealedbounty/owner-<contract>-<programId>.json` (chmod 600) after it succeeds. Back this file up: without it
you cannot read the reports.

```sh
pnpm sb inbox --program 0 [--status Pending]   # decrypt each report; sha256(body)==req_hash; request vs program
pnpm sb dispute --claim 3 [--dry-run]          # reveal the body on-chain to reject a mismatching claim
```
For every claim, `inbox` runs `checkRequestAgainstProgram(body, program, claim.hunter)`, the same
checks the contract's `dispute` runs, in the same order: `system prompt tampered`, `model mismatch`,
`code mismatch`, `hunter mismatch`, `report missing`. On a mismatch it prints the reason and the
`dispute` command to run. The code bundle is printed only when it differs from `program.code_hash`.

`dispute` prints the expected outcome. If the request matches the program it refuses to send, because
the contract would panic with `dispute invalid: request matches program` (`--force` sends it anyway).
Otherwise it sends the dispute and then prints the claim's new status next to the expected reason. A
`hunter mismatch` dispute also frees the `req_hash`, so the real hunter can resubmit.

### Hunter
```sh
pnpm sb submit --program 0 --code bundle.txt --report sqli.md [--dry-run]  # live NEAR AI judgement
pnpm sb submit --program 0 --fixture ../fixtures/demo.sqli.json            # pre-recorded, no API key
pnpm sb submit --program 0 --fixture ../fixtures/demo.sqli.json --dry-run  # fully offline, no network
```
The hunter is the signer account (`--account` or `$NEAR_TESTNET_ACCOUNT_ID`). `--code` must be the
program's bundle: if it does not hash to `program.code_hash`, the CLI refuses unless you pass `--force`.

The flow:
1. Build the v2 body (`TARGET …@…\nHUNTER <you>\n\nCODE\n<bundle>` + `REPORT\n<report>`) and pre-check
   it with `checkRequestAgainstProgram` before spending a NEAR AI call.
2. Judge it, then run `verifyFixture` (hashes, signed text, signature, verdict, prompt hash).
3. Check the request against the program again. Any mismatch is refused unless `--force`.
4. Run the contract pre-checks: open, valid, severity, `min_confidence`, pool balance, signer allowlist.
5. `encryptForOwner(request_body, program.owner_enc_pubkey)`.
6. Call `submit_claim` with a storage deposit of `(ciphertext bytes + 1500) × 1e19 + 0.01 NEAR`. The
   contract refunds the unused part.

`--fixture` sends the fixture's `request_body` as it is, and pre-checks it for *your* account. A
fixture recorded for another hunter only prints `WARNING: hunter mismatch: the owner can dispute`.
Every other mismatch is refused (for example, `demo.fakecode.json` is refused with `code mismatch`).

With `--fixture`, `--dry-run` uses no network at all. It checks against the demo program instead: the
`shared/demo-data.mjs` target, the local system prompt, `$NEARAI_MODEL`, and the `code_hash` of
`--code` or else of `fixtures/vuln-app/bundle.txt`. It encrypts to `--owner-pubkey`, or to the local
owner key, or else to a throwaway key; the ciphertext size is exact in every case. `--full` prints the
args without elision.

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
The tests cover:
- the args builders, including `code_hash` in `create_program`
- the fixture → `submit_claim` mapping (`live.ed25519.json`, `live.ecdsa.json`, `demo.sqli.json`)
- the storage-deposit estimate
- the encrypt/decrypt roundtrip and ciphertext layout
- the owner-key file handling
- `verify-claim` on simulated on-chain fields
- v2: building a bundle from `--code-files` (rebuilds `fixtures/vuln-app/bundle.txt` byte for byte), the
  submit/dispute pre-check reasons, and offline `submit --dry-run` against `demo.sqli.json` (passes;
  warns on hunter mismatch) and `demo.fakecode.json` (refused with `code mismatch`). These tests also
  assert that no network is used.
