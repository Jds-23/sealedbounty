# sealedbounty CLI

Command-line client for the SealedBounty escrow (`contracts/sealed-bounty`). A NEAR AI TEE model
judges each exploit report and signs the verdict. The contract checks that signature onchain. The
full report is encrypted so that only the program owner can read it.

This is the **v3** CLI (docs/INTERFACE.md "v3"). Each program is bound to a published **code bundle**
(`code_hash`). Each judge request is bound to that bundle and to the **hunter** account that submits
it. A hunter therefore can't invent vulnerable code, and nobody can front-run a pending claim.

v3 adds:
- **params pinning** (`params_hash`): temperature, max_tokens, response_format and chat_template_kwargs are fixed.
- a **decryption challenge**: `flag-undecryptable` and `prove-ciphertext`.
- **per-program signer sets**: `set-program-signers` and `revoke-signer`.
- a hunter **bond**, and a **PayoutFailed** status if the payout transfer fails.

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
| `ESCROW_CONTRACT_ID` | `sealedbounty-v3.testnet` | escrow contract (`--contract` overrides it). `CONTRACT_ID` is ignored because it points at the Phase 0 spike. The older escrows `sealedbounty-v2.testnet` (no params_hash/bond/signers) and `escrow.baldingsucks7993.testnet` (v1, no `code_hash`) stay as history. |
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

Each program takes a snapshot of its signers when it is created (v3 #3), so a new global `add_signer`
does **not** reach existing programs. After a rotation, `attest --register` prints a reminder: each
program owner must run `set-program-signers`.

```sh
pnpm sb revoke-signer ed25519:<64 hex> --account <admin>.testnet [--dry-run]
```
`revoke_signer` removes the signer from the allowlist and marks it revoked. At `finalize`, its Pending
claims are Rejected with `"signer revoked"`. The admin can block payouts this way, but can't redirect
them.

### Program owner
```sh
# publish an existing bundle file ...
pnpm sb create-program --name "vuln-app" \
  --repo https://github.com/sealedbounty/sealedbounty/tree/main/fixtures/vuln-app --commit demo-commit-0001 \
  --code ../fixtures/vuln-app/bundle.txt \
  --payout-low 0.1 --payout-medium 0.5 --payout-high 1 --payout-critical 2 \
  --fund 5 --dispute-secs 300 --min-confidence 70 \
  [--bond 0.05] [--challenge-secs 600] [--signers ed25519:<hex>,eth:0x<hex>] [--dry-run]
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
sha256(shared/system-prompt.txt)` and `params_hash = shared.paramsHash()`. The create_program args are,
in order: `(name, repo_url, commit, model_id, system_prompt_hash, code_hash, params_hash, payouts,
owner_enc_pubkey, dispute_secs, min_confidence, bond, challenge_secs, signers)`.
- `--bond` (default 0.05 NEAR) is the stake each hunter attaches on top of storage. It is returned with
  the payout on Paid, and goes to the pool on Rejected.
- `--challenge-secs` (default 600) is how long a hunter has to `prove-ciphertext` after `flag-undecryptable`.
- `--signers` sets an explicit signer list. Each signer must be allowlisted for the model. Without
  it, `signers: null` is sent, and the contract takes a snapshot of every allowlisted signer whose
  model matches.

`create-program` attaches `fund + 0.05 NEAR` (the storage allowance; the contract adds whatever is
left of it to the pool, so the pool starts slightly above `--fund`: the live v3 program 1 got
`--fund 1.5` and started at 1.54248 NEAR). The secret key is written to
`~/.sealedbounty/owner-pending-*.json` **before** the transaction is sent and renamed to
`~/.sealedbounty/owner-<contract>-<programId>.json` (chmod 600) after it succeeds. Back this file up: without it
you cannot read the reports.

```sh
pnpm sb set-program-signers --program 0 --signers ed25519:<hex> eth:0x<hex> [--dry-run]
```
This checks every signer against `get_signers` (`meta.model == program.model_id`) before sending. It
only affects future submissions.

```sh
pnpm sb inbox --program 0 [--status Pending]   # decrypt each report; sha256(body)==req_hash; request vs program
pnpm sb dispute --claim 3 [--dry-run]          # reveal the body on-chain to reject a mismatching claim
```
For every claim, `inbox` runs `checkRequestAgainstProgram(body, program, claim.hunter)`, the same
checks the contract's `dispute` runs, in the same order: `system prompt tampered`, `model mismatch`,
`params tampered`, `code mismatch`, `hunter mismatch`, `report missing`. On a mismatch it prints the
reason and the `dispute` command to run. The code bundle is printed only when it differs from
`program.code_hash`. The checks are gated by the program's contract version (`inbox`, `dispute`,
`verify-claim`, `prove-ciphertext`): a v1 program (no `code_hash`) gets prompt + model only, a v2
program (no `params_hash`) skips params, a v3 program runs all six.

A ciphertext can fail to decrypt, or decrypt to a body whose sha256 is not `req_hash`. In both
cases there is nothing to reveal, so `dispute` can't work, and `inbox` prints
``UNDECRYPTABLE → run `sb flag-undecryptable --claim N` ``. For each claim, `inbox` also shows the
bond and the status. A Challenged claim shows its deadline and the time left.

```sh
pnpm sb flag-undecryptable --claim 3 [--dry-run]   # Pending -> Challenged; deadline = now + challenge_secs
```
The command first checks that the claim is Pending, that the dispute window is open, and that the
caller is the owner. With a local owner key, it also checks that the ciphertext really is
undecryptable.
- If the hunter proves the ciphertext before the deadline, the claim goes back to Pending and can be
  finalized.
- If the hunter's proof fails, or `finalize` runs after the deadline, the claim is Rejected with
  `"undecryptable report"` and the bond goes to the pool.

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
1. Build the request body (`TARGET …@…\nHUNTER <you>\n\nCODE\n<bundle>` + `REPORT\n<report>`, with the pinned params) and pre-check
   it with `checkRequestAgainstProgram` before spending a NEAR AI call.
2. Judge it, then run `verifyFixture` (hashes, signed text, signature, verdict, prompt hash).
3. Check the request against the program again (this includes `params tampered`). Any mismatch is
   refused unless `--force`.
4. Run the contract pre-checks: program open, verdict valid, severity, `min_confidence`, pool
   balance. Then check the signer: it must be in the global allowlist, in **`program.signers`**, and
   not revoked.
5. `encryptForOwnerWithSecret(request_body, program.owner_enc_pubkey)`. The ephemeral secret
   (together with `claim_id`, `req_hash` and `contract`) is written to
   `~/.sealedbounty/hunter-pending-*.json` (chmod 600) **before** sending. After the transaction
   succeeds, the file is renamed to `~/.sealedbounty/hunter-<contract>-<claimId>.json`.
6. Call `submit_claim`, attaching `storage + program.bond`. Storage is
   `(ciphertext bytes + 1500) × 1e19 + 0.01 NEAR`, and the contract refunds the unused part.

```sh
pnpm sb prove-ciphertext --claim 3 --dry-run   # local: open the box with the saved secret, hash, dispute checks
pnpm sb prove-ciphertext --claim 3             # answer the owner's challenge on-chain
```
The command reads the saved secret and mirrors the contract:
1. `x25519(secret) == ciphertext[0..32]`.
2. The box opens.
3. `sha256(plaintext) == req_hash`.
4. The full dispute checks pass.

Then it prints the expected outcome. It refuses to send if the contract would reject the claim
(`--force` sends it anyway).

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
pnpm sb finalize --claim 3            # after finalize_after; prints outcome: Paid / Rejected (reason) / PayoutFailed
pnpm sb verify-claim --claim 3        # offline sig check of model:req_hash:resp_hash from on-chain fields
pnpm sb verify-fixture ../fixtures/live.ed25519.json
```

`program` and `programs` show `params_hash`, `signers`, `bond` and `challenge_secs`. `claims` shows
the bond and the Challenged status (with its countdown) or PayoutFailed. `finalize` reads the
outcome from the `claim_paid`, `claim_rejected` and `payout_failed` events and from the claim's
status after the transaction:
- a revoked signer gives `Rejected (signer revoked)`.
- a Challenged claim past its deadline gives `Rejected (undecryptable report)`.
- a failed transfer gives `PayoutFailed`, and payout + bond are credited back to the pool.

## Tests
```sh
pnpm build && pnpm test      # Tests 83 passed (83)
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
- v3 (`test/v3.test.ts`, which is pure, and `test/v3-commands.test.ts`, where `src/near.js` is mocked
  so nothing touches the chain):
  - the `create_program` arg order and its defaults (bond, challenge_secs, `signers: null`, params_hash)
  - signer parsing
  - the new method args
  - deposit = storage + bond
  - `params tampered` refused
  - the hunter secret saved before sending and renamed afterwards (chmod 600)
  - `inbox` UNDECRYPTABLE hints and the Challenged countdown
  - the prove-ciphertext local check
  - set-program-signers and revoke-signer
  - the finalize outcome (Paid / Rejected / PayoutFailed)
  - the v3 fields in the views
