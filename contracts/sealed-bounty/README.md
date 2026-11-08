# sealed-bounty (escrow contract)

Bug-bounty escrow that pays a hunter when a **NEAR AI Cloud TEE-signed** judge verdict says the
report is valid. v2: each program pins the judged code bundle (`code_hash`), and the judge request
names the hunter, so invented code and front-run claims can be disputed. The binding spec is [`docs/INTERFACE.md`](../../docs/INTERFACE.md).

## Flow
1. Admin allowlists TEE signers (after attestation): `add_signer`.
2. Program owner calls `create_program` with a deposit. The deposit minus the storage cost becomes the pool `balance`.
3. Hunter calls `submit_claim` with the TEE-signed response and attaches about 0.1 NEAR for storage (the unused part is refunded). The contract verifies the signature against `program.model_id` and parses the verdict. If the verdict is payable, it moves the payout from `balance` to `reserved`.
4. During `dispute_secs`, the owner can `dispute` by revealing the exact request body (its sha256 must equal the claim's `req_hash`). The claim is `Rejected` with the FIRST failing reason below, and the payout returns to `balance`:
   1. `system prompt tampered`: not JSON, `messages[0]` not `system`, its sha256 ≠ `system_prompt_hash`, or more than 3 messages
   2. `model mismatch`: `model` ≠ `program.model_id`
   3. `code mismatch`: `messages[1]` is not a `user` message equal to `TARGET <repo_url>@<commit>\nHUNTER <hunter>\n\nCODE\n<bundle>` with sha256(bundle) = `code_hash`. The TARGET line, the framing and the code hash are checked first, so a wrong TARGET or wrong code wins over a wrong HUNTER line.
   4. `hunter mismatch`: everything else in `messages[1]` matches but the HUNTER line ≠ `claim.hunter` (someone front-ran the real hunter's signed claim). The `req_hash` is also released from `used_req_hashes`, so the real hunter can resubmit the same signed verdict.
   5. `report missing`: `messages[2]` missing, not `user`, or not starting with `REPORT\n`

   If every check passes, `dispute` panics with `dispute invalid: request matches program`.
5. After the window, anyone can call `finalize`. The claim becomes `Paid` and the payout is transferred to the hunter.

## Methods
| Method | Who | Notes |
|---|---|---|
| `new(owner?)` | init | admin = `owner` or caller |
| `add_signer(signer, meta)` / `remove_signer(signer)` | admin | `signer` = `"ed25519:<hex>"` / `"eth:0x<hex>"`, `meta = {kind, model?}` |
| `create_program(name, repo_url, commit, model_id, system_prompt_hash, code_hash, payouts, owner_enc_pubkey, dispute_secs, min_confidence) -> u64` | anyone, payable | ids start at 0. Both hashes are 64 hex chars and are stored lowercase |
| `fund_program(program_id)` | anyone, payable | program must be open |
| `close_program(program_id)` | program owner | refunds `balance`, keeps `reserved`. Can be called again to sweep funds from claims rejected later |
| `submit_claim(program_id, req_hash, resp_body, signature, signer, kind, ciphertext) -> u64` | hunter, payable (storage) | |
| `dispute(claim_id, request_body)` | program owner | Pending and `now < finalize_after` |
| `finalize(claim_id) -> Promise` | anyone | Pending and `now >= finalize_after` |
| `verify_tee_response(model, req_hash, resp_body, signature, signer, kind) -> Verdict` | anyone | debug, no state change |

Views: `get_owner`, `get_signers`, `get_program(id)`, `list_programs(from_index?, limit?)`,
`get_claim(id)`, `list_claims(program_id, from_index?, limit?)` (default limit is 50).

Events are NEP-297 `EVENT_JSON:{"standard":"sealedbounty","version":"1.0.0","event":E,"data":[{...}]}`
with E in `signer_added`, `signer_removed`, `program_created`, `program_funded`, `program_closed`,
`claim_submitted`, `claim_rejected`, `claim_paid`.

Panic strings: `owner only`, `program owner only`, `program not found`, `program closed`,
`claim not found`, `claim not pending`, `signer not allowlisted`, `signer kind mismatch`,
`bad signature`, `bad completion json: ...`/`bad verdict json: ...`, `verdict not payable`,
`already claimed`, `insufficient pool`, `insufficient storage deposit`, `body mismatch`,
`dispute invalid: request matches program`, `dispute window closed`, `dispute window open`,
`system_prompt_hash must be 64 hex chars`, `code_hash must be 64 hex chars`, `min_confidence must be <= 100`, `attach a deposit`.

## Build / test / deploy
```sh
cargo near build non-reproducible-wasm      # -> target/near/sealed_bounty.wasm
cargo test -- --nocapture                   # unit tests + near-sandbox e2e (real TEE fixtures)
cargo clippy --all-targets

near contract deploy sealedbounty-v2.testnet use-file target/near/sealed_bounty.wasm \
  with-init-call new json-args '{"owner":"baldingsucks7993.testnet"}' \
  prepaid-gas '100.0 Tgas' attached-deposit '0 NEAR' network-config testnet sign-with-keychain send
```

Test fixtures are in `tests/fixtures/`, all copied so the crate is self-contained:
- `live.*.json`: real TEE-signed v1 responses (single user message). They still drive submit/finalize/close. Under v2, an honest-prompt dispute of these rejects them with `code mismatch`.
- `demo.{sqli,sqli.ecdsa,fakecode,bogus}.json`: real TEE-signed **v2** responses from `/fixtures`, plus `demo.code.sha256` (= `fixtures/vuln-app/bundle.sha256`) and `demo.system-prompt.sha256` (= `shared/system-prompt.sha256`). The v2 sandbox test creates the hunter account `hunter.baldingsucks7993.testnet` (sandbox accounts are state patches, so any name works). It then runs: front-run sqli → `hunter mismatch` → real hunter resubmits → `request matches program` → finalize paid; fakecode (judged valid/critical on invented code) → `code mismatch`, and the funds return.
- `synthetic.*.json`: from `gen.mjs`. The v2 unit tests sign their own v2 request bodies with a throwaway ed25519 key (`ed25519-dalek` dev-dep), so every dispute reason runs through the real `submit_claim`.
