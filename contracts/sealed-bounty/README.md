# sealed-bounty (escrow contract)

Bug-bounty escrow that pays a hunter when a **NEAR AI Cloud TEE-signed** judge verdict says the
report is valid. The binding spec is [`docs/INTERFACE.md`](../../docs/INTERFACE.md).

## Flow
1. Admin allowlists TEE signers (after attestation): `add_signer`.
2. Program owner calls `create_program` with a deposit. The deposit minus the storage cost becomes the pool `balance`.
3. Hunter calls `submit_claim` with the TEE-signed response and attaches about 0.1 NEAR for storage (the unused part is refunded). The contract verifies the signature against `program.model_id` and parses the verdict. If the verdict is payable, it moves the payout from `balance` to `reserved`.
4. During `dispute_secs`, the owner can `dispute` by revealing the exact request body. If the system prompt or the model doesn't match the program, the claim is `Rejected` and the funds return to `balance`.
5. After the window, anyone can call `finalize`. The claim becomes `Paid` and the payout is transferred to the hunter.

## Methods
| Method | Who | Notes |
|---|---|---|
| `new(owner?)` | init | admin = `owner` or caller |
| `add_signer(signer, meta)` / `remove_signer(signer)` | admin | `signer` = `"ed25519:<hex>"` / `"eth:0x<hex>"`, `meta = {kind, model?}` |
| `create_program(name, repo_url, commit, model_id, system_prompt_hash, payouts, owner_enc_pubkey, dispute_secs, min_confidence) -> u64` | anyone, payable | ids start at 0 |
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
`dispute invalid: prompt matches`, `dispute window closed`, `dispute window open`,
`system_prompt_hash must be 64 hex chars`, `min_confidence must be <= 100`, `attach a deposit`.

## Build / test / deploy
```sh
cargo near build non-reproducible-wasm      # -> target/near/sealed_bounty.wasm
cargo test -- --nocapture                   # unit tests + near-sandbox e2e (live TEE fixtures)
cargo clippy --all-targets

near contract deploy escrow.baldingsucks7993.testnet use-file target/near/sealed_bounty.wasm \
  with-init-call new json-args '{"owner":"baldingsucks7993.testnet"}' \
  prepaid-gas '100.0 Tgas' attached-deposit '0 NEAR' network-config testnet sign-with-keychain send
```

Test fixtures are in `tests/fixtures/`: `live.*.json` are real TEE-signed responses (copied from
`/fixtures`), and `synthetic.*.json` come from `gen.mjs`.
