# SealedBounty — shared interface (source of truth for contract, CLI, web)

## Phase 0 proven facts
- Model: `Qwen/Qwen3.8-27B` (NEAR AI Cloud, provider_tee). Non-streaming. Headers: `x-no-aliasing: true`, `Accept-Encoding: identity`.
- Every judge request MUST include `chat_template_kwargs: {"enable_thinking": false}`. Otherwise thinking eats all the tokens and content is null.
- Signed text (provider_tee) = `{model}:{sha256hex(request_body)}:{sha256hex(response_body)}`.
- Signers rotate on NEAR AI redeploy → signers are allowlisted by the contract admin after `attest` and are never hardcoded.
- Reusable code:
  - `contracts/sealed-bounty/src/tee.rs`: `verify_tee_signature`, `parse_verdict`, `Signer`, `SigKind`, `Severity`, `Verdict`
  - `spike/sign/lib.mjs`: record + verify
  - `spike/attest/src/attest.ts`: full attestation

## Encodings
- `Signer` JSON = `"ed25519:<64 hex>"` | `"eth:0x<40 hex>"`.
- `SigKind` = `"provider_tee"` | `"gateway"`.
- `Severity` = `"none"|"low"|"medium"|"high"|"critical"`.
- `Verdict` = `{valid: bool, severity: Severity, cwe: string|null, confidence: u8}`.
  - `confidence` = the probability that the VERDICT is correct (×100), so `valid:false, confidence:100` means "surely bogus".
  - `min_confidence` gates payable verdicts only.
  - JSON schema `cwe` = `{"type":["string","null"]}`.
- System prompt: `shared/system-prompt.txt` (no trailing newline), sha256 `aede4ebac53d6bae5f3ceefc8d60175faff90276ac7751fb26aebff39e5172c2` (v2; v1 was 4fdd9ec8…). Helpers live in `shared/judge.mjs` (browser-safe).
- Demo target: `https://github.com/sealedbounty/vuln-app` @ `demo-commit-0001`. Fixtures: `fixtures/demo.{sqli,sqli.ecdsa,idor,bogus,injection}.json`.
- Amounts: `U128` yoctoNEAR as a decimal string. Timestamps: nanoseconds as `U64` strings.
- Owner encryption key: tweetnacl `box` keypair (x25519). The public key is base64 and goes onchain. The secret key stays local at `~/.sealedbounty/owner-<program_id>.json`, never committed.
- Report ciphertext (base64) = `ephemeralPub(32) || nonce(24) || nacl.box(utf8(request_body), nonce, ownerPub, ephemeralSecret)`.

## Canonical judge request body (built ONCE with JSON.stringify, hashed exactly as sent)
```json
{"model":"<program.model_id>",
 "messages":[{"role":"system","content":"<exact contents of shared/system-prompt.txt>"},
             {"role":"user","content":"TARGET <repo_url>@<commit>\n\n<code excerpt>\n\nREPORT\n<exploit report>"}],
 "response_format":{"type":"json_schema","json_schema":{"name":"verdict","strict":true,"schema":{...verdict schema...}}},
 "chat_template_kwargs":{"enable_thinking":false},
 "temperature":0,"max_tokens":400}
```
`program.system_prompt_hash` = sha256hex(utf8 of the exact system prompt string) = sha256hex of `messages[0].content`.

## Contract `sealed-bounty` (near-sdk 5.30, `unstable` feature)
State: `owner` (admin), `signers: IterableMap<Signer, SignerMeta{kind, model?}>`, `programs: IterableMap<u64, Program>`, `claims: IterableMap<u64, Claim>`, `used_req_hashes: LookupSet<String>`, `next_program_id`, `next_claim_id`.

```
Program { id: u64, owner: AccountId, name: String, repo_url: String, commit: String,
  model_id: String, system_prompt_hash: String, payouts: Payouts{low,medium,high,critical: U128},
  owner_enc_pubkey: String, dispute_secs: u64, min_confidence: u8,
  balance: U128 /*unreserved*/, reserved: U128, open: bool, created_at: U64 }

Claim { id: u64, program_id: u64, hunter: AccountId, req_hash: String, resp_hash: String,
  verdict: Verdict, signer: Signer, kind: SigKind, signature: String, model: String,
  ciphertext: String, status: "Pending"|"Rejected"|"Paid", payout: U128,
  submitted_at: U64, finalize_after: U64, reject_reason: Option<String> }
```

Methods:
- `new(owner: Option<AccountId>)` (init)
- `add_signer(signer, meta)` / `remove_signer(signer)`: admin only. `get_signers()`.
- `create_program(name, repo_url, commit, model_id, system_prompt_hash, payouts, owner_enc_pubkey, dispute_secs, min_confidence) -> u64`: **payable**. The attached deposit minus the storage cost becomes `balance`.
- `fund_program(program_id)`: payable, adds to balance.
- `close_program(program_id)`: program owner only. Sets open=false and refunds `balance` (`reserved` stays for pending claims).
- `submit_claim(program_id, req_hash, resp_body: Base64VecU8, signature, signer, kind, ciphertext) -> u64`: payable for storage. Checks, in order:
  - the program is open
  - the signer is allowlisted with a matching kind
  - `verify_tee_signature` with `model = program.model_id`
  - `parse_verdict`
  - `verdict.valid && severity != none && confidence >= min_confidence`, else panic `"verdict not payable"`
  - `req_hash` not used, else `"already claimed"`
  - `payout = payouts[severity] <= balance`, else `"insufficient pool"`
  - Then: move payout from balance → reserved, store resp_hash = sha256hex(resp_body) (NOT the body), set `finalize_after = now + dispute_secs`, and refund unused storage deposit.
- `dispute(claim_id, request_body: String)`: program owner only, Pending, `now < finalize_after`. It requires `sha256hex(request_body) == req_hash` (else `"body mismatch"`), then parses JSON:
  - if `messages[0].role != "system"`, or `sha256hex(messages[0].content) != system_prompt_hash`, or `model != program.model_id` → status Rejected (reason `"system prompt tampered"` / `"model mismatch"`), and reserved goes back to balance
  - otherwise panic `"dispute invalid: prompt matches"`.
- `finalize(claim_id)`: anyone, Pending, `now >= finalize_after` → Paid, reserved -= payout, `Promise::transfer(hunter, payout)`.
- Views: `get_program(id)`, `list_programs(from_index: Option<u64>, limit: Option<u64>)`, `get_claim(id)`, `list_claims(program_id, from_index, limit)`, `get_owner()`.
- Events: `env::log_str` in NEP-297 JSON (`EVENT_JSON:{"standard":"sealedbounty","version":"1.0.0","event":"claim_submitted",...}`).

## Testnet
- Admin/owner account `baldingsucks7993.testnet`. Escrow contract: `escrow.baldingsucks7993.testnet` (fresh state). The `sealedbounty.*` account keeps the Phase 0 spike.
- Allowlisted signers (attested 9 Nov):
  - `ed25519:89154a43a47684742c3d1753252bb6f49f61da9d8c84fc9b1def2df130cb2d93`
  - `eth:0x835ab53d20294ef795906dff21ae4c045336aa26`

---
# v2 (10 Nov 2026): binds the judged CODE and the HUNTER (supersedes v1 where they conflict)

Fresh-clone judge finding: in v1 the hunter supplied the code excerpt, so they could invent vulnerable code and get paid. v1 also allowed front-running (anyone could copy pending submit_claim args).

## Code bundle (owner publishes it; the hunter must use it byte-for-byte)
- `buildCodeBundle(files: {path, content}[])`: sort by path (byte order), each entry = `// file: <path>\n<content>`, ensure content ends with `\n` (append one if missing), concatenate with no separator.
- `program.code_hash` = sha256hex(utf8(bundle)).
- Demo bundle = `[{path:"src/server.ts", content: fixtures/vuln-app/src/server.ts}]`. Write it to `fixtures/vuln-app/bundle.txt`, with its hash in `fixtures/vuln-app/bundle.sha256` (no trailing newline).
- Demo `repo_url` = `https://github.com/sealedbounty/sealedbounty/tree/main/fixtures/vuln-app` (placeholder org; the README says the code lives in fixtures/vuln-app). Commit stays `demo-commit-0001`.

## Canonical judge request v2 (`buildRequestBody({model, repoUrl, commit, hunter, codeBundle, report})`)
```
messages = [
  {"role":"system","content": SYSTEM_PROMPT},
  {"role":"user","content": "TARGET <repo_url>@<commit>\nHUNTER <hunter_account_id>\n\nCODE\n<codeBundle>"},
  {"role":"user","content": "REPORT\n<report>"}
]
```
Everything else is unchanged (json_schema, `chat_template_kwargs.enable_thinking=false`, temperature 0, max_tokens 400). The system prompt may be updated to explain the two user messages (the CODE is trusted scope, the REPORT is untrusted). If it changes, its hash changes, so update `shared/system-prompt.sha256`.

## Contract v2 changes
- `Program` gains `code_hash: String` (64 lowercase hex). `create_program(..., code_hash, ...)` is a new required arg, placed after `system_prompt_hash`.
- `dispute(claim_id, request_body)`: after the existing sha256 == req_hash check, Reject with the FIRST failing reason, in this order:
  1. `"system prompt tampered"`: messages[0] is not system, or its hash ≠ system_prompt_hash
  2. `"model mismatch"`
  3. `"code mismatch"`: messages[1] is not role user, OR its content doesn't start with the exact prefix `format!("TARGET {}@{}\nHUNTER {}\n\nCODE\n", program.repo_url, program.commit, claim.hunter)`, OR sha256hex(rest after the prefix) ≠ program.code_hash. To tell hunter mismatch apart, check the TARGET line first, then the HUNTER line; if only the HUNTER line differs → reason 4.
  4. `"hunter mismatch"`: the HUNTER line ≠ claim.hunter (front-running). Special: on this reason ALSO remove req_hash from `used_req_hashes`, so the real hunter can resubmit.
  5. `"report missing"`: messages[2] is missing, not role user, or doesn't start with `"REPORT\n"`. (Any extra messages beyond index 2 → `"system prompt tampered"`.)
  - All checks pass → panic `"dispute invalid: request matches program"`. NOTE: the panic string changes from v1's "prompt matches".
- Everything else is the same as v1. Deploy target: **`sealedbounty-v2.testnet`** (fresh state, admin `baldingsucks7993.testnet`). v1 `escrow.baldingsucks7993.testnet` stays as history.

- v2 demo hashes: system_prompt_hash `aede4ebac53d6bae5f3ceefc8d60175faff90276ac7751fb26aebff39e5172c2`, code_hash `82faf3a0cd6148f95ba3b8011f8e9af67d5f9d5b8f8638002be7787a37285abd`. Fixtures `fixtures/demo.{sqli,sqli.ecdsa,idor,bogus,injection,fakecode}.json` (spec v2). Helpers: `shared/judge.mjs` checkRequestAgainstProgram, buildCodeBundle, codeHash, codeMessagePrefix; `shared/demo-data.mjs`.
