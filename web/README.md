# SealedBounty web

A read-only UI for the SealedBounty escrow contract. Vite + React + TypeScript. It has no backend and no wallet: all writes go through the CLI. The browser only does NEAR RPC `call_function` views, re-verifies signatures, and decrypts owner reports locally.

![screenshot](./screenshot.png)

## Run

```bash
pnpm install
pnpm dev            # http://localhost:5173
pnpm test           # vitest: signature verify + decrypt helpers
pnpm build          # tsc + vite build -> dist/ (static, base './', hash routing)
pnpm sync-fixtures  # re-copy ../fixtures into src/fixtures (run after fixtures change)
```

Config (`.env.local`, optional):

| var | default |
|---|---|
| `VITE_ESCROW_CONTRACT_ID` | `escrow.baldingsucks7993.testnet` |
| `VITE_NEAR_RPC` | `https://rpc.testnet.near.org` |

The web app never reads `NEARAI_API_KEY`, and it never calls NEAR AI.

## Pages

- **Programs** (`#/`): name, repo@commit, pool balance/reserved, payout table, model, open/closed.
- **Program detail** (`#/program/:id`): the claims timeline. Pending claims show a live dispute countdown, Rejected claims show their reason, and Paid claims show the payout. Each claim has a **Verified** panel:
  - ✓ (checked in the browser): the signed model equals the program model; the ed25519 (tweetnacl) or secp256k1 EIP-191 (ethers) signature over `model:req_hash:resp_hash`; the signer is in the contract's `get_signers` with a matching kind; the TDX quote `report_data` = signer ‖ nonce (parsed from the bundled quote); and, in demo mode only, that the response body hashes to `resp_hash` and contains the verdict.
  - ◷ (checked offline): the Intel DCAP and NVIDIA NRAS verdicts from the `attest` tool, labelled with the attestation date. The certificate chains are not re-run in the browser.
  - – (not checkable client-side): the verdict↔body link in live mode (the contract keeps only `resp_hash`), and the report contents (encrypted to the owner).
  - A "tamper 1 byte of resp_hash" toggle (in dev or demo) shows the panel turning red.
- **Owner inbox** (`#/inbox`): paste or upload `~/.sealedbounty/owner-<id>.json` (or a bare base64 secret). The page derives the public key, matches it to programs by `owner_enc_pubkey`, decrypts each claim's ciphertext with tweetnacl box, and checks `sha256(plaintext) == req_hash`, the system-prompt hash and the model. The secret stays in React state and is never stored or sent anywhere.
- **How it works** (`#/how`): a diagram and the honest limits.

## Demo mode

Demo mode turns on automatically when RPC fails or the contract has no programs. You can also force it with the auto/live/demo selector. It shows a mock program `vuln-app (demo)` with four claims built from the **real** recorded TEE outputs in `fixtures/demo.*.json`:

| claim | fixture | signer | status |
|---|---|---|---|
| #0 | `sqli.ecdsa` (critical, CWE-89) | eth | Pending |
| #1 | `idor` (high, CWE-639) | ed25519 | Paid |
| #2 | `bogus` (valid:false) | ed25519 | Rejected* |
| #3 | `injection` (valid:false) | ed25519 | Rejected* |

\* The real contract reverts `submit_claim` for non-payable verdicts, so these would never be stored onchain. The UI says so. Their signatures are still real and verify.

The demo owner key in `src/fixtures/demo.json` is derived from a public seed, so it is not a secret. In demo mode, use "Load demo owner key" in the inbox.

## Code map

- `src/lib/verify.ts`: Signer parsing, signature verification, the quote `report_data` binding check. It wraps `@sealedbounty/shared` (`../shared/judge.mjs`: `verifySig`, `sha256hex`, `parseVerdict`, `signerId`).
- `src/lib/crypto.ts`: owner decryption (shared `decryptAsOwner`) and owner-file parsing.
- `src/lib/checks.ts`: builds the per-claim checklist.
- `src/lib/near.ts`: JSON-RPC views (`list_programs`, `list_claims`, `get_signers`).
- `src/lib/demo.ts`: the demo dataset.
- `scripts/sync-fixtures.mjs`: trims `../fixtures/attestation.*.json` (300 KB each) down to a summary plus the model quote, and builds the demo ciphertexts.
