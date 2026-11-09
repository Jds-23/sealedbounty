# SealedBounty guided demo app ("the tour") — spec

Status: agreed with the user on 2026-11-09 through a grill-me session. A builder agent implements this. Deadline 14 Nov 2026 23:59 UTC.

## 1. Goal & audience

- **Audience:** both of these, served by one build.
  1. Hackathon judges (AI judges first, then humans from NEAR, a16z crypto, Electric Capital, Dragonfly) clicking through on their own, **keyless**.
  2. The 2-minute demo video, recorded from an autoplay mode.
- **Format:** a presentation-style flow that runs the real demo. It is an onboarding-style tour where each step explains one claim and proves it live.
- **One takeaway:** *"Trust is enforced onchain."* An attested TEE judges the exploit, and the NEAR contract verifies that signature itself and pays out. There is no human middleman, and every cheat the viewer saw was rejected by code.

## 2. Success criteria (done = both pass)

1. **Keyless 2-min click-through.** Use a fresh browser with no wallet and no helper. Steps 1–8 complete in ≤2 min. Along the way:
   - The TEE signature for claim #0 is re-verified in the browser and by the contract's `verify_tee_response` view.
   - Claim #0's report is decrypted and PAID is shown with tx links.
   - All 4 rejections (#1–#4) are recomputed locally, and the computed reasons match the onchain `reject_reason`.
   - The LIVE badge is on when RPC is reachable.
2. **Live recording run.** Run `pnpm --dir demo-helper start` and open `#/tour/1?autoplay=1&live=1`. The run must show:
   - A fresh TEE judgement through the helper
   - The program-2 honest loop reaching **Paid**
   - A front-run rejected with `hunter mismatch`
   - A real nearblocks tx link for every write

## 3. Phases & timebox (≈2 days of builder time; if time runs out, cut from the end)

| Phase | Priority | Content |
|---|---|---|
| P1 (day 1) | must | 8-step keyless tour, v3 snapshot script + fallback, RPC tx-args reader, free navigation, `?autoplay=1` |
| P2 (day 2) | must | `demo-helper/` local Node server, program 2 setup, live lane in steps 4/6/7, `&live=1` autoplay |
| P3 (½ day) | nice | Wallet Selector (Meteor + MyNearWallet, testnet): hosted tamper + replay writes in steps 5 and 7 |

## 4. Liveness model

Each step's data or action has a source:
- **a** = recorded TEE judgement re-verified live in the browser
- **b** = live testnet read
- **c** = real write
- **d** = live NEAR AI TEE call

Rules:
- **Default path = a + b only.** It always works keyless, with no secrets in the browser.
- **"Do it live" lane** is a per-step button on steps 4–7:
  - **d, plus the c writes signed by the helper:** only through the local `demo-helper` on `localhost:8787`. The UI shows these buttons only when `GET http://localhost:8787/health` answers within 1 s. The hosted/static build never has a NEAR AI key.
  - **c via wallet (P3):** Wallet Selector, available in any build. It is limited to the 2 writes that are rejected instantly onchain (see steps 5 and 7). These writes never reserve pool funds and never need owner action, and a panic refunds the attached deposit.
- When a live call fails, the lane shows the error inline in red monospace and keeps the recorded result visible. The tour never blocks.

## 5. Step-by-step flow

All steps use the split-slide layout (§7). Facts below come from the v3 contract `sealedbounty-v3.testnet`, **program 1** "vuln-app demo (v3)", unless noted. Tx hashes come from the README "Live on testnet (v3)" table. At runtime the builder reads them from RPC/snapshot and must not hard-code them in copy.

### Step 1 — Problem
- **Headline:** "Bug bounties run on trust."
- **Body:** "Hunters must reveal an exploit before they're paid. Owners drown in spam. And an 'AI judge' on someone's server can be faked."
- **Why it matters:** "No one should have to trust the other side."
- **Proof pane:** an animated 3-panel graphic (reveal-before-pay, spam inbox, fake AI verdict), static SVG + CSS.
- **Actions:** none.
- **Source:** none.

### Step 2 — Idea
- **Headline:** "An attested AI judges. The contract checks."
- **Body:** "The exploit goes to an AI model running inside verified hardware. The hardware signs the verdict. A NEAR contract checks that signature itself and pays from escrow."
- **Why it matters:** "The payout depends on math, not on a server."
- **Proof pane:** a flow diagram, hunter → TEE (Intel TDX + NVIDIA GPU, `Qwen/Qwen3.8-27B`) → contract → owner.
  - Hovering or clicking a node shows one line about it.
  - A pulse travels the arrows once on entry.
  - Inline SVG.
- **Actions:** hover/click nodes.
- **Source:** none.

### Step 3 — Live program
- **Headline:** "A real bounty, live on testnet."
- **Body:** "Program 1 escrows real testnet NEAR. Payouts are fixed by severity. Hunters post a bond, and the owner has a window to dispute."
- **Why it matters:** "The rules are fixed before anyone submits."
- **Proof pane:** a 'Load live' button runs `getProgram(1)` + `getSigners()` + `getRevoked()` (`web/src/lib/near.ts`). It shows:
  - Pool balance and reserved amount
  - Payouts table (low 0.05 / med 0.1 / high 0.2 / crit 0.3)
  - Bond 0.05, dispute 180 s, challenge 150 s, min_confidence 80
  - `code_hash`, `params_hash`, `system_prompt_hash` (truncated, copyable)
  - The program signer set (2 attested NEAR AI keys)
  - A nearblocks link for the contract
- **Source:** b (snapshot fallback).

### Step 4 — Hunter submits
- **Headline:** "The exploit stays sealed."
- **Body:** "The hunter's report is encrypted so only the program owner can read it. The AI judges it inside the enclave and returns a signed verdict."
- **Why it matters:** "The hunter never has to reveal first."
- **Proof pane:**
  - An 'Encrypt report' button encrypts `fixtures/exploits/sqli.md` with `encryptReport` (`web/src/lib/crypto.ts`) to program 1's `owner_enc_pubkey`. It shows the plaintext → ciphertext (base64) side by side.
  - Claim #0's onchain verdict (valid, severity, cwe, confidence), `req_hash`, `resp_hash`, signer and signature. These are read from the claim plus its `submit_claim` tx args (`resp_body`).
- **Live lane (P2, helper):**
  - A preset picker over `fixtures/exploits/{sqli,idor,bogus,injection}.md`, loaded into an editable textarea.
  - 'Judge live in TEE' calls `POST /judge` on the helper, which runs `judge()` from `shared/judge.mjs` against the `fixtures/vuln-app` bundle with HUNTER = `hunter.baldingsucks7993.testnet` and the program-2 parameters.
  - It shows the returned verdict, signature and chat_id, and keeps the result in tour state for steps 5–6.
- **Source:** a + b; live: d.

### Step 5 — Contract verifies
- **Headline:** "The contract checks the TEE itself."
- **Body:** "No server decides. The contract checks the enclave's signature and that the signer belongs to this program. You can run the same check right here."
- **Why it matters:** "Change one byte and the payout is refused."
- **Proof pane:**
  - **'Verify in browser'** reuses `VerifyPanel` / `verifyClaim` (`web/src/components/VerifyPanel.tsx`, `web/src/lib/checks.ts`). Checks tick in sequence:
    - Signature (ed25519/ecdsa via `verifySignature`)
    - In the program signer set
    - Not revoked
    - TDX quote binds the signing key (`quoteBindsSigner`)
    - Attestation summary
  - **'Ask the contract'** calls the RPC view `verify_tee_response` (`contracts/sealed-bounty/src/lib.rs:1103`; the builder reads its exact args) with claim #0's data and shows the contract's own answer.
  - **'Flip 1 byte'** is a toggle that flips one byte of `resp_body`. Both checks re-run and go red. This reuses the existing tamper logic.
- **Wallet lane (P3):** 'Submit tampered claim from your wallet' sends `submit_claim` to program 1 with claim #0's args and 1 flipped `resp_body` byte, attaching 0.06 NEAR. Expected panic: `bad signature`. Show the panic text, the tx link and "deposit refunded".
- **Source:** a + b; wallet: c.

### Step 6 — Owner decrypts → challenge → paid
- **Headline:** "Proven, then paid by the contract."
- **Body:** "The owner can claim the report is unreadable. The hunter then reveals the encryption key onchain, and the contract decrypts it itself. Once the window closes, anyone can trigger the payout."
- **Why it matters:** "Neither side can stall or cheat the other."
- **Proof pane:**
  - **'Decrypt'** reads the hunter's revealed ephemeral secret from claim #0's `prove_ciphertext` tx args. It runs `proveCiphertext` (`web/src/lib/crypto.ts`) to decrypt the onchain ciphertext and shows the plaintext report plus `reportMatchesHash` ✓. This is keyless and needs no demo owner key.
  - The 6 dispute checks (`auditRequest`, `web/src/lib/requestChecks.ts`) on claim #0's request body, all ✓.
  - A timeline with tx links: submitted → flagged undecryptable → proven → finalized → **Paid 0.3 + 0.05 bond**. Data comes from the claim plus `findPaidTxs` (`near.ts`).
- **Live lane (P2, helper, program 2):** 'Run the full loop live' uses the step-4 live judgement and calls the helper in sequence:
  1. `submit_claim` (hunter)
  2. `flag_undecryptable` (owner)
  3. `prove_ciphertext` (hunter)
  4. Wait for the dispute window (45 s), then `finalize`

  It shows each tx link as it lands and live countdowns (`countdown()` in `format.ts`). It ends on **Paid**.
- **Source:** a + b; live: c (helper-signed) + d.

### Step 7 — The gauntlet: four cheats, four rejections
- **Headline:** "We tried to cheat. Code said no."
- **Body:** "Four real attacks against the live contract. Each was rejected onchain, and you can recompute every reason yourself."
- **Why it matters:** "The rules are enforced by code, not by anyone's goodwill."
- **Proof pane:** 4 cards. Each card has a 'Run check' button that recomputes the reason locally from the claim plus its `dispute` tx args (`request_body`) using `auditRequest` / `shared/judge.mjs` helpers. It shows "computed: X ✓ matches onchain `reject_reason`: X" with a tx link.
  - **#1 Params tampered.** "The real TEE called a fake report valid/critical once the schema was forced." Recompute `requestParamsHash(body)` ≠ program `params_hash`. Uses `fixtures/attack.params-tampered.json`.
  - **#2 Code mismatch.** "An invented eval() RCE against code that doesn't exist." Recompute the CODE-section hash ≠ `code_hash`.
  - **#3 Front-run.** "Someone copied an honest hunter's signed verdict." The HUNTER line in the body is `hunter.baldingsucks7993.testnet` ≠ claim.hunter `frontrun.baldingsucks7993.testnet`. Note: the req_hash is released so the real hunter can resubmit.
  - **#4 Undecryptable.** "Junk ciphertext, and the hunter never proved it." The challenge deadline passed with no `prove_ciphertext`. Show the deadline vs now and the bond forfeited.
- **Wallet lane (P3):** 'Replay claim #0 from your wallet' sends `submit_claim` with claim #0's exact args. Expected panic: `already claimed`. Show the tx link and "deposit refunded".
- **Live lane (P2, helper, program 2):** 'Front-run live':
  1. The helper takes a fresh hunter-bound judgement.
  2. It submits that judgement from `frontrun.baldingsucks7993.testnet`.
  3. It runs `dispute` as the owner with the request body, which is rejected with `hunter mismatch`.
  4. Optionally, the real hunter resubmits.

  It shows the tx links.
- **Source:** a + b; wallet/live: c (+ d).

### Step 8 — Recap
- **Headline:** "You just verified it yourself."
- **Body:** "Everything you saw was checked in your browser against live testnet: signatures, attestation, decryption, payout and four rejections."
- **Why it matters:** "Private bounties that pay out without trusting anyone."
- **Proof pane:**
  - A scorecard of the checks the viewer actually ran this session (✓, or "not run" with a jump-back link)
  - Links to the repo, the contract on nearblocks, the README testnet table, and the explorer (`#/programs`)
- **Source:** tour state.

## 6. Interactivity & pacing

- **Free navigation, no gating:** Next/Back buttons, ←/→ keys, a clickable 8-segment progress bar, and deep links `#/tour/1` … `#/tour/8`. `#/` redirects to `#/tour/1`.
- **Hero actions:** each one is idempotent and can be re-run. Results persist in tour state (React context) across steps for the session; there is no localStorage requirement.
- **`?autoplay=1`:** a scripted timeline that totals ~2:00 (≈15 s per step).
  - It fires each step's hero actions automatically, then advances.
  - Space toggles pause/resume. Esc exits autoplay. Any manual navigation pauses it.
  - The timeline is a single data table (step, delay, action) so it can be tuned.
- **`?autoplay=1&live=1`:** the same timeline, but it fires the helper actions (step 4 judge on preset `sqli`, step 6 full loop, step 7 front-run). It waits on each action's completion event instead of a fixed timer. Expected length is ~3 min because of TEE latency plus the 45 s + 30 s windows; the user trims it in editing.
- **Indicators:**
  - Top bar shows a `LIVE ●` / `SNAPSHOT <date>` data badge.
  - `● helper` appears when the helper is reachable.
  - A wallet connect button appears in P3.

## 7. Visual design

- **Layout:** split slide, 100vh.
  - Left 40%: narrative (headline, body, "why it matters").
  - Right 60%: proof pane (hex, checks, tx links, buttons).
  - Progress bar on top, Back/Next on the bottom.
  - Below 900 px width the columns stack vertically, narrative first. No horizontal scroll.
- **Style:** "dark forensic". The 3 adjectives are **precise, calm, verifiable**, with Linear-like restraint.
  - Dark by default, with a light toggle.
  - Reuse the existing `web/src/styles.css` tokens (`--ok`, `--bad`, `--accent`, `--mono`, …) and extend them; don't fork them.
  - Hashes and signatures use `--mono`, truncated with copy-on-click.
- **Motion:** subtle. 200 ms fades between steps, checks ticking in sequence (~120 ms stagger), a single pulse along the step-2 diagram. Everything respects `prefers-reduced-motion` (no animation).
- **Copy rules:** headline ≤8 words and phrased as a claim; body ≤40 words in plain English; "why it matters" ≤15 words. Jargon (TDX, ed25519, nacl box, req_hash) appears **only** in the proof pane. The drafts in §5 are the starting copy.

## 8. Architecture & location

- **Tour:** `web/src/tour/` inside the existing Vite + React + TS app.
  - `Tour.tsx` (shell, nav, progress, autoplay)
  - `steps/Step1…Step8.tsx`
  - `tourData.ts` (data layer)
  - `autoplay.ts` (timeline table)
  - `helper.ts` (helper client)
  - `wallet.ts` (P3)

  Routes go in `web/src/App.tsx`:
  - Add `/tour/:step`.
  - `/` redirects to `/tour/1`.
  - The existing Programs page moves to `/programs`; `/program/:id`, `/inbox` and `/how` stay. Update the nav and internal links.
- **Reuse:** `web/src/lib/{near,verify,checks,crypto,requestChecks,status,format,demo}.ts`, `VerifyPanel`, and `shared/judge.mjs`. Don't duplicate crypto.
- **New in `near.ts` / `tourData.ts`:** a tx-args reader. Given a claim id, it finds the claim's `submit_claim`, `dispute`, `flag_undecryptable`, `prove_ciphertext` and `finalize` txs and decodes their args. The tx hashes come from the nearblocks API (as `findPaidTxs` already does) plus RPC `tx` status for the args.
- **Snapshot script:** `web/scripts/record-tour-snapshot.mjs` writes `web/src/fixtures/tour-v3-snapshot.json`. The file holds:
  - Program 1 views, signers, revoked set
  - Claims #0–#4
  - Every tx hash + decoded args above
  - `recorded_at`

  Add a `pnpm --dir web record-tour-snapshot` script. Public onchain data only. The old v2 `live-views.json` is left as is.
- **`demo-helper/`:** a new local-only Node package (plain `node:http`, port 8787, CORS restricted to `http://localhost:5173`).
  - Reads repo-root `.env` (`NEARAI_API_KEY`, `NEARAI_*`, `ESCROW_CONTRACT_ID`, new `DEMO_LIVE_PROGRAM_ID`).
  - Signs with `~/.near-credentials` for `hunter.`, `frontrun.` and owner `baldingsucks7993.testnet`, and uses `~/.sealedbounty/*` secrets. All of this reuses `cli/src` code paths (import or shell out to `pnpm sb …`); no new signing code.
  - Endpoints:
    - `GET /health`
    - `POST /judge {exploitMarkdown}`
    - `POST /loop` (submit → flag → prove → finalize, streaming progress via SSE)
    - `POST /frontrun` (SSE)
  - Every response includes tx hashes. Keys and the API key never leave the helper.
- **Program 2 (one-time setup, run by the user):**
  - The README gains a `pnpm sb create-program` command for "vuln-app live demo". It uses the **same** `repo_url`, `commit`, code bundle and params as program 1, so fresh judgements bind, with dispute 45 s, challenge 30 s, bond 0.05 and fund ~0.5 NEAR.
  - Record its id in `.env` as `DEMO_LIVE_PROGRAM_ID`.
  - The builder writes the exact command; the user runs it (it spends testnet NEAR).
- **P3 wallet:** `@near-wallet-selector/core` + `modal-ui` + `meteor-wallet` + `my-near-wallet`, network testnet, contract `sealedbounty-v3.testnet`. Pin exact versions.
- **Build:** `pnpm --dir web build` must produce a fully static bundle (hash routes, no server needed for anything except the optional helper).

## 9. Data & robustness

- **Canonical source:** live testnet. The snapshot mirrors it.
- **Fetch order:** RPC (`RPC_URLS` in `near.ts`, FastNEAR first, then fallbacks) with a 4 s timeout per call. On any failure or timeout, silently use `tour-v3-snapshot.json` for that datum and flip the badge to `SNAPSHOT <recorded_at>`. Never show a blank pane.
- **Program 2 / live lane:** RPC only, no snapshot. On failure, show an inline error, keep the recorded program-1 result visible, and continue autoplay after 5 s.
- **Helper absent:** live buttons are hidden, not disabled. `&live=1` without the helper falls back to plain autoplay and shows a toast "helper not running — keyless mode".
- **Wallet errors (P3):** user rejection or a network error is shown inline. Panics are displayed as the expected result: `bad signature` and `already claimed` count as ✓.

## 10. Out of scope

- Hosting and deployment. It stays local for now; a later stage decides. The build must stay static-host compatible.
- A hosted backend or any NEAR AI key outside the local helper.
- Live (d) judging on any hosted build.
- Wallet writes other than the two instant-reject ones. No wallet submissions that leave Pending claims.
- Changes to the contract, CLI behaviour, or fixtures (except the new snapshot file).
- Playwright/E2E suites, the helper integration test, i18n, analytics.
- Committing, pushing, or making the repo public.

## 11. Acceptance tests (minimal)

**Automated (vitest, added to `make test-web`):** only the new pure logic.
- **tx-args decoding:** decode recorded `dispute` / `prove_ciphertext` / `submit_claim` args from the snapshot.
- **Gauntlet recompute:** for claims #1–#4, the computed reasons from snapshot data equal `params tampered`, `code mismatch`, `hunter mismatch` and `undecryptable report`. Claim #0 audits clean and decrypts to text whose hash matches.
- **Fallback selector:** an RPC failure or timeout returns snapshot data and the `SNAPSHOT` flag.

**Manual checklist (the user runs it; it is part of done):**
1. **Keyless:** follow §2.1 in a fresh browser at 1440×900 and 390×844.
2. **Offline:** after load, block RPC (devtools offline or a bad `VITE_` RPC URL). The tour still completes with the `SNAPSHOT` badge and no console errors.
3. **Live:** follow §2.2. Each write has a nearblocks link, and program 2 ends with Paid and one `hunter mismatch` rejection.
4. **(P3)** With Meteor or MyNearWallet on testnet, the tampered submit shows `bad signature`, the replay of #0 shows `already claimed`, and the deposit is refunded.

## 12. Open questions

None.
