# Brief: requirements session for the SealedBounty guided demo app

You are a fresh Claude Code session in the SealedBounty repo (`/Users/devaf/woerk/near-hackathom`, GitHub `Jds-23/sealedbounty`, branch `main`). Your only job in this session is to **interview the user until the spec for a new guided demo webapp is unambiguous**. When it is, write it to `docs/demo-app-spec.md`. Don't build anything; a separate builder agent will.

## How to run the session
- Use the `grill-me` skill. Ask **one question at a time**. Give each question 2–4 concrete options, mark your recommended one, and say why in one line. Use AskUserQuestion when options fit; otherwise ask plainly.
- Walk the decision tree. Resolve each branch before moving on, and push back on vague answers ("make it nice" → which reference? which 3 adjectives?).
- Every ~5 questions, summarise what's decided so far in 3–6 bullets so the user can correct you.
- Read the repo whenever an answer depends on what exists. Don't ask the user things the code can answer.
- Finish by writing `docs/demo-app-spec.md`, showing a short summary, and asking the user to confirm. Don't commit, push, or start building.

## What the user asked for (verbatim intent)
"A webapp which follows a presentational style flow but gives the actual demo. Almost like an onboarding flow for an app, but while explaining things." Audience is likely the NEAR Hackathon judges (AI judges Claude Code/Codex first, then humans from NEAR, a16z crypto, Electric Capital, Dragonfly, etc.) and a 2-minute demo video. Confirm this.

## Project facts (so you don't re-derive them)
- **What it is:** a private bug-bounty escrow. A hunter's exploit goes to a NEAR AI Cloud TEE model (`Qwen/Qwen3.8-27B`, attested Intel TDX + NVIDIA GPU). The TEE signs `model:sha256(request):sha256(response)`. A Rust NEAR contract verifies the ed25519/ecdsa signature **onchain** and escrows the payout by severity. The report is encrypted to the owner (nacl box).
  - **v2 binding:** `code_hash` + a HUNTER line.
  - **v3:** `params_hash` pinning, a decryption challenge game (flag → hunter reveals the ephemeral key → contract decrypts), per-program signer sets, a hunter bond, a per-program dedupe key, and a payout callback.
- **Live testnet:** contract `sealedbounty-v3.testnet`, **program 1** "vuln-app demo (v3)" (pool ~1.44 NEAR, bond 0.05, dispute 180 s, challenge 150 s). Its claims:
  - #0 Paid (honest SQLi, challenged → proven → paid 0.3 + bond)
  - #1 Rejected `params tampered` (the real TEE signed valid/critical for a bogus report once the schema was forced: `fixtures/attack.params-tampered.json`)
  - #2 Rejected `code mismatch` (invented eval() RCE)
  - #3 Rejected `hunter mismatch` (front-run)
  - #4 Rejected `undecryptable report` (junk ciphertext, challenge expired)
  - The tx hashes are in the README "Live on testnet" table.
  - Accounts: owner/admin `baldingsucks7993.testnet`, hunter `hunter.baldingsucks7993.testnet`, front-runner `frontrun.baldingsucks7993.testnet`.
- **Existing web app (`web/`):** Vite + React + TS, read-only, no backend, hash routes.
  - Pages: programs list, program detail with an in-browser **Verified panel** (signature, program signer set, revocation, TDX quote binding, attestation summary), owner inbox (local decryption + 6 dispute checks), how-it-works, demo mode built from fixtures, and a tamper-1-byte toggle.
  - Libs in `web/src/lib/` (verify, crypto, checks, near RPC via FastNEAR, demo, requestChecks, paidTxs).
  - Screenshots: `web/screenshot.png` (demo), `web/screenshot-live.png` (live; slightly stale).
- **Shared helpers (`shared/judge.mjs`, browser-safe):** buildRequestBody, buildCodeBundle, codeHash, paramsHash, requestParamsHash, checkRequestAgainstProgram, verifySig, parseVerdict, encryptForOwner(WithSecret), decryptAsOwner, sha256hex, verifyFixture, judge (needs a NEAR AI API key; must NOT run in a public browser).
- **Fixtures (`fixtures/`):**
  - `demo.{sqli,sqli.ecdsa,idor,bogus,injection,fakecode}.json`: real TEE-signed judgements
  - `attack.params-tampered.json`
  - `attestation.{ed25519,ecdsa}.json`
  - `vuln-app/` (the target code + `bundle.txt`)
  - `exploits/*.md`
- **CLI (`cli/`):** does all writes (create-program, submit, inbox, dispute, flag-undecryptable, prove-ciphertext, finalize, attest, verify-claim).
- **Constraints:**
  - The deadline is 14 Nov 2026 23:59 UTC; today is ~9 Nov.
  - No secrets in the browser (no NEAR AI key; testnet keys stay in `~/.near-credentials`).
  - Judges run things keyless.
  - The repo is still private and will go public at submission.

## Decision tree to cover (adapt as answers come in)
1. **Audience and purpose:** judges self-serve vs. the video recording vs. both. What must a judge believe after 2 minutes?
2. **Story arc:** the problem (hunters reveal before pay, spam) → the idea → each step. Propose a concrete step list (e.g. 6–9 screens) and let the user reorder or cut it. Which attacks to show (all 4 v3 rejections + the honest payout?), and in what order? Where does attestation fit?
3. **"Actual demo" meaning per step:**
   - **(a) Recorded but re-verified live in the browser:** real signatures and real onchain reads. Keyless and safe.
   - **(b) Live reads of testnet state.**
   - **(c) Real writes:** a wallet (which one? NEAR Wallet Selector / HOT / Meteor / Intear) or a local helper. That means keys, funds and failure modes.
   - **(d) A live NEAR AI call:** needs a key, so it's server-side only, which means a backend.
   Pin down a, b, c or d for each step.
4. **Interactivity:** what the viewer clicks at each step (e.g. "tamper a byte", "decrypt as owner", "forge a front-run", "force the schema"). The pacing model: free navigation, step gating, auto-play mode for the video, keyboard arrows, a progress bar.
5. **Visual style:** presentation-like full-screen slides vs. app-like onboarding cards. References (Linear, Stripe, Vercel, Arc onboarding…). Light/dark, motion level, diagrams (animated flow of hunter → TEE → contract → owner?), copy tone, length per step.
6. **Where it lives:**
   - a new route in `web/` (e.g. `#/tour`, reusing the libs) vs. a separate `demo/` app
   - whether it's the landing page
   - hosting: static on Vercel/Pages/GitHub Pages, now or later; the repo goes public at submission
7. **Data source and robustness:** live v3 program 1 with the fixture fallback? What happens if RPC is down? Should the live claim data or the recorded fixtures be canonical for the story?
8. **Scope and time:** must-haves vs. nice-to-haves, and a timebox (e.g. ½–1 day of builder time). Tests expected (Playwright walkthrough?).
9. **Done criteria:** what the user will check (e.g. "a judge can click through in 2 min with no keys and see every attack rejected with live proof").

## Output: `docs/demo-app-spec.md`
Sections:
- Goal & audience
- Success criteria
- Step-by-step flow (for each step: title, what the viewer sees, what they can do, data source a/b/c/d, which existing module/fixture it uses, copy draft)
- Interactivity & pacing
- Visual design
- Architecture & location
- Data/robustness
- Out of scope
- Acceptance tests
- Open questions (should be empty)

Keep it concrete enough that a builder agent can execute without asking anything.
