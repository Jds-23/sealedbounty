# demo-helper

The local-only backend for the guided demo's "Do it live" lane (`docs/demo-app-spec.md` §4, §5 steps 4/6/7,
§8). It runs a fresh NEAR AI TEE judgement and drives the program-2 testnet writes, so the browser never holds a
NEAR AI key or a NEAR private key.

```sh
pnpm --dir demo-helper start      # http://127.0.0.1:8787 (loopback only)
pnpm --dir demo-helper test       # node --test, no network, no install needed
```

There are no dependencies. Node >= 23. The writes need `cli/node_modules` (`make setup`), and `/judge` needs
`shared/node_modules`.

## What it reuses

- **Signing and sending**: every write is one existing CLI command, run as
  `pnpm -s --dir cli sb --contract <ESCROW_CONTRACT_ID> <command> … --account <id>`. The helper only builds the
  argv and parses the printed `tx: https://testnet.nearblocks.io/txns/<hash>` and `claim_id: <n>` lines. It then
  reads the claim back over RPC to confirm the new status. There is no signing code in this package.
  - `submit --program <id> --fixture <tmp judgement.json> --account <hunter|frontrun>`. The CLI re-verifies the
    signature, runs the program pre-checks, encrypts the report to `owner_enc_pubkey`, saves the hunter's
    ephemeral secret to `~/.sealedbounty/hunter-<contract>-<claim>.json` and sends `submit_claim` with
    storage + bond. The temp file is chmod 600 and deleted afterwards.
  - `flag-undecryptable --claim <n> --account <owner> --force`. The `--force` is needed because the honest
    ciphertext really does decrypt, so the CLI's own "really undecryptable" pre-check fails on purpose. The demo
    shows an owner stalling and the hunter proving them wrong.
  - `prove-ciphertext --claim <n> --account <hunter>` (reads the saved ephemeral secret).
  - `dispute --claim <n> --account <owner>` (loads `~/.sealedbounty/owner-<contract>-<id>.json`).
  - `finalize --claim <n> --account <hunter>`.
- **Keys**: `~/.near-credentials/testnet/<account>.json` through `cli/src/near.ts` `loadAccount`, for
  `hunter.baldingsucks7993.testnet`, `frontrun.baldingsucks7993.testnet` and the program owner (read from the
  chain: `program.owner`).
- **Judging**: `judge()` from `shared/judge.mjs`, against `fixtures/vuln-app/bundle.txt` (checked against the
  program's `code_hash`), with the program's `repo_url` / `commit` / `model_id` read from the chain, and
  `HUNTER = hunter.baldingsucks7993.testnet`.

## Config

The helper reads the repo-root `.env` in-process; it does not copy it into `process.env`. Variables already set in
the shell win.

| Var | Use |
|---|---|
| `DEMO_LIVE_PROGRAM_ID` | the program-2 id (below). Without it `/health` answers `ok:false` and the writes answer 503 |
| `ESCROW_CONTRACT_ID` | default `sealedbounty-v3.testnet` |
| `NEARAI_API_KEY`, `NEARAI_BASE_URL`, `NEARAI_SIGNING_ALGO` | for `/judge` only. The model comes from `program.model_id` |
| `NEAR_RPC_URL` | default `https://test.rpc.fastnear.com` |
| `DEMO_HUNTER_ACCOUNT`, `DEMO_FRONTRUN_ACCOUNT`, `DEMO_HELPER_PORT` | optional overrides |

**Secrets.** Every JSON response, SSE event and log line goes through a redactor that removes the NEAR AI key,
every secret-looking `.env` value, NEAR private keys (`ed25519:<base58 secret>`), `Bearer …` tokens and
`private_key` / `secret_key` / `ephemeral_secret` JSON fields. Child `sb` processes get `NEARAI_API_KEY=''`,
because none of the commands the helper runs need it.

## API

CORS allows only `http://localhost:5173`. Any other `Origin` gets 403 and nothing runs. Requests with no
`Origin` (curl) are allowed. The helper serves one request at a time: a second `/judge`, `/loop` or
`/frontrun` while one runs gets **409** `{error: "busy: loop is running; …"}`. `/health` always answers.

| Endpoint | Request | Response |
|---|---|---|
| `GET /health` | | `{ok:true, programId, contractId}` or `{ok:false, reason, contractId}` |
| `POST /judge` | `{exploitMarkdown}` (≤ 64 KiB) | `{verdict, signature, chat_id, request_body, response_body_b64, req_hash, signer, kind, resp_hash, model, signer_in_attestation}` |
| `POST /loop` | `{judgement}` (a `/judge` response) | SSE |
| `POST /frontrun[?resubmit=1]` | `{judgement?}` (or an empty body) | SSE |

Errors are JSON `{error}`: 400 for a bad body or judgement, 403 for an origin, 404, 405, 409 when busy, 413 for a body
over 1 MiB, 502 when the judge failed, and 503 when there is no live program. A judgement must be attested: either
this helper process judged it, or it carries `signer_in_attestation: true`.

**SSE.** Each frame is one `data: <json>\n\n` line. A `: ping` comment is sent every 15 s. Events:

```
{step, status: 'pending'|'done'|'error', tx?, claimId?, message?, remaining?}
...
{step: 'end', outcome, claimId?, message?}
```

`tx` is the bare tx hash; the link is `https://testnet.nearblocks.io/txns/<tx>`. A failed step emits
`status:'error'` (with `tx` when the transaction landed but failed or left the wrong status), followed by
`{step:'end', outcome:'error'}`.

- `/loop` steps: `submit_claim` (hunter) → `flag_undecryptable` (owner) → `prove_ciphertext` (hunter) → `wait`
  (one `pending` event per second with `remaining` seconds until `finalize_after` plus 2 s, then `done`) →
  `finalize` (hunter). Then `end` with `outcome: 'Paid'`, or `'Rejected: <reason>'` if the chain says so.
  A successful `prove_ciphertext` sets `finalize_after = now` onchain, so the countdown after it is just the
  2 s margin. The flag must land inside the 45 s dispute window, which it does: each CLI call takes about 5 s.
- `/frontrun` steps: `judge` (only when no judgement is given; a fresh judgement of `fixtures/exploits/sqli.md`
  bound to the real hunter) → `submit_claim` (from `frontrun.baldingsucks7993.testnet`) → `dispute` (owner reveals
  the body; must end Rejected `hunter mismatch`) → `resubmit` (with `?resubmit=1` or `{resubmit:true}`: the real
  hunter submits the same judgement, because the req_hash was released). Then `end` with
  `outcome: 'Rejected: hunter mismatch'`. The resubmitted claim stays Pending and pays out to the hunter once
  anyone runs `sb finalize --claim <id>` after 45 s.

If the browser disconnects mid-stream, the helper still runs the flow to a settled state and then frees the lock.

## Program 2 setup (one time, the user runs it: it spends testnet NEAR)

Program 2 uses the same `repo_url`, `commit`, code bundle and judge params as program 1, so fresh judgements bind to
it. It has the same payouts and bond, short windows (dispute 45 s, challenge 30 s) and a 0.5 NEAR pool. Run this from
the repo root as the owner account. Run it with `--dry-run` first:

```sh
pnpm --dir cli sb --contract sealedbounty-v3.testnet create-program --name "vuln-app live demo" \
  --repo https://github.com/sealedbounty/sealedbounty/tree/main/fixtures/vuln-app --commit demo-commit-0001 \
  --code ../fixtures/vuln-app/bundle.txt \
  --payout-low 0.05 --payout-medium 0.1 --payout-high 0.2 --payout-critical 0.3 --fund 0.5 \
  --dispute-secs 45 --min-confidence 80 --bond 0.05 --challenge-secs 30 \
  --account baldingsucks7993.testnet
```

`--code` is relative to `cli/`, because `pnpm --dir cli` runs there. The command attaches 0.55 NEAR (fund + the
0.05 storage allowance) and saves the owner key to `~/.sealedbounty/owner-sealedbounty-v3.testnet-<id>.json`. Then
add `DEMO_LIVE_PROGRAM_ID=<id>` to `.env`.

Each honest loop reserves the payout (0.3 for a critical) plus the hunter's 0.05 bond and pays it out. Each
front-run forfeits the front-runner's bond to the pool. Top the pool up when it runs low.

## Live smoke test

1. `make setup` (or `pnpm install` in `cli/` and `shared/`). Check `~/.near-credentials/testnet/` has
   `hunter.`, `frontrun.` and `baldingsucks7993.testnet` with some testnet NEAR each (each submit attaches the
   bond + ~0.03 storage).
2. Create program 2 (above), then set `DEMO_LIVE_PROGRAM_ID` in `.env`.
3. `pnpm --dir demo-helper start`, then `curl -s localhost:8787/health`.
4. Judge (spends one NEAR AI call):
   `curl -s localhost:8787/judge -H 'content-type: application/json' -d "$(jq -Rs '{exploitMarkdown: .}' fixtures/exploits/sqli.md)" > /tmp/j.json`
5. Loop: `curl -N localhost:8787/loop -H 'content-type: application/json' -d "$(jq '{judgement: .}' /tmp/j.json)"`.
   It should end `{"step":"end","outcome":"Paid",…}`.
6. Front-run: `curl -N -X POST 'localhost:8787/frontrun?resubmit=1'` (judges fresh; or pass `{judgement}` from a
   new `/judge`, not the one already paid). It should end `"outcome":"Rejected: hunter mismatch"`.
7. Open each `tx` on `https://testnet.nearblocks.io/txns/<tx>`, then run the tour with
   `#/tour/1?autoplay=1&live=1`.
