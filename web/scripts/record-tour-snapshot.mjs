#!/usr/bin/env node
// Records the public onchain data the guided tour (#/tour) shows into src/fixtures/tour-v3-snapshot.json.
// Read-only: NEAR RPC `call_function` views + RPC `tx` status + the public nearblocks list API. No keys, no writes.
//
//   pnpm --dir web record-tour-snapshot
//   CONTRACT=sealedbounty-v3.testnet PROGRAM=1 CLAIMS=0,1,2,3,4 RPC=https://test.rpc.fastnear.com pnpm record-tour-snapshot
//
// The tour decodes the stored (trimmed) RPC tx results with the same code it uses on live RPC answers, so a
// snapshot entry is exactly what a live `tx` call returns, minus the receipt fields the tour never reads.
import { writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const CONTRACT = process.env.CONTRACT || 'sealedbounty-v3.testnet';
const PROGRAM = Number(process.env.PROGRAM || 1);
const CLAIMS = (process.env.CLAIMS || '0,1,2,3,4').split(',').map(Number);
const RPC = process.env.RPC || 'https://test.rpc.fastnear.com';
const NB = 'https://api-testnet.nearblocks.io/v3';
const METHODS = new Set(['submit_claim', 'dispute', 'flag_undecryptable', 'prove_ciphertext', 'finalize']);
const OUT = join(dirname(fileURLToPath(import.meta.url)), '..', 'src', 'fixtures', 'tour-v3-snapshot.json');

async function rpc(method, params) {
  for (let attempt = 0; ; attempt++) {
    try {
      const r = await fetch(RPC, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 'snap', method, params }),
        signal: AbortSignal.timeout(15000),
      });
      if (!r.ok) throw new Error(`RPC HTTP ${r.status}`);
      const j = await r.json();
      if (j.error) throw new Error(JSON.stringify(j.error).slice(0, 300));
      return j.result;
    } catch (e) {
      if (attempt >= 3) throw e;
      await new Promise((res) => setTimeout(res, 800 * (attempt + 1)));
    }
  }
}

async function view(method_name, args = {}) {
  const res = await rpc('query', {
    request_type: 'call_function',
    finality: 'final',
    account_id: CONTRACT,
    method_name,
    args_base64: Buffer.from(JSON.stringify(args)).toString('base64'),
  });
  if (res.error) throw new Error(`${method_name}: ${res.error}`);
  return JSON.parse(Buffer.from(res.result).toString('utf8'));
}

/** Keep only what the tour decodes: the actions (method + base64 args), the status and each receipt's logs/status. */
const trimTx = (t) => ({
  transaction: {
    hash: t.transaction.hash,
    signer_id: t.transaction.signer_id,
    receiver_id: t.transaction.receiver_id,
    actions: t.transaction.actions,
  },
  status: t.status,
  receipts_outcome: t.receipts_outcome.map((r) => ({
    id: r.id,
    outcome: { executor_id: r.outcome.executor_id, logs: r.outcome.logs, status: r.outcome.status },
  })),
});

const program = await view('get_program', { id: PROGRAM });
if (!program) throw new Error(`program ${PROGRAM} not found on ${CONTRACT}`);
const signers = await view('get_signers');
const claims = [];
for (const id of CLAIMS) {
  const c = await view('get_claim', { id });
  if (!c || c.program_id !== PROGRAM) throw new Error(`claim ${id} missing or not in program ${PROGRAM}`);
  claims.push(c);
}
const revoked = {};
for (const s of new Set([...(program.signers ?? []), ...claims.map((c) => c.signer)])) revoked[s] = await view('is_signer_revoked', { signer: s });

const list = await fetch(`${NB}/accounts/${CONTRACT}/txns?limit=100`, { signal: AbortSignal.timeout(20000) }).then((r) => r.json());
const rows = (list.data ?? [])
  .filter((t) => t.actions?.some((a) => METHODS.has(a.method)))
  .sort((a, b) => (BigInt(a.block_timestamp) < BigInt(b.block_timestamp) ? -1 : 1));
const firstSubmit = claims.reduce((m, c) => (BigInt(c.submitted_at) < m ? BigInt(c.submitted_at) : m), BigInt(claims[0].submitted_at));

const txs = [];
for (const row of rows) {
  // submitted_at is the receipt block; the tx lands a block or two earlier.
  if (BigInt(row.block_timestamp) < firstSubmit - 60_000_000_000n) continue;
  const raw = await rpc('tx', { tx_hash: row.transaction_hash, sender_account_id: row.signer_account_id, wait_until: 'FINAL' });
  // Only txs that touch the recorded claims: claim_id arg, a claim_submitted event, or a submit of a recorded req_hash.
  const fc = raw.transaction.actions.find((a) => a.FunctionCall)?.FunctionCall;
  let args = {};
  try {
    args = JSON.parse(Buffer.from(fc?.args ?? '', 'base64').toString('utf8'));
  } catch {
    /* non-JSON args */
  }
  const logs = raw.receipts_outcome.flatMap((r) => r.outcome.logs);
  const touches =
    CLAIMS.includes(args.claim_id) ||
    logs.some((l) => CLAIMS.some((id) => l.includes(`"claim_id":${id},`) && l.includes(`"program_id":${PROGRAM}`))) ||
    (fc?.method_name === 'submit_claim' && args.program_id === PROGRAM && claims.some((c) => c.req_hash === String(args.req_hash).toLowerCase()));
  if (!touches) continue;
  txs.push({ hash: row.transaction_hash, signer: row.signer_account_id, method: fc?.method_name, block_timestamp: row.block_timestamp, ok: row.outcomes?.status === true, raw: trimTx(raw) });
  process.stdout.write(`  ${fc?.method_name.padEnd(18)} ${row.transaction_hash} ${row.outcomes?.status ? 'ok' : 'FAILED'}\n`);
}

const snapshot = {
  _note: `Public onchain data of ${CONTRACT} program ${PROGRAM}, claims ${CLAIMS.join(',')}, recorded read-only by web/scripts/record-tour-snapshot.mjs (RPC ${RPC} + nearblocks). The tour's offline fallback.`,
  recorded_at: new Date().toISOString(),
  contract_id: CONTRACT,
  program_id: PROGRAM,
  views: { get_program: program, get_signers: signers, is_signer_revoked: revoked, claims },
  txs,
};
writeFileSync(OUT, JSON.stringify(snapshot, null, 1) + '\n');
console.log(`wrote ${OUT}: program ${PROGRAM}, ${claims.length} claims, ${txs.length} txs`);
