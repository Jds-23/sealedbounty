import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';
import { makeCliDeps, parseSbOutput } from '../src/cli.mjs';
import { createHelperServer } from '../src/server.mjs';
import { FAKE_API_KEY, ORIGIN, fakeChain, http, jsonHeaders, judgementFor, listen, makeJudgement, parseSse } from './helpers.mjs';

const baseConfig = {
  programId: 2,
  contractId: 'sealedbounty-v3.testnet',
  apiKey: FAKE_API_KEY,
  hunter: 'hunter.baldingsucks7993.testnet',
  frontrun: 'frontrun.baldingsucks7993.testnet',
  marginMs: 0,
};
let open = [];
async function start(deps) {
  const logs = [];
  const s = await listen(createHelperServer({ config: baseConfig, deps, log: (...a) => logs.push(a.join(' ')) }));
  open.push(s);
  return { ...s, logs };
}
afterEach(async () => {
  await Promise.all(open.map((s) => s.close()));
  open = [];
});

/** Deterministic judge (like the TEE at temperature 0) + a chain that refuses a req_hash it has seen (used_req_hashes). */
function dedupingChain() {
  const deps = fakeChain();
  deps.judge = async ({ exploitMarkdown }) => {
    deps.calls.push(['judge', exploitMarkdown]);
    return judgementFor(exploitMarkdown);
  };
  const used = new Set();
  const submit = deps.submit;
  deps.submit = async (a) => {
    if (used.has(a.record.req_hash)) throw new Error('Smart contract panicked: already claimed');
    used.add(a.record.req_hash);
    return submit(a);
  };
  const dispute = deps.dispute;
  deps.dispute = async (a) => {
    const r = await dispute(a);
    const c = deps.calls.find((x) => x[0] === 'submit' && x[1] === 'frontrun.baldingsucks7993.testnet');
    used.delete(c[2]); // hunter mismatch releases the req_hash
    return r;
  };
  return deps;
}

describe('each live run is a new claim (identical requests are deduped per program onchain)', () => {
  it('two /judge calls for the same exploit send different report text and get different req_hash + runId', async () => {
    const deps = dedupingChain();
    const { base } = await start(deps);
    const one = JSON.parse((await http(base, { method: 'POST', path: '/judge', headers: jsonHeaders(), body: { exploitMarkdown: '# sqli' } })).text);
    const two = JSON.parse((await http(base, { method: 'POST', path: '/judge', headers: jsonHeaders(), body: { exploitMarkdown: '# sqli' } })).text);
    const [a, b] = deps.calls.filter((c) => c[0] === 'judge').map((c) => c[1]);
    assert.notEqual(a, b);
    for (const [sent, res] of [
      [a, one],
      [b, two],
    ]) {
      assert.ok(sent.startsWith('# sqli\n'), 'the original report comes first, unchanged');
      assert.match(sent, /\n\n---\nDemo run: \d{4}-\d\d-\d\dT[\d:.]+Z #[0-9a-f]{6}$/);
      assert.equal(typeof res.runId, 'string');
      assert.ok(sent.endsWith(res.runId), 'runId is the trailer id');
    }
    assert.notEqual(one.req_hash, two.req_hash);
    assert.notEqual(one.runId, two.runId);
  });

  it('/frontrun without a judgement uses a fresh, never-claimed request (after a /loop on the same exploit)', async () => {
    const deps = dedupingChain();
    const { base } = await start(deps);
    const j = JSON.parse((await http(base, { method: 'POST', path: '/judge', headers: jsonHeaders(), body: { exploitMarkdown: '# SQLi in /users' } })).text);
    assert.equal(parseSse((await http(base, { method: 'POST', path: '/loop', headers: jsonHeaders(), body: { judgement: j } })).text).at(-1).outcome, 'Paid');
    const events = parseSse((await http(base, { method: 'POST', path: '/frontrun?resubmit=1', headers: { origin: ORIGIN } })).text);
    assert.equal(events.at(-1).outcome, 'Rejected: hunter mismatch', JSON.stringify(events.filter((e) => e.status === 'error')));
    const submitted = deps.calls.filter((c) => c[0] === 'submit').map((c) => c[2]);
    assert.notEqual(submitted[1], submitted[0], 'frontrun submitted a different req_hash than the paid loop');
    assert.ok(events.find((e) => e.step === 'judge' && e.status === 'done').runId);
  });
});

describe('cli failures surface the failing pre-check rows', () => {
  it('parseSbOutput collects the FAIL rows (whitespace collapsed)', () => {
    const out = '  PASS  a  1\n  FAIL  payout <= pool balance   0.3 NEAR of 0.24 NEAR\n  FAIL  signer in program.signers  x\n  => 2 FAILED\nerror: pre-checks failed\n';
    assert.deepEqual(parseSbOutput(out).fails, ['payout <= pool balance 0.3 NEAR of 0.24 NEAR', 'signer in program.signers x']);
  });

  it('the SSE error message names the FAIL rows, still redacted', async () => {
    const out = `Local verification
  PASS  req_hash == sha256(request_body)  ab12
  FAIL  req_hash not already claimed       claim 5 (key ${FAKE_API_KEY})
  => 1 FAILED

Contract pre-checks (mirrors submit_claim)
  PASS  program open                       true
  FAIL  payout <= pool balance             0.3 NEAR of 0.24248 NEAR
  => 1 FAILED

error: pre-checks failed; not sending (use --force to send anyway)
`;
    const config = { repoRoot: '/repo', contractId: 'sealedbounty-v3.testnet', programId: 2 };
    const deps = { ...fakeChain(), ...makeCliDeps({ config, runSb: async () => ({ code: 1, stdout: out, stderr: '' }) }) };
    const { base, logs } = await start(deps);
    const r = await http(base, { method: 'POST', path: '/loop', headers: jsonHeaders(), body: { judgement: makeJudgement() } });
    const err = parseSse(r.text).find((e) => e.status === 'error');
    assert.equal(err.step, 'submit_claim');
    assert.match(err.message, /pre-checks failed/);
    assert.match(err.message, /FAIL req_hash not already claimed claim 5/);
    assert.match(err.message, /FAIL payout <= pool balance 0\.3 NEAR of 0\.24248 NEAR/);
    assert.ok(!err.message.includes('PASS'));
    assert.ok(!(r.text + logs.join('\n')).includes(FAKE_API_KEY));
  });
});
