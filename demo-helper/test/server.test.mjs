import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';
import { createHelperServer } from '../src/server.mjs';
import { FAKE_API_KEY, FAKE_PRIVATE_KEY, ORIGIN, fakeChain, http, jsonHeaders, listen, makeJudgement, parseSse } from './helpers.mjs';

const baseConfig = {
  programId: 2,
  contractId: 'sealedbounty-v3.testnet',
  apiKey: FAKE_API_KEY,
  hunter: 'hunter.baldingsucks7993.testnet',
  frontrun: 'frontrun.baldingsucks7993.testnet',
  marginMs: 0,
};

let open = [];
async function start({ config = {}, deps = fakeChain() } = {}) {
  const logs = [];
  const server = createHelperServer({ config: { ...baseConfig, ...config }, deps, log: (...a) => logs.push(a.join(' ')) });
  const s = await listen(server);
  open.push(s);
  return { ...s, deps, logs };
}
afterEach(async () => {
  await Promise.all(open.map((s) => s.close()));
  open = [];
});

describe('GET /health', () => {
  it('reports the live program id, with CORS for the tour origin', async () => {
    const { base } = await start();
    const r = await http(base, { path: '/health', headers: { origin: ORIGIN } });
    assert.equal(r.status, 200);
    assert.deepEqual(JSON.parse(r.text), { ok: true, programId: 2, contractId: 'sealedbounty-v3.testnet' });
    assert.equal(r.headers['access-control-allow-origin'], ORIGIN);
    assert.match(r.headers['content-type'], /application\/json/);
  });
  it('ok:false with a reason when DEMO_LIVE_PROGRAM_ID is missing', async () => {
    const { base } = await start({ config: { programId: null } });
    const j = JSON.parse((await http(base, { path: '/health' })).text);
    assert.equal(j.ok, false);
    assert.match(j.reason, /DEMO_LIVE_PROGRAM_ID/);
  });
});

describe('CORS', () => {
  it('preflight from the tour origin: 204 + allow POST/content-type', async () => {
    const { base } = await start();
    const r = await http(base, {
      method: 'OPTIONS',
      path: '/loop',
      headers: { origin: ORIGIN, 'access-control-request-method': 'POST', 'access-control-request-headers': 'content-type' },
    });
    assert.equal(r.status, 204);
    assert.equal(r.headers['access-control-allow-origin'], ORIGIN);
    assert.match(r.headers['access-control-allow-methods'], /POST/);
    assert.match(r.headers['access-control-allow-headers'], /content-type/i);
  });
  it('any other origin: 403, no CORS headers, nothing runs', async () => {
    const { base, deps } = await start();
    for (const [method, path] of [
      ['OPTIONS', '/judge'],
      ['GET', '/health'],
      ['POST', '/judge'],
      ['POST', '/frontrun'],
    ]) {
      const r = await http(base, { method, path, headers: { origin: 'https://evil.example', 'content-type': 'application/json' }, body: method === 'POST' ? { exploitMarkdown: 'x' } : undefined });
      assert.equal(r.status, 403, `${method} ${path}`);
      assert.equal(r.headers['access-control-allow-origin'], undefined);
    }
    assert.deepEqual(deps.calls, []);
  });
});

describe('routing + validation', () => {
  it('404 unknown path, 405 wrong method', async () => {
    const { base } = await start();
    assert.equal((await http(base, { path: '/nope' })).status, 404);
    assert.equal((await http(base, { path: '/judge' })).status, 405);
    assert.equal((await http(base, { method: 'POST', path: '/health', headers: jsonHeaders() })).status, 405);
  });
  it('400 on bad JSON or a bad body, 413 on an oversized body', async () => {
    const { base, deps } = await start();
    const bad = await http(base, { method: 'POST', path: '/judge', headers: jsonHeaders(), body: '{nope' });
    assert.equal(bad.status, 400);
    assert.match(JSON.parse(bad.text).error, /JSON/);
    assert.equal((await http(base, { method: 'POST', path: '/judge', headers: jsonHeaders(), body: { exploitMarkdown: '' } })).status, 400);
    assert.equal((await http(base, { method: 'POST', path: '/loop', headers: jsonHeaders(), body: {} })).status, 400);
    assert.equal((await http(base, { method: 'POST', path: '/loop', headers: jsonHeaders(), body: { judgement: makeJudgement({ req_hash: '00'.repeat(32) }) } })).status, 400);
    assert.equal((await http(base, { method: 'POST', path: '/frontrun', headers: jsonHeaders(), body: { judgement: 'x' } })).status, 400);
    assert.equal((await http(base, { method: 'POST', path: '/judge', headers: jsonHeaders(), body: { exploitMarkdown: 'a'.repeat(2 * 1024 * 1024) } })).status, 413);
    assert.deepEqual(deps.calls, []);
  });
  it('503 on the write endpoints when no live program is configured', async () => {
    const { base } = await start({ config: { programId: null } });
    for (const path of ['/judge', '/loop', '/frontrun'])
      assert.equal((await http(base, { method: 'POST', path, headers: jsonHeaders(), body: { exploitMarkdown: 'x', judgement: makeJudgement() } })).status, 503, path);
  });
  it('a judgement not attested (no flag, not judged by this helper) is refused', async () => {
    const { base } = await start();
    const j = makeJudgement();
    delete j.signer_in_attestation;
    const r = await http(base, { method: 'POST', path: '/loop', headers: jsonHeaders(), body: { judgement: j } });
    assert.equal(r.status, 400);
    assert.match(JSON.parse(r.text).error, /attest/);
  });
});

describe('POST /judge', () => {
  it('returns the judgement fields; the helper remembers it as attested', async () => {
    const { base, deps } = await start();
    const r = await http(base, { method: 'POST', path: '/judge', headers: jsonHeaders(), body: { exploitMarkdown: '# sqli' } });
    assert.equal(r.status, 200, r.text);
    const j = JSON.parse(r.text);
    for (const k of ['verdict', 'signature', 'chat_id', 'request_body', 'response_body_b64', 'req_hash', 'signer', 'kind']) assert.ok(k in j, k);
    assert.deepEqual(deps.calls, [['judge', '# sqli']]);
    delete j.signer_in_attestation;
    const loop = await http(base, { method: 'POST', path: '/loop', headers: jsonHeaders(), body: { judgement: j } });
    assert.equal(loop.status, 200, loop.text);
  });
});

describe('key redaction', () => {
  it('a judge error carrying the API key and a private key never leaks into the response or logs', async () => {
    const deps = fakeChain();
    deps.judge = async () => {
      throw new Error(`completion HTTP 401: bad key ${FAKE_API_KEY}; signer ${FAKE_PRIVATE_KEY}`);
    };
    const { base, logs } = await start({ deps });
    const r = await http(base, { method: 'POST', path: '/judge', headers: jsonHeaders(), body: { exploitMarkdown: '# x' } });
    assert.equal(r.status, 502);
    assert.match(JSON.parse(r.text).error, /HTTP 401/);
    const all = r.text + JSON.stringify(r.headers) + logs.join('\n');
    assert.ok(logs.length > 0, 'errors are logged');
    assert.ok(!all.includes(FAKE_API_KEY), 'api key leaked');
    assert.ok(!all.includes(FAKE_PRIVATE_KEY.slice(8)), 'private key leaked');
  });
  it('SSE error events are redacted too', async () => {
    const deps = fakeChain();
    deps.submit = async () => {
      throw new Error(`no credentials ${FAKE_PRIVATE_KEY} Bearer ${FAKE_API_KEY}`);
    };
    const { base, logs } = await start({ deps });
    const r = await http(base, { method: 'POST', path: '/loop', headers: jsonHeaders(), body: { judgement: makeJudgement() } });
    const events = parseSse(r.text);
    assert.deepEqual(events.map((e) => `${e.step}:${e.status ?? e.outcome}`), ['submit_claim:pending', 'submit_claim:error', 'end:error']);
    const all = r.text + logs.join('\n');
    assert.ok(!all.includes(FAKE_API_KEY));
    assert.ok(!all.includes(FAKE_PRIVATE_KEY.slice(8)));
  });
});

describe('SSE endpoints', () => {
  it('POST /loop streams text/event-stream frames ending in end:Paid', async () => {
    const { base } = await start();
    const r = await http(base, { method: 'POST', path: '/loop', headers: jsonHeaders(), body: { judgement: makeJudgement() } });
    assert.equal(r.status, 200);
    assert.match(r.headers['content-type'], /^text\/event-stream/);
    assert.equal(r.headers['cache-control'], 'no-cache');
    assert.equal(r.headers['access-control-allow-origin'], ORIGIN);
    const events = parseSse(r.text);
    assert.deepEqual(events.at(-1), { step: 'end', outcome: 'Paid', claimId: 7 });
    assert.deepEqual([...new Set(events.map((e) => e.step))], ['submit_claim', 'flag_undecryptable', 'prove_ciphertext', 'wait', 'finalize', 'end']);
  });
  it('POST /frontrun?resubmit=1 with no body judges fresh, is rejected hunter mismatch, then resubmits', async () => {
    const { base, deps } = await start();
    const r = await http(base, { method: 'POST', path: '/frontrun?resubmit=1', headers: { origin: ORIGIN } });
    const events = parseSse(r.text);
    assert.deepEqual([...new Set(events.map((e) => e.step))], ['judge', 'submit_claim', 'dispute', 'resubmit', 'end']);
    assert.equal(events.at(-1).outcome, 'Rejected: hunter mismatch');
    assert.deepEqual(deps.calls.map((c) => c[0]), ['judge', 'submit', 'dispute', 'submit']);
  });
});

describe('mutex', () => {
  it('one request at a time: concurrent writes get 409, /health still answers, lock frees after the stream ends', async () => {
    const deps = fakeChain();
    let unblock;
    const gate = new Promise((r) => (unblock = r));
    const submit = deps.submit;
    deps.submit = async (a) => {
      await gate;
      return submit(a);
    };
    const { base } = await start({ deps });
    const loop = http(base, { method: 'POST', path: '/loop', headers: jsonHeaders(), body: { judgement: makeJudgement() } });
    await new Promise((r) => setTimeout(r, 50));

    for (const [path, body] of [
      ['/judge', { exploitMarkdown: '# x' }],
      ['/loop', { judgement: makeJudgement() }],
      ['/frontrun', {}],
    ]) {
      const r = await http(base, { method: 'POST', path, headers: jsonHeaders(), body });
      assert.equal(r.status, 409, path);
      assert.match(JSON.parse(r.text).error, /busy.*loop/);
    }
    assert.equal((await http(base, { path: '/health' })).status, 200);

    unblock();
    assert.equal(parseSse((await loop).text).at(-1).outcome, 'Paid');
    assert.equal((await http(base, { method: 'POST', path: '/judge', headers: jsonHeaders(), body: { exploitMarkdown: '# x' } })).status, 200);
  });
  it('a failed request releases the lock', async () => {
    const deps = fakeChain();
    deps.judge = async () => {
      throw new Error('boom');
    };
    const { base } = await start({ deps });
    assert.equal((await http(base, { method: 'POST', path: '/judge', headers: jsonHeaders(), body: { exploitMarkdown: '# x' } })).status, 502);
    assert.equal((await http(base, { method: 'POST', path: '/judge', headers: jsonHeaders(), body: { exploitMarkdown: '# x' } })).status, 502);
  });
});
