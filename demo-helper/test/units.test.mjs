import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { ALLOWED_ORIGIN, corsHeaders, originAllowed } from '../src/cors.mjs';
import { loadConfig, parseDotenv } from '../src/env.mjs';
import { createMutex } from '../src/mutex.mjs';
import { makeRedactor, redactDeep, secretsFromEnv } from '../src/redact.mjs';
import { sseFrame } from '../src/sse.mjs';
import { judgeResponse, toJudgeRecord, validateJudgeRequest, validateJudgement } from '../src/validate.mjs';
import { FAKE_API_KEY, FAKE_PRIVATE_KEY, makeJudgement, parseSse, sha256hex } from './helpers.mjs';

describe('sseFrame', () => {
  it('frames one event as a single `data:` line ended by a blank line', () => {
    const f = sseFrame({ step: 'submit_claim', status: 'pending' });
    assert.equal(f, 'data: {"step":"submit_claim","status":"pending"}\n\n');
  });
  it('escapes newlines inside strings so a frame never splits', () => {
    const f = sseFrame({ step: 'x', status: 'error', message: 'line1\nline2\r\n\n' });
    assert.equal(f.split('\n\n').length, 2);
    assert.deepEqual(parseSse(f), [{ step: 'x', status: 'error', message: 'line1\nline2\r\n\n' }]);
  });
});

describe('CORS policy', () => {
  it('allows only http://localhost:5173', () => {
    assert.equal(ALLOWED_ORIGIN, 'http://localhost:5173');
    assert.equal(originAllowed('http://localhost:5173'), true);
    for (const o of ['http://localhost:5174', 'https://localhost:5173', 'http://127.0.0.1:5173', 'https://evil.example', 'null', 'http://localhost:5173.evil.example'])
      assert.equal(originAllowed(o), false, o);
  });
  it('no Origin header (curl) is allowed: browsers always send one cross-origin', () => {
    assert.equal(originAllowed(undefined), true);
  });
  it('only echoes the allowed origin', () => {
    const h = corsHeaders('http://localhost:5173');
    assert.equal(h['Access-Control-Allow-Origin'], 'http://localhost:5173');
    assert.equal(h.Vary, 'Origin');
    assert.equal(corsHeaders('https://evil.example')['Access-Control-Allow-Origin'], undefined);
    assert.equal(corsHeaders(undefined)['Access-Control-Allow-Origin'], undefined);
  });
});

describe('env', () => {
  it('parses a dotenv file (comments, quotes, export, blank lines)', () => {
    const e = parseDotenv('# c\n\nA=1\nexport B="two words"\nC=\'x=y\'\nD = spaced # trailing\nBAD LINE\n');
    assert.deepEqual(e, { A: '1', B: 'two words', C: 'x=y', D: 'spaced' });
  });
  it('builds the helper config; process env wins over .env', () => {
    const c = loadConfig({
      fileEnv: { NEARAI_API_KEY: FAKE_API_KEY, DEMO_LIVE_PROGRAM_ID: '2', ESCROW_CONTRACT_ID: 'from-file.testnet' },
      env: { ESCROW_CONTRACT_ID: 'sealedbounty-v3.testnet' },
    });
    assert.equal(c.programId, 2);
    assert.equal(c.contractId, 'sealedbounty-v3.testnet');
    assert.equal(c.apiKey, FAKE_API_KEY);
    assert.equal(c.hunter, 'hunter.baldingsucks7993.testnet');
    assert.equal(c.frontrun, 'frontrun.baldingsucks7993.testnet');
    assert.equal(c.port, 8787);
  });
  it('a missing or bad DEMO_LIVE_PROGRAM_ID gives programId null', () => {
    assert.equal(loadConfig({ fileEnv: {}, env: {} }).programId, null);
    assert.equal(loadConfig({ fileEnv: { DEMO_LIVE_PROGRAM_ID: 'two' }, env: {} }).programId, null);
    assert.equal(loadConfig({ fileEnv: {}, env: {} }).contractId, 'sealedbounty-v3.testnet');
  });
});

describe('redaction', () => {
  const redact = makeRedactor([FAKE_API_KEY]);
  it('removes the API key and private keys from strings', () => {
    const s = redact(`HTTP 401 Bearer ${FAKE_API_KEY} key ${FAKE_PRIVATE_KEY} {"private_key":"abc123secretvalue"}`);
    assert.ok(!s.includes(FAKE_API_KEY));
    assert.ok(!s.includes(FAKE_PRIVATE_KEY.slice(8)));
    assert.ok(!s.includes('abc123secretvalue'));
    assert.match(s, /\[REDACTED\]/);
  });
  it('keeps public data (signer ids, tx hashes, req_hash) intact', () => {
    const pub = `ed25519:${'ab'.repeat(32)} tx 9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin ${sha256hex('x')}`;
    assert.equal(redact(pub), pub);
  });
  it('redactDeep walks objects and arrays', () => {
    const out = redactDeep({ a: [`k=${FAKE_API_KEY}`], b: { c: FAKE_PRIVATE_KEY }, n: 3 }, redact);
    assert.ok(!JSON.stringify(out).includes(FAKE_API_KEY));
    assert.ok(!JSON.stringify(out).includes(FAKE_PRIVATE_KEY.slice(8)));
    assert.equal(out.n, 3);
  });
  it('collects secret-looking env values', () => {
    const s = secretsFromEnv({ NEARAI_API_KEY: FAKE_API_KEY, SOME_SECRET: 'hunter2-long-secret', NEAR_NETWORK: 'testnet', EMPTY_KEY: '' });
    assert.deepEqual(s.sort(), [FAKE_API_KEY, 'hunter2-long-secret'].sort());
  });
});

describe('mutex', () => {
  it('one holder at a time; release frees it; double release is harmless', () => {
    const m = createMutex();
    const r1 = m.tryAcquire('loop');
    assert.ok(r1);
    assert.equal(m.holder(), 'loop');
    assert.equal(m.tryAcquire('judge'), null);
    r1();
    r1();
    assert.equal(m.holder(), null);
    const r2 = m.tryAcquire('judge');
    assert.ok(r2);
    assert.equal(m.tryAcquire('loop'), null);
    r2();
  });
});

describe('request validation', () => {
  it('/judge needs a non-empty exploitMarkdown string under 64 KiB', () => {
    assert.equal(validateJudgeRequest({ exploitMarkdown: '# sqli' }).ok, true);
    for (const bad of [null, [], 'x', {}, { exploitMarkdown: '' }, { exploitMarkdown: '   ' }, { exploitMarkdown: 3 }, { exploitMarkdown: 'a'.repeat(65 * 1024) }])
      assert.equal(validateJudgeRequest(bad).ok, false, JSON.stringify(bad)?.slice(0, 40));
  });
  it('accepts a well-formed judgement', () => {
    const r = validateJudgement(makeJudgement());
    assert.equal(r.ok, true, r.error);
  });
  it('rejects malformed judgements with a reason', () => {
    const cases = {
      missing: undefined,
      'not object': 'x',
      'no request_body': makeJudgement({ request_body: undefined }),
      'req_hash != sha256(request_body)': makeJudgement({ req_hash: 'ff'.repeat(32) }),
      'bad req_hash': makeJudgement({ req_hash: 'zz' }),
      'bad signer': makeJudgement({ signer: 'ed25519:xyz' }),
      'bad kind': makeJudgement({ kind: 'server' }),
      'bad signature': makeJudgement({ signature: 'nothex' }),
      'bad base64': makeJudgement({ response_body_b64: '%%%' }),
      'request_body not JSON': (() => {
        const b = 'not json';
        return makeJudgement({ request_body: b, req_hash: sha256hex(b) });
      })(),
      'no chat_id': makeJudgement({ chat_id: '' }),
    };
    for (const [name, j] of Object.entries(cases)) {
      const r = validateJudgement(j);
      assert.equal(r.ok, false, name);
      assert.equal(typeof r.error, 'string', name);
    }
  });
  it('toJudgeRecord rebuilds the cli JudgeRecord (fixture shape) from the API fields', () => {
    const j = makeJudgement();
    const rec = toJudgeRecord(j);
    const respHash = sha256hex(Buffer.from(j.response_body_b64, 'base64'));
    assert.equal(rec.model, 'Qwen/Qwen3.8-27B');
    assert.equal(rec.resp_hash, respHash);
    assert.equal(rec.signing_algo, 'ed25519');
    assert.equal(rec.signing_address, 'ab'.repeat(32));
    assert.equal(rec.signature_kind, 'provider_tee');
    assert.equal(rec.text, `Qwen/Qwen3.8-27B:${j.req_hash}:${respHash}`);
    assert.equal(rec.signer_in_attestation, true);
    const eth = toJudgeRecord(makeJudgement({ signer: 'eth:0x' + 'AB'.repeat(20), kind: 'gateway', signature: '0x' + 'cd'.repeat(65) }));
    assert.equal(eth.signing_algo, 'ecdsa');
    assert.equal(eth.signing_address, '0x' + 'AB'.repeat(20));
    assert.equal(eth.text, `${eth.req_hash}:${eth.resp_hash}`);
  });
  it('judgeResponse exposes the API fields and nothing secret', () => {
    const rec = { ...toJudgeRecord(makeJudgement()), verdict: makeJudgement().verdict, signer: makeJudgement().signer, apiKey: FAKE_API_KEY };
    const out = judgeResponse(rec);
    for (const k of ['verdict', 'signature', 'chat_id', 'request_body', 'response_body_b64', 'req_hash', 'signer', 'kind']) assert.ok(k in out, k);
    assert.ok(!JSON.stringify(out).includes(FAKE_API_KEY));
    assert.equal(validateJudgement(out).ok, true);
  });
});
