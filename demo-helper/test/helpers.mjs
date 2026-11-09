import { createHash } from 'node:crypto';
import { request } from 'node:http';

export const sha256hex = (s) => createHash('sha256').update(s).digest('hex');

export const FAKE_API_KEY = 'sk-FAKEnearaiKEY-0123456789abcdefXYZ';
// 64-byte base58 ed25519 secret key shape (what ~/.near-credentials holds)
export const FAKE_PRIVATE_KEY =
  'ed25519:3D4YudUahN1nawWogh8pAKSj92sUNMdbZGjn7kERKzYoTy8tnFQuwoGUC51DowKqorvkr2pytJSnwuSbsNVfqygr';

/** A structurally valid judgement as POST /judge returns it (synthetic, not a real TEE signature). */
export function makeJudgement(over = {}) {
  const request_body = JSON.stringify({
    model: 'Qwen/Qwen3.8-27B',
    messages: [
      { role: 'system', content: 'judge' },
      { role: 'user', content: 'TARGET x@y\nHUNTER hunter.baldingsucks7993.testnet\n\nCODE\n...\n\nREPORT\nsqli' },
    ],
  });
  const response = JSON.stringify({ id: 'chatcmpl-1', choices: [] });
  return {
    verdict: { valid: true, severity: 'critical', cwe: 'CWE-89', confidence: 95 },
    signature: 'cd'.repeat(64),
    chat_id: 'chatcmpl-1',
    request_body,
    response_body_b64: Buffer.from(response).toString('base64'),
    req_hash: sha256hex(request_body),
    signer: 'ed25519:' + 'ab'.repeat(32),
    kind: 'provider_tee',
    signer_in_attestation: true,
    ...over,
  };
}

/** Deterministic mock judge output (like the real TEE at temperature 0): same report -> same req_hash. */
export function judgementFor(report) {
  const request_body = JSON.stringify({
    model: 'Qwen/Qwen3.8-27B',
    messages: [
      { role: 'system', content: 'judge' },
      { role: 'user', content: `TARGET x@y\nHUNTER hunter.baldingsucks7993.testnet\n\nCODE\n...\n\nREPORT\n${report}` },
    ],
  });
  return makeJudgement({ request_body, req_hash: sha256hex(request_body) });
}

/** Plain node:http request (fetch can't be trusted to send an Origin header verbatim). */
export function http(base, { method = 'GET', path = '/', headers = {}, body } = {}) {
  const u = new URL(path, base);
  return new Promise((resolve, reject) => {
    const req = request(u, { method, headers }, (res) => {
      let text = '';
      res.setEncoding('utf8');
      res.on('data', (c) => (text += c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, text }));
    });
    req.on('error', reject);
    if (body !== undefined) req.write(typeof body === 'string' ? body : JSON.stringify(body));
    req.end();
  });
}

export const ORIGIN = 'http://localhost:5173';
export const jsonHeaders = (extra = {}) => ({ 'content-type': 'application/json', origin: ORIGIN, ...extra });

/** Parses an SSE stream body into its JSON events; throws on any malformed frame. */
export function parseSse(text) {
  if (!text.endsWith('\n\n')) throw new Error('stream does not end on a frame boundary');
  return text
    .slice(0, -2)
    .split('\n\n')
    .filter((f) => !f.startsWith(':')) // comments / keep-alives
    .map((f) => {
      if (!f.startsWith('data: ') || f.includes('\n')) throw new Error(`bad frame: ${JSON.stringify(f)}`);
      return JSON.parse(f.slice(6));
    });
}

export async function listen(server) {
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const { port } = server.address();
  return { base: `http://127.0.0.1:${port}`, close: () => new Promise((r) => server.close(r)) };
}

/** Fake chain + CLI: a tiny claim state machine mirroring the v3 contract for the steps the helper drives. */
export function fakeChain({ nowMs = 1_700_000_000_000, disputeSecs = 45, owner = 'baldingsucks7993.testnet' } = {}) {
  const calls = [];
  const claims = new Map();
  const clock = { now: nowMs };
  let nextId = 7;
  let tx = 0;
  const ns = (ms) => String(BigInt(ms) * 1_000_000n);
  const hash = () => `Tx${String(++tx).padStart(41, '1')}`;
  return {
    calls,
    claims,
    clock,
    now: () => clock.now,
    sleep: async (ms) => {
      clock.now += ms;
    },
    getProgram: async (id) => ({ id, owner, repo_url: 'r', commit: 'c', model_id: 'Qwen/Qwen3.8-27B', code_hash: 'h' }),
    getClaim: async (id) => {
      const c = claims.get(id);
      return c ? { ...c } : null;
    },
    submit: async ({ record, account }) => {
      calls.push(['submit', account, record.req_hash]);
      const id = nextId++;
      claims.set(id, { id, hunter: account, status: 'Pending', finalize_after: ns(clock.now + disputeSecs * 1000), reject_reason: null });
      return { tx: hash(), claimId: id };
    },
    flagUndecryptable: async ({ claimId, account }) => {
      calls.push(['flag', account, claimId]);
      claims.get(claimId).status = 'Challenged';
      return { tx: hash() };
    },
    proveCiphertext: async ({ claimId, account }) => {
      calls.push(['prove', account, claimId]);
      const c = claims.get(claimId);
      c.status = 'Pending';
      c.finalize_after = ns(clock.now + 5000); // pretend 5 s remain so the countdown is visible
      return { tx: hash() };
    },
    finalize: async ({ claimId, account }) => {
      calls.push(['finalize', account, claimId]);
      const c = claims.get(claimId);
      if (clock.now < Number(BigInt(c.finalize_after) / 1_000_000n)) throw new Error('claim is not finalizable yet');
      c.status = 'Paid';
      return { tx: hash() };
    },
    dispute: async ({ claimId, account }) => {
      calls.push(['dispute', account, claimId]);
      const c = claims.get(claimId);
      c.status = 'Rejected';
      c.reject_reason = 'hunter mismatch';
      return { tx: hash() };
    },
    judge: async ({ exploitMarkdown }) => {
      calls.push(['judge', exploitMarkdown]);
      return makeJudgement();
    },
    defaultExploit: async () => '# SQLi in /users',
  };
}
