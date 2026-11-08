// Records REAL signed NEAR AI completions into fixtures/live.{ed25519,ecdsa}.json.
// Never prints/writes the API key.
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import dotenv from 'dotenv';
import { sha256hex, normAddr, inferKind, expectedText, verifySig, checkFixture } from './lib.mjs';

const here = (p) => fileURLToPath(new URL(p, import.meta.url));
dotenv.config({ path: here('../../.env'), quiet: true });
const KEY = process.env.NEARAI_API_KEY;
const BASE = (process.env.NEARAI_BASE_URL || 'https://cloud-api.near.ai/v1').replace(/\/$/, '');
const MODEL = process.env.NEARAI_MODEL;
if (!KEY || !MODEL) { console.error('missing NEARAI_API_KEY / NEARAI_MODEL'); process.exit(1); }
const redact = (s) => String(s).split(KEY).join('[REDACTED]');
const SKIP_SMOKE = process.argv.includes('--skip-smoke');

let calls = 0;
const MAX_CALLS = 8;

async function complete(bodyObj) {
  if (++calls > MAX_CALLS) throw new Error('call budget exceeded');
  const bodyStr = JSON.stringify(bodyObj); // built ONCE, sent and hashed as-is
  const res = await fetch(`${BASE}/chat/completions`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${KEY}`,
      'Content-Type': 'application/json',
      'x-no-aliasing': 'true',
      'Accept-Encoding': 'identity',
    },
    body: bodyStr,
  });
  const respBytes = Buffer.from(await res.arrayBuffer()); // exact raw bytes
  return { status: res.status, bodyStr, respBytes };
}

async function getSig(id, algo) {
  const url = `${BASE}/signature/${encodeURIComponent(id)}?model=${encodeURIComponent(MODEL)}&signing_algo=${algo}`;
  for (let i = 0; i < 7; i++) {
    const res = await fetch(url, { headers: { Authorization: `Bearer ${KEY}` } });
    const txt = await res.text();
    if (res.status === 404 && i < 6) { await new Promise((r) => setTimeout(r, 1000)); continue; }
    if (res.status !== 200) return { error: `HTTP ${res.status}: ${redact(txt).slice(0, 300)}` };
    const j = JSON.parse(txt);
    if (j.error_code || !j.signature) return { error: `unavailable: ${redact(txt).slice(0, 300)}` };
    return j;
  }
}

async function getAttestation(algo, nonce) {
  const url = `${BASE}/attestation/report?model=${encodeURIComponent(MODEL)}&provider=near&signing_algo=${algo}&nonce=${nonce}`;
  const res = await fetch(url, { headers: { Authorization: `Bearer ${KEY}`, 'x-no-aliasing': 'true' } });
  const txt = await res.text();
  if (res.status !== 200) throw new Error(`attestation HTTP ${res.status}: ${redact(txt).slice(0, 300)}`);
  return JSON.parse(txt);
}

// ---- 1. smoke test
if (!SKIP_SMOKE) {
  const s = await complete({ model: MODEL, messages: [{ role: 'user', content: 'Say OK' }], max_tokens: 5, stream: false });
  console.log(`smoke: HTTP ${s.status}`);
  if (s.status !== 200) {
    console.error(redact(s.respBytes.toString('utf8')).slice(0, 400));
    if (s.status === 402) { console.error('STOP: 402 (no credits / spending limit)'); }
    process.exit(2);
  }
}

// ---- 2. real judge request
const SYSTEM = readFileSync(here('./system-prompt.txt'), 'utf8');
const USER = `## Target code (TypeScript, Express)
\`\`\`ts
import express from 'express';
import { pool } from './db';
const app = express();
app.get('/users', async (req, res) => {
  const id = req.query.id;
  const rows = await pool.query("SELECT id, email FROM users WHERE id = '" + id + "'");
  res.json(rows.rows);
});
\`\`\`

## Vulnerability report
Title: SQL injection in GET /users
The \`id\` query parameter is concatenated directly into the SQL string without parameterization or validation. An attacker can supply a crafted \`id\` value that breaks out of the string literal and alters the query, e.g. returning all rows of the users table. Impact: unauthenticated read of all user emails.`;

const VERDICT_SCHEMA = {
  type: 'json_schema',
  json_schema: {
    name: 'verdict',
    strict: true,
    schema: {
      type: 'object',
      properties: {
        valid: { type: 'boolean' },
        severity: { type: 'string', enum: ['none', 'low', 'medium', 'high', 'critical'] },
        cwe: { type: 'string' },
        confidence: { type: 'integer', minimum: 0, maximum: 100 },
      },
      required: ['valid', 'severity', 'cwe', 'confidence'],
      additionalProperties: false,
    },
  },
};
const PROMPT_ONLY_SUFFIX = '\nOutput exactly one JSON object: {"valid": boolean, "severity": "none"|"low"|"medium"|"high"|"critical", "cwe": string, "confidence": integer 0-100}. No other text.';

let usedJsonSchema = true;
async function judge() {
  let r = await complete({
    model: MODEL,
    messages: [{ role: 'system', content: SYSTEM }, { role: 'user', content: USER }],
    response_format: VERDICT_SCHEMA,
    chat_template_kwargs: { enable_thinking: false }, // reasoning model: keep budget for the verdict
    max_tokens: 400,
    temperature: 0,
    stream: false,
  });
  if (r.status >= 400 && r.status < 500 && r.status !== 402) {
    console.log(`json_schema request failed HTTP ${r.status}: ${redact(r.respBytes.toString('utf8')).slice(0, 300)}`);
    console.log('retrying with prompt-only JSON instruction');
    usedJsonSchema = false;
    r = await complete({
      model: MODEL,
      messages: [{ role: 'system', content: SYSTEM + PROMPT_ONLY_SUFFIX }, { role: 'user', content: USER }],
      chat_template_kwargs: { enable_thinking: false },
      max_tokens: 400,
      temperature: 0,
      stream: false,
    });
  }
  if (r.status !== 200) throw new Error(`completion HTTP ${r.status}: ${redact(r.respBytes.toString('utf8')).slice(0, 300)}`);
  const json = JSON.parse(r.respBytes.toString('utf8'));
  const msg = json.choices?.[0]?.message ?? {};
  console.log(`completion id=${json.id} finish=${json.choices?.[0]?.finish_reason} json_schema=${usedJsonSchema}`);
  console.log(`  content: ${JSON.stringify(msg.content)}`);
  const reasoning = msg.reasoning_content ?? msg.reasoning;
  if (reasoning) console.log(`  reasoning field present (${String(reasoning).length} chars)`);
  let clean = false;
  try { const v = JSON.parse(msg.content); clean = v !== null && typeof v === 'object'; } catch {}
  console.log(`  content is clean JSON: ${clean ? 'yes' : 'NO'}`);
  if (!clean) throw new Error('content is not clean JSON; refusing to record');
  return { ...r, json };
}

function buildFixture(c, sig, algo, nonce, att) {
  const req_hash = sha256hex(Buffer.from(c.bodyStr, 'utf8'));
  const resp_hash = sha256hex(c.respBytes);
  const kind = sig.signature_kind || inferKind(sig.text);
  const exp = expectedText(kind, MODEL, req_hash, resp_hash);
  const addr = normAddr(sig.signing_address);
  const attAddrs = kind === 'provider_tee'
    ? (att.model_attestations || []).map((a) => a.signing_address)
    : [att.gateway_attestation?.signing_address];
  const signer_in_attestation = attAddrs.filter(Boolean).some((a) => normAddr(a) === addr);
  console.log(`[${algo}] kind=${kind}${sig.signature_kind ? '' : ' (inferred)'} text==expected: ${sig.text === exp} sig verifies: ${verifySig({ ...sig, signing_algo: algo })} signer_in_attestation: ${signer_in_attestation} (${attAddrs.length} candidate addrs)`);
  return {
    model: MODEL,
    request_body: c.bodyStr,
    response_body_b64: c.respBytes.toString('base64'),
    req_hash,
    resp_hash,
    chat_id: c.json.id,
    signature: sig.signature,
    signing_address: sig.signing_address,
    signing_algo: algo,
    signature_kind: kind,
    text: sig.text,
    attestation_nonce: nonce,
    signer_in_attestation,
    recorded_at: new Date().toISOString(),
  };
}

const c1 = await judge();
const fixtures = {};
let c2 = null;
for (const algo of ['ed25519', 'ecdsa']) {
  let c = c1;
  let sig = await getSig(c1.json.id, algo);
  if (sig.error) {
    console.log(`[${algo}] signature on first completion: ${sig.error}`);
    c2 ??= await judge();
    c = c2;
    sig = await getSig(c2.json.id, algo);
    if (sig.error) { console.log(`[${algo}] signature on second completion: ${sig.error}`); continue; }
  }
  const nonce = randomBytes(32).toString('hex');
  const att = await getAttestation(algo, nonce);
  fixtures[algo] = buildFixture(c, sig, algo, nonce, att);
}

const outDir = here('../../fixtures/');
mkdirSync(outDir, { recursive: true });
for (const [algo, f] of Object.entries(fixtures)) {
  const s = JSON.stringify(f, null, 2) + '\n';
  if (s.includes(KEY)) throw new Error('refusing to write: key found in fixture');
  writeFileSync(`${outDir}live.${algo}.json`, s);
  const bad = checkFixture(f).filter(([, ok]) => !ok);
  console.log(`wrote fixtures/live.${algo}.json  offline-check: ${bad.length ? 'FAIL ' + bad.map((b) => b[0]).join(', ') : 'PASS'}`);
}
console.log(`completion calls used: ${calls}`);
