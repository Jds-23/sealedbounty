// Records LIVE signed v2 judge verdicts for the demo exploits into fixtures/demo.<name>.json.
// Usage: node record-demo.mjs [--skip-smoke] [--only sqli,idor,fakecode] [--max-calls N]
// `fakecode` is adversarial: the hunter swaps in invented vulnerable code (not the program bundle).
// The TEE may well say valid; the contract's dispute catches it with "code mismatch".
// Reads NEARAI_API_KEY from ../.env inside this process. Never prints or writes the key.
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  judge, signRecord, buildRequestBody, buildCodeBundle, codeHash, parseVerdict, verifyFixture, systemPromptHash, DEFAULT_MODEL,
} from './judge.mjs';
import { DEMO_TARGET, DEMO_HUNTER, FAKE_CODE_BUNDLE, FAKE_CODE_REPORT } from './demo-data.mjs';

const here = (p) => fileURLToPath(new URL(p, import.meta.url));
if (existsSync(here('../.env'))) process.loadEnvFile(here('../.env'));
const KEY = process.env.NEARAI_API_KEY;
const BASE = process.env.NEARAI_BASE_URL || undefined;
const MODEL = process.env.NEARAI_MODEL || DEFAULT_MODEL;
if (!KEY) { console.error('missing NEARAI_API_KEY'); process.exit(1); }

const arg = (name) => { const i = process.argv.indexOf(name); return i > 0 ? process.argv[i + 1] : undefined; };
const ONLY = arg('--only')?.split(',');
const MAX_CALLS = Number(arg('--max-calls') ?? 6);

// The program's bundle, rebuilt from source and checked against the committed bundle files.
const codeBundle = buildCodeBundle([{ path: 'src/server.ts', content: readFileSync(here('../fixtures/vuln-app/src/server.ts'), 'utf8') }]);
if (codeBundle !== readFileSync(here('../fixtures/vuln-app/bundle.txt'), 'utf8') ||
    codeHash(codeBundle) !== readFileSync(here('../fixtures/vuln-app/bundle.sha256'), 'utf8')) {
  throw new Error('fixtures/vuln-app/bundle.{txt,sha256} are stale vs src/server.ts');
}
const EXPLOITS = ['sqli', 'idor', 'bogus', 'injection', 'fakecode'].filter((n) => !ONLY || ONLY.includes(n));

// Counting fetch: hard cap on completion calls (signature/attestation fetches are not completions).
let calls = 0;
const countingFetch = (url, init) => {
  if (String(url).endsWith('/chat/completions')) {
    if (++calls > MAX_CALLS) throw new Error(`completion budget (${MAX_CALLS}) exceeded`);
  }
  return fetch(url, init);
};

if (!process.argv.includes('--skip-smoke')) {
  // Smoke test: canonical body shape (incl. strict schema with nullable cwe) on a trivial input.
  const body = buildRequestBody({ model: MODEL, ...DEMO_TARGET, hunter: DEMO_HUNTER, codeBundle: buildCodeBundle([{ path: 'add.ts', content: 'export const add = (a: number, b: number) => a + b;' }]), report: 'add() is fine. No vulnerability.' });
  const res = await countingFetch(`${(BASE || 'https://cloud-api.near.ai/v1').replace(/\/$/, '')}/chat/completions`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${KEY}`, 'Content-Type': 'application/json', 'x-no-aliasing': 'true', 'Accept-Encoding': 'identity' },
    body,
  });
  const txt = await res.text();
  console.log(`smoke: HTTP ${res.status}`);
  if (res.status !== 200) { console.error(txt.split(KEY).join('[REDACTED]').slice(0, 400)); process.exit(2); }
  console.log(`  smoke verdict: ${JSON.stringify(parseVerdict(txt))}`);
}

const save = (name, rec) => {
  const s = JSON.stringify(rec, null, 2) + '\n';
  if (s.includes(KEY)) throw new Error('refusing to write: key found in fixture');
  writeFileSync(here(`../fixtures/demo.${name}.json`), s);
  const v = verifyFixture(rec, { systemPromptHash: systemPromptHash(), codeBundle });
  const bad = v.checks.filter((c) => !c.ok).map((c) => c.name);
  console.log(`  wrote fixtures/demo.${name}.json  offline: ${bad.length ? 'FAIL ' + bad.join(', ') : 'PASS'}`);
};

for (const name of EXPLOITS) {
  const fake = name === 'fakecode';
  // inputs.codeBundle is omitted for honest fixtures (it is fixtures/vuln-app/bundle.txt); fakecode carries its own.
  const inputs = fake
    ? { ...DEMO_TARGET, hunter: DEMO_HUNTER, codeBundle: FAKE_CODE_BUNDLE, report: FAKE_CODE_REPORT }
    : { ...DEMO_TARGET, hunter: DEMO_HUNTER, report: readFileSync(here(`../fixtures/exploits/${name}.md`), 'utf8').replace(/\n$/, '') };
  const rec = await judge({ apiKey: KEY, baseUrl: BASE, model: MODEL, codeBundle, ...inputs, signingAlgo: 'ed25519', fetchImpl: countingFetch });
  console.log(`${name}: verdict=${JSON.stringify(rec.verdict)} kind=${rec.signature_kind} signer=${rec.signer} attested=${rec.signer_in_attestation}`);
  save(name, { spec: 'v2', ...rec, inputs });
  if (name === 'sqli') {
    const ec = await signRecord({ apiKey: KEY, baseUrl: BASE, record: rec, algo: 'ecdsa', fetchImpl: countingFetch });
    console.log(`sqli[ecdsa]: kind=${ec.signature_kind} signer=${ec.signer} attested=${ec.signer_in_attestation}`);
    save('sqli.ecdsa', { spec: 'v2', ...ec, inputs });
  }
}
console.log(`completion calls used this run: ${calls}`);
