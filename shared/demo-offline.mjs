// Offline demo: re-verifies every fixtures/demo.*.json (no key, no network), runs the dispute
// pre-check (checkRequestAgainstProgram, v3: incl. params_hash) against the demo program, simulates
// a front-run, and checks the owner encrypt -> decrypt roundtrip. Exit code 1 on any failure.
import { readFileSync, readdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import {
  verifyFixture, systemPromptHash, SYSTEM_PROMPT, DEFAULT_MODEL,
  buildCodeBundle, codeHash, checkRequestAgainstProgram, paramsHash,
  encryptForOwner, decryptAsOwner, generateOwnerKeypair,
} from './judge.mjs';
import { DEMO_TARGET, DEMO_HUNTER, DEMO_FRONTRUNNER } from './demo-data.mjs';

const here = (p) => fileURLToPath(new URL(p, import.meta.url));
let fail = 0;

// 1. frozen prompt: txt file == embedded module string == .sha256 file == systemPromptHash()
const txt = readFileSync(here('./system-prompt.txt'), 'utf8');
const fileHash = readFileSync(here('./system-prompt.sha256'), 'utf8').trim();
const realHash = createHash('sha256').update(txt, 'utf8').digest('hex');
const promptOk = txt === SYSTEM_PROMPT && realHash === fileHash && realHash === systemPromptHash();
console.log(`system prompt sha256 ${realHash}  ${promptOk ? 'OK' : 'MISMATCH (run pnpm gen:prompt)'}`);
if (!promptOk) fail++;

// 2. program code bundle: src/server.ts -> bundle.txt -> bundle.sha256
const bundle = readFileSync(here('../fixtures/vuln-app/bundle.txt'), 'utf8');
const bundleHash = readFileSync(here('../fixtures/vuln-app/bundle.sha256'), 'utf8').trim();
const rebuiltBundle = buildCodeBundle([{ path: 'src/server.ts', content: readFileSync(here('../fixtures/vuln-app/src/server.ts'), 'utf8') }]);
const bundleOk = rebuiltBundle === bundle && codeHash(bundle) === bundleHash;
console.log(`code bundle sha256   ${bundleHash}  ${bundleOk ? 'OK' : 'MISMATCH (bundle.txt/.sha256 stale vs src/server.ts)'}`);
if (!bundleOk) fail++;

// Demo program as the contract stores it (Program view, snake_case).
const program = {
  repo_url: DEMO_TARGET.repoUrl, commit: DEMO_TARGET.commit, model_id: DEFAULT_MODEL,
  system_prompt_hash: systemPromptHash(), code_hash: bundleHash, params_hash: paramsHash(),
};
console.log(`params sha256        ${program.params_hash}  (canonical request params, v3 #1)`);
// Expected dispute outcome per fixture: null = dispute fails ("request matches program").
const EXPECT_DISPUTE = { fakecode: 'code mismatch' };

// 3. fixtures
const dir = here('../fixtures/');
const files = readdirSync(dir).filter((f) => /^demo\..+\.json$/.test(f)).sort();
if (!files.length) { console.log('no fixtures/demo.*.json found'); fail++; }
const rows = [];
const ciphertextChecks = [];
for (const f of files) {
  const obj = JSON.parse(readFileSync(dir + f, 'utf8'));
  const name = f.replace(/^demo\.|\.json$/g, '');
  const r = verifyFixture(obj, { systemPromptHash: systemPromptHash(), codeBundle: bundle });
  const specOk = obj.spec === 'v2' && obj.inputs?.hunter === DEMO_HUNTER;
  if (!specOk) console.log(`  FAIL ${f}: not a v2 fixture for ${DEMO_HUNTER}`);
  if (!r.ok) for (const c of r.checks.filter((c) => !c.ok)) console.log(`  FAIL ${f}: ${c.name} [${c.detail}]`);
  const d = checkRequestAgainstProgram(obj.request_body, program, obj.inputs?.hunter);
  const want = EXPECT_DISPUTE[name.split('.')[0]] ?? null;
  const dOk = d.reason === want;
  if (!dOk) console.log(`  FAIL ${f}: dispute pre-check got ${d.reason ?? 'matches'}, expected ${want ?? 'matches'}`);
  if (!r.ok || !specOk || !dOk) fail++;
  const v = r.verdict;
  rows.push({
    exploit: name,
    verdict: v ? `${v.valid ? 'VALID' : 'invalid'} ${v.severity} ${v.cwe ?? '-'} conf=${v.confidence}` : '?',
    kind: obj.signature_kind,
    'sig ok': r.ok ? 'yes' : 'NO',
    signer: r.signer ?? '?',
    dispute: d.ok ? 'fails (request matches)' : `REJECT: ${d.reason}`,
    expected: dOk ? 'yes' : 'NO',
  });
  if (name === 'sqli') {
    // Front-run: someone copies the pending submit_claim args (same body) and claims as themselves.
    const fr = checkRequestAgainstProgram(obj.request_body, program, DEMO_FRONTRUNNER);
    const frOk = fr.reason === 'hunter mismatch';
    console.log(`  front-run sim: sqli body claimed by ${DEMO_FRONTRUNNER} -> ${fr.reason ?? 'matches'}  ${frOk ? 'OK' : 'FAIL'}`);
    if (!frOk) fail++;
  }
  ciphertextChecks.push(obj.request_body);
}
const cols = Object.keys(rows[0] ?? {});
const width = (c) => Math.max(c.length, ...rows.map((r) => String(r[c]).length));
const line = (r) => cols.map((c) => String(r[c]).padEnd(width(c))).join('  ');
console.log('\n' + line(Object.fromEntries(cols.map((c) => [c, c]))));
console.log(cols.map((c) => '-'.repeat(width(c))).join('  '));
for (const r of rows) console.log(line(r));

// 3. owner encryption roundtrip on every real request body (+ wrong key must fail)
const owner = generateOwnerKeypair();
const other = generateOwnerKeypair();
let encOk = ciphertextChecks.length > 0;
for (const body of ciphertextChecks) {
  const ct = encryptForOwner(body, owner.publicKey);
  if (decryptAsOwner(ct, owner.secretKey) !== body) encOk = false;
  try { decryptAsOwner(ct, other.secretKey); encOk = false; } catch {}
}
console.log(`\nencrypt -> decrypt roundtrip (${ciphertextChecks.length} bodies, wrong key rejected): ${encOk ? 'OK' : 'FAIL'}`);
if (!encOk) fail++;

console.log(fail ? `\nFAILED (${fail})` : '\nALL PASS');
process.exit(fail ? 1 : 0);
