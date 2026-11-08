// Offline demo: re-verifies every fixtures/demo.*.json (no key, no network) and checks the
// owner encrypt -> decrypt roundtrip. Exit code 1 on any failure.
import { readFileSync, readdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import {
  verifyFixture, systemPromptHash, SYSTEM_PROMPT,
  encryptForOwner, decryptAsOwner, generateOwnerKeypair,
} from './judge.mjs';

const here = (p) => fileURLToPath(new URL(p, import.meta.url));
let fail = 0;

// 1. frozen prompt: txt file == embedded module string == .sha256 file == systemPromptHash()
const txt = readFileSync(here('./system-prompt.txt'), 'utf8');
const fileHash = readFileSync(here('./system-prompt.sha256'), 'utf8').trim();
const realHash = createHash('sha256').update(txt, 'utf8').digest('hex');
const promptOk = txt === SYSTEM_PROMPT && realHash === fileHash && realHash === systemPromptHash();
console.log(`system prompt sha256 ${realHash}  ${promptOk ? 'OK' : 'MISMATCH (run pnpm gen:prompt)'}`);
if (!promptOk) fail++;

// 2. fixtures
const dir = here('../fixtures/');
const files = readdirSync(dir).filter((f) => /^demo\..+\.json$/.test(f)).sort();
if (!files.length) { console.log('no fixtures/demo.*.json found'); fail++; }
const rows = [];
const ciphertextChecks = [];
for (const f of files) {
  const obj = JSON.parse(readFileSync(dir + f, 'utf8'));
  const r = verifyFixture(obj, { systemPromptHash: systemPromptHash() });
  if (!r.ok) {
    fail++;
    for (const c of r.checks.filter((c) => !c.ok)) console.log(`  FAIL ${f}: ${c.name} [${c.detail}]`);
  }
  const v = r.verdict;
  rows.push({
    exploit: f.replace(/^demo\.|\.json$/g, ''),
    verdict: v ? `${v.valid ? 'VALID' : 'invalid'} ${v.severity} ${v.cwe ?? '-'} conf=${v.confidence}` : '?',
    kind: obj.signature_kind,
    'sig ok': r.ok ? 'yes' : 'NO',
    signer: r.signer ?? '?',
  });
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
