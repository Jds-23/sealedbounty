// Offline re-verification of saved fixtures. No network, no key.
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { checkFixture } from './lib.mjs';

const dir = fileURLToPath(new URL('../../fixtures/', import.meta.url));
let fail = 0;
for (const algo of ['ed25519', 'ecdsa']) {
  const p = `${dir}live.${algo}.json`;
  if (!existsSync(p)) { console.log(`MISSING ${p}`); fail++; continue; }
  const f = JSON.parse(readFileSync(p, 'utf8'));
  console.log(`\n== live.${algo}.json (kind=${f.signature_kind}, chat_id=${f.chat_id})`);
  for (const [name, ok, detail] of checkFixture(f)) {
    console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${name}${ok ? '' : `  [${detail}]`}`);
    if (!ok) fail++;
  }
}
console.log(fail ? `\nFAILED (${fail})` : '\nALL PASS');
process.exit(fail ? 1 : 0);
