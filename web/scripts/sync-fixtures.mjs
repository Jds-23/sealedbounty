// Copies the real recorded fixtures from ../fixtures into src/fixtures, trimmed for bundling.
// Also builds a DEMO owner keypair + ciphertext (deterministic, clearly not a real secret).
// Run: pnpm sync-fixtures
import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import nacl from 'tweetnacl';
import { checkRequestAgainstProgram, encryptForOwner, encryptForOwnerWithSecret, paramsHash } from '@sealedbounty/shared';

const sha256hexNode = (t) => createHash('sha256').update(t, 'utf8').digest('hex');

const here = dirname(fileURLToPath(import.meta.url));
const src = join(here, '..', '..', 'fixtures');
const out = join(here, '..', 'src', 'fixtures');
const read = (f) => JSON.parse(readFileSync(join(src, f), 'utf8'));
const write = (f, o) => writeFileSync(join(out, f), JSON.stringify(o, null, 2) + '\n');

const summaries = {};
for (const algo of ['ed25519', 'ecdsa']) {
  const a = read(`attestation.${algo}.json`);
  const m = a.raw_response.model_attestations[0];
  summaries[algo] = {
    source: `fixtures/attestation.${algo}.json`,
    fetched_at: a.fetched_at,
    model: a.model,
    nonce: a.nonce,
    policy: { required_model_checks: a.policy.required_model_checks, note: a.policy.note },
    model_attestation: {
      model_name: m.model_name,
      signing_address: m.signing_address,
      signing_algo: m.signing_algo,
      request_nonce: m.request_nonce,
      intel_quote: m.intel_quote,
      app_name: m.info?.app_name ?? null,
      compose_hash: m.info?.compose_hash ?? null,
      gpu_arch: (() => {
        try { return JSON.parse(m.nvidia_payload).evidence_list.map((e) => e.arch); } catch { return []; }
      })(),
    },
    verified_signers: a.verified_signers.map(({ signing_algo, signing_address, kind, verified, checks }) => ({
      signing_algo, signing_address, kind, verified, checks,
    })),
  };
}
write('attestation.summary.json', summaries);

// Real recorded judge runs (spec v2, provider_tee signatures) against the demo target.
const DEMO_CASES = ['sqli', 'sqli.ecdsa', 'idor', 'bogus', 'injection', 'fakecode'];
const cases = {};
for (const c of DEMO_CASES) {
  const { inputs, ...rest } = read(`demo.${c}.json`);
  if (rest.spec !== 'v2') throw new Error(`demo.${c}.json is not spec v2`);
  cases[c] = { ...rest, target: { repoUrl: inputs.repoUrl, commit: inputs.commit }, hunter: inputs.hunter };
}

// The program's published code bundle (fixtures/vuln-app/bundle.txt) and its hash (program.code_hash).
const codeBundle = readFileSync(join(src, 'vuln-app', 'bundle.txt'), 'utf8');
const codeHash = readFileSync(join(src, 'vuln-app', 'bundle.sha256'), 'utf8').trim();
if (sha256hexNode(codeBundle) !== codeHash) throw new Error('bundle.txt does not hash to bundle.sha256');

// DEMO owner key: derived from a public, fixed seed. Anyone can derive it. Demo only.
const seed = createHash('sha256').update('sealedbounty-demo-owner-key-v2-DO-NOT-USE').digest();
const owner = nacl.box.keyPair.fromSecretKey(new Uint8Array(seed));
const ownerPub = Buffer.from(owner.publicKey).toString('base64');
const ciphertexts = Object.fromEntries(Object.entries(cases).map(([k, v]) => [k, encryptForOwner(v.request_body, ownerPub)]));

// ---- v3 cases, derived offline from the recorded fixtures (no NEAR AI calls) ----
const seeded = (label, n) => {
  const out = new Uint8Array(n);
  for (let i = 0, ctr = 0; i < n; ctr++) {
    const block = createHash('sha256').update(`sealedbounty-demo-v3:${label}:${ctr}`).digest();
    out.set(block.subarray(0, Math.min(32, n - i)), i);
    i += 32;
  }
  return out;
};
const sha256hex = (s) => sha256hexNode(s);
const program = {
  repo_url: cases.sqli.target.repoUrl, commit: cases.sqli.target.commit, model_id: cases.sqli.model,
  system_prompt_hash: sha256hex(JSON.parse(cases.sqli.request_body).messages[0].content), code_hash: codeHash,
  params_hash: paramsHash(),
};
for (const [k, v] of Object.entries(cases)) {
  if (paramsHash(JSON.parse(v.request_body)) !== program.params_hash) throw new Error(`demo.${k}.json params are not canonical`);
}

// #1: the honest sqli request with a response_format that forces a payable verdict. Same prompt,
// model, code, hunter and report; only the params differ, so dispute rejects "params tampered".
// Synthetic: there is no TEE signature over this body (that would need a NEAR AI call).
const tampered = JSON.parse(cases.sqli.request_body);
const props = tampered.response_format.json_schema.schema.properties;
props.valid = { type: 'boolean', const: true };
props.severity = { type: 'string', enum: ['critical'] };
props.confidence = { type: 'integer', const: 100 };
const tamperedBody = JSON.stringify(tampered);
const tCheck = checkRequestAgainstProgram(tamperedBody, program, cases.sqli.hunter);
if (tCheck.reason !== 'params tampered') throw new Error(`tampered body: expected "params tampered", got ${tCheck.reason}`);

// #2: junk ciphertexts (right length and layout, but the box does not open) and an honest one whose
// ephemeral secret the hunter reveals with prove_ciphertext.
const junk = (label, len) => Buffer.from(seeded(`junk:${label}`, 56 + len)).toString('base64');
const proven = encryptForOwnerWithSecret(cases.sqli.request_body, ownerPub, {
  ephemeralSecret: seeded('proven-ephemeral', 32),
  nonce: seeded('proven-nonce', 24),
});
const v3 = {
  note: 'Derived offline from the fixtures above; no NEAR AI calls. params_tampered has no TEE signature over its body.',
  params_hash: program.params_hash,
  params_tampered: {
    base: 'sqli',
    change: 'response_format schema forces valid:true, severity critical, confidence 100',
    request_body: tamperedBody,
    req_hash: sha256hex(tamperedBody),
    ciphertext: encryptForOwner(tamperedBody, ownerPub),
  },
  junk: { fakecode: junk('fakecode', 400), idor: junk('idor', 400) },
  proven: { base: 'sqli', ciphertext: proven.ciphertext, ephemeral_secret: proven.ephemeralSecretHex },
};

write('demo.json', {
  note: 'DEMO ONLY. Owner key derived from a public seed; not a secret. Cases are real recorded TEE outputs from fixtures/demo.*.json (spec v2); v3 cases are derived from them offline.',
  spec: 'v2',
  code_bundle: { source: 'fixtures/vuln-app/bundle.txt', code_hash: codeHash, bundle: codeBundle },
  // Same shape as the CLI's ~/.sealedbounty/owner-<id>.json
  owner_secret: {
    publicKey: ownerPub,
    secretKey: Buffer.from(owner.secretKey).toString('base64'),
    program_id: 0,
    contract_id: 'demo',
    network: 'demo',
    created_at: '2026-11-10T00:00:00.000Z',
  },
  cases,
  ciphertexts,
  v3,
});
console.log('fixtures synced to', out);
