// Copies the real recorded fixtures from ../fixtures into src/fixtures, trimmed for bundling.
// Also builds a DEMO owner keypair + ciphertext (deterministic, clearly not a real secret).
// Run: pnpm sync-fixtures
import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import nacl from 'tweetnacl';
import { encryptForOwner } from '@sealedbounty/shared';

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

// Real recorded judge runs (provider_tee signatures) against the demo target.
const DEMO_CASES = ['sqli', 'sqli.ecdsa', 'idor', 'bogus', 'injection'];
const cases = {};
for (const c of DEMO_CASES) {
  const { inputs, ...rest } = read(`demo.${c}.json`);
  cases[c] = { ...rest, target: { repoUrl: inputs?.repoUrl, commit: inputs?.commit } };
}

// DEMO owner key: derived from a public, fixed seed. Anyone can derive it. Demo only.
const seed = createHash('sha256').update('sealedbounty-demo-owner-key-DO-NOT-USE').digest();
const owner = nacl.box.keyPair.fromSecretKey(new Uint8Array(seed));
const ownerPub = Buffer.from(owner.publicKey).toString('base64');
const ciphertexts = Object.fromEntries(Object.entries(cases).map(([k, v]) => [k, encryptForOwner(v.request_body, ownerPub)]));
write('demo.json', {
  note: 'DEMO ONLY. Owner key derived from a public seed; not a secret. Cases are real recorded TEE outputs from fixtures/demo.*.json.',
  // Same shape as the CLI's ~/.sealedbounty/owner-<id>.json
  owner_secret: {
    publicKey: ownerPub,
    secretKey: Buffer.from(owner.secretKey).toString('base64'),
    program_id: 0,
    contract_id: 'demo',
    network: 'demo',
    created_at: '2026-11-08T00:00:00.000Z',
  },
  cases,
  ciphertexts,
});
console.log('fixtures synced to', out);
