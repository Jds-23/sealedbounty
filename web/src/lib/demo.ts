// Demo dataset: a mock program whose claims carry REAL recorded TEE signatures (fixtures/demo.*.json).
import { systemPromptHash } from '@sealedbounty/shared';
import demo from '../fixtures/demo.json';
import type { Claim, Program, SignerEntry } from './types';
import { parseVerdict, b64ToBytes, signerFrom } from './verify';

export const DEMO_OWNER_SECRET = JSON.stringify(demo.owner_secret, null, 2);

const NEAR = (n: number) => (BigInt(Math.round(n * 1000)) * 10n ** 21n).toString();
const ns = (ms: number) => (BigInt(Math.round(ms)) * 1_000_000n).toString();

type CaseName = keyof typeof demo.cases;
const C = demo.cases;

/** Mirrors the testnet allowlist in docs/INTERFACE.md (the two attested provider_tee keys). */
export const DEMO_SIGNERS: SignerEntry[] = [
  { signer: signerFrom('ed25519', C.sqli.signing_address), meta: { kind: 'provider_tee', model: C.sqli.model } },
  { signer: signerFrom('ecdsa', C['sqli.ecdsa'].signing_address), meta: { kind: 'provider_tee', model: C.sqli.model } },
];

/** Response bodies by claim id. Onchain only resp_hash is stored; demo mode can show the full check. */
export const DEMO_RESP_BODIES: Record<number, string> = {};

export function buildDemo(now = Date.now()): { programs: Program[]; claims: Claim[] } {
  const target = C.sqli.target;
  const programs: Program[] = [
    {
      id: 0,
      owner: 'vuln-app-owner.testnet',
      name: 'vuln-app (demo)',
      repo_url: target.repoUrl,
      commit: target.commit,
      model_id: C.sqli.model,
      system_prompt_hash: systemPromptHash(),
      payouts: { low: NEAR(1), medium: NEAR(3), high: NEAR(8), critical: NEAR(20) },
      owner_enc_pubkey: demo.owner_secret.publicKey,
      dispute_secs: 86400,
      min_confidence: 70,
      balance: NEAR(72),
      reserved: NEAR(20),
      open: true,
      created_at: ns(now - 3 * 86400_000),
    },
  ];

  const mk = (id: number, name: CaseName, status: Claim['status'], submittedAgo: number, extra: Partial<Claim> = {}): Claim => {
    const f = C[name];
    DEMO_RESP_BODIES[id] = f.response_body_b64;
    const verdict = parseVerdict(b64ToBytes(f.response_body_b64));
    const submitted = now - submittedAgo;
    return {
      id,
      program_id: 0,
      hunter: ['whitehat.testnet', 'hunter42.testnet', 'spammer.testnet', 'trickster.testnet'][id] ?? 'anon.testnet',
      req_hash: f.req_hash,
      resp_hash: f.resp_hash,
      verdict,
      signer: signerFrom(f.signing_algo, f.signing_address),
      kind: f.signature_kind as Claim['kind'],
      signature: f.signature,
      model: f.model,
      ciphertext: demo.ciphertexts[name],
      status,
      payout: NEAR(verdict.severity === 'critical' ? 20 : verdict.severity === 'high' ? 8 : 0),
      submitted_at: ns(submitted),
      finalize_after: ns(submitted + 86400_000),
      reject_reason: null,
      ...extra,
    };
  };

  const notPayable = 'verdict not payable: submit_claim reverts, so this would not be stored onchain (shown for the demo)';
  const claims: Claim[] = [
    mk(0, 'sqli.ecdsa', 'Pending', 5 * 3600_000),
    mk(1, 'idor', 'Paid', 2 * 86400_000),
    mk(2, 'bogus', 'Rejected', 30 * 3600_000, { reject_reason: notPayable }),
    mk(3, 'injection', 'Rejected', 20 * 3600_000, { reject_reason: `${notPayable}. The report tried prompt injection; the judge ignored it.` }),
  ];
  return { programs, claims };
}
