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

/** The program's published code bundle (fixtures/vuln-app/bundle.txt) and its code_hash. */
export const DEMO_CODE_BUNDLE = demo.code_bundle;
/** Account that copied a pending claim's args (same body, same signature) in the demo. */
export const DEMO_FRONTRUNNER = 'frontrunner.testnet';

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
      code_hash: demo.code_bundle.code_hash,
      params_hash: null,
      signers: null,
      bond: null,
      challenge_secs: null,
      payouts: { low: NEAR(1), medium: NEAR(3), high: NEAR(8), critical: NEAR(20) },
      owner_enc_pubkey: demo.owner_secret.publicKey,
      dispute_secs: 86400,
      min_confidence: 70,
      // funded 100: sqli paid 20, idor (8) reserved, fakecode + front-run rejected -> back to balance
      balance: NEAR(72),
      reserved: NEAR(8),
      open: true,
      created_at: ns(now - 3 * 86400_000),
    },
  ];

  const payoutFor = (sev: string) => NEAR(({ low: 1, medium: 3, high: 8, critical: 20 } as Record<string, number>)[sev] ?? 0);
  const mk = (id: number, name: CaseName, hunter: string, status: Claim['status'], submittedAgo: number, extra: Partial<Claim> = {}): Claim => {
    const f = C[name];
    DEMO_RESP_BODIES[id] = f.response_body_b64;
    const verdict = parseVerdict(b64ToBytes(f.response_body_b64));
    const submitted = now - submittedAgo;
    return {
      id,
      program_id: 0,
      hunter,
      req_hash: f.req_hash,
      resp_hash: f.resp_hash,
      verdict,
      signer: signerFrom(f.signing_algo, f.signing_address),
      kind: f.signature_kind as Claim['kind'],
      signature: f.signature,
      model: f.model,
      ciphertext: demo.ciphertexts[name],
      status,
      payout: verdict.valid ? payoutFor(verdict.severity) : '0',
      submitted_at: ns(submitted),
      finalize_after: ns(submitted + 86400_000),
      reject_reason: null,
      bond: null,
      challenge_deadline: null,
      ...extra,
    };
  };

  const H = C.sqli.hunter; // the account bound into every recorded request
  const H_ = 3600_000;
  const claims: Claim[] = [
    // A front-runner copied the pending sqli submit_claim args. The body names H, so the owner's dispute
    // rejects it ("hunter mismatch") and frees req_hash; H then resubmits (claim 1) and is paid.
    mk(0, 'sqli', DEMO_FRONTRUNNER, 'Rejected', 60 * H_, { reject_reason: 'hunter mismatch' }),
    mk(1, 'sqli.ecdsa', H, 'Paid', 58 * H_),
    // The TEE said valid/critical, but the hunter judged invented code instead of the program's bundle.
    mk(3, 'fakecode', H, 'Rejected', 2 * H_, { reject_reason: 'code mismatch' }),
    mk(2, 'idor', H, 'Pending', 6 * H_),
    // Never stored onchain: submit_claim reverts on non-payable verdicts. Shown with their real TEE outputs.
    mk(4, 'bogus', H, 'Rejected', 20 * H_, { refused_at_submit: 'verdict not payable' }),
    mk(5, 'injection', H, 'Rejected', 10 * H_, {
      refused_at_submit: 'verdict not payable (the report tried prompt injection; the judge ignored it)',
    }),
  ];
  return { programs, claims };
}
