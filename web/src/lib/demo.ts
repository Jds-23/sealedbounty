// Demo dataset: mock v3 programs whose claims carry REAL recorded TEE signatures (fixtures/demo.*.json).
// The v3 cases (demo.json `v3`) are derived offline from those fixtures by scripts/sync-fixtures.mjs.
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

const FUNDED = NEAR(100);
const BOND = NEAR(0.5);
const CHALLENGE_SECS = 12 * 3600;

export function buildDemo(now = Date.now()): { programs: Program[]; claims: Claim[] } {
  const target = C.sqli.target;
  const baseProgram = (id: number, name: string, createdAgo: number): Program => ({
    id,
    owner: 'vuln-app-owner.testnet',
    name,
    repo_url: target.repoUrl,
    commit: target.commit,
    model_id: C.sqli.model,
    system_prompt_hash: systemPromptHash(),
    code_hash: demo.code_bundle.code_hash,
    params_hash: demo.v3.params_hash,
    signers: DEMO_SIGNERS.map((s) => s.signer),
    bond: BOND,
    challenge_secs: CHALLENGE_SECS,
    payouts: { low: NEAR(1), medium: NEAR(3), high: NEAR(8), critical: NEAR(20) },
    owner_enc_pubkey: demo.owner_secret.publicKey,
    dispute_secs: 86400,
    min_confidence: 70,
    balance: FUNDED, // recomputed from the claims below
    reserved: '0',
    open: true,
    created_at: ns(now - createdAgo),
  });
  const programs: Program[] = [
    baseProgram(0, 'vuln-app (demo)', 3 * 86400_000),
    // Same owner + code, second program for the v3 cases (dedupe is per program, so fixtures can be reused).
    baseProgram(1, 'vuln-app · v3 cases (demo)', 2 * 86400_000),
  ];

  const payoutFor = (sev: string) => NEAR(({ low: 1, medium: 3, high: 8, critical: 20 } as Record<string, number>)[sev] ?? 0);
  const mk = (
    id: number,
    program_id: number,
    name: CaseName,
    hunter: string,
    status: Claim['status'],
    submittedAgo: number,
    extra: Partial<Claim> = {},
  ): Claim => {
    const f = C[name];
    DEMO_RESP_BODIES[id] = f.response_body_b64;
    const verdict = parseVerdict(b64ToBytes(f.response_body_b64));
    const submitted = now - submittedAgo;
    return {
      id,
      program_id,
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
      bond: BOND,
      challenge_deadline: null,
      ...extra,
    };
  };

  const H = C.sqli.hunter; // the account bound into every recorded request
  const M = 'mallory.testnet';
  const H_ = 3600_000;
  const CH = CHALLENGE_SECS * 1000;
  const at = (ago: number) => ns(now - ago);
  const V3 = demo.v3;
  const claims: Claim[] = [
    // A front-runner copied the pending sqli submit_claim args. The body names H, so the owner's dispute
    // rejects it ("hunter mismatch") and frees req_hash; H then resubmits (claim 1) and is paid.
    mk(0, 0, 'sqli', DEMO_FRONTRUNNER, 'Rejected', 60 * H_, { reject_reason: 'hunter mismatch' }),
    mk(1, 0, 'sqli.ecdsa', H, 'Paid', 58 * H_),
    // The TEE said valid/critical, but the hunter judged invented code instead of the program's bundle.
    mk(3, 0, 'fakecode', H, 'Rejected', 2 * H_, { reject_reason: 'code mismatch' }),
    mk(2, 0, 'idor', H, 'Pending', 6 * H_),
    // Never stored onchain: submit_claim reverts on non-payable verdicts. Shown with their real TEE outputs.
    mk(4, 0, 'bogus', H, 'Rejected', 20 * H_, { refused_at_submit: 'verdict not payable', bond: null }),
    mk(5, 0, 'injection', H, 'Rejected', 10 * H_, {
      refused_at_submit: 'verdict not payable (the report tried prompt injection; the judge ignored it)',
      bond: null,
    }),

    // ---- v3 cases (program 1) ----
    // #1: the sqli request with a response_format that forces valid:true / critical / 100. Synthetic.
    mk(6, 1, 'sqli', H, 'Rejected', 40 * H_, {
      req_hash: V3.params_tampered.req_hash,
      ciphertext: V3.params_tampered.ciphertext,
      reject_reason: 'params tampered',
      synthetic: `request = fixture sqli with ${V3.params_tampered.change}, built offline with no NEAR AI call, so no TEE signature covers it. A real attacker would get one: the TEE signs whatever request it is sent.`,
      history: [
        { at: at(40 * H_), event: 'submit_claim' },
        { at: at(39 * H_), event: 'dispute: the request params do not hash to program.params_hash → Rejected "params tampered"' },
      ],
    }),
    // #2: a junk ciphertext hides a fake-code claim. Flagged, no proof before the deadline → Rejected.
    mk(7, 1, 'fakecode', M, 'Rejected', 36 * H_, {
      ciphertext: V3.junk.fakecode,
      challenge_deadline: at(35 * H_ - CH),
      reject_reason: 'undecryptable report',
      history: [
        { at: at(36 * H_), event: 'submit_claim (the ciphertext does not open with the owner key)' },
        { at: at(35 * H_), event: 'flag_undecryptable → Challenged (12h to prove)' },
        { at: at(35 * H_ - CH - 60_000), event: 'finalize after the deadline with no proof → Rejected "undecryptable report"' },
      ],
    }),
    // #2: junk ciphertext, still inside its challenge window.
    mk(8, 1, 'idor', M, 'Challenged', 5 * H_, {
      ciphertext: V3.junk.idor,
      challenge_deadline: at(4 * H_ - CH),
      history: [
        { at: at(5 * H_), event: 'submit_claim (the ciphertext does not open with the owner key)' },
        { at: at(4 * H_), event: 'flag_undecryptable → Challenged (12h to prove)' },
      ],
    }),
    // #2: an honest claim flagged anyway. The hunter reveals the ephemeral secret, the contract opens the box
    // and runs the dispute checks (all pass) → finalizable → Paid (payout + bond).
    mk(9, 1, 'sqli', H, 'Paid', 30 * H_, {
      ciphertext: V3.proven.ciphertext,
      proof_secret: V3.proven.ephemeral_secret,
      challenge_deadline: at(29 * H_ - CH),
      history: [
        { at: at(30 * H_), event: 'submit_claim' },
        { at: at(29 * H_), event: 'flag_undecryptable → Challenged (12h to prove)' },
        { at: at(27 * H_), event: 'prove_ciphertext: the box opens to req_hash and the dispute checks pass → Pending, finalizable now' },
        { at: at(27 * H_ - 60_000), event: 'finalize → Paid (payout + bond to the hunter)' },
      ],
    }),
  ];

  // Pool accounting (v3 #4): held = Pending + Challenged payouts; bonds of Rejected claims go to the pool.
  for (const p of programs) {
    const mine = claims.filter((c) => c.program_id === p.id && !c.refused_at_submit);
    const sum = (f: (c: Claim) => boolean, v: (c: Claim) => string) => mine.filter(f).reduce((a, c) => a + BigInt(v(c)), 0n);
    const held = sum((c) => c.status === 'Pending' || c.status === 'Challenged', (c) => c.payout);
    const paid = sum((c) => c.status === 'Paid', (c) => c.payout);
    const forfeited = sum((c) => c.status === 'Rejected', (c) => c.bond ?? '0');
    p.reserved = held.toString();
    p.balance = (BigInt(FUNDED) - held - paid + forfeited).toString();
  }
  return { programs, claims };
}
