// Pure builders for contract call args (no network). Unit-tested in test/args.test.ts.
import { shared, type ProgramBinding, type RequestCheck } from './shared.js';
import type { CheckRow, JudgeRecord, Payouts, Program, SigKind, Signer, Verdict } from './types.js';
import { formatNear, nearToYocto } from './util.js';

/** NEAR storage price: 1e19 yoctoNEAR per byte (10 kB = 0.1 NEAR). */
export const STORAGE_PRICE_PER_BYTE = 10n ** 19n;
/** Generous fixed size of a Claim record + map/index entries + used_req_hashes entry, excluding the ciphertext. */
export const CLAIM_FIXED_BYTES = 1500n;
/** Extra safety margin attached to submit_claim. The contract refunds everything unused. */
export const CLAIM_DEPOSIT_MARGIN = nearToYocto('0.01');
/** Storage allowance attached to create_program on top of --fund. Whatever is unused lands in `balance`. */
export const PROGRAM_STORAGE_ALLOWANCE = nearToYocto('0.05');

export const GAS = {
  addSigner: 30n * 10n ** 12n,
  createProgram: 50n * 10n ** 12n,
  submitClaim: 150n * 10n ** 12n,
  dispute: 100n * 10n ** 12n,
  finalize: 50n * 10n ** 12n,
};

// ---------- add_signer ----------
export function addSignerArgs(algo: 'ed25519' | 'ecdsa', signingAddress: string, kind: SigKind, model: string | null) {
  return { signer: shared.signerId({ signing_algo: algo, signing_address: signingAddress }) as Signer, meta: { kind, model } };
}

// ---------- create_program ----------
export interface CreateProgramInput {
  name: string;
  repoUrl: string;
  commit: string;
  modelId: string;
  systemPromptHash: string;
  /** sha256hex of the published code bundle (shared.codeHash). */
  codeHash: string;
  payoutsNear: { low: string; medium: string; high: string; critical: string };
  ownerEncPubkey: string;
  disputeSecs: number;
  minConfidence: number;
  fundNear: string;
}

export function createProgramArgs(i: CreateProgramInput) {
  if (!/^[0-9a-f]{64}$/.test(i.systemPromptHash)) throw new Error('system_prompt_hash must be 64 lowercase hex');
  if (!/^[0-9a-f]{64}$/.test(i.codeHash)) throw new Error('code_hash must be 64 lowercase hex');
  if (!Number.isInteger(i.minConfidence) || i.minConfidence < 0 || i.minConfidence > 100)
    throw new Error('min-confidence must be an integer 0..100');
  if (!Number.isInteger(i.disputeSecs) || i.disputeSecs < 0) throw new Error('dispute-secs must be a non-negative integer');
  if (Buffer.from(i.ownerEncPubkey, 'base64').length !== 32) throw new Error('owner_enc_pubkey must be 32 bytes base64');
  const payouts: Payouts = {
    low: nearToYocto(i.payoutsNear.low).toString(),
    medium: nearToYocto(i.payoutsNear.medium).toString(),
    high: nearToYocto(i.payoutsNear.high).toString(),
    critical: nearToYocto(i.payoutsNear.critical).toString(),
  };
  const args = {
    name: i.name,
    repo_url: i.repoUrl,
    commit: i.commit,
    model_id: i.modelId,
    system_prompt_hash: i.systemPromptHash,
    code_hash: i.codeHash, // v2: right after system_prompt_hash
    payouts,
    owner_enc_pubkey: i.ownerEncPubkey,
    dispute_secs: i.disputeSecs,
    min_confidence: i.minConfidence,
  };
  const deposit = nearToYocto(i.fundNear) + PROGRAM_STORAGE_ALLOWANCE;
  return { args, deposit };
}

// ---------- submit_claim ----------
export function submitClaimArgs(programId: number, r: JudgeRecord, ciphertext: string) {
  if (r.signature_kind !== 'provider_tee' && r.signature_kind !== 'gateway') throw new Error(`bad kind ${r.signature_kind}`);
  return {
    program_id: programId,
    req_hash: r.req_hash,
    resp_body: r.response_body_b64, // Base64VecU8
    signature: r.signature,
    signer: shared.signerId(r) as Signer,
    kind: r.signature_kind,
    ciphertext,
  };
}

/** Deposit for submit_claim: (ciphertext bytes + fixed claim bytes) x storage price + margin. Excess is refunded. */
export function estimateClaimStorageDeposit(ciphertext: string): { bytes: bigint; deposit: bigint } {
  const bytes = BigInt(Buffer.byteLength(ciphertext, 'utf8')) + CLAIM_FIXED_BYTES;
  return { bytes, deposit: bytes * STORAGE_PRICE_PER_BYTE + CLAIM_DEPOSIT_MARGIN };
}

// ---------- dispute / finalize ----------
export const disputeArgs = (claimId: number, requestBody: string) => ({ claim_id: claimId, request_body: requestBody });
export const finalizeArgs = (claimId: number) => ({ claim_id: claimId });

// ---------- local pre-checks mirroring the contract ----------
/** Mirrors submit_claim's payability checks so hunters don't burn gas on a doomed claim. */
export function payabilityChecks(v: Verdict, program: Program): CheckRow[] {
  const payout = v.severity === 'none' ? 0n : BigInt(program.payouts[v.severity]);
  return [
    ['program open', program.open, String(program.open)],
    ['verdict.valid', v.valid === true, String(v.valid)],
    ['severity != none', v.severity !== 'none', v.severity],
    [`confidence >= min_confidence (${program.min_confidence})`, v.confidence >= program.min_confidence, String(v.confidence)],
    ['payout <= pool balance', payout <= BigInt(program.balance), `${formatNear(payout)} of ${formatNear(program.balance)}`],
  ];
}

/** Contract panic when a dispute is sent for a request that passes every v2 check. */
export const DISPUTE_INVALID_PANIC = 'dispute invalid: request matches program';

export interface SubmitPrecheck {
  check: RequestCheck;
  /** Non-null: do not send (unless --force). */
  refuse: string | null;
  /** Non-null: send is allowed but the owner can dispute. */
  warn: string | null;
}

/**
 * Hunter-side pre-check of the exact request body against the program (v2 dispute rules).
 * A fresh judgement must pass outright. A pre-recorded fixture is bound to whoever recorded it, so
 * a "hunter mismatch" there is only a warning (the owner can dispute it; nothing else is wrong).
 */
export function submitPrecheck(requestBody: string, program: ProgramBinding, hunter: string, fromFixture: boolean): SubmitPrecheck {
  const check = shared.checkRequestAgainstProgram(requestBody, program, hunter);
  if (check.ok) return { check, refuse: null, warn: null };
  if (check.reason === 'hunter mismatch' && fromFixture) {
    const bound = splitRequest(requestBody).hunter ?? '?';
    return { check, refuse: null, warn: `hunter mismatch: the owner can dispute (request is bound to ${bound}, you submit as ${hunter})` };
  }
  return { check, refuse: `${check.reason}: the program owner's dispute would reject this claim`, warn: null };
}

/** Bundle supplied by the hunter/owner must hash to program.code_hash. */
export function codeHashRow(bundle: string, expected: string): CheckRow {
  const h = shared.codeHash(bundle);
  return ['sha256(code bundle) == program.code_hash', h === expected, h];
}

/** Human summary of what a dispute will do for a given check result. */
export function disputeOutcome(check: RequestCheck): string {
  if (check.ok) return `contract would panic "${DISPUTE_INVALID_PANIC}"`;
  const extra = check.reason === 'hunter mismatch' ? '; req_hash is freed so the real hunter can resubmit' : '';
  return `claim -> Rejected, reason "${check.reason}"; payout returns to the pool${extra}`;
}

/** Splits a v2 request body into its parts (best effort, for display). */
export function splitRequest(requestBody: string): { target?: string; hunter?: string; code?: string; report?: string; raw: string } {
  let req: any;
  try {
    req = JSON.parse(requestBody);
  } catch {
    return { raw: requestBody };
  }
  const m1: string = typeof req?.messages?.[1]?.content === 'string' ? req.messages[1].content : '';
  const m2: string = typeof req?.messages?.[2]?.content === 'string' ? req.messages[2].content : '';
  const raw = [m1, m2].filter(Boolean).join('\n\n');
  const m = /^TARGET ([^\n]*)\nHUNTER ([^\n]*)\n\nCODE\n([\s\S]*)$/.exec(m1);
  if (!m) return { raw };
  return { target: m[1], hunter: m[2], code: m[3], report: m2.startsWith('REPORT\n') ? m2.slice(7) : undefined, raw };
}
