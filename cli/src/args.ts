// Pure builders for contract call args (no network). Unit-tested in test/args.test.ts.
import { shared } from './shared.js';
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
  payoutsNear: { low: string; medium: string; high: string; critical: string };
  ownerEncPubkey: string;
  disputeSecs: number;
  minConfidence: number;
  fundNear: string;
}

export function createProgramArgs(i: CreateProgramInput) {
  if (!/^[0-9a-f]{64}$/.test(i.systemPromptHash)) throw new Error('system_prompt_hash must be 64 lowercase hex');
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

/** What the program owner would check in a dispute: is the request bound to this program's prompt + model? */
export function promptBindingChecks(requestBody: string, program: Pick<Program, 'model_id' | 'system_prompt_hash'>, sha: (s: string) => string): CheckRow[] {
  let req: any;
  try {
    req = JSON.parse(requestBody);
  } catch (e) {
    return [['request_body is JSON', false, (e as Error).message]];
  }
  const m0 = req?.messages?.[0];
  const h = m0?.role === 'system' && typeof m0.content === 'string' ? sha(m0.content) : '(no system message)';
  return [
    ['messages[0].role == system', m0?.role === 'system', String(m0?.role)],
    ['sha256(system prompt) == program.system_prompt_hash', h === program.system_prompt_hash, h],
    ['model == program.model_id', req?.model === program.model_id, String(req?.model)],
  ];
}

/** Extracts the hunter's user message ("TARGET ...\n\n<code>\n\nREPORT\n<report>"). */
export function splitUserMessage(requestBody: string): { target?: string; code?: string; report?: string; raw: string } {
  const req = JSON.parse(requestBody);
  const raw: string = req?.messages?.find((m: any) => m.role === 'user')?.content ?? '';
  const m = /^TARGET (.*?)\n\n([\s\S]*)\n\nREPORT\n([\s\S]*)$/.exec(raw);
  if (!m) return { raw };
  return { target: m[1], code: m[2], report: m[3], raw };
}
