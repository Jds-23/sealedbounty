// Pure builders for contract call args (no network). Unit-tested in test/args.test.ts.
import { shared, type DisputeReason, type ProgramBinding, type RequestCheck } from './shared.js';
import type { CheckRow, Claim, ClaimStatus, JudgeRecord, Payouts, Program, SigKind, Signer, Verdict } from './types.js';
import { formatNear, nearToYocto, nsToIso } from './util.js';

/** v3 defaults for create-program. */
export const DEFAULT_BOND_NEAR = '0.05';
export const DEFAULT_CHALLENGE_SECS = 600;

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
  // finalize -> transfer -> on_payout (10 Tgas static) callback
  finalize: 80n * 10n ** 12n,
  flagUndecryptable: 30n * 10n ** 12n,
  // opens the nacl box + full dispute checks on the plaintext
  proveCiphertext: 150n * 10n ** 12n,
  setProgramSigners: 30n * 10n ** 12n,
  revokeSigner: 30n * 10n ** 12n,
};

// ---------- signers ----------
const SIGNER_RE = /^(ed25519:[0-9a-f]{64}|eth:0x[0-9a-f]{40})$/;

/** Normalizes + validates one contract Signer string. */
export function normalizeSigner(s: string): Signer {
  const v = s.trim().toLowerCase();
  if (!SIGNER_RE.test(v)) throw new Error(`bad signer "${s}": expected ed25519:<64 hex> or eth:0x<40 hex>`);
  return v;
}

/** `--signers a,b c` -> deduped, validated list (order kept). */
export function parseSigners(list: string[] | string): Signer[] {
  const parts = (Array.isArray(list) ? list : [list]).flatMap((x) => x.split(/[\s,]+/)).filter(Boolean);
  return [...new Set(parts.map(normalizeSigner))];
}

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
  /** v3 #1: shared.paramsHash(). */
  paramsHash: string;
  payoutsNear: { low: string; medium: string; high: string; critical: string };
  ownerEncPubkey: string;
  disputeSecs: number;
  minConfidence: number;
  fundNear: string;
  /** v3 #4: hunter bond in NEAR (default DEFAULT_BOND_NEAR). */
  bondNear?: string;
  /** v3 #2: prove_ciphertext window (default DEFAULT_CHALLENGE_SECS). */
  challengeSecs?: number;
  /** v3 #3: explicit program signers; undefined/empty -> null = contract snapshots the model-matched allowlist. */
  signers?: Signer[];
}

export function createProgramArgs(i: CreateProgramInput) {
  if (!/^[0-9a-f]{64}$/.test(i.systemPromptHash)) throw new Error('system_prompt_hash must be 64 lowercase hex');
  if (!/^[0-9a-f]{64}$/.test(i.codeHash)) throw new Error('code_hash must be 64 lowercase hex');
  if (!/^[0-9a-f]{64}$/.test(i.paramsHash)) throw new Error('params_hash must be 64 lowercase hex');
  const challengeSecs = i.challengeSecs ?? DEFAULT_CHALLENGE_SECS;
  if (!Number.isInteger(challengeSecs) || challengeSecs < 0) throw new Error('challenge-secs must be a non-negative integer');
  const bond = nearToYocto(i.bondNear ?? DEFAULT_BOND_NEAR);
  const signers = i.signers?.length ? i.signers.map(normalizeSigner) : null;
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
    params_hash: i.paramsHash, // v3 #1
    payouts,
    owner_enc_pubkey: i.ownerEncPubkey,
    dispute_secs: i.disputeSecs,
    min_confidence: i.minConfidence,
    bond: bond.toString(), // v3 #4
    challenge_secs: challengeSecs, // v3 #2
    signers, // v3 #3: null = snapshot of the model-matched global allowlist
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

/** v3 #4: submit_claim attaches storage + program.bond (else "insufficient bond"). Unused storage is refunded. */
export function submitDeposit(ciphertext: string, programBond: string | bigint | undefined) {
  const { bytes, deposit: storage } = estimateClaimStorageDeposit(ciphertext);
  const bond = BigInt(programBond ?? 0);
  return { bytes, storage, bond, deposit: storage + bond };
}

// ---------- dispute / finalize / v3 methods ----------
export const disputeArgs = (claimId: number, requestBody: string) => ({ claim_id: claimId, request_body: requestBody });
export const finalizeArgs = (claimId: number) => ({ claim_id: claimId });
export const flagUndecryptableArgs = (claimId: number) => ({ claim_id: claimId });
export function proveCiphertextArgs(claimId: number, ephemeralSecretHex: string) {
  if (!/^[0-9a-f]{64}$/.test(ephemeralSecretHex)) throw new Error('ephemeral_secret must be 64 hex chars (lowercase)');
  return { claim_id: claimId, ephemeral_secret: ephemeralSecretHex };
}
export function setProgramSignersArgs(programId: number, signers: Signer[]) {
  if (!signers.length) throw new Error('set_program_signers needs at least one signer');
  return { program_id: programId, signers: signers.map(normalizeSigner) };
}
export const revokeSignerArgs = (signer: Signer) => ({ signer: normalizeSigner(signer) });

/** Printed after `attest --register`: programs snapshot their signers, so rotation is per program. */
export const attestRotationHint = () =>
  'NOTE: programs snapshot their signer set at creation (v3 #3); a newly registered signer does NOT apply to existing programs.\n' +
  '  each program owner must run: sealedbounty set-program-signers --program <id> --signers <signer>[,<signer>...]';

// ---------- status display ----------
const NS = 1_000_000_000n;
export function fmtDuration(secs: bigint): string {
  const s = secs < 0n ? 0n : secs;
  const h = s / 3600n;
  const m = (s % 3600n) / 60n;
  const r = s % 60n;
  return h ? `${h}h ${m}m` : `${m}m ${r}s`;
}

/** One-line status incl. the v3 Challenged deadline countdown and PayoutFailed. */
export function claimStatusLabel(c: Claim, nowNs: bigint = BigInt(Date.now()) * 1_000_000n): string {
  switch (c.status) {
    case 'Challenged': {
      if (!c.challenge_deadline) return 'Challenged';
      const d = BigInt(c.challenge_deadline);
      if (d <= nowNs) return 'Challenged (deadline passed: finalize rejects "undecryptable report")';
      return `Challenged (hunter must prove by ${nsToIso(c.challenge_deadline)}, ${fmtDuration((d - nowNs) / NS)} left)`;
    }
    case 'PayoutFailed':
      return 'PayoutFailed (transfer failed; payout + bond credited back to the pool)';
    case 'Pending':
      return BigInt(c.finalize_after) <= nowNs ? 'Pending (finalizable)' : 'Pending';
    default:
      return c.status + (c.reject_reason ? ` (${c.reject_reason})` : '');
  }
}

// ---------- finalize outcome ----------
export interface FinalizeOutcome {
  status: ClaimStatus | 'unknown';
  reason?: string;
  text: string;
}

/** NEP-297 events in tx logs (EVENT_JSON:{...}); malformed lines are skipped. */
export function parseEvents(logs: string[]): { event: string; data: any }[] {
  const out: { event: string; data: any }[] = [];
  for (const l of logs) {
    if (!l.startsWith('EVENT_JSON:')) continue;
    try {
      const e = JSON.parse(l.slice('EVENT_JSON:'.length));
      if (e && typeof e.event === 'string') out.push({ event: e.event, data: e.data });
    } catch {
      /* not an event */
    }
  }
  return out;
}

/** What finalize did, from its tx logs (payout_failed > claim_rejected > claim_paid), else from the claim after the tx. */
export function finalizeOutcome(logs: string[], after?: Claim | null): FinalizeOutcome {
  const ev = parseEvents(logs);
  const has = (n: string) => ev.find((e) => e.event === n);
  const failed = has('payout_failed');
  if (failed || after?.status === 'PayoutFailed') {
    const amt = failed?.data?.amount;
    return { status: 'PayoutFailed', text: `PayoutFailed: transfer to the hunter failed; ${amt ? formatNear(amt) + ' ' : ''}(payout + bond) credited back to the pool` };
  }
  const rej = has('claim_rejected');
  if (rej || after?.status === 'Rejected') {
    const reason: string = rej?.data?.reason ?? after?.reject_reason ?? '?';
    return { status: 'Rejected', reason, text: `Rejected (${reason}); payout + bond go to the pool` };
  }
  const paid = has('claim_paid');
  if (paid || after?.status === 'Paid') {
    const amt = paid?.data?.payout ? ` ${formatNear(paid.data.payout)}${paid.data.bond ? ` + bond ${formatNear(paid.data.bond)}` : ''}` : '';
    return { status: 'Paid', text: `Paid${amt} to the hunter` };
  }
  if (after) return { status: after.status, text: after.status };
  return { status: 'unknown', text: 'unknown (no claim_paid / claim_rejected / payout_failed event in the logs)' };
}

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

// ---------- dispute rules by program version (#14) ----------
export type ProgramVersion = 1 | 2 | 3;
/** v1: no code_hash. v2: code_hash, no params_hash. v3: both. (Older contracts' views omit the fields.) */
export function programVersion(p: { code_hash?: unknown; params_hash?: unknown }): ProgramVersion {
  if (p.code_hash == null) return 1;
  return p.params_hash == null ? 2 : 3;
}

type Step = 'prompt' | 'model' | 'params' | 'code' | 'hunter' | 'report';
const STEPS: { step: Step; name: string; reason: DisputeReason }[] = [
  { step: 'prompt', name: 'system prompt', reason: 'system prompt tampered' },
  { step: 'model', name: 'model', reason: 'model mismatch' },
  { step: 'params', name: 'params', reason: 'params tampered' },
  { step: 'code', name: 'code', reason: 'code mismatch' },
  { step: 'hunter', name: 'hunter', reason: 'hunter mismatch' },
  { step: 'report', name: 'report', reason: 'report missing' },
];
const STEPS_BY_VERSION: Record<ProgramVersion, Step[]> = {
  1: ['prompt', 'model'],
  2: ['prompt', 'model', 'code', 'hunter', 'report'],
  3: ['prompt', 'model', 'params', 'code', 'hunter', 'report'],
};

/** e.g. "v1 dispute rules: prompt, model" */
export function disputeRules(program: { code_hash?: unknown; params_hash?: unknown }): string {
  const v = programVersion(program);
  return `v${v} dispute rules: ${STEPS_BY_VERSION[v].join(', ')}`;
}

export interface VersionedCheck {
  version: ProgramVersion;
  /** e.g. "v1 dispute rules: prompt, model" */
  rules: string;
  check: RequestCheck;
  /** One row per applicable step in contract order, up to and including the first failure. */
  rows: CheckRow[];
}

/**
 * v1 contract dispute: only the system prompt hash and the model are pinned (no code/hunter/params).
 * Gated here rather than in shared/judge.mjs, whose checkRequestAgainstProgram assumes a code_hash.
 */
function checkV1(requestBody: string, program: Pick<ProgramBinding, 'system_prompt_hash' | 'model_id'>): RequestCheck {
  const fail = (reason: DisputeReason): RequestCheck => ({ ok: false, reason });
  let req: any;
  try {
    req = JSON.parse(requestBody);
  } catch {
    return fail('system prompt tampered');
  }
  const m0 = Array.isArray(req?.messages) ? req.messages[0] : undefined;
  if (!m0 || m0.role !== 'system' || typeof m0.content !== 'string' || shared.sha256hex(m0.content) !== program.system_prompt_hash) {
    return fail('system prompt tampered');
  }
  if (req.model !== program.model_id) return fail('model mismatch');
  return { ok: true, reason: null };
}

/** The owner's dispute rules for this program's contract version (v1: prompt + model; v2: no params; v3: all six). */
export function checkRequestForProgram(requestBody: string, program: ProgramBinding, hunter: string, rowPrefix = ''): VersionedCheck {
  const version = programVersion(program);
  const steps = STEPS.filter((s) => STEPS_BY_VERSION[version].includes(s.step));
  const rules = disputeRules(program);
  const check = version === 1 ? checkV1(requestBody, program) : shared.checkRequestAgainstProgram(requestBody, program, hunter);
  const rows: CheckRow[] = [];
  for (const s of steps) {
    const failed = !check.ok && check.reason === s.reason;
    rows.push([`${rowPrefix}${s.name}`, !failed, failed ? s.reason : 'ok']);
    if (failed) break;
  }
  return { version, rules, check, rows };
}

/**
 * Hunter-side pre-check of the exact request body against the program (dispute rules for its version).
 * A fresh judgement must pass outright. A pre-recorded fixture is bound to whoever recorded it, so
 * a "hunter mismatch" there is only a warning (the owner can dispute it; nothing else is wrong).
 */
export function submitPrecheck(requestBody: string, program: ProgramBinding, hunter: string, fromFixture: boolean): SubmitPrecheck {
  const { check } = checkRequestForProgram(requestBody, program, hunter);
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
