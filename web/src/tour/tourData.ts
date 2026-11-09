// Guided tour data layer (docs/demo-app-spec.md §8, §9). Live testnet is canonical; every datum falls back to the
// recorded snapshot (src/fixtures/tour-v3-snapshot.json) on any RPC failure or after a 4 s timeout, and the badge
// flips to SNAPSHOT. Pure helpers (claimTxs, recomputeReject, decryptClaim, withFallback) are unit-tested.
import { requestParamsHash } from '@sealedbounty/shared';
import snap from '../fixtures/tour-v3-snapshot.json';
import { proveCiphertext, type ProofResult } from '../lib/crypto';
import {
  decodeTx,
  getClaim,
  getProgram,
  getRevoked,
  getSigners,
  listContractTxs,
  panicMessage,
  parseClaim,
  parseProgram,
  RPC_URLS,
  rpcTx,
  verifyTeeResponse,
  type DecodedTx,
  type NbTxRow,
  type RpcOpts,
  type VerifyTeeArgs,
} from '../lib/near';
import { auditRequest, type RequestAudit } from '../lib/requestChecks';
import type { Claim, Program, SignerEntry, Verdict } from '../lib/types';
import { normaliseSigners, sha256hex } from '../lib/verify';
import { nsToMs } from '../lib/format';

export const TOUR_PROGRAM_ID: number = snap.program_id;
export const TOUR_CLAIM_IDS: number[] = snap.views.claims.map((c) => c.id);
export const SNAPSHOT_RECORDED_AT: string = snap.recorded_at;
export const TOUR_TIMEOUT_MS = 4000;
/**
 * An explicitly configured VITE_NEAR_RPC is the only RPC the tour uses (so a bad URL really exercises the snapshot
 * fallback); otherwise the app's usual list (FastNEAR first, then fallbacks). 4 s per call.
 */
export const TOUR_RPC: RpcOpts = {
  urls: import.meta.env.VITE_NEAR_RPC ? [import.meta.env.VITE_NEAR_RPC as string] : RPC_URLS,
  timeoutMs: TOUR_TIMEOUT_MS,
};

export type Source = 'live' | 'snapshot';
export interface Sourced<T> {
  data: T;
  source: Source;
  error: string | null;
}

/** Runs the live fetch; on any error or after `timeoutMs` returns the snapshot datum with source 'snapshot'. Never rejects. */
export function withFallback<T>(live: () => Promise<T>, snapshot: T, timeoutMs = TOUR_TIMEOUT_MS): Promise<Sourced<T>> {
  return new Promise((resolve) => {
    let done = false;
    const finish = (r: Sourced<T>) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      resolve(r);
    };
    const timer = setTimeout(() => finish({ data: snapshot, source: 'snapshot', error: `timeout after ${timeoutMs} ms` }), timeoutMs);
    let p: Promise<T>;
    try {
      p = live();
    } catch (e) {
      p = Promise.reject(e);
    }
    p.then(
      (data) => finish({ data, source: 'live', error: null }),
      (e) => finish({ data: snapshot, source: 'snapshot', error: (e as Error)?.message || String(e) }),
    );
  });
}

// ---- snapshot ----

export interface TourData {
  program: Program;
  signers: SignerEntry[];
  revoked: ReadonlySet<string>;
  claims: Claim[];
  txs: DecodedTx[];
}

const SNAP_TXS: DecodedTx[] = snap.txs.map((t) => decodeTx(t.raw, t.block_timestamp));
const SNAP_TX_BY_HASH = new Map(SNAP_TXS.map((t) => [t.hash, t]));
const SNAP_REVOKED: ReadonlySet<string> = new Set(
  Object.entries(snap.views.is_signer_revoked as Record<string, boolean>)
    .filter(([, r]) => r)
    .map(([s]) => s),
);

export function snapshotData(): TourData {
  return {
    program: parseProgram(snap.views.get_program),
    signers: normaliseSigners(snap.views.get_signers),
    revoked: SNAP_REVOKED,
    claims: snap.views.claims.map(parseClaim),
    txs: SNAP_TXS,
  };
}

// ---- tx-args reader: a claim's submit / dispute / flag / prove / finalize txs ----

export interface ClaimTxs {
  submit: DecodedTx | null;
  /** Failed submit_claim txs for the same req_hash (e.g. the honest hunter's "already claimed" after a front-run). */
  attempts: DecodedTx[];
  dispute: DecodedTx | null;
  flag: DecodedTx | null;
  prove: DecodedTx | null;
  /** The finalize that settled it (claim_paid or claim_rejected), else the last successful one. */
  finalize: DecodedTx | null;
  /** Other failed txs on this claim (e.g. finalize before the challenge deadline: "challenge open"). */
  failed: DecodedTx[];
}

export function claimTxs(txs: DecodedTx[], claim: Claim): ClaimTxs {
  const on = (t: DecodedTx) => t.claimIds.includes(claim.id);
  const ok = (m: string) => txs.filter((t) => t.ok && t.method === m && on(t));
  const fins = ok('finalize');
  return {
    submit: ok('submit_claim')[0] ?? null,
    attempts: txs.filter(
      (t) =>
        !t.ok &&
        t.method === 'submit_claim' &&
        t.args?.program_id === claim.program_id &&
        String(t.args?.req_hash ?? '').toLowerCase() === claim.req_hash.toLowerCase(),
    ),
    dispute: ok('dispute')[0] ?? null,
    flag: ok('flag_undecryptable')[0] ?? null,
    prove: ok('prove_ciphertext')[0] ?? null,
    finalize: fins.find((t) => t.paidClaimIds.includes(claim.id) || t.rejected.some((r) => r.claim_id === claim.id)) ?? fins.at(-1) ?? null,
    failed: txs.filter((t) => !t.ok && on(t)),
  };
}

// ---- gauntlet recompute ----

export interface RejectRecompute {
  /** The reason the contract would reject with, recomputed here (null = it would not reject). */
  computed: string | null;
  onchain: string | null;
  match: boolean;
  /** The tx whose args the recompute used (dispute / prove / finalize). */
  tx: string | null;
  via: 'dispute' | 'proof' | 'challenge' | 'none';
  /** Human lines explaining the computation (jargon OK: proof pane only). */
  detail: string[];
  audit: RequestAudit | null;
}

const short = (h: string | null | undefined) => (h ? `${h.slice(0, 10)}…` : 'null');

export function recomputeReject(claim: Claim, program: Program, txs: ClaimTxs, nowMs: number): RejectRecompute {
  const out = (computed: string | null, via: RejectRecompute['via'], tx: string | null, detail: string[], audit: RequestAudit | null = null): RejectRecompute => ({
    computed,
    onchain: claim.reject_reason,
    match: computed === claim.reject_reason,
    tx,
    via,
    detail,
    audit,
  });

  const auditBody = (body: string, via: 'dispute' | 'proof', tx: string): RejectRecompute => {
    const detail: string[] = [];
    const bh = sha256hex(body);
    detail.push(`sha256(request_body) ${bh === claim.req_hash ? '=' : '≠'} claim.req_hash (${short(claim.req_hash)})`);
    if (bh !== claim.req_hash) return out('body mismatch', via, tx, detail);
    const audit = auditRequest(body, program, claim.hunter);
    let ph: string | null = null;
    try {
      ph = requestParamsHash(body);
    } catch {
      /* rejected number token */
    }
    for (const c of audit.checks) {
      if (c.key === 'params') detail.push(`requestParamsHash(body) ${short(ph)} ${ph === program.params_hash ? '=' : '≠'} program.params_hash ${short(program.params_hash)}`);
      else if (c.ok === false) detail.push(`${c.label}: ${c.detail}`);
    }
    if (audit.ok) detail.push('all 6 dispute checks pass');
    return out(audit.reason, via, tx, detail, audit);
  };

  if (txs.dispute?.args && typeof txs.dispute.args.request_body === 'string') return auditBody(txs.dispute.args.request_body, 'dispute', txs.dispute.hash);

  if (txs.flag) {
    if (txs.prove) {
      const p = decryptClaim(claim, program, txs);
      if (!p.ok) return out('undecryptable report', 'proof', txs.prove.hash, [`prove_ciphertext secret does not open the box: ${p.reason}`]);
      return auditBody(p.plaintext, 'proof', txs.prove.hash);
    }
    const deadline = claim.challenge_deadline;
    if (deadline === null) return out(null, 'challenge', txs.flag.hash, ['flagged, but no challenge_deadline onchain']);
    const dl = nsToMs(deadline);
    const passed = nowMs >= dl;
    const detail = [
      `flag_undecryptable → challenge_deadline ${new Date(dl).toISOString()}`,
      `no prove_ciphertext tx from ${claim.hunter}`,
      passed ? `now ${new Date(nowMs).toISOString()} ≥ deadline: finalize must reject` : `deadline not reached: the hunter can still prove`,
    ];
    if (passed && claim.bond) detail.push(`bond forfeited to the pool`);
    return out(passed ? 'undecryptable report' : null, 'challenge', txs.finalize?.hash ?? txs.flag.hash, detail);
  }
  return out(null, 'none', null, ['never disputed or challenged']);
}

/** Keyless decryption of a challenged-then-proven claim: the hunter's revealed ephemeral secret opens the onchain box. */
export function decryptClaim(claim: Claim, program: Program, txs: ClaimTxs): ProofResult & { secret?: string } {
  const secret = txs.prove?.args?.ephemeral_secret;
  if (typeof secret !== 'string') return { ok: false, reason: 'bad secret' };
  return { ...proveCiphertext(claim.ciphertext, program.owner_enc_pubkey, secret, claim.req_hash), secret };
}

// ---- live loaders (each datum falls back on its own) ----

export interface ProgramView {
  program: Program;
  signers: SignerEntry[];
  revoked: ReadonlySet<string>;
}

export interface LoadResult<T> {
  data: T;
  source: Source;
  errors: string[];
}

const combine = (rs: Sourced<unknown>[]): { source: Source; errors: string[] } => ({
  source: rs.every((r) => r.source === 'live') ? 'live' : 'snapshot',
  errors: rs.map((r) => r.error).filter((e): e is string => !!e),
});

/** Step 3 'Load live': getProgram + getSigners + getRevoked. */
export async function loadProgramView(): Promise<LoadResult<ProgramView>> {
  const s = snapshotData();
  const [p, sg] = await Promise.all([
    withFallback(async () => {
      const p = await getProgram(TOUR_PROGRAM_ID, TOUR_RPC);
      if (!p) throw new Error(`program ${TOUR_PROGRAM_ID} not found`);
      return p;
    }, s.program),
    withFallback(() => getSigners(TOUR_RPC), s.signers),
  ]);
  const rv = await withFallback(
    async () => (await getRevoked([...(p.data.signers ?? []), ...s.claims.map((c) => c.signer)], { ...TOUR_RPC, strict: true }))!,
    s.revoked,
  );
  return { data: { program: p.data, signers: sg.data, revoked: rv.data }, ...combine([p, sg, rv]) };
}

export async function loadClaims(): Promise<LoadResult<Claim[]>> {
  const s = snapshotData();
  const rs = await Promise.all(
    s.claims.map((c) =>
      withFallback(async () => {
        const live = await getClaim(c.id, TOUR_RPC);
        if (!live) throw new Error(`claim ${c.id} not found`);
        return live;
      }, c),
    ),
  );
  return { data: rs.map((r) => r.data), ...combine(rs) };
}

const TX_METHODS = new Set(['submit_claim', 'dispute', 'flag_undecryptable', 'prove_ciphertext', 'finalize']);

/**
 * Tx hashes from nearblocks (the program-1 window), then each tx's args from RPC `tx`. A tx that can't be read live
 * falls back to its snapshot copy; nearblocks down → the snapshot's hash list.
 */
export async function loadTxs(claims: Claim[]): Promise<LoadResult<DecodedTx[]>> {
  const snapRows: NbTxRow[] = snap.txs.map((t) => ({ hash: t.hash, signer: t.signer, method: t.method, ok: t.ok, blockTimestamp: t.block_timestamp }));
  const rows = await withFallback(() => listContractTxs({ timeoutMs: TOUR_TIMEOUT_MS }), snapRows);
  const lo = claims.reduce((m, c) => (BigInt(c.submitted_at) < m ? BigInt(c.submitted_at) : m), BigInt(claims[0].submitted_at)) - 60_000_000_000n;
  const hi = snapRows.reduce((m, r) => (BigInt(r.blockTimestamp) > m ? BigInt(r.blockTimestamp) : m), 0n) + 600_000_000_000n;
  const cand = new Map<string, NbTxRow>();
  for (const r of rows.data) {
    const ts = BigInt(r.blockTimestamp || '0');
    if (r.method && TX_METHODS.has(r.method) && ts >= lo && ts <= hi) cand.set(r.hash, r);
  }
  if (rows.source === 'live') for (const r of snapRows) if (!cand.has(r.hash)) cand.set(r.hash, r); // keep the recorded set complete
  const list = [...cand.values()];
  const results: Sourced<DecodedTx | null>[] = [];
  for (let i = 0; i < list.length; i += 6) {
    results.push(
      ...(await Promise.all(
        list.slice(i, i + 6).map((r) =>
          withFallback(async () => decodeTx(await rpcTx(r.hash, r.signer, TOUR_RPC), r.blockTimestamp), SNAP_TX_BY_HASH.get(r.hash) ?? null),
        ),
      )),
    );
  }
  const ids = new Set(claims.map((c) => c.id));
  const reqs = new Set(claims.map((c) => c.req_hash));
  const txs = results
    .map((r) => r.data)
    .filter((t): t is DecodedTx => !!t && (t.claimIds.some((id) => ids.has(id)) || (t.method === 'submit_claim' && reqs.has(String(t.args?.req_hash ?? '').toLowerCase()))))
    .sort((a, b) => (BigInt(a.blockTimestamp ?? '0') < BigInt(b.blockTimestamp ?? '0') ? -1 : 1));
  return { data: txs, ...combine([rows, ...results]) };
}

// ---- step 5 'Ask the contract': a free RPC view of verify_tee_response ----

/** verify_tee_response args from a claim's submit_claim tx (resp_body overridable: the flipped-byte variant). */
export function askContractArgs(claim: Claim, submit: DecodedTx, respBodyB64?: string): VerifyTeeArgs {
  const a = submit.args ?? {};
  return {
    model: claim.model,
    req_hash: String(a.req_hash ?? claim.req_hash),
    resp_body: respBodyB64 ?? String(a.resp_body ?? ''),
    signature: String(a.signature ?? claim.signature),
    signer: String(a.signer ?? claim.signer),
    kind: String(a.kind ?? claim.kind),
  };
}

type AskAnswer = { ok: true; verdict: Verdict } | { ok: false; error: string };
export type AskResult = AskAnswer & {
  /** 'snapshot': the RPC was unreachable and the answer is the recorded one (rpcError says why). */
  source: Source;
  rpcError: string | null;
};

const b64Bytes = (b: string): Uint8Array | null => {
  try {
    return Uint8Array.from(atob(b), (c) => c.charCodeAt(0));
  } catch {
    return null;
  }
};

/**
 * Snapshot answer: the contract accepted this exact (req_hash, resp_body, signature, signer) in a recorded
 * submit_claim, so it returns that claim's stored verdict; any other body breaks the signature → "bad signature".
 */
function snapshotAnswer(args: VerifyTeeArgs): AskAnswer {
  const body = b64Bytes(args.resp_body);
  const h = body ? sha256hex(body) : null;
  const c = snapshotData().claims.find(
    (c) => c.req_hash === args.req_hash.toLowerCase() && c.resp_hash === h && c.signature === args.signature.toLowerCase() && c.signer === args.signer,
  );
  return c ? { ok: true, verdict: c.verdict } : { ok: false, error: 'bad signature' };
}

/** Asks the deployed contract (RPC call_function: no wallet, no gas). A panic is an answer; a transport failure → snapshot. */
export async function askContract(args: VerifyTeeArgs, rpc: RpcOpts = TOUR_RPC): Promise<AskResult> {
  const r = await withFallback<AskAnswer>(
    async () => {
      try {
        return { ok: true, verdict: await verifyTeeResponse(args, rpc) };
      } catch (e) {
        const panic = panicMessage(e);
        if (panic !== null) return { ok: false, error: panic };
        throw e;
      }
    },
    snapshotAnswer(args),
    rpc.timeoutMs ?? TOUR_TIMEOUT_MS,
  );
  return { ...r.data, source: r.source, rpcError: r.error };
}
