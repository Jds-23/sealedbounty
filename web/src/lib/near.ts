// Read-only NEAR JSON-RPC (call_function). No wallet, no writes.
// Shapes checked against the live v1 contract (src/fixtures/live-views.json); v2 adds Program.code_hash,
// v3 adds Program.{params_hash, signers, bond, challenge_secs}, Claim.{bond, challenge_deadline}, is_signer_revoked:
//   list_programs {from_index, limit}  get_program {id}  list_claims {program_id, from_index, limit}
//   get_claim {id}  get_signers {} -> [[signer, {kind, model}]]  get_owner {} -> account id
// ids are u64 JSON numbers, amounts U128 decimal strings, timestamps U64 nanosecond strings.
import type { Claim, ClaimStatus, Program, SignerEntry } from './types';
import { normaliseSigners } from './verify';

export const CONTRACT_ID: string = import.meta.env.VITE_ESCROW_CONTRACT_ID || 'sealedbounty-v3.testnet';
/**
 * Configured RPC first, then public fallbacks. FastNEAR is the default: rpc.testnet.near.org rate-limits
 * hard (HTTP 429 without CORS headers, so the browser sees a CORS error).
 */
export const RPC_URLS: string[] = [
  ...new Set([import.meta.env.VITE_NEAR_RPC || 'https://test.rpc.fastnear.com', 'https://test.rpc.fastnear.com', 'https://rpc.testnet.near.org']),
];
/** Index of the last RPC that answered; later calls start there instead of re-hitting a failing one. */
let rpcStart = 0;
export const RPC_URL = RPC_URLS[0];
export const EXPLORER = 'https://testnet.nearblocks.io';
export const explorerAccount = (a: string) => `${EXPLORER}/address/${a}`;
export const explorerTx = (h: string) => `${EXPLORER}/txns/${h}`;

const b64 = (s: string) => btoa(unescape(encodeURIComponent(s)));

/** Per-call overrides (the tour uses a 4 s timeout and, with an explicit VITE_NEAR_RPC, that RPC only). */
export interface RpcOpts {
  urls?: string[];
  timeoutMs?: number;
}

async function viewAt<T>(url: string, method: string, args: Record<string, unknown>, timeoutMs = 8000): Promise<T> {
  const res = await fetch(url, {
    method: 'POST',
    signal: AbortSignal.timeout(timeoutMs),
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 'sb',
      method: 'query',
      params: {
        request_type: 'call_function',
        finality: 'final',
        account_id: CONTRACT_ID,
        method_name: method,
        args_base64: b64(JSON.stringify(args)),
      },
    }),
  });
  if (!res.ok) throw new Error(`RPC HTTP ${res.status}`);
  const j = await res.json();
  if (j.error) {
    const data = typeof j.error?.data === 'string' ? j.error.data : '';
    const vm = String(j.error?.cause?.info?.vm_error ?? '');
    // Keep the panic text when there is one, so callers can show "bad signature" (see panicMessage).
    throw new Error([vm, data].find((s) => /GuestPanic/.test(s)) || j.error?.cause?.name || data || j.error?.message || 'RPC error');
  }
  if (j.result?.error) throw new Error(j.result.error);
  const bytes = new Uint8Array(j.result.result as number[]);
  return JSON.parse(new TextDecoder().decode(bytes)) as T;
}

/** Contract-level errors (CodeDoesNotExist, panics) are final; transport errors (429, 5xx, timeout) try the next RPC. */
const isContractError = (m: string) => /CodeDoesNotExist|AccountDoesNotExist|GuestPanic|MethodNotFound|wasm execution/i.test(m);

export async function view<T>(method: string, args: Record<string, unknown> = {}, opts: RpcOpts = {}): Promise<T> {
  if (opts.urls) return viewVia<T>(opts.urls, method, args, opts.timeoutMs);
  let last: Error = new Error('no RPC configured');
  for (let i = 0; i < RPC_URLS.length; i++) {
    const idx = (rpcStart + i) % RPC_URLS.length;
    try {
      const r = await viewAt<T>(RPC_URLS[idx], method, args, opts.timeoutMs);
      rpcStart = idx;
      return r;
    } catch (e) {
      last = e as Error;
      if (isContractError(last.message)) throw last;
    }
  }
  throw last;
}

async function viewVia<T>(urls: string[], method: string, args: Record<string, unknown>, timeoutMs?: number): Promise<T> {
  let last: Error = new Error('no RPC configured');
  for (const url of urls) {
    try {
      return await viewAt<T>(url, method, args, timeoutMs);
    } catch (e) {
      last = e as Error;
      if (isContractError(last.message)) throw last;
    }
  }
  throw last;
}

// ---- runtime parsing: accept the contract's JSON, coerce tolerable variants, reject garbage ----

const num = (v: unknown, f: string): number => {
  const n = typeof v === 'string' && /^\d+$/.test(v) ? Number(v) : v;
  if (typeof n !== 'number' || !Number.isInteger(n) || n < 0) throw new Error(`${f}: expected u64 number, got ${JSON.stringify(v)}`);
  return n;
};
/** U128/U64 are JSON strings; tolerate numbers (exact only if safe ints). */
const big = (v: unknown, f: string): string => {
  if (typeof v === 'string' && /^\d+$/.test(v)) return v;
  if (typeof v === 'number' && Number.isSafeInteger(v) && v >= 0) return String(v);
  throw new Error(`${f}: expected decimal string, got ${JSON.stringify(v)}`);
};
const str = (v: unknown, f: string): string => {
  if (typeof v !== 'string') throw new Error(`${f}: expected string`);
  return v;
};
const hex = (v: unknown, f: string): string => str(v, f).toLowerCase().replace(/^0x/, '');
const sha256Hex = (v: unknown, f: string): string => {
  const h = hex(v, f);
  if (!/^[0-9a-f]{64}$/.test(h)) throw new Error(`${f}: expected 64 hex chars`);
  return h;
};
const signerList = (v: unknown): string[] => {
  if (!Array.isArray(v) || !v.every((x) => typeof x === 'string')) throw new Error('signers: expected string[]');
  return v as string[];
};
const STATUSES: ClaimStatus[] = ['Pending', 'Rejected', 'Paid', 'Challenged', 'PayoutFailed'];

export function parseProgram(r: unknown): Program {
  const p = r as Record<string, any>;
  if (!p || typeof p !== 'object') throw new Error('program: not an object');
  return {
    id: num(p.id, 'program.id'),
    owner: str(p.owner, 'owner'),
    name: str(p.name, 'name'),
    repo_url: str(p.repo_url, 'repo_url'),
    commit: str(p.commit, 'commit'),
    model_id: str(p.model_id, 'model_id'),
    system_prompt_hash: hex(p.system_prompt_hash, 'system_prompt_hash'),
    // v2 programs carry code_hash; v1 (escrow.baldingsucks7993.testnet) data has none.
    code_hash: p.code_hash == null ? null : sha256Hex(p.code_hash, 'code_hash'),
    // v3 fields; v1/v2 programs have none (-> null).
    params_hash: p.params_hash == null ? null : sha256Hex(p.params_hash, 'params_hash'),
    signers: p.signers == null ? null : signerList(p.signers),
    bond: p.bond == null ? null : big(p.bond, 'bond'),
    challenge_secs: p.challenge_secs == null ? null : num(p.challenge_secs, 'challenge_secs'),
    payouts: {
      low: big(p.payouts?.low, 'payouts.low'),
      medium: big(p.payouts?.medium, 'payouts.medium'),
      high: big(p.payouts?.high, 'payouts.high'),
      critical: big(p.payouts?.critical, 'payouts.critical'),
    },
    owner_enc_pubkey: str(p.owner_enc_pubkey, 'owner_enc_pubkey'),
    dispute_secs: num(p.dispute_secs, 'dispute_secs'),
    min_confidence: num(p.min_confidence, 'min_confidence'),
    balance: big(p.balance, 'balance'),
    reserved: big(p.reserved, 'reserved'),
    open: Boolean(p.open),
    created_at: big(p.created_at, 'created_at'),
  };
}

export function parseClaim(r: unknown): Claim {
  const c = r as Record<string, any>;
  if (!c || typeof c !== 'object') throw new Error('claim: not an object');
  const status = STATUSES.find((s) => s.toLowerCase() === String(c.status).toLowerCase());
  if (!status) throw new Error(`claim.status: unknown ${JSON.stringify(c.status)}`);
  const v = c.verdict ?? {};
  return {
    id: num(c.id, 'claim.id'),
    program_id: num(c.program_id, 'claim.program_id'),
    hunter: str(c.hunter, 'hunter'),
    req_hash: hex(c.req_hash, 'req_hash'),
    resp_hash: hex(c.resp_hash, 'resp_hash'),
    verdict: {
      valid: Boolean(v.valid),
      severity: str(v.severity, 'verdict.severity') as Claim['verdict']['severity'],
      cwe: v.cwe ?? null,
      confidence: num(v.confidence, 'verdict.confidence'),
    },
    signer: str(c.signer, 'signer'),
    kind: str(c.kind, 'kind') as Claim['kind'],
    signature: hex(c.signature, 'signature'),
    model: str(c.model, 'model'),
    ciphertext: str(c.ciphertext, 'ciphertext'),
    status,
    payout: big(c.payout, 'payout'),
    submitted_at: big(c.submitted_at, 'submitted_at'),
    finalize_after: big(c.finalize_after, 'finalize_after'),
    reject_reason: c.reject_reason ?? null,
    bond: c.bond == null ? null : big(c.bond, 'bond'),
    challenge_deadline: c.challenge_deadline == null ? null : big(c.challenge_deadline, 'challenge_deadline'),
  };
}

const PAGE = 50; // contract DEFAULT_LIMIT

async function paged<T>(fetchPage: (from: number) => Promise<unknown[]>, parse: (r: unknown) => T): Promise<T[]> {
  const out: T[] = [];
  for (let from = 0; ; from += PAGE) {
    const page = await fetchPage(from);
    out.push(...page.map(parse));
    if (page.length < PAGE || from > 10_000) return out;
  }
}

export const getSigners = async (opts?: RpcOpts): Promise<SignerEntry[]> => normaliseSigners(await view('get_signers', {}, opts));
export const listPrograms = () => paged((from_index) => view<unknown[]>('list_programs', { from_index, limit: PAGE }), parseProgram);
export const getProgram = async (id: number, opts?: RpcOpts) => {
  const r = await view<unknown>('get_program', { id }, opts);
  return r == null ? null : parseProgram(r);
};
export const listClaims = (program_id: number) =>
  paged((from_index) => view<unknown[]>('list_claims', { program_id, from_index, limit: PAGE }), parseClaim);
export const getClaim = async (id: number, opts?: RpcOpts) => {
  const r = await view<unknown>('get_claim', { id }, opts);
  return r == null ? null : parseClaim(r);
};
export const getOwner = () => view<string>('get_owner');

/** verify_tee_response view args: the TEE fields of a submit_claim, plus the signed model. */
export interface VerifyTeeArgs {
  model: string;
  req_hash: string;
  /** base64 */
  resp_body: string;
  /** hex */
  signature: string;
  /** "ed25519:<hex>" */
  signer: string;
  kind: string;
}

/** The contract's panic text from an RPC error ("...GuestPanic { panic_msg: \"bad signature\" }" → "bad signature"), else null. */
export function panicMessage(e: unknown): string | null {
  const m = /GuestPanic\s*\{\s*panic_msg:\s*\\?"((?:[^"\\]|\\.)*?)\\?"\s*\}/.exec(String((e as Error)?.message ?? e));
  return m ? m[1] : null;
}

/** Free RPC view: the contract re-runs its TEE signature check and returns the Verdict, or panics (thrown). */
export const verifyTeeResponse = (args: VerifyTeeArgs, opts?: RpcOpts) =>
  view<Claim['verdict']>('verify_tee_response', args as unknown as Record<string, unknown>, opts);
/** v3 #6: is_signer_revoked for each signer. Returns null if the view is unavailable (pre-v3 contract, RPC down). */
export async function getRevoked(signers: string[], opts?: RpcOpts & { strict?: boolean }): Promise<Set<string> | null> {
  try {
    const flags = await Promise.all([...new Set(signers)].map(async (signer) => [signer, await view<boolean>('is_signer_revoked', { signer }, opts)] as const));
    return new Set(flags.filter(([, r]) => r === true).map(([s]) => s));
  } catch (e) {
    if (opts?.strict) throw e;
    return null;
  }
}

// ---- explorer lookups (best effort, nearblocks v3 public API) ----

export const NB_API = 'https://api-testnet.nearblocks.io/v3';
let paidTxCache: Promise<Record<number, string>> | null = null;

/**
 * Claim ids a finalize tx actually paid, from its receipt logs: a `claim_paid` EVENT_JSON (standard sealedbounty)
 * in a successful receipt, minus any `payout_failed` for the same id. A finalize that succeeds but emits
 * `claim_rejected` (undecryptable report, revoked signer, ...) pays nothing (#13).
 */
export function paidClaimIds(txResult: unknown): number[] {
  const paid = new Set<number>();
  const failed = new Set<number>();
  for (const r of ((txResult as any)?.receipts_outcome ?? []) as any[]) {
    const st = r?.outcome?.status;
    if (!st || typeof st !== 'object' || 'Failure' in st) continue;
    for (const log of (r.outcome.logs ?? []) as unknown[]) {
      if (typeof log !== 'string' || !log.startsWith('EVENT_JSON:')) continue;
      let ev: any;
      try {
        ev = JSON.parse(log.slice('EVENT_JSON:'.length));
      } catch {
        continue;
      }
      if (ev?.standard !== 'sealedbounty') continue;
      const into = ev.event === 'claim_paid' ? paid : ev.event === 'payout_failed' ? failed : null;
      if (!into) continue;
      for (const d of Array.isArray(ev.data) ? ev.data : [ev.data]) if (Number.isInteger(d?.claim_id)) into.add(d.claim_id);
    }
  }
  return [...paid].filter((id) => !failed.has(id));
}

/** RPC `tx` (read-only status lookup) with the same fallback order as `view`. */
export async function rpcTx(hash: string, sender: string, opts: RpcOpts = {}): Promise<unknown> {
  let last: Error = new Error('no RPC configured');
  for (const url of opts.urls ?? RPC_URLS) {
    try {
      const res = await fetch(url, {
        method: 'POST',
        signal: AbortSignal.timeout(opts.timeoutMs ?? 8000),
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 'sb', method: 'tx', params: { tx_hash: hash, sender_account_id: sender, wait_until: 'FINAL' } }),
      });
      if (!res.ok) throw new Error(`RPC HTTP ${res.status}`);
      const j = await res.json();
      if (j.error) throw new Error(j.error?.cause?.name || j.error?.message || 'RPC error');
      return j.result;
    } catch (e) {
      last = e as Error;
    }
  }
  throw last;
}

/**
 * Maps claim_id -> hash of the `finalize` tx that paid it (emitted `claim_paid`). Best effort: returns {} on any error.
 * Lists the contract's successful finalize txns on nearblocks, then reads each one's receipt logs over RPC.
 */
export function findPaidTxs(): Promise<Record<number, string>> {
  paidTxCache ??= (async () => {
    const out: Record<number, string> = {};
    try {
      const list = await fetch(`${NB_API}/accounts/${CONTRACT_ID}/txns?limit=100`, { signal: AbortSignal.timeout(8000) }).then((r) => r.json());
      const fin = ((list?.data ?? []) as any[])
        .filter((t) => t?.outcomes?.status === true && t?.actions?.some((a: any) => a?.method === 'finalize'))
        .slice(0, 10);
      for (const t of fin) {
        try {
          const tx = await rpcTx(t.transaction_hash, t.signer_account_id);
          for (const id of paidClaimIds(tx)) out[id] ??= t.transaction_hash;
        } catch {
          /* this tx unreadable: no link for it */
        }
      }
    } catch {
      /* explorer API unavailable: links fall back to the contract page */
    }
    return out;
  })();
  return paidTxCache;
}

// ---- tx-args reader (guided tour): a contract call's args, outcome and events from an RPC `tx` result ----

export interface SbEvent {
  event: string;
  data: Record<string, any>;
}

export interface DecodedTx {
  hash: string;
  signer: string;
  method: string | null;
  /** JSON args of the first FunctionCall (null if not JSON). */
  args: Record<string, any> | null;
  /** The tx and every receipt succeeded. */
  ok: boolean;
  /** Panic / error text of the first failed receipt ("Smart contract panicked: already claimed"). */
  failure: string | null;
  /** sealedbounty events from successful receipts. */
  events: SbEvent[];
  /** Claims this tx acted on: the claim_id arg, or the claim_submitted event of a submit_claim. */
  claimIds: number[];
  /** Claims a finalize actually paid (claim_paid minus payout_failed; see paidClaimIds). */
  paidClaimIds: number[];
  rejected: { claim_id: number; reason: string }[];
  /** ns block timestamp, when the caller knows it (nearblocks list). */
  blockTimestamp: string | null;
}

const b64ToUtf8 = (b: string) => new TextDecoder().decode(Uint8Array.from(atob(b), (c) => c.charCodeAt(0)));

function failureText(st: unknown): string | null {
  if (!st || typeof st !== 'object' || !('Failure' in st)) return null;
  const f = (st as any).Failure;
  const exec = f?.ActionError?.kind?.FunctionCallError?.ExecutionError;
  return typeof exec === 'string' ? exec : JSON.stringify(f).slice(0, 200);
}

/** Decodes an RPC `tx` result (live, or the trimmed copy in tour-v3-snapshot.json). Pure; tolerates odd shapes. */
export function decodeTx(raw: unknown, blockTimestamp: string | null = null): DecodedTx {
  const r = raw as any;
  const t = r?.transaction ?? {};
  const fc = ((t.actions ?? []) as any[]).find((a) => a && typeof a === 'object' && a.FunctionCall)?.FunctionCall;
  let args: Record<string, any> | null = null;
  try {
    const j = JSON.parse(b64ToUtf8(fc?.args ?? ''));
    if (j && typeof j === 'object') args = j;
  } catch {
    /* not JSON */
  }
  const receipts = ((r?.receipts_outcome ?? []) as any[]).map((x) => x?.outcome ?? {});
  const failure = failureText(r?.status) ?? receipts.map((o) => failureText(o.status)).find(Boolean) ?? null;
  const events: SbEvent[] = [];
  for (const o of receipts) {
    if (failureText(o.status)) continue;
    for (const log of (o.logs ?? []) as unknown[]) {
      if (typeof log !== 'string' || !log.startsWith('EVENT_JSON:')) continue;
      try {
        const ev = JSON.parse(log.slice('EVENT_JSON:'.length));
        if (ev?.standard !== 'sealedbounty') continue;
        for (const d of Array.isArray(ev.data) ? ev.data : [ev.data]) events.push({ event: String(ev.event), data: d ?? {} });
      } catch {
        /* not an event */
      }
    }
  }
  const ids = new Set<number>();
  if (Number.isInteger(args?.claim_id)) ids.add(args!.claim_id);
  for (const e of events) if (e.event === 'claim_submitted' && Number.isInteger(e.data.claim_id)) ids.add(e.data.claim_id);
  return {
    hash: String(t.hash ?? ''),
    signer: String(t.signer_id ?? ''),
    method: fc?.method_name ?? null,
    args,
    ok: failure === null && r?.status != null,
    failure,
    events,
    claimIds: [...ids],
    paidClaimIds: paidClaimIds(raw),
    rejected: events.filter((e) => e.event === 'claim_rejected').map((e) => ({ claim_id: e.data.claim_id, reason: e.data.reason })),
    blockTimestamp,
  };
}

export interface NbTxRow {
  hash: string;
  signer: string;
  method: string | null;
  ok: boolean;
  blockTimestamp: string;
}

/** The contract's recent txs from the public nearblocks API (hash, signer, method; no args). */
export async function listContractTxs(opts: { timeoutMs?: number; limit?: number } = {}): Promise<NbTxRow[]> {
  const res = await fetch(`${NB_API}/accounts/${CONTRACT_ID}/txns?limit=${opts.limit ?? 100}`, { signal: AbortSignal.timeout(opts.timeoutMs ?? 8000) });
  if (!res.ok) throw new Error(`nearblocks HTTP ${res.status}`);
  const j = await res.json();
  return ((j?.data ?? []) as any[]).map((t) => ({
    hash: String(t.transaction_hash),
    signer: String(t.signer_account_id),
    method: t.actions?.find((a: any) => a?.method)?.method ?? null,
    ok: t.outcomes?.status === true,
    blockTimestamp: String(t.block_timestamp ?? t.block?.block_timestamp ?? '0'),
  }));
}
