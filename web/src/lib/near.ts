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

async function viewAt<T>(url: string, method: string, args: Record<string, unknown>): Promise<T> {
  const res = await fetch(url, {
    method: 'POST',
    signal: AbortSignal.timeout(8000),
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
  if (j.error) throw new Error(j.error?.cause?.name || j.error?.data || j.error?.message || 'RPC error');
  if (j.result?.error) throw new Error(j.result.error);
  const bytes = new Uint8Array(j.result.result as number[]);
  return JSON.parse(new TextDecoder().decode(bytes)) as T;
}

/** Contract-level errors (CodeDoesNotExist, panics) are final; transport errors (429, 5xx, timeout) try the next RPC. */
const isContractError = (m: string) => /CodeDoesNotExist|AccountDoesNotExist|GuestPanic|MethodNotFound|wasm execution/i.test(m);

export async function view<T>(method: string, args: Record<string, unknown> = {}): Promise<T> {
  let last: Error = new Error('no RPC configured');
  for (let i = 0; i < RPC_URLS.length; i++) {
    const idx = (rpcStart + i) % RPC_URLS.length;
    try {
      const r = await viewAt<T>(RPC_URLS[idx], method, args);
      rpcStart = idx;
      return r;
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

export const getSigners = async (): Promise<SignerEntry[]> => normaliseSigners(await view('get_signers'));
export const listPrograms = () => paged((from_index) => view<unknown[]>('list_programs', { from_index, limit: PAGE }), parseProgram);
export const getProgram = async (id: number) => {
  const r = await view<unknown>('get_program', { id });
  return r == null ? null : parseProgram(r);
};
export const listClaims = (program_id: number) =>
  paged((from_index) => view<unknown[]>('list_claims', { program_id, from_index, limit: PAGE }), parseClaim);
export const getClaim = async (id: number) => {
  const r = await view<unknown>('get_claim', { id });
  return r == null ? null : parseClaim(r);
};
export const getOwner = () => view<string>('get_owner');
/** v3 #6: is_signer_revoked for each signer. Returns null if the view is unavailable (pre-v3 contract, RPC down). */
export async function getRevoked(signers: string[]): Promise<Set<string> | null> {
  try {
    const flags = await Promise.all([...new Set(signers)].map(async (signer) => [signer, await view<boolean>('is_signer_revoked', { signer })] as const));
    return new Set(flags.filter(([, r]) => r === true).map(([s]) => s));
  } catch {
    return null;
  }
}

// ---- explorer lookups (best effort, nearblocks v3 public API) ----

const NB_API = 'https://api-testnet.nearblocks.io/v3';
let paidTxCache: Promise<Record<number, string>> | null = null;

/**
 * Maps claim_id -> hash of the successful `finalize` tx that paid it. Best effort: returns {} on any error.
 * Lists the contract's txns, then reads args of each successful finalize (claim_id is only in the args).
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
        const d = await fetch(`${NB_API}/txns/${t.transaction_hash}`, { signal: AbortSignal.timeout(8000) }).then((r) => r.json());
        for (const a of d?.data?.actions ?? []) {
          const id = a?.args?.args_json?.claim_id;
          if (a?.method === 'finalize' && Number.isInteger(id)) out[id] = t.transaction_hash;
        }
      }
    } catch {
      /* explorer API unavailable: links fall back to the contract page */
    }
    return out;
  })();
  return paidTxCache;
}
