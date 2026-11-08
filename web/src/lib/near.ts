// Read-only NEAR JSON-RPC (call_function). No wallet, no writes.
import type { Claim, Program, SignerEntry } from './types';
import { normaliseSigners } from './verify';

export const CONTRACT_ID: string = import.meta.env.VITE_ESCROW_CONTRACT_ID || 'escrow.baldingsucks7993.testnet';
export const RPC_URL: string = import.meta.env.VITE_NEAR_RPC || 'https://rpc.testnet.near.org';

const b64 = (s: string) => btoa(unescape(encodeURIComponent(s)));

export async function view<T>(method: string, args: Record<string, unknown> = {}): Promise<T> {
  const res = await fetch(RPC_URL, {
    method: 'POST',
    signal: AbortSignal.timeout(8000),
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 'sb',
      method: 'query',
      params: { request_type: 'call_function', finality: 'final', account_id: CONTRACT_ID, method_name: method, args_base64: b64(JSON.stringify(args)) },
    }),
  });
  if (!res.ok) throw new Error(`RPC HTTP ${res.status}`);
  const j = await res.json();
  if (j.error) throw new Error(j.error?.cause?.name || j.error?.message || 'RPC error');
  if (j.result?.error) throw new Error(j.result.error);
  const bytes = new Uint8Array(j.result.result as number[]);
  return JSON.parse(new TextDecoder().decode(bytes)) as T;
}

export const getSigners = async (): Promise<SignerEntry[]> => normaliseSigners(await view('get_signers'));
export const listPrograms = () => view<Program[]>('list_programs', { from_index: 0, limit: 100 });
export const getProgram = (id: number) => view<Program | null>('get_program', { id });
export const listClaims = (program_id: number) => view<Claim[]>('list_claims', { program_id, from_index: 0, limit: 100 });
