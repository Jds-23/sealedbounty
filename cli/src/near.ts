import { existsSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { Account, JsonRpcProvider, KeyPairSigner, actions, getTransactionLastResult, type KeyPairString } from 'near-api-js';
import { config } from './config.js';
import type { Claim, Program, SignerMeta } from './types.js';
import { formatNear } from './util.js';

let provider: JsonRpcProvider | undefined;
export function getProvider(): JsonRpcProvider {
  provider ??= new JsonRpcProvider({ url: config().rpcUrl });
  return provider;
}

/** Read-only view call on the escrow contract. */
export async function view<T>(method: string, args: Record<string, unknown> = {}): Promise<T> {
  const r = await getProvider().callFunction<any>({ contractId: config().contractId, method, args });
  return r as T;
}

export const getProgram = (id: number) => view<Program | null>('get_program', { id });
export const getClaim = (id: number) => view<Claim | null>('get_claim', { id });
export const listPrograms = (from_index = 0, limit = 50) => view<Program[]>('list_programs', { from_index, limit });
export const listClaims = (program_id: number, from_index = 0, limit = 50) => view<Claim[]>('list_claims', { program_id, from_index, limit });
export const getSigners = () => view<[string, SignerMeta][]>('get_signers');
/** v3 #6 */
export const isSignerRevoked = (signer: string) => view<boolean>('is_signer_revoked', { signer });

export async function mustGetProgram(id: number): Promise<Program> {
  const p = await getProgram(id);
  if (!p) throw new Error(`program ${id} not found on ${config().contractId}`);
  return p;
}
export async function mustGetClaim(id: number): Promise<Claim> {
  const c = await getClaim(id);
  if (!c) throw new Error(`claim ${id} not found on ${config().contractId}`);
  return c;
}

/** Load a full-access key from ~/.near-credentials/<network>/<account>.json (or NEAR_CREDENTIALS_PATH). */
export function loadAccount(accountId?: string): Account {
  const cfg = config();
  const id = accountId ?? cfg.accountId;
  if (!id) throw new Error('no signer account: pass --account or set NEAR_TESTNET_ACCOUNT_ID');
  const candidates = [
    ...(cfg.credentialsPath && (!accountId || cfg.credentialsPath.includes(id)) ? [cfg.credentialsPath] : []),
    join(homedir(), '.near-credentials', cfg.network, `${id}.json`),
  ];
  const path = candidates.find((p) => existsSync(p));
  if (!path) throw new Error(`no credentials for ${id} (looked in ${candidates.join(', ')})`);
  const cred = JSON.parse(readFileSync(path, 'utf8'));
  const sk = (cred.private_key ?? cred.secret_key) as KeyPairString | undefined;
  if (!sk) throw new Error(`${path} has no private_key`);
  return new Account(id, getProvider(), KeyPairSigner.fromSecretKey(sk));
}

export interface TxResult {
  hash: string;
  ok: boolean;
  value: unknown;
  error?: string;
  logs: string[];
}

/** Sign + send one FunctionCall to the escrow contract. Always prints the explorer link. */
export async function callContract(
  account: Account,
  method: string,
  args: Record<string, unknown>,
  opts: { gas: bigint; deposit?: bigint },
): Promise<TxResult> {
  const cfg = config();
  const deposit = opts.deposit ?? 0n;
  console.log(`\n-> ${account.accountId} calls ${cfg.contractId}.${method}  gas=${opts.gas / 10n ** 12n}Tgas deposit=${formatNear(deposit)}`);
  const outcome: any = await account.signAndSendTransaction({
    receiverId: cfg.contractId,
    actions: [actions.functionCall(method, args, opts.gas, deposit)],
    throwOnFailure: false,
    waitUntil: 'FINAL',
  });
  const hash: string = outcome?.transaction?.hash ?? outcome?.transaction_outcome?.id;
  const logs: string[] = [...(outcome?.receipts_outcome ?? [])].flatMap((r: any) => r?.outcome?.logs ?? []);
  const failure = outcome?.status?.Failure;
  console.log(`   tx: ${cfg.explorerTx(hash)}`);
  for (const l of logs) console.log(`   log: ${l}`);
  if (failure) {
    const err = extractPanic(failure);
    console.log(`   FAILED: ${err}`);
    return { hash, ok: false, value: undefined, error: err, logs };
  }
  let value: unknown;
  try {
    value = getTransactionLastResult(outcome);
  } catch {
    value = undefined;
  }
  return { hash, ok: true, value, logs };
}

function extractPanic(failure: any): string {
  const s = JSON.stringify(failure);
  const m = /"(?:ExecutionError|PanicMsg)":"((?:[^"\\]|\\.)*)"/.exec(s);
  return m ? m[1] : s.slice(0, 400);
}
