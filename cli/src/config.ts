import { existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import dotenv from 'dotenv';

const HERE = dirname(fileURLToPath(import.meta.url));
/** Repo root (cli/src or cli/dist -> ../..). */
export const REPO_ROOT = resolve(HERE, '../..');

let loaded = false;
export function loadEnv(): void {
  if (loaded) return;
  loaded = true;
  const p = join(REPO_ROOT, '.env');
  if (existsSync(p)) dotenv.config({ path: p, quiet: true });
}

export const expandHome = (p: string) => (p.startsWith('~') ? join(homedir(), p.slice(1)) : p);

export interface Config {
  network: string;
  rpcUrl: string;
  contractId: string;
  accountId?: string;
  credentialsPath?: string;
  nearaiBaseUrl: string;
  nearaiModel: string;
  nearaiAlgo: 'ed25519' | 'ecdsa';
  explorerTx: (hash: string) => string;
}

export function config(): Config {
  loadEnv();
  const e = process.env;
  const network = e.NEAR_NETWORK || 'testnet';
  const algo = (e.NEARAI_SIGNING_ALGO || 'ed25519').toLowerCase();
  return {
    network,
    rpcUrl: e.NEAR_RPC_URL || `https://rpc.${network}.near.org`,
    // Deliberately NOT falling back to CONTRACT_ID: in .env that points at the Phase 0 spike contract.
    contractId: e.ESCROW_CONTRACT_ID || 'escrow.baldingsucks7993.testnet',
    accountId: e.NEAR_TESTNET_ACCOUNT_ID || e.NEAR_ACCOUNT_ID || undefined,
    credentialsPath: e.NEAR_CREDENTIALS_PATH ? expandHome(e.NEAR_CREDENTIALS_PATH) : undefined,
    nearaiBaseUrl: (e.NEARAI_BASE_URL || 'https://cloud-api.near.ai/v1').replace(/\/$/, ''),
    nearaiModel: e.NEARAI_MODEL || 'Qwen/Qwen3.8-27B',
    nearaiAlgo: algo === 'ecdsa' ? 'ecdsa' : 'ed25519',
    explorerTx: (hash) =>
      network === 'mainnet' ? `https://nearblocks.io/txns/${hash}` : `https://testnet.nearblocks.io/txns/${hash}`,
  };
}

/** Never returned anywhere except the Authorization header. */
export function nearaiApiKey(): string | undefined {
  loadEnv();
  return process.env.NEARAI_API_KEY || undefined;
}

export const SB_HOME = () => join(homedir(), '.sealedbounty');
