// Reads the repo-root .env in-process (never into process.env, so child processes don't inherit the
// NEAR AI key from us) and builds the helper config.
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../..');

/** Minimal dotenv: KEY=VALUE, optional `export `, single/double quotes, `#` comments. */
export function parseDotenv(text) {
  const out = {};
  for (const raw of text.split(/\r?\n/)) {
    const m = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/.exec(raw);
    if (!m) continue;
    let v = m[2].trim();
    const q = v[0];
    if ((q === '"' || q === "'") && v.lastIndexOf(q) > 0) v = v.slice(1, v.lastIndexOf(q));
    else v = v.replace(/\s+#.*$/, '').trim();
    out[m[1]] = v;
  }
  return out;
}

export function readRepoEnv(repoRoot = REPO_ROOT) {
  const p = join(repoRoot, '.env');
  return existsSync(p) ? parseDotenv(readFileSync(p, 'utf8')) : {};
}

/**
 * @param {{fileEnv?: Record<string,string>, env?: Record<string,string|undefined>, repoRoot?: string}} [o]
 *   process env wins over .env (dotenv semantics)
 */
export function loadConfig({ fileEnv, env = process.env, repoRoot = REPO_ROOT } = {}) {
  const e = { ...(fileEnv ?? readRepoEnv(repoRoot)), ...Object.fromEntries(Object.entries(env).filter(([, v]) => v !== undefined && v !== '')) };
  const pid = e.DEMO_LIVE_PROGRAM_ID;
  const network = e.NEAR_NETWORK || 'testnet';
  return {
    repoRoot,
    port: Number(e.DEMO_HELPER_PORT || 8787),
    programId: pid !== undefined && /^\d+$/.test(pid) ? Number(pid) : null,
    contractId: e.ESCROW_CONTRACT_ID || 'sealedbounty-v3.testnet',
    network,
    rpcUrl: e.NEAR_RPC_URL || (network === 'mainnet' ? 'https://free.rpc.fastnear.com' : 'https://test.rpc.fastnear.com'),
    apiKey: e.NEARAI_API_KEY || undefined,
    baseUrl: (e.NEARAI_BASE_URL || 'https://cloud-api.near.ai/v1').replace(/\/$/, ''),
    signingAlgo: (e.NEARAI_SIGNING_ALGO || 'ed25519').toLowerCase() === 'ecdsa' ? 'ecdsa' : 'ed25519',
    hunter: e.DEMO_HUNTER_ACCOUNT || 'hunter.baldingsucks7993.testnet',
    frontrun: e.DEMO_FRONTRUN_ACCOUNT || 'frontrun.baldingsucks7993.testnet',
    marginMs: 2000,
    /** every secret-looking value, for the redactor */
    env: e,
  };
}
