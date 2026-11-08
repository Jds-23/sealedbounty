// Local storage of the program owner's x25519 secret (~/.sealedbounty/owner-<id>.json, chmod 600).
// Key generation and encryption live in shared/judge.mjs.
import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { SB_HOME } from './config.js';

// ---------- local owner key storage ----------
export interface OwnerKeyPair {
  publicKey: string; // base64
  secretKey: string; // base64
}

export interface OwnerKeyFile extends OwnerKeyPair {
  program_id: number | null;
  contract_id: string;
  network: string;
  created_at: string;
}

export const ownerKeyPath = (programId: number | string, home = SB_HOME()) => join(home, `owner-${programId}.json`);

function writeSecret(path: string, data: unknown) {
  writeFileSync(path, JSON.stringify(data, null, 2) + '\n', { mode: 0o600 });
  chmodSync(path, 0o600);
}

/** Saves the keypair BEFORE the create_program tx so a crash can't lose it. Returns the pending path. */
export function savePendingOwnerKey(kp: OwnerKeyPair, contractId: string, network: string, home = SB_HOME()): string {
  mkdirSync(home, { recursive: true, mode: 0o700 });
  const tag = Buffer.from(kp.publicKey, 'base64').toString('hex').slice(0, 16);
  const path = join(home, `owner-pending-${tag}.json`);
  writeSecret(path, { ...kp, program_id: null, contract_id: contractId, network, created_at: new Date().toISOString() });
  return path;
}

export function finalizeOwnerKey(pendingPath: string, programId: number, home = SB_HOME()): string {
  const data = JSON.parse(readFileSync(pendingPath, 'utf8')) as OwnerKeyFile;
  const dest = ownerKeyPath(programId, home);
  if (existsSync(dest)) throw new Error(`${dest} already exists; refusing to overwrite (pending key kept at ${pendingPath})`);
  data.program_id = programId;
  writeSecret(pendingPath, data);
  renameSync(pendingPath, dest);
  return dest;
}

export function loadOwnerKey(programId: number | string, home = SB_HOME()): OwnerKeyFile {
  const p = ownerKeyPath(programId, home);
  if (!existsSync(p)) throw new Error(`no owner key for program ${programId} at ${p}`);
  return JSON.parse(readFileSync(p, 'utf8')) as OwnerKeyFile;
}

export function tryLoadOwnerKey(programId: number | string, home = SB_HOME()): OwnerKeyFile | undefined {
  try {
    return loadOwnerKey(programId, home);
  } catch {
    return undefined;
  }
}
