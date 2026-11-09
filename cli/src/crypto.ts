// Local storage of the program owner's x25519 secret (~/.sealedbounty/owner-<contract>-<id>.json, chmod 600)
// and of the hunter's per-claim ephemeral secret (~/.sealedbounty/hunter-<contract>-<claim>.json, chmod 600).
// Key generation and encryption live in shared/judge.mjs.
import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import nacl from 'tweetnacl';
import { SB_HOME, config } from './config.js';

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

/** Keys are namespaced by contract: program ids restart at 0 on every escrow deployment. */
export const ownerKeyPath = (programId: number | string, home = SB_HOME(), contractId = config().contractId) =>
  join(home, `owner-${contractId}-${programId}.json`);
/** Pre-namespacing location (v1 CLI); only used if its contract_id matches. */
const legacyOwnerKeyPath = (programId: number | string, home = SB_HOME()) => join(home, `owner-${programId}.json`);

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
  const dest = ownerKeyPath(programId, home, data.contract_id);
  if (existsSync(dest)) throw new Error(`${dest} already exists; refusing to overwrite (pending key kept at ${pendingPath})`);
  data.program_id = programId;
  writeSecret(pendingPath, data);
  renameSync(pendingPath, dest);
  return dest;
}

export function loadOwnerKey(programId: number | string, home = SB_HOME(), contractId = config().contractId): OwnerKeyFile {
  const p = ownerKeyPath(programId, home, contractId);
  if (existsSync(p)) return JSON.parse(readFileSync(p, 'utf8')) as OwnerKeyFile;
  const legacy = legacyOwnerKeyPath(programId, home);
  if (existsSync(legacy)) {
    const data = JSON.parse(readFileSync(legacy, 'utf8')) as OwnerKeyFile;
    if (data.contract_id === contractId) return data;
  }
  throw new Error(`no owner key for program ${programId} on ${contractId} at ${p}`);
}

export function tryLoadOwnerKey(programId: number | string, home = SB_HOME()): OwnerKeyFile | undefined {
  try {
    return loadOwnerKey(programId, home);
  } catch {
    return undefined;
  }
}

// ---------- hunter ephemeral secret (v3 #2: prove_ciphertext) ----------
export interface HunterSecret {
  /** x25519 ephemeral secret that encrypted the report (64 hex), from shared.encryptForOwnerWithSecret. */
  ephemeralSecretHex: string;
  req_hash: string;
  contract: string;
  program_id: number;
}
export interface HunterSecretFile extends HunterSecret {
  claim_id: number | null;
  created_at: string;
}

export const hunterSecretPath = (claimId: number | string, home = SB_HOME(), contractId = config().contractId) =>
  join(home, `hunter-${contractId}-${claimId}.json`);

/** Saved BEFORE submit_claim is sent (the claim id is not known yet). Returns the pending path. */
export function savePendingHunterSecret(s: HunterSecret, home = SB_HOME()): string {
  mkdirSync(home, { recursive: true, mode: 0o700 });
  const path = join(home, `hunter-pending-${s.contract}-${s.req_hash.slice(0, 16)}.json`);
  writeSecret(path, { ...s, claim_id: null, created_at: new Date().toISOString() });
  return path;
}

export function finalizeHunterSecret(pendingPath: string, claimId: number, home = SB_HOME()): string {
  const data = JSON.parse(readFileSync(pendingPath, 'utf8')) as HunterSecretFile;
  const dest = hunterSecretPath(claimId, home, data.contract);
  if (existsSync(dest)) throw new Error(`${dest} already exists; refusing to overwrite (pending secret kept at ${pendingPath})`);
  data.claim_id = claimId;
  writeSecret(pendingPath, data);
  renameSync(pendingPath, dest);
  return dest;
}

export function loadHunterSecret(claimId: number | string, home = SB_HOME(), contractId = config().contractId): HunterSecretFile {
  const p = hunterSecretPath(claimId, home, contractId);
  if (!existsSync(p)) throw new Error(`no hunter secret for claim ${claimId} on ${contractId} at ${p}`);
  return JSON.parse(readFileSync(p, 'utf8')) as HunterSecretFile;
}

/**
 * Opens a report ciphertext the way the contract's prove_ciphertext does: requires
 * x25519_base(secret) == ciphertext[0..32], then nacl.box.open(box, nonce, ownerPub, secret).
 */
export function openWithEphemeral(ciphertextB64: string, ownerPubB64: string, ephemeralSecretHex: string): string {
  if (!/^[0-9a-f]{64}$/.test(ephemeralSecretHex)) throw new Error('ephemeral secret must be 64 hex');
  const ct = new Uint8Array(Buffer.from(ciphertextB64, 'base64'));
  if (ct.length < 32 + 24 + nacl.box.overheadLength) throw new Error('ciphertext too short');
  const secret = new Uint8Array(Buffer.from(ephemeralSecretHex, 'hex'));
  const pub = nacl.box.keyPair.fromSecretKey(secret).publicKey;
  if (Buffer.compare(Buffer.from(pub), Buffer.from(ct.subarray(0, 32))) !== 0) {
    throw new Error('ephemeral secret does not match ciphertext[0..32]');
  }
  const opened = nacl.box.open(ct.subarray(56), ct.subarray(32, 56), new Uint8Array(Buffer.from(ownerPubB64, 'base64')), secret);
  if (!opened) throw new Error('box does not open with this ephemeral secret');
  return new TextDecoder('utf-8', { fatal: true }).decode(opened);
}
