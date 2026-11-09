// Owner-side report decryption. Runs only in the browser; the secret never leaves this module's caller.
// Ciphertext (base64) = ephemeralPub(32) || nonce(24) || nacl.box(utf8(request_body), nonce, ownerPub, ephemeralSecret)
import nacl from 'tweetnacl';
import { decodeBase64, encodeBase64 } from 'ethers';
import { decryptAsOwner, encryptForOwner } from '@sealedbounty/shared';
import { sha256hex } from './verify';

export function decryptReport(ciphertextB64: string, ownerSecretKey: Uint8Array): string {
  try {
    return decryptAsOwner(ciphertextB64.trim(), encodeBase64(ownerSecretKey));
  } catch (e) {
    const m = (e as Error).message;
    throw new Error(m === 'decryption failed' ? 'decryption failed (wrong key or tampered ciphertext)' : m);
  }
}

/** Same encryption as the CLI (shared encryptForOwner); used by tests. */
export const encryptReport = (plaintext: string, ownerPublicKey: Uint8Array): string => encryptForOwner(plaintext, encodeBase64(ownerPublicKey));

const KEY_FIELDS = ['secret_key', 'secretKey', 'box_secret_key', 'boxSecretKey', 'enc_secret_key', 'sk', 'secret'];

function tryKey(v: unknown): Uint8Array | null {
  if (typeof v !== 'string') return null;
  try {
    const b = decodeBase64(v.trim());
    return b.length === 32 ? b : null;
  } catch {
    return null;
  }
}

/**
 * Accepts the owner secret file JSON (~/.sealedbounty/owner-<contract>-<id>.json) or a bare base64 key.
 * The exact field name is not fixed by the spec, so known names are tried first, then any
 * string field that decodes to 32 bytes and is not the public key.
 */
export function parseOwnerSecret(input: string): { secretKey: Uint8Array; publicKeyB64: string; programId?: number } {
  const text = input.trim();
  let key: Uint8Array | null = null;
  let programId: number | undefined;
  if (text.startsWith('{')) {
    const obj = JSON.parse(text) as Record<string, unknown>;
    if (typeof obj.program_id === 'number') programId = obj.program_id;
    for (const f of KEY_FIELDS) if ((key = tryKey(obj[f]))) break;
    if (!key) {
      for (const [k, v] of Object.entries(obj)) {
        if (/pub/i.test(k)) continue;
        if ((key = tryKey(v))) break;
      }
    }
  } else {
    key = tryKey(text);
  }
  if (!key) throw new Error('no 32-byte base64 box secret key found');
  const kp = nacl.box.keyPair.fromSecretKey(key);
  return { secretKey: key, publicKeyB64: encodeBase64(kp.publicKey), programId };
}

export function reportMatchesHash(plaintext: string, reqHash: string): boolean {
  return sha256hex(plaintext) === reqHash.toLowerCase();
}

export type ProofResult = { ok: true; plaintext: string } | { ok: false; reason: 'bad secret' | 'ephemeral key mismatch' | 'undecryptable report' };

/**
 * Re-runs the contract's prove_ciphertext (INTERFACE.md v3 #2) with the hunter's revealed ephemeral secret:
 * x25519_base(secret) must equal ciphertext[0..32] (else the tx panics), the box must open with
 * (owner_enc_pubkey, secret), and sha256(plaintext) must equal req_hash (else "undecryptable report").
 * Needs no owner secret: anyone can check a proof.
 */
export function proveCiphertext(ciphertextB64: string, ownerPubB64: string, secretHex: string, reqHash: string): ProofResult {
  if (!/^[0-9a-fA-F]{64}$/.test(secretHex)) return { ok: false, reason: 'bad secret' };
  const secret = Uint8Array.from(secretHex.match(/../g)!, (h) => parseInt(h, 16));
  let ct: Uint8Array;
  try {
    ct = decodeBase64(ciphertextB64.trim());
  } catch {
    return { ok: false, reason: 'undecryptable report' };
  }
  const eph = nacl.box.keyPair.fromSecretKey(secret).publicKey;
  if (ct.length < 56 || !eph.every((b, i) => b === ct[i])) return { ok: false, reason: 'ephemeral key mismatch' };
  const opened = nacl.box.open(ct.slice(56), ct.slice(32, 56), decodeBase64(ownerPubB64), secret);
  if (!opened) return { ok: false, reason: 'undecryptable report' };
  const plaintext = new TextDecoder().decode(opened);
  return reportMatchesHash(plaintext, reqHash) ? { ok: true, plaintext } : { ok: false, reason: 'undecryptable report' };
}
