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
 * Accepts the owner secret file JSON (~/.sealedbounty/owner-<id>.json) or a bare base64 key.
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
