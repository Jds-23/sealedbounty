// Client-side re-verification of TEE signatures. Pure functions, no network.
// Crypto primitives come from shared/judge.mjs (same code the CLI uses); this adds Signer-string handling.
import { decodeBase64 } from 'ethers';
import { expectedText, parseVerdict as sharedParseVerdict, sha256hex, signerId, verifySig } from '@sealedbounty/shared';
import type { SigKind, Signer, SignerEntry, Verdict } from './types';

export { sha256hex };

export const strip0x = (h: string) => (h.startsWith('0x') || h.startsWith('0X') ? h.slice(2) : h);
/** The exact text the TEE signs (matches tee.rs `signed_text`). */
export function signedText(kind: SigKind, model: string, reqHash: string, respHash: string): string {
  return expectedText(kind, model, reqHash, respHash);
}

export type ParsedSigner = { algo: 'ed25519'; pubkey: string } | { algo: 'ecdsa'; address: string };

export function parseSigner(s: Signer): ParsedSigner {
  if (s.startsWith('ed25519:')) {
    const pk = s.slice(8).toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(pk)) throw new Error('ed25519 signer must be 64 hex chars');
    return { algo: 'ed25519', pubkey: pk };
  }
  if (s.startsWith('eth:')) {
    const a = strip0x(s.slice(4)).toLowerCase();
    if (!/^[0-9a-f]{40}$/.test(a)) throw new Error('eth signer must be 0x + 40 hex chars');
    return { algo: 'ecdsa', address: '0x' + a };
  }
  throw new Error(`unknown signer encoding: ${s}`);
}

/** Build the Signer string from a NEAR AI signing_address/algo pair. */
export function signerFrom(algo: string, address: string): Signer {
  return signerId({ signing_address: address, signing_algo: algo === 'ecdsa' ? 'ecdsa' : 'ed25519' });
}

/** Returns ok + reason; never throws (malformed input => false). Delegates to shared verifySig. */
export function verifySignature(signer: Signer, text: string, signature: string): { ok: boolean; detail: string } {
  try {
    const p = parseSigner(signer);
    const ok = verifySig({
      text,
      signature,
      signing_address: p.algo === 'ed25519' ? p.pubkey : p.address,
      signing_algo: p.algo,
    });
    if (p.algo === 'ed25519') return { ok, detail: ok ? 'ed25519 (tweetnacl) verify ok' : 'ed25519 signature does NOT match' };
    return { ok, detail: ok ? `secp256k1 EIP-191 recovers ${p.address}` : `signature does not recover ${p.address}` };
  } catch (e) {
    return { ok: false, detail: `verify error: ${(e as Error).message}` };
  }
}

/** Normalise get_signers output: [[signer, meta], ...] or [{signer, meta}] or {signer: meta}. */
export function normaliseSigners(raw: unknown): SignerEntry[] {
  if (Array.isArray(raw)) {
    return raw.map((r) => (Array.isArray(r) ? { signer: r[0], meta: r[1] } : (r as SignerEntry)));
  }
  if (raw && typeof raw === 'object') {
    return Object.entries(raw as Record<string, SignerEntry['meta']>).map(([signer, meta]) => ({ signer, meta }));
  }
  return [];
}

export function findSigner(signers: SignerEntry[], s: Signer): SignerEntry | undefined {
  const norm = (x: string) => x.toLowerCase();
  return signers.find((e) => norm(e.signer) === norm(s));
}

/** Extract the verdict from a chat completion body (shared parseVerdict mirrors contract parse_verdict). */
export const parseVerdict = (respBody: Uint8Array | string): Verdict => sharedParseVerdict(respBody);

export const b64ToBytes = (b: string) => decodeBase64(b);

/**
 * Binding check of the TDX quote: TD report body report_data (bytes 568..632 of a v4 quote)
 * must equal signer (padded to 32) || request_nonce. This is a structural check only; it does
 * NOT verify the quote's Intel signature chain (DCAP), which needs PCCS and can't be done here.
 */
export function quoteBindsSigner(quoteHex: string, signingAddress: string, nonce: string): { ok: boolean; detail: string } {
  const q = strip0x(quoteHex).toLowerCase();
  const REPORT_DATA_OFFSET = 568 * 2;
  if (q.length < (568 + 64) * 2) return { ok: false, detail: 'quote too short' };
  const rd = q.slice(REPORT_DATA_OFFSET, REPORT_DATA_OFFSET + 128);
  const signer = strip0x(signingAddress).toLowerCase().padEnd(64, '0');
  const ok = rd.slice(0, 64) === signer && rd.slice(64) === strip0x(nonce).toLowerCase();
  return { ok, detail: ok ? 'report_data = signer ‖ nonce' : `report_data mismatch (${rd.slice(0, 16)}…)` };
}
