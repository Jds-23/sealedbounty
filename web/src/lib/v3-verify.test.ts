// v3 #3/#6 per-program signers + revocation in the Verified panel, and #2 prove_ciphertext checked in the browser.
import { describe, expect, it } from 'vitest';
import nacl from 'tweetnacl';
import { encodeBase64 } from 'ethers';
import demo from '../fixtures/demo.json';
import { buildDemo, DEMO_SIGNERS } from './demo';
import { verifyClaim } from './checks';
import { proveCiphertext } from './crypto';
import { encryptForOwnerWithSecret } from './shared-v3.mjs';
import { sha256hex } from './verify';

const { programs, claims } = buildDemo(0);
const c = claims.find((x) => x.status === 'Paid')!;
const ED = DEMO_SIGNERS[0].signer;
const ETH = DEMO_SIGNERS[1].signer;
const v3 = { ...programs[0], signers: [ED, ETH] };
const find = (cs: ReturnType<typeof verifyClaim>, p: string) => cs.find((x) => x.label.startsWith(p));
const opts = { signersSource: 'demo' as const, revoked: new Set<string>() };

describe('Verified panel: per-program signer set (v3 #3)', () => {
  it('signer in program.signers → pass, named after the PROGRAM set', () => {
    const k = find(verifyClaim(c, v3, DEMO_SIGNERS, opts), 'Signer in PROGRAM set')!;
    expect(k.status).toBe('pass');
    expect(k.detail).toMatch(/program\.signers \(2\)/);
  });

  it('signer globally allowlisted but not in the program set → fail', () => {
    const p = { ...v3, signers: [c.signer === ED ? ETH : ED] };
    expect(find(verifyClaim(c, p, DEMO_SIGNERS, opts), 'Signer in PROGRAM set')!.status).toBe('fail');
  });

  it('kind still comes from the global allowlist', () => {
    const wrongKind = DEMO_SIGNERS.map((s) => ({ ...s, meta: { ...s.meta, kind: 'gateway' as const } }));
    expect(find(verifyClaim(c, v3, wrongKind, opts), 'Signer in PROGRAM set')!.status).toBe('fail');
  });

  it('v2 program (signers null) keeps the global allowlist check only', () => {
    const cs = verifyClaim(c, { ...v3, signers: null }, DEMO_SIGNERS, opts);
    expect(find(cs, 'Signer in PROGRAM set')).toBeUndefined();
    expect(find(cs, 'Signer allowlisted')!.status).toBe('pass');
  });
});

describe('Verified panel: revocation (v3 #6)', () => {
  it('not revoked → pass', () => {
    expect(find(verifyClaim(c, v3, DEMO_SIGNERS, opts), 'Signer not revoked')!.status).toBe('pass');
  });
  it('revoked → fail, explains finalize rejects it', () => {
    const k = find(verifyClaim(c, v3, DEMO_SIGNERS, { ...opts, revoked: new Set([c.signer]) }), 'Signer not revoked')!;
    expect(k.status).toBe('fail');
    expect(k.detail).toMatch(/signer revoked/);
  });
  it('unknown (RPC failed) → n/a; v2 program → no revocation row', () => {
    expect(find(verifyClaim(c, v3, DEMO_SIGNERS, { ...opts, revoked: null }), 'Signer not revoked')!.status).toBe('na');
    expect(find(verifyClaim(c, { ...v3, signers: null }, DEMO_SIGNERS, opts), 'Signer not revoked')).toBeUndefined();
  });
});

describe('proveCiphertext (v3 #2, mirrors the contract)', () => {
  const owner = nacl.box.keyPair.fromSecretKey(Uint8Array.from(atob(demo.owner_secret.secretKey), (x) => x.charCodeAt(0)));
  const ownerPub = encodeBase64(owner.publicKey);
  const body = demo.cases.sqli.request_body;
  const { ciphertext, ephemeralSecretHex } = encryptForOwnerWithSecret(body, ownerPub);

  it('the right ephemeral secret opens the box to req_hash', () => {
    expect(proveCiphertext(ciphertext, ownerPub, ephemeralSecretHex, sha256hex(body))).toEqual({ ok: true, plaintext: body });
  });

  it('a secret that is not the ciphertext ephemeral key is refused (contract panics)', () => {
    const other = '11'.repeat(32);
    expect(proveCiphertext(ciphertext, ownerPub, other, sha256hex(body))).toMatchObject({ ok: false, reason: 'ephemeral key mismatch' });
  });

  it('box that does not open, or plaintext ≠ req_hash → undecryptable report', () => {
    const bytes = Uint8Array.from(atob(ciphertext), (x) => x.charCodeAt(0));
    bytes[bytes.length - 1] ^= 1;
    expect(proveCiphertext(encodeBase64(bytes), ownerPub, ephemeralSecretHex, sha256hex(body))).toMatchObject({ ok: false, reason: 'undecryptable report' });
    expect(proveCiphertext(ciphertext, ownerPub, ephemeralSecretHex, sha256hex('other'))).toMatchObject({ ok: false, reason: 'undecryptable report' });
  });

  it('malformed secret is refused', () => {
    expect(proveCiphertext(ciphertext, ownerPub, 'zz', sha256hex(body))).toMatchObject({ ok: false });
  });
});
