import { describe, expect, it } from 'vitest';
import nacl from 'tweetnacl';
import { encodeBase64 } from 'ethers';
import att from '../fixtures/attestation.summary.json';
import demo from '../fixtures/demo.json';

const liveEd = demo.cases.idor;
const cases = Object.entries(demo.cases);
import { b64ToBytes, normaliseSigners, parseVerdict, quoteBindsSigner, sha256hex, signedText, signerFrom, verifySignature } from './verify';
import { decryptReport, encryptReport, parseOwnerSecret, reportMatchesHash } from './crypto';
import { verifyClaim } from './checks';
import { buildDemo, DEMO_RESP_BODIES, DEMO_SIGNERS } from './demo';

/** Test helper: flip one hex nibble at position i. */
const tamperHex = (h: string, i = 10) => h.slice(0, i) + (h[i] === '0' ? '1' : '0') + h.slice(i + 1);

describe.each(cases)('recorded fixture %s', (_name, f) => {
  const signer = signerFrom(f.signing_algo, f.signing_address);
  const text = signedText('provider_tee', f.model, f.req_hash, f.resp_hash);

  it('hashes match the recorded bodies', () => {
    expect(sha256hex(f.request_body)).toBe(f.req_hash);
    expect(sha256hex(b64ToBytes(f.response_body_b64))).toBe(f.resp_hash);
    expect(text).toBe(f.text);
  });

  it('real signature verifies', () => {
    expect(verifySignature(signer, text, f.signature).ok).toBe(true);
  });

  it('one tampered byte in resp_hash fails', () => {
    const bad = signedText('provider_tee', f.model, f.req_hash, tamperHex(f.resp_hash));
    expect(verifySignature(signer, bad, f.signature).ok).toBe(false);
  });

  it('one tampered byte in the signature fails', () => {
    expect(verifySignature(signer, text, tamperHex(f.signature, 20)).ok).toBe(false);
  });

  it('wrong model fails', () => {
    const bad = signedText('provider_tee', 'Qwen/Other', f.req_hash, f.resp_hash);
    expect(verifySignature(signer, bad, f.signature).ok).toBe(false);
  });

  it('verdict parses from signed body and matches the recorded verdict', () => {
    expect(parseVerdict(b64ToBytes(f.response_body_b64))).toEqual(f.verdict);
  });
});

describe('signer handling', () => {
  it('rejects malformed signers without throwing', () => {
    expect(verifySignature('ed25519:abcd', 'x', '00').ok).toBe(false);
    expect(verifySignature('foo:bar', 'x', '00').ok).toBe(false);
  });
  it('normalises get_signers tuple output', () => {
    const s = normaliseSigners([['ed25519:aa', { kind: 'provider_tee', model: null }]]);
    expect(s[0]).toEqual({ signer: 'ed25519:aa', meta: { kind: 'provider_tee', model: null } });
  });
});

describe('attestation quote binding', () => {
  for (const a of Object.values(att)) {
    const m = a.model_attestation;
    it(`${m.signing_algo} quote report_data binds signer`, () => {
      expect(quoteBindsSigner(m.intel_quote, m.signing_address, m.request_nonce).ok).toBe(true);
      expect(quoteBindsSigner(m.intel_quote, tamperHex(m.signing_address, 5), m.request_nonce).ok).toBe(false);
    });
  }
});

describe('verifyClaim (demo data)', () => {
  const { programs, claims } = buildDemo(0);
  it('all computable checks pass for real data', () => {
    for (const c of claims) {
      const checks = verifyClaim(c, programs[c.program_id], DEMO_SIGNERS, { respBodyB64: DEMO_RESP_BODIES[c.id], signersSource: 'demo' });
      expect(checks.filter((x) => x.status === 'fail')).toEqual([]);
      expect(checks.filter((x) => x.status === 'pass').length).toBeGreaterThanOrEqual(4);
    }
  });
  it('tampered claim shows red', () => {
    const c = { ...claims[0], resp_hash: tamperHex(claims[0].resp_hash) };
    const checks = verifyClaim(c, programs[0], DEMO_SIGNERS, { signersSource: 'demo' });
    expect(checks.find((x) => x.label.startsWith('TEE signature'))!.status).toBe('fail');
  });
  it('unknown signer fails allowlist', () => {
    const checks = verifyClaim(claims[0], programs[0], [], { signersSource: 'contract' });
    expect(checks.find((x) => x.label.startsWith('Signer allowlisted'))!.status).toBe('fail');
  });
});

describe('owner decryption', () => {
  it('round-trips and hash-checks', () => {
    const kp = nacl.box.keyPair();
    const ct = encryptReport(liveEd.request_body, kp.publicKey);
    const pt = decryptReport(ct, kp.secretKey);
    expect(pt).toBe(liveEd.request_body);
    expect(reportMatchesHash(pt, liveEd.req_hash)).toBe(true);
  });
  it('wrong key throws', () => {
    const ct = encryptReport('hi', nacl.box.keyPair().publicKey);
    expect(() => decryptReport(ct, nacl.box.keyPair().secretKey)).toThrow(/decryption failed/);
  });
  it('tampered ciphertext throws', () => {
    const kp = nacl.box.keyPair();
    const ct = b64ToBytes(encryptReport('hi', kp.publicKey));
    ct[60] ^= 1;
    expect(() => decryptReport(encodeBase64(ct), kp.secretKey)).toThrow();
  });
  it('decrypts every bundled demo ciphertext with the demo owner file (CLI shape)', () => {
    const { secretKey, publicKeyB64 } = parseOwnerSecret(JSON.stringify(demo.owner_secret));
    expect(publicKeyB64).toBe(demo.owner_secret.publicKey);
    for (const [name, ct] of Object.entries(demo.ciphertexts)) {
      const pt = decryptReport(ct, secretKey);
      expect(reportMatchesHash(pt, demo.cases[name as keyof typeof demo.cases].req_hash)).toBe(true);
    }
  });
  it('parses unknown field names and bare base64', () => {
    const sk = encodeBase64(nacl.randomBytes(32));
    expect(parseOwnerSecret(JSON.stringify({ public_key: encodeBase64(nacl.randomBytes(32)), whatever: sk })).secretKey).toEqual(b64ToBytes(sk));
    expect(parseOwnerSecret(sk).secretKey).toEqual(b64ToBytes(sk));
    expect(() => parseOwnerSecret('{"a":1}')).toThrow();
  });
});
