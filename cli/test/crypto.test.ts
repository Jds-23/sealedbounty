import { mkdtempSync, readFileSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import nacl from 'tweetnacl';
import { describe, expect, it } from 'vitest';
import { finalizeOwnerKey, loadOwnerKey, savePendingOwnerKey } from '../src/crypto.js';
import { shared } from '../src/shared.js';

const body = readFileSync(new URL('../../fixtures/demo.sqli.json', import.meta.url), 'utf8');
const requestBody: string = JSON.parse(body).request_body;

describe('owner encryption (shared/judge.mjs)', () => {
  it('roundtrips the exact request body', () => {
    const kp = shared.generateOwnerKeypair();
    const ct = shared.encryptForOwner(requestBody, kp.publicKey);
    expect(shared.decryptAsOwner(ct, kp.secretKey)).toBe(requestBody);
    expect(shared.sha256hex(shared.decryptAsOwner(ct, kp.secretKey))).toBe(JSON.parse(body).req_hash);
  });
  it('has the INTERFACE.md layout: ephPub(32) || nonce(24) || box', () => {
    const kp = shared.generateOwnerKeypair();
    const ct = Buffer.from(shared.encryptForOwner('héllo', kp.publicKey), 'base64');
    expect(ct.length).toBe(32 + 24 + nacl.box.overheadLength + Buffer.byteLength('héllo'));
    const opened = nacl.box.open(ct.subarray(56), ct.subarray(32, 56), ct.subarray(0, 32), Buffer.from(kp.secretKey, 'base64'));
    expect(Buffer.from(opened!).toString('utf8')).toBe('héllo');
  });
  it('fails with the wrong key and is randomized', () => {
    const a = shared.generateOwnerKeypair();
    const b = shared.generateOwnerKeypair();
    const ct = shared.encryptForOwner('x', a.publicKey);
    expect(() => shared.decryptAsOwner(ct, b.secretKey)).toThrow();
    expect(shared.encryptForOwner('x', a.publicKey)).not.toBe(ct);
  });
});

describe('owner key file', () => {
  it('saves pending, then renames to owner-<id>.json with mode 600', () => {
    const home = mkdtempSync(join(tmpdir(), 'sb-'));
    const kp = shared.generateOwnerKeypair();
    const pending = savePendingOwnerKey(kp, 'escrow.x.testnet', 'testnet', home);
    expect(statSync(pending).mode & 0o777).toBe(0o600);
    const dest = finalizeOwnerKey(pending, 7, home);
    expect(dest).toBe(join(home, 'owner-7.json'));
    expect(statSync(dest).mode & 0o777).toBe(0o600);
    const loaded = loadOwnerKey(7, home);
    expect(loaded).toMatchObject({ ...kp, program_id: 7, contract_id: 'escrow.x.testnet' });
    expect(() => finalizeOwnerKey(savePendingOwnerKey(shared.generateOwnerKeypair(), 'c', 'testnet', home), 7, home)).toThrow(/already exists/);
  });
});
