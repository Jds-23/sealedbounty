// Parses the recorded real view JSON from escrow.baldingsucks7993.testnet and runs the browser checks on it.
import { existsSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import live from '../fixtures/live-views.json';
import { parseClaim, parseProgram } from './near';
import { normaliseSigners, sha256hex } from './verify';
import { verifyClaim } from './checks';
import { decryptReport, parseOwnerSecret, reportMatchesHash } from './crypto';
import { fmtSecs, yoctoToNear } from './format';

const V = live.views;
const programs = V.list_programs.result.map(parseProgram);
const claims = V.list_claims.result.map(parseClaim);
const signers = normaliseSigners(V.get_signers.result);

describe('live view shapes', () => {
  it('records the arg names the contract accepts', () => {
    expect(V.get_program.args).toEqual({ id: 0 });
    expect(V.get_claim.args).toEqual({ id: 0 });
    expect(Object.keys(V.list_claims.args).sort()).toEqual(['from_index', 'limit', 'program_id']);
  });

  it('parses program 0 (u64 ids as numbers, U128 strings, ns timestamps)', () => {
    const p = programs[0];
    expect(p.id).toBe(0);
    expect(p.name).toBe('vuln-app demo');
    expect(yoctoToNear(p.balance)).toBe('0.74');
    expect(yoctoToNear(p.reserved)).toBe('0.00');
    expect(yoctoToNear(p.payouts.high, 1)).toBe('0.3');
    expect(fmtSecs(p.dispute_secs)).toBe('90s');
    expect(new Date(Number(BigInt(p.created_at) / 1_000_000n)).getUTCFullYear()).toBeGreaterThanOrEqual(2026);
    expect(parseProgram(V.get_program.result)).toEqual(p);
  });

  it('parses claim 0 as Paid with a null reject_reason', () => {
    const c = claims[0];
    expect(c).toMatchObject({ id: 0, program_id: 0, status: 'Paid', hunter: 'hunter.baldingsucks7993.testnet', reject_reason: null });
    expect(c.verdict).toEqual({ valid: true, severity: 'high', cwe: 'CWE-639', confidence: 98 });
    expect(c.payout).toBe(programs[0].payouts.high);
    expect(c.signature).toMatch(/^[0-9a-f]{128}$/);
    expect(BigInt(c.finalize_after) - BigInt(c.submitted_at)).toBe(BigInt(programs[0].dispute_secs) * 1_000_000_000n);
    expect(parseClaim(V.get_claim.result)).toEqual(c);
  });

  it('normalises get_signers tuples', () => {
    expect(signers.map((s) => s.signer)).toEqual([
      'ed25519:89154a43a47684742c3d1753252bb6f49f61da9d8c84fc9b1def2df130cb2d93',
      'eth:0x835ab53d20294ef795906dff21ae4c045336aa26',
    ]);
    expect(signers[0].meta).toEqual({ kind: 'provider_tee', model: 'Qwen/Qwen3.8-27B' });
  });

  it('coerces tolerable variants and rejects garbage', () => {
    const raw = V.list_claims.result[0];
    expect(parseClaim({ ...raw, id: '0', payout: 5, signature: '0x' + raw.signature.toUpperCase(), status: 'paid' })).toMatchObject({
      id: 0,
      payout: '5',
      signature: raw.signature,
      status: 'Paid',
    });
    expect(() => parseClaim({ ...raw, status: 'Weird' })).toThrow(/status/);
    expect(() => parseProgram({ ...V.get_program.result, balance: 1e30 })).toThrow(/balance/);
  });
});

describe('verified panel on live claim 0', () => {
  const checks = verifyClaim(claims[0], programs[0], signers, { signersSource: 'contract' });
  const by = (prefix: string) => checks.find((x) => x.label.startsWith(prefix))!;

  it('signature, allowlist, model and quote binding are green; nothing fails', () => {
    expect(checks.filter((x) => x.status === 'fail')).toEqual([]);
    expect(by('Signed model').status).toBe('pass');
    expect(by('TEE signature').status).toBe('pass');
    expect(by('Signer allowlisted').status).toBe('pass');
    expect(by('TDX quote').status).toBe('pass');
  });

  it('verdict item is honest about what is stored', () => {
    expect(by('Verdict bound via onchain resp_hash; body not stored').status).toBe('na');
  });

  it('fails if the signer is pinned to another model', () => {
    const pinned = signers.map((s) => ({ ...s, meta: { ...s.meta, model: 'Other/Model' } }));
    expect(
      verifyClaim(claims[0], programs[0], pinned, { signersSource: 'contract' }).find((x) => x.label.startsWith('Signer allowlisted'))!.status,
    ).toBe('fail');
  });

  it('tampered resp_hash fails the signature', () => {
    const c = { ...claims[0], resp_hash: claims[0].resp_hash.replace(/^./, (x) => (x === '0' ? '1' : '0')) };
    expect(verifyClaim(c, programs[0], signers, { signersSource: 'contract' }).find((x) => x.label.startsWith('TEE signature'))!.status).toBe('fail');
  });
});

// Reads the real owner key at test time only (never copied into the repo). Skipped where it doesn't exist (CI).
const OWNER_FILE = process.env.SB_OWNER_FILE || join(homedir(), '.sealedbounty', 'owner-0.json');
describe.skipIf(!existsSync(OWNER_FILE))('owner inbox with the real program-0 key', () => {
  it('decrypts claim 0: sha256 == req_hash, system prompt and model match', () => {
    const { secretKey, publicKeyB64 } = parseOwnerSecret(readFileSync(OWNER_FILE, 'utf8'));
    expect(publicKeyB64).toBe(programs[0].owner_enc_pubkey);
    const pt = decryptReport(claims[0].ciphertext, secretKey);
    expect(reportMatchesHash(pt, claims[0].req_hash)).toBe(true);
    const req = JSON.parse(pt) as { model: string; messages: { role: string; content: string }[] };
    expect(req.model).toBe(programs[0].model_id);
    expect(req.messages[0].role).toBe('system');
    expect(sha256hex(req.messages[0].content)).toBe(programs[0].system_prompt_hash);
  });
});
