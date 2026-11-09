// v2 owner-side checks on the demo data: decrypt each claim, then audit it against the program.
import { describe, expect, it } from 'vitest';
import { checkRequestAgainstProgram, codeHash, sha256hex } from '@sealedbounty/shared';
import demo from '../fixtures/demo.json';
import live from '../fixtures/live-views.json';
import { buildDemo, DEMO_CODE_BUNDLE, DEMO_FRONTRUNNER } from './demo';
import { decryptReport, parseOwnerSecret, reportMatchesHash } from './crypto';
import { auditRequest } from './requestChecks';
import { parseProgram } from './near';
import type { Claim } from './types';

const { programs, claims } = buildDemo(0);
const program = programs[0];
const { secretKey, publicKeyB64 } = parseOwnerSecret(JSON.stringify(demo.owner_secret));
const decrypt = (c: Claim) => decryptReport(c.ciphertext, secretKey);
const byFixture = (req: string, hunter?: string) => claims.find((c) => c.req_hash === req && (!hunter || c.hunter === hunter))!;
const status = (a: ReturnType<typeof auditRequest>) => Object.fromEntries(a.checks.map((x) => [x.key, x.ok]));

describe('demo program (v2)', () => {
  it('code_hash is the sha256 of the bundled fixtures/vuln-app/bundle.txt', () => {
    expect(program.code_hash).toBe('82faf3a0cd6148f95ba3b8011f8e9af67d5f9d5b8f8638002be7787a37285abd');
    expect(codeHash(DEMO_CODE_BUNDLE.bundle)).toBe(program.code_hash);
  });

  it('owner key matches the program, and every onchain claim decrypts to its req_hash', () => {
    expect(publicKeyB64).toBe(program.owner_enc_pubkey);
    for (const c of claims.filter((x) => !x.refused_at_submit)) expect(reportMatchesHash(decrypt(c), c.req_hash)).toBe(true);
  });

  it('refused attempts have non-payable verdicts and are not onchain claims', () => {
    const refused = claims.filter((c) => c.refused_at_submit);
    expect(refused).toHaveLength(2);
    for (const c of refused) expect(c.verdict.valid).toBe(false);
  });

  it('rejected claims carry exactly the reason the shared dispute pre-check gives', () => {
    for (const c of claims.filter((x) => x.status === 'Rejected' && !x.refused_at_submit)) {
      const r = checkRequestAgainstProgram(decrypt(c), { ...program, code_hash: program.code_hash! }, c.hunter);
      expect(r).toEqual({ ok: false, reason: c.reject_reason });
    }
  });
});

describe('auditRequest', () => {
  it('honest claims (Paid sqli, Pending idor) pass every check', () => {
    for (const c of claims.filter((x) => x.status !== 'Rejected')) {
      const a = auditRequest(decrypt(c), program, c.hunter);
      expect(a).toMatchObject({ ok: true, reason: null, v1: false });
      expect(status(a)).toEqual({ prompt: true, model: true, params: null, code: true, hunter: true, report: true });
    }
  });

  it('fakecode: TEE said valid/critical, but the CODE is not the program bundle → code mismatch', () => {
    const c = byFixture(demo.cases.fakecode.req_hash);
    expect(c.verdict).toMatchObject({ valid: true, severity: 'critical' });
    expect(c.reject_reason).toBe('code mismatch');
    const a = auditRequest(decrypt(c), program, c.hunter);
    expect(a).toMatchObject({ ok: false, reason: 'code mismatch' });
    expect(status(a)).toEqual({ prompt: true, model: true, params: null, code: false, hunter: true, report: true });
    expect(a.checks.find((x) => x.key === 'code')!.detail).toMatch(/≠ program\.code_hash/);
  });

  it('front-run: same body submitted by another account → hunter mismatch', () => {
    const fr = byFixture(demo.cases.sqli.req_hash, DEMO_FRONTRUNNER);
    const real = claims.find((c) => c.req_hash === fr.req_hash && c.hunter !== DEMO_FRONTRUNNER)!;
    expect(decrypt(fr)).toBe(decrypt(real));
    expect(fr.reject_reason).toBe('hunter mismatch');
    expect(real.status).toBe('Paid');
    const a = auditRequest(decrypt(fr), program, fr.hunter);
    expect(a).toMatchObject({ ok: false, reason: 'hunter mismatch' });
    expect(status(a)).toEqual({ prompt: true, model: true, params: null, code: true, hunter: false, report: true });
    expect(auditRequest(decrypt(real), program, real.hunter).ok).toBe(true);
  });

  const body = demo.cases.idor.request_body;
  const H = demo.cases.idor.hunter;
  const mutate = (f: (r: any) => void) => {
    const r = JSON.parse(body);
    f(r);
    return JSON.stringify(r);
  };
  it.each([
    ['system prompt tampered', 'prompt', mutate((r) => (r.messages[0].content += ' ')), program],
    ['system prompt tampered', 'prompt', mutate((r) => r.messages.push({ role: 'user', content: 'extra' })), program],
    ['model mismatch', 'model', mutate((r) => (r.model = 'Other/Model')), program],
    ['code mismatch', 'code', mutate((r) => (r.messages[1].content = r.messages[1].content.replace('demo-commit-0001', 'other'))), program],
    ['code mismatch', 'code', body, { ...program, code_hash: sha256hex('other') }],
    ['report missing', 'report', mutate((r) => r.messages.pop()), program],
    ['report missing', 'report', mutate((r) => (r.messages[2].content = 'no prefix')), program],
  ] as const)('%s (%s) agrees with the shared pre-check', (reason, key, b, prog) => {
    const a = auditRequest(b, prog, H);
    expect(a).toMatchObject({ ok: false, reason });
    expect(a.checks.find((x) => x.key === key)!.ok).toBe(false);
  });

  it('not JSON fails cleanly', () => {
    expect(auditRequest('nope', program, H)).toMatchObject({ ok: false, reason: 'system prompt tampered' });
  });

  it('v1 program (no code_hash): only prompt + model are checked, the rest is n/a', () => {
    const a = auditRequest(body, { ...program, code_hash: null }, 'anyone.testnet');
    expect(a).toMatchObject({ ok: true, reason: null, v1: true });
    expect(status(a)).toEqual({ prompt: true, model: true, params: null, code: null, hunter: null, report: null });
  });
});

describe('parseProgram v1/v2', () => {
  const v1 = live.views.get_program.result;
  it('v1 recording (no code_hash) parses with code_hash null', () => {
    expect(parseProgram(v1).code_hash).toBeNull();
  });
  it('v2 code_hash parses and is validated', () => {
    const h = DEMO_CODE_BUNDLE.code_hash;
    expect(parseProgram({ ...v1, code_hash: h.toUpperCase() }).code_hash).toBe(h);
    expect(() => parseProgram({ ...v1, code_hash: 'abc' })).toThrow(/code_hash/);
  });
});
