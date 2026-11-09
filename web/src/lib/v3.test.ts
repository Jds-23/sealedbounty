// v3 (docs/INTERFACE.md "v3"): program + claim additions, new statuses and reject reasons.
import { describe, expect, it } from 'vitest';
import live from '../fixtures/live-views.json';
import demo from '../fixtures/demo.json';
import { parseClaim, parseProgram } from './near';
import { buildDemo } from './demo';
import { auditRequest } from './requestChecks';
import { paramsHash } from './shared-v3.mjs';
import { claimStatusInfo, rejectInfo, undecryptableHint } from './status';
import { countdown } from './format';
import type { Claim } from './types';

const V = live.views;
const v1Program = V.get_program.result;
const v1Claim = V.get_claim.result;
const ED = 'ed25519:89154a43a47684742c3d1753252bb6f49f61da9d8c84fc9b1def2df130cb2d93';
const ETH = 'eth:0x835ab53d20294ef795906dff21ae4c045336aa26';
const PH = '61b52e7b87e42a2bc4b6f417d21ba0e9d44f3e1f4ff49fa9d2f3334e5aa0eda7';

describe('parseProgram v3', () => {
  const v3 = { ...v1Program, code_hash: PH, params_hash: PH.toUpperCase(), signers: [ED, ETH], bond: '500000000000000000000000', challenge_secs: 43200 };

  it('parses params_hash, signers, bond, challenge_secs', () => {
    expect(parseProgram(v3)).toMatchObject({ params_hash: PH, signers: [ED, ETH], bond: '500000000000000000000000', challenge_secs: 43200 });
  });

  it('v1/v2 data (fields missing) parses with the v3 fields null', () => {
    expect(parseProgram(v1Program)).toMatchObject({ params_hash: null, signers: null, bond: null, challenge_secs: null });
  });

  it('rejects garbage v3 fields', () => {
    expect(() => parseProgram({ ...v3, params_hash: 'abc' })).toThrow(/params_hash/);
    expect(() => parseProgram({ ...v3, signers: 'x' })).toThrow(/signers/);
    expect(() => parseProgram({ ...v3, signers: [1] })).toThrow(/signers/);
    expect(() => parseProgram({ ...v3, bond: -1 })).toThrow(/bond/);
    expect(() => parseProgram({ ...v3, challenge_secs: 'soon' })).toThrow(/challenge_secs/);
  });
});

describe('parseClaim v3', () => {
  it('parses bond and challenge_deadline', () => {
    const c = parseClaim({ ...v1Claim, status: 'Challenged', bond: '500000000000000000000000', challenge_deadline: '1794166992223273651' });
    expect(c).toMatchObject({ status: 'Challenged', bond: '500000000000000000000000', challenge_deadline: '1794166992223273651' });
  });

  it('accepts PayoutFailed', () => {
    expect(parseClaim({ ...v1Claim, status: 'PayoutFailed', bond: '0', challenge_deadline: null }).status).toBe('PayoutFailed');
  });

  it('v1/v2 claims parse with bond and challenge_deadline null', () => {
    expect(parseClaim(v1Claim)).toMatchObject({ bond: null, challenge_deadline: null });
  });
});

// ---- #1 params pinning: owner inbox runs 6 checks ----
describe('auditRequest v3 (params pinning)', () => {
  const base = buildDemo(0).programs[0];
  const program = { ...base, params_hash: paramsHash() };
  const body = demo.cases.idor.request_body;
  const H = demo.cases.idor.hunter;
  const mutate = (f: (r: any) => void) => {
    const r = JSON.parse(body);
    f(r);
    return JSON.stringify(r);
  };
  const status = (a: ReturnType<typeof auditRequest>) => Object.fromEntries(a.checks.map((x) => [x.key, x.ok]));

  it('paramsHash of every recorded demo request is the canonical pinned hash', () => {
    expect(paramsHash()).toBe(PH);
    for (const f of Object.values(demo.cases)) expect(paramsHash(JSON.parse(f.request_body))).toBe(PH);
  });

  it('honest request passes all 6 checks in contract order', () => {
    const a = auditRequest(body, program, H);
    expect(a).toMatchObject({ ok: true, reason: null, v1: false });
    expect(a.checks.map((x) => x.key)).toEqual(['prompt', 'model', 'params', 'code', 'hunter', 'report']);
    expect(status(a)).toEqual({ prompt: true, model: true, params: true, code: true, hunter: true, report: true });
    expect(a.checks.find((x) => x.key === 'params')!.detail).toMatch(/= program\.params_hash/);
  });

  it.each([
    ['temperature', mutate((r) => (r.temperature = 1.5))],
    ['response_format', mutate((r) => (r.response_format.json_schema.schema.properties.valid = { type: 'boolean', const: true }))],
    ['max_tokens', mutate((r) => (r.max_tokens = 4000))],
    ['logit_bias', mutate((r) => (r.logit_bias = { 1: 100 }))],
    ['response_format', mutate((r) => delete r.response_format)],
  ])('tampered %s → "params tampered", the detail names it', (key, b) => {
    const a = auditRequest(b, program, H);
    expect(a).toMatchObject({ ok: false, reason: 'params tampered' });
    expect(status(a)).toMatchObject({ prompt: true, model: true, params: false });
    expect(a.checks.find((x) => x.key === 'params')!.detail).toContain(key);
  });

  it('reason order: model mismatch is reported before params', () => {
    const b = mutate((r) => {
      r.model = 'Other/Model';
      r.temperature = 1.5;
    });
    expect(auditRequest(b, program, H).reason).toBe('model mismatch');
  });

  it('v2 program (no params_hash): params check is n/a, rest unchanged', () => {
    const a = auditRequest(mutate((r) => (r.temperature = 1.5)), base, H);
    expect(a).toMatchObject({ ok: true, reason: null });
    expect(status(a).params).toBeNull();
  });
});

// ---- statuses and reject reasons ----
const claim = (over: Partial<Claim>): Claim => ({ ...buildDemo(0).claims[0], ...over });

describe('reject reasons (v3)', () => {
  it.each([
    ['params tampered', /params/i],
    ['undecryptable report', /ciphertext|decrypt/i],
    ['signer revoked', /revoked/i],
  ])('%s has a one-line explanation', (reason, re) => {
    const r = rejectInfo(reason);
    expect(r.why).toMatch(re);
    expect(r.why).not.toContain('\n');
    expect(r.source.length).toBeGreaterThan(0);
  });

  it('v2 reasons are still explained; unknown reasons degrade gracefully', () => {
    expect(rejectInfo('code mismatch').why).toMatch(/code_hash/);
    expect(rejectInfo('weird').why).toBe('');
    expect(rejectInfo(null).source).toMatch(/Rejected/);
  });

  it('undecryptable report comes from the challenge, signer revoked from finalize', () => {
    expect(rejectInfo('undecryptable report').source).toMatch(/challenge/i);
    expect(rejectInfo('signer revoked').source).toMatch(/finalize/i);
    expect(rejectInfo('params tampered').source).toMatch(/dispute/i);
  });
});

describe('claim status info (v3)', () => {
  const now = 1_000_000_000;
  const ns = (ms: number) => (BigInt(ms) * 1_000_000n).toString();

  it('Challenged: deadline countdown, hunter must reveal key', () => {
    const i = claimStatusInfo(claim({ status: 'Challenged', challenge_deadline: ns(now + 3_600_000) }), now);
    expect(i.tone).toBe('warn');
    expect(i.headline).toMatch(/hunter must reveal key/);
    expect(i.deadline).toBe(ns(now + 3_600_000));
    expect(i.detail).toMatch(/prove_ciphertext/);
  });

  it('Challenged past the deadline: finalize rejects it', () => {
    const i = claimStatusInfo(claim({ status: 'Challenged', challenge_deadline: ns(now - 1) }), now);
    expect(i.detail).toMatch(/undecryptable report/);
  });

  it('PayoutFailed: payout + bond back to the pool', () => {
    const i = claimStatusInfo(claim({ status: 'PayoutFailed', bond: '1' }), now);
    expect(i.tone).toBe('bad');
    expect(i.headline).toMatch(/payout failed/i);
    expect(i.detail).toMatch(/back to the pool/);
  });

  it('countdown labels the challenge window', () => {
    expect(countdown(3_661_000, 'challenge')).toBe('1h 01m 01s left for the hunter to prove_ciphertext');
    expect(countdown(0, 'challenge')).toMatch(/challenge expired/);
    expect(countdown(3_661_000)).toBe('1h 01m 01s left to dispute');
  });
});

describe('owner inbox: undecryptable ciphertext', () => {
  it('Pending → tells the owner to flag it', () => {
    expect(undecryptableHint(claim({ id: 7, status: 'Pending' }))).toBe('UNDECRYPTABLE → `sb flag-undecryptable --claim 7`');
  });
  it('Challenged / Rejected → no new action', () => {
    expect(undecryptableHint(claim({ id: 7, status: 'Challenged' }))).toMatch(/already flagged/);
    expect(undecryptableHint(claim({ id: 7, status: 'Rejected', reject_reason: 'undecryptable report' }))).toMatch(/rejected/i);
  });
});
