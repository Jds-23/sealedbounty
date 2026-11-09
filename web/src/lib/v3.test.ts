// v3 (docs/INTERFACE.md "v3"): program + claim additions, new statuses and reject reasons.
import { describe, expect, it } from 'vitest';
import live from '../fixtures/live-views.json';
import { parseClaim, parseProgram } from './near';

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
