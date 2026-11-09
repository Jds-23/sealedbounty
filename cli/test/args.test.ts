import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  CLAIM_DEPOSIT_MARGIN,
  CLAIM_FIXED_BYTES,
  PROGRAM_STORAGE_ALLOWANCE,
  addSignerArgs,
  createProgramArgs,
  disputeArgs,
  estimateClaimStorageDeposit,
  finalizeArgs,
  payabilityChecks,
  splitRequest,
  submitClaimArgs,
} from '../src/args.js';
import { verifyClaimChecks } from '../src/commands.js';
import { shared } from '../src/shared.js';
import type { Claim, JudgeRecord, Program } from '../src/types.js';
import { formatNear, nearToYocto } from '../src/util.js';

const load = (f: string): JudgeRecord => JSON.parse(readFileSync(new URL(`../../fixtures/${f}`, import.meta.url), 'utf8'));
const live = load('live.ed25519.json');
const liveEcdsa = load('live.ecdsa.json');
const sqli = load('demo.sqli.json');
const DEMO_CODE_HASH = '82faf3a0cd6148f95ba3b8011f8e9af67d5f9d5b8f8638002be7787a37285abd';

const program = (o: Partial<Program> = {}): Program => ({
  id: 0,
  owner: 'owner.testnet',
  name: 'demo',
  repo_url: 'https://github.com/sealedbounty/sealedbounty/tree/main/fixtures/vuln-app',
  commit: 'demo-commit-0001',
  model_id: 'Qwen/Qwen3.8-27B',
  system_prompt_hash: shared.systemPromptHash(),
  code_hash: DEMO_CODE_HASH,
  payouts: { low: '1', medium: '2', high: nearToYocto(3).toString(), critical: nearToYocto(5).toString() },
  owner_enc_pubkey: shared.generateOwnerKeypair().publicKey,
  dispute_secs: 60,
  min_confidence: 70,
  balance: nearToYocto(10).toString(),
  reserved: '0',
  open: true,
  created_at: '0',
  ...o,
});

describe('units', () => {
  it('nearToYocto is exact', () => {
    expect(nearToYocto('1')).toBe(10n ** 24n);
    expect(nearToYocto('0.5')).toBe(5n * 10n ** 23n);
    expect(nearToYocto('0.000000000000000000000001')).toBe(1n);
    expect(() => nearToYocto('-1')).toThrow();
    expect(() => nearToYocto('1e3')).toThrow();
  });
  it('formatNear', () => {
    expect(formatNear(nearToYocto('1.25'))).toBe('1.25 NEAR');
    expect(formatNear(0n)).toBe('0 NEAR');
  });
});

describe('add_signer args', () => {
  it('ed25519', () => {
    expect(addSignerArgs('ed25519', live.signing_address, 'provider_tee', 'Qwen/Qwen3.8-27B')).toEqual({
      signer: 'ed25519:89154a43a47684742c3d1753252bb6f49f61da9d8c84fc9b1def2df130cb2d93',
      meta: { kind: 'provider_tee', model: 'Qwen/Qwen3.8-27B' },
    });
  });
  it('ecdsa lowercases and keeps 0x', () => {
    expect(addSignerArgs('ecdsa', '0x835AB53D20294EF795906DFF21AE4C045336AA26', 'provider_tee', null).signer).toBe(
      'eth:0x835ab53d20294ef795906dff21ae4c045336aa26',
    );
  });
});

describe('create_program args', () => {
  const base = {
    name: 'demo',
    repoUrl: 'https://github.com/sealedbounty/vuln-app',
    commit: 'demo-commit-0001',
    modelId: 'Qwen/Qwen3.8-27B',
    systemPromptHash: shared.systemPromptHash(),
    codeHash: DEMO_CODE_HASH,
    paramsHash: shared.paramsHash(),
    payoutsNear: { low: '0.1', medium: '0.5', high: '1', critical: '2.5' },
    ownerEncPubkey: shared.generateOwnerKeypair().publicKey,
    disputeSecs: 300,
    minConfidence: 70,
    fundNear: '5',
  };
  it('maps to contract field names with yocto U128 strings', () => {
    const { args, deposit } = createProgramArgs(base);
    expect(Object.keys(args)).toEqual([
      'name', 'repo_url', 'commit', 'model_id', 'system_prompt_hash', 'code_hash', 'params_hash', 'payouts', 'owner_enc_pubkey',
      'dispute_secs', 'min_confidence', 'bond', 'challenge_secs', 'signers',
    ]);
    expect(args.code_hash).toBe(DEMO_CODE_HASH);
    expect(args.payouts).toEqual({
      low: '100000000000000000000000',
      medium: '500000000000000000000000',
      high: '1000000000000000000000000',
      critical: '2500000000000000000000000',
    });
    expect(args.system_prompt_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(deposit).toBe(nearToYocto(5) + PROGRAM_STORAGE_ALLOWANCE);
  });
  it('validates inputs', () => {
    expect(() => createProgramArgs({ ...base, minConfidence: 101 })).toThrow();
    expect(() => createProgramArgs({ ...base, ownerEncPubkey: 'AAAA' })).toThrow();
    expect(() => createProgramArgs({ ...base, systemPromptHash: 'xyz' })).toThrow();
    expect(() => createProgramArgs({ ...base, codeHash: 'xyz' })).toThrow(/code_hash/);
    expect(() => createProgramArgs({ ...base, codeHash: DEMO_CODE_HASH.toUpperCase() })).toThrow(/code_hash/);
  });
});

describe('fixture -> submit_claim args', () => {
  it('maps live.ed25519.json', () => {
    const args = submitClaimArgs(0, live, 'CT');
    expect(args).toEqual({
      program_id: 0,
      req_hash: '533e6d1fd59e76068fef8019c2986bbe9a27304b4472623834f9b8350f3cd577',
      resp_body: live.response_body_b64,
      signature: live.signature,
      signer: 'ed25519:89154a43a47684742c3d1753252bb6f49f61da9d8c84fc9b1def2df130cb2d93',
      kind: 'provider_tee',
      ciphertext: 'CT',
    });
  });
  it('maps live.ecdsa.json to an eth signer', () => {
    expect(submitClaimArgs(3, liveEcdsa, 'CT').signer).toBe('eth:0x835ab53d20294ef795906dff21ae4c045336aa26');
  });
  it('matches the convenience signer field shared writes into demo fixtures', () => {
    expect(submitClaimArgs(0, sqli, 'CT').signer).toBe(sqli.signer);
  });
  it('the resulting on-chain claim fields verify offline (verify-claim)', async () => {
    const a = submitClaimArgs(0, sqli, 'CT');
    const claim = {
      id: 0, program_id: 0, hunter: 'h.testnet', req_hash: a.req_hash, resp_hash: sqli.resp_hash,
      verdict: (sqli as any).verdict, signer: a.signer, kind: a.kind, signature: a.signature, model: 'Qwen/Qwen3.8-27B',
      ciphertext: 'CT', status: 'Pending', payout: '0', submitted_at: '0', finalize_after: '0', reject_reason: null,
    } as Claim;
    const allow = new Map([[a.signer, { kind: 'provider_tee' }]]);
    const rows = await verifyClaimChecks(claim, program(), allow);
    expect(rows.every((r) => r[1])).toBe(true);
    const bad = await verifyClaimChecks({ ...claim, resp_hash: live.resp_hash }, program(), allow);
    expect(bad.find((r) => r[0].startsWith('signature'))![1]).toBe(false);
  });
});

describe('storage deposit estimate', () => {
  it('is (len + fixed) * 1e19 + margin', () => {
    const ct = 'x'.repeat(1000);
    const { bytes, deposit } = estimateClaimStorageDeposit(ct);
    expect(bytes).toBe(1000n + CLAIM_FIXED_BYTES);
    expect(deposit).toBe((1000n + CLAIM_FIXED_BYTES) * 10n ** 19n + CLAIM_DEPOSIT_MARGIN);
  });
  it('covers a real encrypted demo report with < 0.2 NEAR', () => {
    const ct = shared.encryptForOwner(sqli.request_body, shared.generateOwnerKeypair().publicKey);
    const { deposit } = estimateClaimStorageDeposit(ct);
    expect(deposit).toBeGreaterThan(BigInt(ct.length) * 10n ** 19n);
    expect(deposit).toBeLessThan(nearToYocto('0.2'));
  });
});

describe('dispute / finalize args', () => {
  it('shapes', () => {
    expect(disputeArgs(4, '{"a":1}')).toEqual({ claim_id: 4, request_body: '{"a":1}' });
    expect(finalizeArgs(4)).toEqual({ claim_id: 4 });
  });
});

describe('local pre-checks', () => {
  it('payability mirrors the contract', () => {
    const v = (sqli as any).verdict;
    expect(payabilityChecks(v, program()).every((r) => r[1])).toBe(true);
    expect(payabilityChecks({ ...v, confidence: 10 }, program()).some((r) => !r[1])).toBe(true);
    expect(payabilityChecks(v, program({ balance: '0' })).some((r) => !r[1])).toBe(true);
    expect(payabilityChecks({ valid: false, severity: 'none', cwe: null, confidence: 100 }, program()).filter((r) => !r[1]).length).toBe(2);
  });
  it('v2 request check: demo fixture matches the demo program for its own hunter, phase-0 fixture does not', () => {
    const hunter = (sqli as any).inputs.hunter;
    expect(shared.checkRequestAgainstProgram(sqli.request_body, program(), hunter)).toEqual({ ok: true, reason: null });
    expect(shared.checkRequestAgainstProgram(live.request_body, program(), hunter).ok).toBe(false);
  });
  it('splitRequest recovers the v2 inputs', () => {
    const u = splitRequest(sqli.request_body);
    const inputs = (sqli as any).inputs;
    expect(u.target).toBe(`${inputs.repoUrl}@${inputs.commit}`);
    expect(u.hunter).toBe(inputs.hunter);
    expect(shared.codeHash(u.code!)).toBe(DEMO_CODE_HASH);
    expect(u.report).toBe(inputs.report);
  });
});
