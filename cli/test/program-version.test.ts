// #14: owner-side request checks are gated by program version (mocked chain, nothing touches the network).
// v1 program (no code_hash/params_hash/signers/bond): prompt + model only.
// v2 program (code_hash, no params_hash): everything but params.
// v3 program: all six (prompt, model, params, code, hunter, report).
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { Claim, JudgeRecord, Program } from '../src/types.js';

const near = vi.hoisted(() => ({
  callContract: vi.fn(),
  mustGetProgram: vi.fn(),
  mustGetClaim: vi.fn(),
  listClaims: vi.fn(),
  listPrograms: vi.fn(),
  getSigners: vi.fn(),
  isSignerRevoked: vi.fn(async () => false),
  loadAccount: vi.fn((id?: string) => ({ accountId: id ?? 'hunter.testnet' })),
}));
vi.mock('../src/near.js', () => near);

const { cmdVerifyClaim, cmdInbox, cmdDispute } = await import('../src/commands.js');
const { demo, shared } = await import('../src/shared.js');
const { nearToYocto } = await import('../src/util.js');
const { savePendingOwnerKey, finalizeOwnerKey } = await import('../src/crypto.js');

const root = (f: string) => new URL(`../../${f}`, import.meta.url).pathname;
const live: JudgeRecord = JSON.parse(readFileSync(root('fixtures/live.ed25519.json'), 'utf8'));
const sqli: JudgeRecord = JSON.parse(readFileSync(root('fixtures/demo.sqli.json'), 'utf8'));
const views = JSON.parse(readFileSync(root('web/src/fixtures/live-views.json'), 'utf8')).views;
const ED = 'ed25519:89154a43a47684742c3d1753252bb6f49f61da9d8c84fc9b1def2df130cb2d93';
const CONTRACT = 'escrow.baldingsucks7993.testnet';
const V1_HUNTER = views.list_claims.result[0].hunter as string;

let owner: { publicKey: string; secretKey: string };
let logs: string[];
const out = () => logs.join('\n');

/** The real v1 get_program view (no code_hash / params_hash / signers / bond / challenge_secs). Its
 * system_prompt_hash is re-pointed at the live.ed25519 fixture's prompt so the recorded v1 body matches. */
const v1Program = (): Program => {
  const sys = JSON.parse(live.request_body).messages[0].content;
  return { ...views.get_program.result, system_prompt_hash: shared.sha256hex(sys), owner_enc_pubkey: owner.publicKey };
};
const v3Program = (o: Partial<Program> = {}): Program => ({
  id: 0, owner: 'owner.testnet', name: 'demo', repo_url: demo.DEMO_TARGET.repoUrl, commit: demo.DEMO_TARGET.commit,
  model_id: 'Qwen/Qwen3.8-27B', system_prompt_hash: shared.systemPromptHash(),
  code_hash: '82faf3a0cd6148f95ba3b8011f8e9af67d5f9d5b8f8638002be7787a37285abd', params_hash: shared.paramsHash(),
  signers: [ED], bond: nearToYocto('0.05').toString(), challenge_secs: 600,
  payouts: { low: '1', medium: '2', high: nearToYocto(3).toString(), critical: nearToYocto(5).toString() },
  owner_enc_pubkey: owner.publicKey, dispute_secs: 60, min_confidence: 70, balance: nearToYocto(10).toString(), reserved: '0',
  open: true, created_at: '0', ...o,
});
/** A v2 program view: code_hash, but no params_hash / signers / bond / challenge_secs. */
const v2Program = (): Program => {
  const { params_hash: _p, signers: _s, bond: _b, challenge_secs: _c, ...rest } = v3Program();
  return rest as Program;
};
const claimFor = (rec: JudgeRecord, body: string, hunter: string, o: Partial<Claim> = {}): Claim => ({
  id: 0, program_id: 0, hunter, req_hash: shared.sha256hex(body), resp_hash: rec.resp_hash,
  verdict: (rec as any).verdict ?? { valid: true, severity: 'high', cwe: null, confidence: 98 },
  signer: ED, kind: 'provider_tee', signature: rec.signature, model: rec.model,
  ciphertext: shared.encryptForOwner(body, owner.publicKey), status: 'Pending', payout: '1',
  submitted_at: '0', finalize_after: String(BigInt(Date.now() + 3_600_000) * 1_000_000n), reject_reason: null,
  bond: null as any, challenge_deadline: null, ...o,
});
/** sqli body with temperature bumped: params tampered under v3, not checked under v2. */
const hotBody = () => {
  const r = JSON.parse(sqli.request_body);
  r.temperature = 1.5;
  return JSON.stringify(r);
};
const ownerRows = () => logs.filter((l) => l.includes('[owner]'));

beforeEach(() => {
  process.env.HOME = mkdtempSync(join(tmpdir(), 'sb-home-'));
  process.env.ESCROW_CONTRACT_ID = CONTRACT;
  owner = shared.generateOwnerKeypair();
  finalizeOwnerKey(savePendingOwnerKey(owner, CONTRACT, 'testnet'), 0);
  logs = [];
  const cap = (...a: unknown[]) => void logs.push(a.join(' '));
  vi.spyOn(console, 'log').mockImplementation(cap);
  vi.spyOn(console, 'warn').mockImplementation(cap);
  vi.spyOn(globalThis, 'fetch').mockImplementation(() => {
    throw new Error('network used');
  });
  for (const f of Object.values(near)) f.mockClear();
  near.getSigners.mockResolvedValue([[ED, { kind: 'provider_tee', model: 'Qwen/Qwen3.8-27B' }]]);
  process.exitCode = undefined;
});
afterEach(() => {
  vi.restoreAllMocks();
  process.exitCode = undefined;
});

describe('verify-claim: owner checks gated by program version (#14)', () => {
  it('v1 program + v1 body: only prompt + model apply, both pass, no "code mismatch"', async () => {
    near.mustGetProgram.mockResolvedValue(v1Program());
    near.mustGetClaim.mockResolvedValue(claimFor(live, live.request_body, V1_HUNTER));
    await cmdVerifyClaim({ claim: '0' });
    const s = out();
    expect(s).not.toContain('code mismatch');
    expect(s).toMatch(/v1 dispute rules: prompt, model/);
    expect(s).toMatch(/PASS\s+\[owner\] system prompt/);
    expect(s).toMatch(/PASS\s+\[owner\] model/);
    expect(s).not.toMatch(/\[owner\] (params|code|hunter|report)/);
    expect(ownerRows().every((l) => l.includes('PASS'))).toBe(true);
    expect(process.exitCode).toBeUndefined();
  });
  it('v1 program still catches a wrong model', async () => {
    near.mustGetProgram.mockResolvedValue({ ...v1Program(), model_id: 'other/model' });
    near.mustGetClaim.mockResolvedValue(claimFor(live, live.request_body, V1_HUNTER, { model: 'other/model' }));
    await cmdVerifyClaim({ claim: '0' });
    expect(out()).toMatch(/FAIL\s+\[owner\] model\s+model mismatch/);
    expect(process.exitCode).toBe(1);
  });
  it('v2 program (code_hash, no params_hash): params skipped, the other five run', async () => {
    near.mustGetProgram.mockResolvedValue(v2Program());
    near.mustGetClaim.mockResolvedValue(claimFor(sqli, hotBody(), demo.DEMO_HUNTER));
    await cmdVerifyClaim({ claim: '0' });
    const s = out();
    expect(s).toMatch(/v2 dispute rules: prompt, model, code, hunter, report/);
    for (const k of ['system prompt', 'model', 'code', 'hunter', 'report']) expect(s).toMatch(new RegExp(`PASS\\s+\\[owner\\] ${k}`));
    expect(s).not.toMatch(/\[owner\] params/);
    expect(s).not.toContain('params tampered');
  });
  it('v3 program: all six run; tampered params fail', async () => {
    near.mustGetProgram.mockResolvedValue(v3Program());
    near.mustGetClaim.mockResolvedValue(claimFor(sqli, sqli.request_body, demo.DEMO_HUNTER));
    await cmdVerifyClaim({ claim: '0' });
    let s = out();
    expect(s).toMatch(/v3 dispute rules: prompt, model, params, code, hunter, report/);
    for (const k of ['system prompt', 'model', 'params', 'code', 'hunter', 'report']) expect(s).toMatch(new RegExp(`PASS\\s+\\[owner\\] ${k}`));
    logs = [];
    near.mustGetClaim.mockResolvedValue(claimFor(sqli, hotBody(), demo.DEMO_HUNTER));
    await cmdVerifyClaim({ claim: '0' });
    s = out();
    expect(s).toMatch(/FAIL\s+\[owner\] params\s+params tampered/);
  });
});

describe('inbox / dispute share the gate (#14)', () => {
  it('inbox: a v1 claim is OK, not "code mismatch"', async () => {
    near.mustGetProgram.mockResolvedValue(v1Program());
    near.listClaims.mockResolvedValue([claimFor(live, live.request_body, V1_HUNTER)]);
    await cmdInbox({ program: '0' });
    expect(out()).not.toContain('code mismatch');
    expect(out()).toMatch(/request vs program: OK \(v1 dispute rules: prompt, model/);
  });
  it('dispute --dry-run: a v1 claim matching prompt + model would be an invalid dispute', async () => {
    near.mustGetProgram.mockResolvedValue(v1Program());
    near.mustGetClaim.mockResolvedValue(claimFor(live, live.request_body, V1_HUNTER));
    await cmdDispute({ claim: '0', dryRun: true });
    expect(out()).not.toContain('code mismatch');
    expect(out()).toMatch(/expected: contract would panic/);
  });
});
