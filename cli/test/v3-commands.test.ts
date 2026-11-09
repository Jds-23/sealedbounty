// v3 command flows against a mocked chain (src/near.js is replaced; nothing touches the network).
import { existsSync, mkdtempSync, readFileSync, readdirSync, statSync } from 'node:fs';
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

const { cmdAttestRegisterHint, cmdClaims, cmdCreateProgram, cmdFinalize, cmdFlagUndecryptable, cmdInbox, cmdProveCiphertext, cmdRevokeSigner, cmdSetProgramSigners, cmdSubmit } =
  await import('../src/commands.js');
const { demo, shared } = await import('../src/shared.js');
const { nearToYocto } = await import('../src/util.js');
const { estimateClaimStorageDeposit } = await import('../src/args.js');

const fx = (f: string) => new URL(`../../fixtures/${f}`, import.meta.url).pathname;
const sqli: JudgeRecord = JSON.parse(readFileSync(fx('demo.sqli.json'), 'utf8'));
const HUNTER = demo.DEMO_HUNTER;
const ED = 'ed25519:89154a43a47684742c3d1753252bb6f49f61da9d8c84fc9b1def2df130cb2d93';
const ETH = 'eth:0x835ab53d20294ef795906dff21ae4c045336aa26';
const CONTRACT = 'sealedbounty-v3.testnet';
const SB = () => join(process.env.HOME!, '.sealedbounty');
const ev = (event: string, data: object) => `EVENT_JSON:${JSON.stringify({ standard: 'sealedbounty', version: '1.0.0', event, data })}`;

let owner: { publicKey: string; secretKey: string };
const program = (o: Partial<Program> = {}): Program => ({
  id: 0, owner: 'owner.testnet', name: 'demo', repo_url: demo.DEMO_TARGET.repoUrl, commit: demo.DEMO_TARGET.commit,
  model_id: 'Qwen/Qwen3.8-27B', system_prompt_hash: shared.systemPromptHash(),
  code_hash: '82faf3a0cd6148f95ba3b8011f8e9af67d5f9d5b8f8638002be7787a37285abd', params_hash: shared.paramsHash(),
  signers: [ED], bond: nearToYocto('0.05').toString(), challenge_secs: 600,
  payouts: { low: '1', medium: '2', high: nearToYocto(3).toString(), critical: nearToYocto(5).toString() },
  owner_enc_pubkey: owner.publicKey, dispute_secs: 60, min_confidence: 70, balance: nearToYocto(10).toString(), reserved: '0',
  open: true, created_at: '0', ...o,
});
const claim = (o: Partial<Claim> = {}): Claim => ({
  id: 2, program_id: 0, hunter: HUNTER, req_hash: sqli.req_hash, resp_hash: sqli.resp_hash, verdict: (sqli as any).verdict,
  signer: ED, kind: 'provider_tee', signature: sqli.signature, model: 'Qwen/Qwen3.8-27B',
  ciphertext: shared.encryptForOwner(sqli.request_body, owner.publicKey), status: 'Pending', payout: nearToYocto(3).toString(),
  submitted_at: '0', finalize_after: String(BigInt(Date.now() + 3_600_000) * 1_000_000n), reject_reason: null,
  bond: nearToYocto('0.05').toString(), challenge_deadline: null, ...o,
});

let logs: string[];
const out = () => logs.join('\n');
beforeEach(() => {
  process.env.HOME = mkdtempSync(join(tmpdir(), 'sb-home-'));
  process.env.ESCROW_CONTRACT_ID = CONTRACT;
  owner = shared.generateOwnerKeypair();
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

describe('create-program', () => {
  const base = {
    name: 'demo', repo: 'https://x', commit: 'c', payoutLow: '0.1', payoutMedium: '0.5', payoutHigh: '1', payoutCritical: '2',
    fund: '5', disputeSecs: '300', minConfidence: '70', code: fx('vuln-app/bundle.txt'), dryRun: true,
  };
  it('defaults: bond 0.05, challenge 600, signers null, params_hash from shared', async () => {
    const r = (await cmdCreateProgram(base)) as any;
    expect(r.args).toMatchObject({ params_hash: shared.paramsHash(), bond: nearToYocto('0.05').toString(), challenge_secs: 600, signers: null });
    expect(near.callContract).not.toHaveBeenCalled();
  });
  it('--bond --challenge-secs --signers', async () => {
    const r = (await cmdCreateProgram({ ...base, bond: '0.2', challengeSecs: '120', signers: [`${ED},${ETH}`] })) as any;
    expect(r.args).toMatchObject({ bond: nearToYocto('0.2').toString(), challenge_secs: 120, signers: [ED, ETH] });
  });
});

describe('submit (live path, mocked chain)', () => {
  it('attaches storage + bond and saves the ephemeral secret BEFORE sending, renamed after', async () => {
    near.mustGetProgram.mockResolvedValue(program());
    let pendingAtSend: string[] = [];
    near.callContract.mockImplementation(async (_acc: unknown, method: string, args: any, opts: any) => {
      pendingAtSend = readdirSync(SB()).filter((f) => f.startsWith('hunter-pending-'));
      expect(method).toBe('submit_claim');
      const storage = estimateClaimStorageDeposit(args.ciphertext).deposit;
      expect(opts.deposit).toBe(storage + nearToYocto('0.05'));
      return { ok: true, value: 7, logs: [], hash: 'h' };
    });
    await cmdSubmit({ program: '0', fixture: fx('demo.sqli.json'), account: HUNTER });
    expect(pendingAtSend.length).toBe(1);
    const dest = join(SB(), `hunter-${CONTRACT}-7.json`);
    expect(existsSync(dest)).toBe(true);
    expect(statSync(dest).mode & 0o777).toBe(0o600);
    const saved = JSON.parse(readFileSync(dest, 'utf8'));
    expect(saved).toMatchObject({ claim_id: 7, req_hash: sqli.req_hash, contract: CONTRACT });
    expect(saved.ephemeralSecretHex).toMatch(/^[0-9a-f]{64}$/);
    expect(readdirSync(SB()).filter((f) => f.startsWith('hunter-pending-'))).toEqual([]);
    expect(out()).toContain(dest);
  });
  it('refuses a signer outside program.signers', async () => {
    near.mustGetProgram.mockResolvedValue(program({ signers: [ETH] }));
    await expect(cmdSubmit({ program: '0', fixture: fx('demo.sqli.json'), account: HUNTER })).rejects.toThrow(/pre-checks failed/);
    expect(out()).toMatch(/FAIL\s+signer in program\.signers/);
    expect(near.callContract).not.toHaveBeenCalled();
  });
});

describe('inbox', () => {
  it('flags undecryptable claims, shows Challenged countdown and bond', async () => {
    const { savePendingOwnerKey, finalizeOwnerKey } = await import('../src/crypto.js');
    finalizeOwnerKey(savePendingOwnerKey(owner, CONTRACT, 'testnet'), 0);
    near.mustGetProgram.mockResolvedValue(program());
    const deadline = String(BigInt(Date.now() + 120_000) * 1_000_000n);
    near.listClaims.mockResolvedValue([
      claim({ id: 1 }),
      claim({ id: 2, ciphertext: Buffer.alloc(90, 1).toString('base64') }),
      claim({ id: 3, status: 'Challenged', challenge_deadline: deadline }),
    ]);
    await cmdInbox({ program: '0' });
    const s = out();
    expect(s).toContain('UNDECRYPTABLE → run `sb flag-undecryptable --claim 2`');
    expect(s).not.toContain('flag-undecryptable --claim 1');
    expect(s).toMatch(/claim 3\s+Challenged \(hunter must prove by .*, 1m \d+s left\)/);
    expect(s).toMatch(/bond 0\.05 NEAR/);
  });
});

describe('claims view', () => {
  it('shows Challenged / PayoutFailed and bond', async () => {
    near.listClaims.mockResolvedValue([
      claim({ id: 1, status: 'PayoutFailed' }),
      claim({ id: 2, status: 'Challenged', challenge_deadline: String(BigInt(Date.now() + 60_000) * 1_000_000n) }),
    ]);
    await cmdClaims('0', {});
    expect(out()).toMatch(/bond/);
    expect(out()).toMatch(/PayoutFailed/);
    expect(out()).toMatch(/Challenged \(hunter must prove by/);
  });
});

describe('flag-undecryptable', () => {
  it('owner flags a Pending claim', async () => {
    near.mustGetClaim.mockResolvedValue(claim({ ciphertext: 'AAAA' }));
    near.mustGetProgram.mockResolvedValue(program());
    near.callContract.mockResolvedValue({ ok: true, value: undefined, logs: [], hash: 'h' });
    await cmdFlagUndecryptable({ claim: '2', account: 'owner.testnet' });
    expect(near.callContract).toHaveBeenCalledWith(expect.anything(), 'flag_undecryptable', { claim_id: 2 }, expect.anything());
  });
  it('dry-run does not send; refuses a non-Pending claim', async () => {
    near.mustGetClaim.mockResolvedValue(claim({ status: 'Paid' }));
    near.mustGetProgram.mockResolvedValue(program());
    await expect(cmdFlagUndecryptable({ claim: '2' })).rejects.toThrow(/preconditions failed/);
    await cmdFlagUndecryptable({ claim: '2', dryRun: true });
    expect(near.callContract).not.toHaveBeenCalled();
  });
});

describe('prove-ciphertext', () => {
  it('reads the saved secret, dry-run prints the local decrypted check, live sends', async () => {
    const enc = shared.encryptForOwnerWithSecret(sqli.request_body, owner.publicKey);
    const { savePendingHunterSecret, finalizeHunterSecret } = await import('../src/crypto.js');
    finalizeHunterSecret(savePendingHunterSecret({ ephemeralSecretHex: enc.ephemeralSecretHex, req_hash: sqli.req_hash, contract: CONTRACT, program_id: 0 }), 2);
    const deadline = String(BigInt(Date.now() + 120_000) * 1_000_000n);
    near.mustGetClaim.mockResolvedValue(claim({ ciphertext: enc.ciphertext, status: 'Challenged', challenge_deadline: deadline }));
    near.mustGetProgram.mockResolvedValue(program());
    await cmdProveCiphertext({ claim: '2', dryRun: true });
    expect(out()).toMatch(/PASS\s+sha256\(plaintext\) == req_hash/);
    expect(out()).toMatch(/back to Pending/);
    expect(near.callContract).not.toHaveBeenCalled();
    near.callContract.mockResolvedValue({ ok: true, value: undefined, logs: [], hash: 'h' });
    await cmdProveCiphertext({ claim: '2', account: HUNTER });
    expect(near.callContract).toHaveBeenCalledWith(expect.anything(), 'prove_ciphertext', { claim_id: 2, ephemeral_secret: enc.ephemeralSecretHex }, expect.anything());
  });
  it('no saved secret -> clear error', async () => {
    near.mustGetClaim.mockResolvedValue(claim({ status: 'Challenged' }));
    near.mustGetProgram.mockResolvedValue(program());
    await expect(cmdProveCiphertext({ claim: '2', dryRun: true })).rejects.toThrow(/no hunter secret/);
  });
});

describe('set-program-signers / revoke-signer', () => {
  it('set-program-signers checks the global allowlist model and sends', async () => {
    near.mustGetProgram.mockResolvedValue(program());
    near.callContract.mockResolvedValue({ ok: true, value: undefined, logs: [], hash: 'h' });
    await expect(cmdSetProgramSigners({ program: '0', signers: [ETH], account: 'owner.testnet' })).rejects.toThrow(/not allowlisted/);
    await cmdSetProgramSigners({ program: '0', signers: [ED], account: 'owner.testnet' });
    expect(near.callContract).toHaveBeenCalledWith(expect.anything(), 'set_program_signers', { program_id: 0, signers: [ED] }, expect.anything());
  });
  it('revoke-signer sends revoke_signer', async () => {
    near.callContract.mockResolvedValue({ ok: true, value: true, logs: [], hash: 'h' });
    await cmdRevokeSigner(ED, { account: 'admin.testnet' });
    expect(near.callContract).toHaveBeenCalledWith(expect.anything(), 'revoke_signer', { signer: ED }, expect.anything());
    expect(out()).toMatch(/finalize/);
  });
});

describe('finalize prints the outcome', () => {
  const ready = () => claim({ finalize_after: '0' });
  it.each([
    [[ev('claim_paid', { claim_id: 2 })], 'Paid', /outcome: Paid/],
    [[ev('claim_paid', { claim_id: 2 }), ev('payout_failed', { claim_id: 2, amount: '1' })], 'PayoutFailed', /outcome: PayoutFailed/],
    [[ev('claim_rejected', { claim_id: 2, reason: 'signer revoked' })], 'Rejected', /outcome: Rejected \(signer revoked\)/],
  ])('%#', async (logsOut, status, re) => {
    near.mustGetClaim.mockResolvedValueOnce(ready()).mockResolvedValueOnce(claim({ status: status as any }));
    near.callContract.mockResolvedValue({ ok: true, value: undefined, logs: logsOut, hash: 'h' });
    await cmdFinalize({ claim: '2', account: 'x.testnet' });
    expect(out()).toMatch(re);
  });
});

describe('attest --register hint', () => {
  it('prints the set-program-signers hint', () => {
    cmdAttestRegisterHint();
    expect(out()).toMatch(/set-program-signers/);
  });
});
