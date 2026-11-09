// v3 (docs/INTERFACE.md "v3"): params pinning, decryption challenge, program signers, bond, payout callback.
// Pure helpers only (no network). Command flows with a mocked chain live in v3-commands.test.ts.
import { mkdtempSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  DEFAULT_BOND_NEAR,
  DEFAULT_CHALLENGE_SECS,
  attestRotationHint,
  claimStatusLabel,
  createProgramArgs,
  estimateClaimStorageDeposit,
  finalizeOutcome,
  flagUndecryptableArgs,
  parseSigners,
  proveCiphertextArgs,
  revokeSignerArgs,
  setProgramSignersArgs,
  submitDeposit,
  submitPrecheck,
} from '../src/args.js';
import { DEMO_BUNDLE_PATH, cmdSubmit, inboxDecrypt, offlineProgramBinding, printProgram, proveCheck } from '../src/commands.js';
import { config } from '../src/config.js';
import { finalizeHunterSecret, hunterSecretPath, loadHunterSecret, openWithEphemeral, savePendingHunterSecret } from '../src/crypto.js';
import { demo, shared } from '../src/shared.js';
import type { Claim, JudgeRecord, Program } from '../src/types.js';
import { nearToYocto } from '../src/util.js';

const fx = (f: string) => new URL(`../../fixtures/${f}`, import.meta.url).pathname;
const load = (f: string): JudgeRecord => JSON.parse(readFileSync(fx(f), 'utf8'));
const sqli = load('demo.sqli.json');
const HUNTER = demo.DEMO_HUNTER;
const ED = 'ed25519:89154a43a47684742c3d1753252bb6f49f61da9d8c84fc9b1def2df130cb2d93';
const ETH = 'eth:0x835ab53d20294ef795906dff21ae4c045336aa26';
const DEMO_CODE_HASH = '82faf3a0cd6148f95ba3b8011f8e9af67d5f9d5b8f8638002be7787a37285abd';

const owner = shared.generateOwnerKeypair();
const program = (o: Partial<Program> = {}): Program => ({
  id: 0,
  owner: 'owner.testnet',
  name: 'demo',
  repo_url: demo.DEMO_TARGET.repoUrl,
  commit: demo.DEMO_TARGET.commit,
  model_id: 'Qwen/Qwen3.8-27B',
  system_prompt_hash: shared.systemPromptHash(),
  code_hash: DEMO_CODE_HASH,
  params_hash: shared.paramsHash(),
  signers: [ED],
  bond: nearToYocto('0.05').toString(),
  challenge_secs: 600,
  payouts: { low: '1', medium: '2', high: nearToYocto(3).toString(), critical: nearToYocto(5).toString() },
  owner_enc_pubkey: owner.publicKey,
  dispute_secs: 60,
  min_confidence: 70,
  balance: nearToYocto(10).toString(),
  reserved: '0',
  open: true,
  created_at: '0',
  ...o,
});
const claim = (o: Partial<Claim> = {}): Claim => ({
  id: 2, program_id: 0, hunter: HUNTER, req_hash: sqli.req_hash, resp_hash: sqli.resp_hash,
  verdict: (sqli as any).verdict, signer: ED, kind: 'provider_tee', signature: sqli.signature, model: 'Qwen/Qwen3.8-27B',
  ciphertext: shared.encryptForOwner(sqli.request_body, owner.publicKey), status: 'Pending', payout: nearToYocto(3).toString(),
  submitted_at: '0', finalize_after: '0', reject_reason: null, bond: nearToYocto('0.05').toString(), challenge_deadline: null,
  ...o,
});
const tamper = (body: string, f: (r: any) => void) => {
  const r = JSON.parse(body);
  f(r);
  return JSON.stringify(r);
};

describe('shared v3 helpers (shared/judge.mjs)', () => {
  it('paramsHash = sha256(canonicalJson of the 4 params) and matches the demo request', () => {
    const req = JSON.parse(sqli.request_body);
    expect(shared.paramsHash()).toMatch(/^[0-9a-f]{64}$/);
    expect(shared.paramsHash(req)).toBe(shared.paramsHash());
    expect(shared.canonicalJson({ b: 1, a: [{ d: null, c: 'x' }] })).toBe('{"a":[{"c":"x","d":null}],"b":1}');
  });
  it('encryptForOwnerWithSecret returns a ciphertext the owner can open and a 64-hex ephemeral secret', () => {
    const { ciphertext, ephemeralSecretHex } = shared.encryptForOwnerWithSecret('héllo', owner.publicKey);
    expect(ephemeralSecretHex).toMatch(/^[0-9a-f]{64}$/);
    expect(shared.decryptAsOwner(ciphertext, owner.secretKey)).toBe('héllo');
    expect(openWithEphemeral(ciphertext, owner.publicKey, ephemeralSecretHex)).toBe('héllo');
    expect(() => openWithEphemeral(ciphertext, owner.publicKey, '11'.repeat(32))).toThrow(/ephemeral/);
  });
  it('checkRequestAgainstProgram: "params tampered" after model, before code', () => {
    const p = program();
    expect(shared.checkRequestAgainstProgram(sqli.request_body, p, HUNTER)).toEqual({ ok: true, reason: null });
    const hot = tamper(sqli.request_body, (r) => (r.temperature = 0.7));
    expect(shared.checkRequestAgainstProgram(hot, p, HUNTER)).toEqual({ ok: false, reason: 'params tampered' });
    const extra = tamper(sqli.request_body, (r) => (r.top_p = 0.1));
    expect(shared.checkRequestAgainstProgram(extra, p, HUNTER).reason).toBe('params tampered');
    const both = tamper(sqli.request_body, (r) => ((r.temperature = 1), (r.model = 'x')));
    expect(shared.checkRequestAgainstProgram(both, p, HUNTER).reason).toBe('model mismatch');
  });
});

describe('create_program v3 args', () => {
  const base = {
    name: 'demo', repoUrl: 'https://x', commit: 'c', modelId: 'Qwen/Qwen3.8-27B',
    systemPromptHash: shared.systemPromptHash(), codeHash: DEMO_CODE_HASH, paramsHash: shared.paramsHash(),
    payoutsNear: { low: '0.1', medium: '0.5', high: '1', critical: '2.5' }, ownerEncPubkey: owner.publicKey,
    disputeSecs: 300, minConfidence: 70, fundNear: '5', bondNear: DEFAULT_BOND_NEAR, challengeSecs: DEFAULT_CHALLENGE_SECS,
  };
  it('defaults: bond 0.05 NEAR, challenge 600 s', () => {
    expect(DEFAULT_BOND_NEAR).toBe('0.05');
    expect(DEFAULT_CHALLENGE_SECS).toBe(600);
  });
  it('spec arg order, params_hash, bond in yocto, signers null = contract snapshot', () => {
    const { args } = createProgramArgs(base);
    expect(Object.keys(args)).toEqual([
      'name', 'repo_url', 'commit', 'model_id', 'system_prompt_hash', 'code_hash', 'params_hash', 'payouts',
      'owner_enc_pubkey', 'dispute_secs', 'min_confidence', 'bond', 'challenge_secs', 'signers',
    ]);
    expect(args.params_hash).toBe(shared.paramsHash());
    expect(args.bond).toBe('50000000000000000000000');
    expect(args.challenge_secs).toBe(600);
    expect(args.signers).toBeNull();
  });
  it('explicit signers list', () => {
    expect(createProgramArgs({ ...base, signers: [ED, ETH] }).args.signers).toEqual([ED, ETH]);
  });
  it('validates params_hash, challenge_secs', () => {
    expect(() => createProgramArgs({ ...base, paramsHash: 'nope' })).toThrow(/params_hash/);
    expect(() => createProgramArgs({ ...base, challengeSecs: -1 })).toThrow(/challenge-secs/);
    expect(() => createProgramArgs({ ...base, bondNear: '-1' })).toThrow();
  });
});

describe('signer list parsing', () => {
  it('accepts comma or space separated, lowercases, dedupes', () => {
    expect(parseSigners([`${ED},${ETH.toUpperCase().replace('ETH:0X', 'eth:0x')}`, ED])).toEqual([ED, ETH]);
    expect(parseSigners(['  '])).toEqual([]);
  });
  it('rejects malformed signers', () => {
    expect(() => parseSigners(['ed25519:abc'])).toThrow(/bad signer/);
    expect(() => parseSigners(['secp:0x00'])).toThrow(/bad signer/);
  });
});

describe('new method args', () => {
  it('shapes', () => {
    expect(flagUndecryptableArgs(3)).toEqual({ claim_id: 3 });
    expect(proveCiphertextArgs(3, 'ab'.repeat(32))).toEqual({ claim_id: 3, ephemeral_secret: 'ab'.repeat(32) });
    expect(() => proveCiphertextArgs(3, 'xyz')).toThrow(/64 hex/);
    expect(setProgramSignersArgs(1, [ED])).toEqual({ program_id: 1, signers: [ED] });
    expect(() => setProgramSignersArgs(1, [])).toThrow(/at least one/);
    expect(revokeSignerArgs(ETH)).toEqual({ signer: ETH });
    expect(() => revokeSignerArgs('bad')).toThrow(/bad signer/);
  });
});

describe('submit deposit = storage + program.bond', () => {
  it('adds the bond on top of the storage estimate', () => {
    const ct = 'x'.repeat(1000);
    const bond = nearToYocto('0.05');
    const d = submitDeposit(ct, bond.toString());
    expect(d.storage).toBe(estimateClaimStorageDeposit(ct).deposit);
    expect(d.bond).toBe(bond);
    expect(d.deposit).toBe(d.storage + bond);
    expect(submitDeposit(ct, undefined).bond).toBe(0n);
  });
});

describe('submitPrecheck: params tampered is refused even for a fixture', () => {
  it('refuses', () => {
    const hot = tamper(sqli.request_body, (r) => (r.max_tokens = 4000));
    const p = submitPrecheck(hot, program(), HUNTER, true);
    expect(p.check.reason).toBe('params tampered');
    expect(p.refuse).toMatch(/^params tampered/);
  });
  it('offline binding pins the canonical params', () => {
    expect(offlineProgramBinding('Qwen/Qwen3.8-27B').params_hash).toBe(shared.paramsHash());
  });
});

describe('hunter secret file', () => {
  it('saves pending (600) before send, renames to hunter-<contract>-<claim>.json', () => {
    const home = mkdtempSync(join(tmpdir(), 'sb-h-'));
    const s = { ephemeralSecretHex: 'ab'.repeat(32), req_hash: sqli.req_hash, contract: 'esc.testnet', program_id: 0 };
    const pending = savePendingHunterSecret(s, home);
    expect(pending).toMatch(/hunter-pending-/);
    expect(statSync(pending).mode & 0o777).toBe(0o600);
    expect(JSON.parse(readFileSync(pending, 'utf8'))).toMatchObject({ ...s, claim_id: null });
    const dest = finalizeHunterSecret(pending, 9, home);
    expect(dest).toBe(join(home, 'hunter-esc.testnet-9.json'));
    expect(dest).toBe(hunterSecretPath(9, home, 'esc.testnet'));
    expect(statSync(dest).mode & 0o777).toBe(0o600);
    expect(loadHunterSecret(9, home, 'esc.testnet')).toMatchObject({ ...s, claim_id: 9 });
    expect(() => loadHunterSecret(8, home, 'esc.testnet')).toThrow(/no hunter secret/);
    expect(() => finalizeHunterSecret(savePendingHunterSecret({ ...s, req_hash: 'cd'.repeat(32) }, home), 9, home)).toThrow(/already exists/);
  });
});

describe('inbox decrypt', () => {
  it('ok when it decrypts and hashes to req_hash', () => {
    const r = inboxDecrypt(claim(), program(), owner.secretKey);
    expect(r.ok).toBe(true);
  });
  it('garbage ciphertext -> UNDECRYPTABLE hint', () => {
    const r = inboxDecrypt(claim({ ciphertext: Buffer.alloc(80, 7).toString('base64') }), program(), owner.secretKey);
    expect(r.ok).toBe(false);
    expect(r.hint).toBe('UNDECRYPTABLE → run `sb flag-undecryptable --claim 2`');
  });
  it('decrypts but sha256 != req_hash -> UNDECRYPTABLE', () => {
    const r = inboxDecrypt(claim({ ciphertext: shared.encryptForOwner('other body', owner.publicKey) }), program(), owner.secretKey);
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/req_hash/);
    expect(r.hint).toContain('flag-undecryptable --claim 2');
  });
});

describe('prove-ciphertext local check', () => {
  const enc = shared.encryptForOwnerWithSecret(sqli.request_body, owner.publicKey);
  it('right secret, matching request -> back to Pending (finalizable)', () => {
    const r = proveCheck(claim({ ciphertext: enc.ciphertext, status: 'Challenged' }), program(), enc.ephemeralSecretHex);
    expect(r.reason).toBeNull();
    expect(r.rows.every((x) => x[1])).toBe(true);
    expect(r.outcome).toMatch(/Pending.*finaliz/);
  });
  it('wrong secret -> Rejected "undecryptable report"', () => {
    const r = proveCheck(claim({ ciphertext: enc.ciphertext }), program(), '22'.repeat(32));
    expect(r.reason).toBe('undecryptable report');
    expect(r.outcome).toContain('"undecryptable report"');
  });
  it('decrypts but the request is tampered -> Rejected with that reason', () => {
    const t = shared.encryptForOwnerWithSecret(tamper(sqli.request_body, (x) => (x.temperature = 1)), owner.publicKey);
    // req_hash of the claim = hash of the tampered body (that is what the hunter signed)
    const r = proveCheck(claim({ ciphertext: t.ciphertext, req_hash: shared.sha256hex(tamper(sqli.request_body, (x) => (x.temperature = 1))) }), program(), t.ephemeralSecretHex);
    expect(r.reason).toBe('params tampered');
  });
});

describe('claim status label', () => {
  const now = 1_000_000n * 1_000_000_000n; // ns
  it('Challenged shows the deadline countdown', () => {
    const c = claim({ status: 'Challenged', challenge_deadline: String(now + 300n * 1_000_000_000n) });
    expect(claimStatusLabel(c, now)).toMatch(/^Challenged \(hunter must prove by .*Z, 5m 0s left\)$/);
    const late = claim({ status: 'Challenged', challenge_deadline: String(now - 1n) });
    expect(claimStatusLabel(late, now)).toMatch(/^Challenged \(deadline passed: finalize rejects/);
  });
  it('PayoutFailed / Rejected / finalizable Pending', () => {
    expect(claimStatusLabel(claim({ status: 'PayoutFailed' }), now)).toMatch(/^PayoutFailed/);
    expect(claimStatusLabel(claim({ status: 'Rejected', reject_reason: 'signer revoked' }), now)).toBe('Rejected (signer revoked)');
    expect(claimStatusLabel(claim({ finalize_after: '0' }), now)).toBe('Pending (finalizable)');
  });
});

describe('finalize outcome', () => {
  const ev = (event: string, data: object) => `EVENT_JSON:${JSON.stringify({ standard: 'sealedbounty', version: '1.0.0', event, data })}`;
  it('Paid', () => {
    expect(finalizeOutcome([ev('claim_paid', { claim_id: 2, payout: '3', bond: '1' })]).status).toBe('Paid');
  });
  it('PayoutFailed wins over claim_paid', () => {
    const o = finalizeOutcome([ev('claim_paid', { claim_id: 2 }), ev('payout_failed', { claim_id: 2, amount: '4' })]);
    expect(o.status).toBe('PayoutFailed');
    expect(o.text).toMatch(/credited back/);
  });
  it('Rejected with the reason', () => {
    const o = finalizeOutcome([ev('claim_rejected', { claim_id: 2, reason: 'undecryptable report' })]);
    expect(o).toMatchObject({ status: 'Rejected', reason: 'undecryptable report' });
    expect(o.text).toContain('undecryptable report');
  });
  it('falls back to the claim status when there are no events', () => {
    expect(finalizeOutcome([], claim({ status: 'Rejected', reject_reason: 'signer revoked' }))).toMatchObject({ status: 'Rejected', reason: 'signer revoked' });
    expect(finalizeOutcome(['garbage']).status).toBe('unknown');
  });
});

describe('views and hints', () => {
  let logs: string[];
  beforeEach(() => {
    logs = [];
    vi.spyOn(console, 'log').mockImplementation((...a) => void logs.push(a.join(' ')));
  });
  afterEach(() => vi.restoreAllMocks());
  it('printProgram shows bond, params_hash, signers, challenge_secs', () => {
    printProgram(program({ signers: [ED, ETH] }));
    const out = logs.join('\n');
    expect(out).toMatch(/bond\s+0\.05 NEAR/);
    expect(out).toContain(shared.paramsHash());
    expect(out).toContain(ED);
    expect(out).toContain(ETH);
    expect(out).toMatch(/challenge_secs\s+600/);
  });
  it('attest rotation hint mentions set-program-signers', () => {
    expect(attestRotationHint()).toMatch(/set-program-signers --program <id> --signers/);
  });
  it('default contract is sealedbounty-v3.testnet', () => {
    config();
    const prev = process.env.ESCROW_CONTRACT_ID;
    delete process.env.ESCROW_CONTRACT_ID;
    try {
      expect(config().contractId).toBe('sealedbounty-v3.testnet');
    } finally {
      if (prev !== undefined) process.env.ESCROW_CONTRACT_ID = prev;
    }
  });
});

describe('offline submit --dry-run: params tampered refused', () => {
  beforeEach(() => {
    vi.spyOn(console, 'log').mockImplementation(() => {});
    vi.spyOn(console, 'warn').mockImplementation(() => {});
  });
  afterEach(() => vi.restoreAllMocks());
  it('refuses a fixture whose params were changed, --force lets it through', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'sb-fx-'));
    const f = join(dir, 'hot.json');
    writeFileSync(f, JSON.stringify({ ...sqli, request_body: tamper(sqli.request_body, (r) => (r.temperature = 0.9)) }));
    await expect(cmdSubmit({ program: '0', fixture: f, dryRun: true, account: HUNTER })).rejects.toThrow(/^params tampered: .*not sending/);
    const r = (await cmdSubmit({ program: '0', fixture: f, dryRun: true, account: HUNTER, force: true })) as any;
    expect(r.check.reason).toBe('params tampered');
    expect(DEMO_BUNDLE_PATH).toBeTruthy();
  });
});
