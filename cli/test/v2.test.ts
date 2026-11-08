// v2 (docs/INTERFACE.md "v2"): code bundle + hunter binding, submit/dispute pre-checks, offline dry-run.
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { DISPUTE_INVALID_PANIC, codeHashRow, disputeOutcome, submitPrecheck } from '../src/args.js';
import { buildBundleFromFiles, collectCodeFiles, globToRegExp } from '../src/bundle.js';
import { DEMO_BUNDLE_PATH, cmdSubmit, offlineProgramBinding } from '../src/commands.js';
import { demo, shared } from '../src/shared.js';
import type { JudgeRecord } from '../src/types.js';

const fx = (f: string) => new URL(`../../fixtures/${f}`, import.meta.url).pathname;
const load = (f: string): JudgeRecord => JSON.parse(readFileSync(fx(f), 'utf8'));
const sqli = load('demo.sqli.json');
const fakecode = load('demo.fakecode.json');
const DEMO_CODE_HASH = readFileSync(fx('vuln-app/bundle.sha256'), 'utf8');
const HUNTER = demo.DEMO_HUNTER;
const program = offlineProgramBinding('Qwen/Qwen3.8-27B');

describe('code bundle', () => {
  it('spec hash: fixtures/vuln-app/bundle.txt hashes to the v2 demo code_hash', () => {
    expect(DEMO_CODE_HASH).toBe('82faf3a0cd6148f95ba3b8011f8e9af67d5f9d5b8f8638002be7787a37285abd');
    expect(shared.codeHash(readFileSync(DEMO_BUNDLE_PATH, 'utf8'))).toBe(DEMO_CODE_HASH);
    expect(program.code_hash).toBe(DEMO_CODE_HASH);
  });

  it('--code-files rebuilds the demo bundle byte for byte and writes bundle.txt + bundle.sha256', () => {
    const root = mkdtempSync(join(tmpdir(), 'sb-bundle-'));
    mkdirSync(join(root, 'src'));
    writeFileSync(join(root, 'src/server.ts'), readFileSync(fx('vuln-app/src/server.ts')));
    for (const pats of [['src/server.ts'], ['src/**/*.ts'], ['**/*.ts'], ['src'], ['.']]) {
      const b = buildBundleFromFiles(pats, root);
      expect(b.hash).toBe(DEMO_CODE_HASH);
      expect(b.paths).toEqual(['src/server.ts']);
      expect(readFileSync(join(root, 'bundle.txt'), 'utf8')).toBe(readFileSync(DEMO_BUNDLE_PATH, 'utf8'));
      expect(readFileSync(join(root, 'bundle.sha256'), 'utf8')).toBe(DEMO_CODE_HASH);
    }
  });

  it('collects multiple files with repo-relative paths, never bundles its own outputs', () => {
    const root = mkdtempSync(join(tmpdir(), 'sb-bundle-'));
    mkdirSync(join(root, 'src/lib'), { recursive: true });
    writeFileSync(join(root, 'src/b.ts'), 'b');
    writeFileSync(join(root, 'src/lib/a.ts'), 'a\n');
    writeFileSync(join(root, 'bundle.txt'), 'old');
    const files = collectCodeFiles(['**/*'], root);
    expect(files.map((f) => f.path).sort()).toEqual(['src/b.ts', 'src/lib/a.ts']);
    expect(shared.buildCodeBundle(files)).toBe('// file: src/b.ts\nb\n// file: src/lib/a.ts\na\n');
    expect(() => collectCodeFiles(['nope/*.ts'], root)).toThrow(/matched nothing/);
    expect(() => collectCodeFiles(['../x.ts'], root)).toThrow();
  });

  it('globToRegExp', () => {
    expect(globToRegExp('src/**/*.ts').test('src/a.ts')).toBe(true);
    expect(globToRegExp('src/**/*.ts').test('src/x/y/a.ts')).toBe(true);
    expect(globToRegExp('src/*.ts').test('src/x/a.ts')).toBe(false);
    expect(globToRegExp('*.{ts,js}').test('a.js')).toBe(true);
    expect(globToRegExp('a?.ts').test('ab.ts')).toBe(true);
    expect(globToRegExp('a.ts').test('aXts')).toBe(false);
  });

  it('codeHashRow', () => {
    expect(codeHashRow(readFileSync(DEMO_BUNDLE_PATH, 'utf8'), DEMO_CODE_HASH)[1]).toBe(true);
    expect(codeHashRow(demo.FAKE_CODE_BUNDLE, DEMO_CODE_HASH)[1]).toBe(false);
  });
});

describe('submitPrecheck / disputeOutcome', () => {
  it('sqli for its own hunter: ok', () => {
    expect(submitPrecheck(sqli.request_body, program, HUNTER, true)).toEqual({ check: { ok: true, reason: null }, refuse: null, warn: null });
  });
  it('fixture recorded for another hunter: warn only', () => {
    const p = submitPrecheck(sqli.request_body, program, 'someone.testnet', true);
    expect(p.check).toEqual({ ok: false, reason: 'hunter mismatch' });
    expect(p.refuse).toBeNull();
    expect(p.warn).toMatch(/^hunter mismatch: the owner can dispute/);
  });
  it('fresh judgement for another hunter: refused', () => {
    expect(submitPrecheck(sqli.request_body, program, 'someone.testnet', false).refuse).toMatch(/^hunter mismatch/);
  });
  it('fakecode: refused with code mismatch', () => {
    const p = submitPrecheck(fakecode.request_body, program, HUNTER, true);
    expect(p.check).toEqual({ ok: false, reason: 'code mismatch' });
    expect(p.refuse).toMatch(/^code mismatch/);
  });
  it('other reasons in contract order', () => {
    expect(submitPrecheck(sqli.request_body, { ...program, model_id: 'x' }, HUNTER, true).check.reason).toBe('model mismatch');
    expect(submitPrecheck(sqli.request_body, { ...program, system_prompt_hash: '0'.repeat(64) }, HUNTER, true).check.reason).toBe('system prompt tampered');
  });
  it('dispute outcome text', () => {
    expect(disputeOutcome({ ok: true, reason: null })).toContain(DISPUTE_INVALID_PANIC);
    expect(DISPUTE_INVALID_PANIC).toBe('dispute invalid: request matches program');
    expect(disputeOutcome({ ok: false, reason: 'code mismatch' })).toContain('"code mismatch"');
    expect(disputeOutcome({ ok: false, reason: 'hunter mismatch' })).toMatch(/resubmit/);
  });
});

describe('submit --dry-run --fixture (offline, no network)', () => {
  let logs: string[];
  beforeEach(() => {
    logs = [];
    const cap = (...a: unknown[]) => void logs.push(a.join(' '));
    vi.spyOn(console, 'log').mockImplementation(cap);
    vi.spyOn(console, 'warn').mockImplementation(cap);
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => {
      throw new Error('network used in offline dry-run');
    });
  });
  afterEach(() => vi.restoreAllMocks());

  it('demo.sqli.json as its hunter: passes, prints submit_claim args', async () => {
    const r = (await cmdSubmit({ program: '0', fixture: fx('demo.sqli.json'), dryRun: true, account: HUNTER, ownerPubkey: shared.generateOwnerKeypair().publicKey })) as any;
    expect(r.check).toEqual({ ok: true, reason: null });
    expect(r.args.req_hash).toBe(sqli.req_hash);
    expect(logs.join('\n')).toContain('--dry-run: not sent');
  });

  it('demo.sqli.json with --code = the demo bundle: passes', async () => {
    const r = (await cmdSubmit({ program: '0', fixture: fx('demo.sqli.json'), code: DEMO_BUNDLE_PATH, dryRun: true, account: HUNTER })) as any;
    expect(r.check.ok).toBe(true);
  });

  it('demo.sqli.json as a different signer: warns hunter mismatch, still dry-runs', async () => {
    const r = (await cmdSubmit({ program: '0', fixture: fx('demo.sqli.json'), dryRun: true, account: 'other.testnet' })) as any;
    expect(r.check).toEqual({ ok: false, reason: 'hunter mismatch' });
    expect(logs.join('\n')).toContain('WARNING: hunter mismatch: the owner can dispute');
  });

  it('demo.fakecode.json: refused with "code mismatch"', async () => {
    await expect(cmdSubmit({ program: '0', fixture: fx('demo.fakecode.json'), dryRun: true, account: HUNTER })).rejects.toThrow(
      /^code mismatch: .*not sending/,
    );
    expect(logs.join('\n')).not.toContain('submit_claim args');
  });

  it('demo.fakecode.json --force: goes through with a warning', async () => {
    const r = (await cmdSubmit({ program: '0', fixture: fx('demo.fakecode.json'), dryRun: true, account: HUNTER, force: true })) as any;
    expect(r.check.reason).toBe('code mismatch');
    expect(logs.join('\n')).toContain('WARNING (--force): code mismatch');
  });

  it('--code that is not the program bundle is refused', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'sb-code-'));
    const fake = join(dir, 'bundle.txt');
    writeFileSync(fake, demo.FAKE_CODE_BUNDLE);
    // offline: --code defines the assumed program bundle, so the fixture's (real) code no longer matches it
    await expect(cmdSubmit({ program: '0', fixture: fx('demo.sqli.json'), code: fake, dryRun: true, account: HUNTER })).rejects.toThrow(/code mismatch/);
  });
});
