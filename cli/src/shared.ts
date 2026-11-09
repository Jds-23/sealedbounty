// Typed facade over ../../shared/judge.mjs (single source of truth shared with web/).
// The relative path works from both cli/src (tsx) and cli/dist (node). shared/ ships no .d.ts,
// so the module is typed here.
import { createHash } from 'node:crypto';
import nacl from 'tweetnacl';
// @ts-ignore TS7016: shared/judge.mjs is plain JS (JSDoc-typed)
import * as judgeMjs from '../../shared/judge.mjs';
// @ts-ignore TS7016: shared/demo-data.mjs is plain JS
import * as demoMjs from '../../shared/demo-data.mjs';
import type { JudgeRecord, Program, SigKind, Verdict } from './types.js';

/** v2 judge inputs (docs/INTERFACE.md "Canonical judge request v2"). */
export interface JudgeInputs {
  repoUrl: string;
  commit: string;
  /** NEAR account that calls submit_claim (bound into the HUNTER line). */
  hunter: string;
  /** The program's published code bundle, byte for byte (sha256 == program.code_hash). */
  codeBundle: string;
  report: string;
}

export type DisputeReason =
  | 'system prompt tampered'
  | 'model mismatch'
  | 'params tampered'
  | 'code mismatch'
  | 'hunter mismatch'
  | 'report missing';
export type RequestCheck = { ok: true; reason: null } | { ok: false; reason: DisputeReason };
/** v3: params_hash is pinned. A program without it (v2 contract) skips the params step, as the v2 contract does. */
export type ProgramBinding = Pick<Program, 'repo_url' | 'commit' | 'model_id' | 'system_prompt_hash' | 'code_hash'> & {
  params_hash?: string;
};
export type JudgeParams = { chat_template_kwargs?: unknown; max_tokens?: unknown; response_format?: unknown; temperature?: unknown };

export interface FixtureVerification {
  ok: boolean;
  checks: { name: string; ok: boolean; detail: string }[];
  verdict: Verdict | null;
  signer: string | null;
}

export interface SharedJudge {
  SYSTEM_PROMPT: string;
  DEFAULT_MODEL: string;
  sha256hex(data: string | Uint8Array): string;
  systemPromptHash(): string;
  buildRequestBody(p: JudgeInputs & { model: string }): string;
  buildCodeBundle(files: { path: string; content: string }[]): string;
  codeHash(bundle: string): string;
  codeMessagePrefix(p: { repoUrl: string; commit: string; hunter: string }): string;
  /** v3 #1: object keys sorted recursively (utf8 byte order), no whitespace. */
  canonicalJson(v: unknown): string;
  /** v3 #1: sha256hex(canonicalJson({chat_template_kwargs, max_tokens, response_format, temperature})); default = the canonical params. */
  paramsHash(req?: JudgeParams): string;
  /** Mirrors the v3 contract's dispute checks (first failing reason, contract order). */
  checkRequestAgainstProgram(requestBody: string, program: ProgramBinding, hunter: string): RequestCheck;
  parseVerdict(responseBody: string | Uint8Array): Verdict;
  verifySig(s: { text: string; signature: string; signing_address: string; signing_algo: 'ed25519' | 'ecdsa' }): boolean;
  signerId(r: { signing_address: string; signing_algo: 'ed25519' | 'ecdsa' }): string;
  expectedText(kind: SigKind, model: string, reqHash: string, respHash: string): string;
  judge(
    p: JudgeInputs & { apiKey: string; baseUrl?: string; model?: string; signingAlgo?: 'ed25519' | 'ecdsa'; checkAttestation?: boolean },
  ): Promise<JudgeRecord & { verdict: Verdict; signer: string }>;
  verifyFixture(obj: JudgeRecord, opts?: { systemPromptHash?: string; codeBundle?: string; codeHash?: string }): FixtureVerification;
  encryptForOwner(requestBody: string, ownerPubB64: string): string;
  /** v3 #2: also returns the ephemeral x25519 secret (64 hex) the hunter needs for prove_ciphertext. */
  encryptForOwnerWithSecret(requestBody: string, ownerPubB64: string): { ciphertext: string; ephemeralSecretHex: string };
  decryptAsOwner(ciphertextB64: string, ownerSecretB64: string): string;
  generateOwnerKeypair(): { publicKey: string; secretKey: string };
}

// ---------------------------------------------------------------------------------------------
// TEMPORARY v3 shim. origin/main's shared/judge.mjs predates v3. Until the CLI is rebased onto
// integrate/v3 (all fix branches merged), fall back to copies of the fix-branch functions:
//   fix/1-params-pinning: canonicalJson, paramsHash, "params tampered" in checkRequestAgainstProgram
//   fix/2-decryption-challenge: encryptForOwnerWithSecret
// Each fallback is used only if the real shared/judge.mjs lacks it. Remove after the rebase.
const raw = judgeMjs as unknown as SharedJudge & Partial<Pick<SharedJudge, 'canonicalJson' | 'paramsHash' | 'encryptForOwnerWithSecret'>> & {
  VERDICT_RESPONSE_FORMAT: unknown;
};
const shimSha = (s: string) => createHash('sha256').update(Buffer.from(s, 'utf8')).digest('hex');
const utf8Cmp = (a: string, b: string) => Buffer.compare(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'));
function shimCanonicalJson(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(shimCanonicalJson).join(',')}]`;
  if (v !== null && typeof v === 'object') {
    const o = v as Record<string, unknown>;
    return `{${Object.keys(o)
      .sort(utf8Cmp)
      .map((k) => `${JSON.stringify(k)}:${shimCanonicalJson(o[k])}`)
      .join(',')}}`;
  }
  const s = JSON.stringify(v);
  if (s === undefined) throw new Error(`canonicalJson: not a JSON value (${typeof v})`);
  return s;
}
const SHIM_PARAMS: JudgeParams = {
  response_format: raw.VERDICT_RESPONSE_FORMAT,
  chat_template_kwargs: { enable_thinking: false },
  temperature: 0,
  max_tokens: 400,
};
function shimParamsHash(req: JudgeParams = SHIM_PARAMS): string {
  const { chat_template_kwargs, max_tokens, response_format, temperature } = req;
  return shimSha(shimCanonicalJson({ chat_template_kwargs, max_tokens, response_format, temperature }));
}
const REQUEST_KEYS = ['model', 'messages', 'response_format', 'chat_template_kwargs', 'temperature', 'max_tokens'];
/** Paths of duplicated object keys in valid JSON text (JSON.parse keeps the last copy; the contract rejects them). */
function duplicateKeyPaths(text: string): (string | number)[][] {
  const dups: (string | number)[][] = [];
  let i = 0;
  const ws = () => {
    while (/\s/.test(text[i] ?? '')) i++;
  };
  const str = (): string => {
    const m = /"(?:[^"\\]|\\.)*"/y;
    m.lastIndex = i;
    const s = m.exec(text)![0];
    i += s.length;
    return JSON.parse(s);
  };
  const value = (path: (string | number)[]): void => {
    ws();
    const c = text[i];
    if (c === '{') {
      i++;
      ws();
      const seen = new Set<string>();
      if (text[i] === '}') return void i++;
      for (;;) {
        ws();
        const k = str();
        ws();
        i++; // ':'
        if (seen.has(k)) dups.push([...path, k]);
        seen.add(k);
        value([...path, k]);
        ws();
        if (text[i++] === '}') return; // else ','
      }
    }
    if (c === '[') {
      i++;
      ws();
      if (text[i] === ']') return void i++;
      for (let n = 0; ; n++) {
        value([...path, n]);
        ws();
        if (text[i++] === ']') return;
      }
    }
    if (c === '"') return void str();
    const m = /-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|true|false|null/y;
    m.lastIndex = i;
    i += m.exec(text)![0].length;
  };
  value([]);
  return dups;
}
/** v2 check plus the v3 params step: prompt -> model -> params -> code -> hunter -> report. */
function shimCheckRequest(requestBody: string, program: ProgramBinding, hunter: string): RequestCheck {
  const v2 = raw.checkRequestAgainstProgram(requestBody, program, hunter);
  if (!v2.ok && (v2.reason === 'system prompt tampered' || v2.reason === 'model mismatch')) return v2;
  const req = JSON.parse(requestBody); // passed the prompt step, so it parses
  const dups = duplicateKeyPaths(requestBody);
  const structDup = (p: (string | number)[]) =>
    (p.length === 1 && (p[0] === 'model' || p[0] === 'messages')) ||
    (p.length === 3 && p[0] === 'messages' && (p[2] === 'role' || p[2] === 'content'));
  if (dups.some(structDup)) return { ok: false, reason: 'system prompt tampered' };
  if (program.params_hash != null) {
    const keys = Object.keys(req);
    const exactShape =
      keys.length === REQUEST_KEYS.length &&
      REQUEST_KEYS.every((k) => Object.hasOwn(req, k)) &&
      (req.messages as object[]).every((m) => Object.keys(m).length === 2);
    if (!exactShape || dups.length || shimParamsHash(req) !== program.params_hash) return { ok: false, reason: 'params tampered' };
  }
  return v2;
}
function shimEncryptWithSecret(requestBody: string, ownerPubB64: string) {
  const ownerPub = new Uint8Array(Buffer.from(ownerPubB64, 'base64'));
  if (ownerPub.length !== nacl.box.publicKeyLength) throw new Error('owner pubkey must be 32 bytes');
  const eph = nacl.box.keyPair();
  const nonce = nacl.randomBytes(nacl.box.nonceLength);
  const boxed = nacl.box(new Uint8Array(Buffer.from(requestBody, 'utf8')), nonce, ownerPub, eph.secretKey);
  const ct = Buffer.concat([eph.publicKey, nonce, boxed]);
  return { ciphertext: ct.toString('base64'), ephemeralSecretHex: Buffer.from(eph.secretKey).toString('hex') };
}

export const shared: SharedJudge = {
  ...raw,
  canonicalJson: raw.canonicalJson ?? shimCanonicalJson,
  paramsHash: raw.paramsHash ?? shimParamsHash,
  checkRequestAgainstProgram: typeof raw.paramsHash === 'function' ? raw.checkRequestAgainstProgram : shimCheckRequest,
  encryptForOwnerWithSecret: raw.encryptForOwnerWithSecret ?? shimEncryptWithSecret,
};
// --------------------------------------------------------------------------- end of v3 shim

/** Contract Signer string ("ed25519:<hex>" / "eth:0x<hex>") -> shared.verifySig. */
export function verifySignerSig(signer: string, signature: string, text: string): boolean {
  if (signer.startsWith('ed25519:')) return shared.verifySig({ text, signature, signing_address: signer.slice(8), signing_algo: 'ed25519' });
  if (signer.startsWith('eth:')) return shared.verifySig({ text, signature, signing_address: signer.slice(4), signing_algo: 'ecdsa' });
  throw new Error(`bad signer encoding: ${signer}`);
}

export const demo = demoMjs as unknown as {
  DEMO_TARGET: { repoUrl: string; commit: string };
  DEMO_HUNTER: string;
  /** Invented bundle used by fixtures/demo.fakecode.json (must NOT match the program). */
  FAKE_CODE_BUNDLE: string;
};
