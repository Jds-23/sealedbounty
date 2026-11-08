// Typed facade over ../../shared/judge.mjs (single source of truth shared with web/).
// The relative path works from both cli/src (tsx) and cli/dist (node). shared/ ships no .d.ts,
// so the module is typed here.
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

export type DisputeReason = 'system prompt tampered' | 'model mismatch' | 'code mismatch' | 'hunter mismatch' | 'report missing';
export type RequestCheck = { ok: true; reason: null } | { ok: false; reason: DisputeReason };
export type ProgramBinding = Pick<Program, 'repo_url' | 'commit' | 'model_id' | 'system_prompt_hash' | 'code_hash'>;

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
  /** Mirrors the v2 contract's dispute checks (first failing reason, contract order). */
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
  decryptAsOwner(ciphertextB64: string, ownerSecretB64: string): string;
  generateOwnerKeypair(): { publicKey: string; secretKey: string };
}

export const shared = judgeMjs as unknown as SharedJudge;

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
