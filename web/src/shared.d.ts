// Types for the browser-safe shared library (../shared/judge.mjs). Only what the web uses.
declare module '@sealedbounty/shared' {
  export type Severity = 'none' | 'low' | 'medium' | 'high' | 'critical';
  export interface VerdictT { valid: boolean; severity: Severity; cwe: string | null; confidence: number }
  export function sha256hex(data: string | Uint8Array): string;
  export function systemPromptHash(): string;
  export function parseVerdict(responseBody: string | Uint8Array): VerdictT;
  export function expectedText(kind: 'provider_tee' | 'gateway', model: string, reqHash: string, respHash: string): string;
  export function verifySig(s: { text: string; signature: string; signing_address: string; signing_algo: 'ed25519' | 'ecdsa' }): boolean;
  export function signerId(r: { signing_address: string; signing_algo: 'ed25519' | 'ecdsa' }): string;
  export function encryptForOwner(requestBody: string, ownerPubB64: string): string;
  export function decryptAsOwner(ciphertextB64: string, ownerSecretB64: string): string;
  export function generateOwnerKeypair(): { publicKey: string; secretKey: string };
  // v2: code bundle + hunter binding
  export type DisputeReason =
    | 'system prompt tampered'
    | 'model mismatch'
    | 'params tampered'
    | 'code mismatch'
    | 'hunter mismatch'
    | 'report missing';
  export function buildCodeBundle(files: { path: string; content: string }[]): string;
  export function codeHash(bundle: string): string;
  export function codeMessagePrefix(p: { repoUrl: string; commit: string; hunter: string }): string;
  export function checkRequestAgainstProgram(
    requestBody: string,
    program: { repo_url: string; commit: string; model_id: string; system_prompt_hash: string; code_hash: string; params_hash?: string | null },
    hunter: string,
  ): { ok: true; reason: null } | { ok: false; reason: DisputeReason };
  // v3 #1 params pinning, #2 decryption challenge
  export interface JudgeParams {
    response_format?: unknown;
    chat_template_kwargs?: unknown;
    temperature?: unknown;
    max_tokens?: unknown;
  }
  export function canonicalJson(v: unknown): string;
  export const JUDGE_PARAMS: Readonly<Required<JudgeParams>>;
  export function paramsHash(req?: JudgeParams): string;
  /** The contract's params hash of a request body (exact number tokens); null if the body is not a strict judge request. */
  export function requestParamsHash(requestBody: string, opts?: { strictNumbers?: boolean }): string | null;
  export function encryptForOwnerWithSecret(
    requestBody: string,
    ownerPubB64: string,
    opts?: { ephemeralSecret?: Uint8Array; nonce?: Uint8Array },
  ): { ciphertext: string; ephemeralSecretHex: string };
}

declare module '@sealedbounty/shared/demo-data.mjs' {
  export const DEMO_TARGET: { repoUrl: string; commit: string };
  export const DEMO_HUNTER: string;
  export const DEMO_FRONTRUNNER: string;
  export const FAKE_CODE_BUNDLE: string;
  export const FAKE_CODE_REPORT: string;
}
