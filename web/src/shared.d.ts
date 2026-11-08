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
  export type DisputeReason = 'system prompt tampered' | 'model mismatch' | 'code mismatch' | 'hunter mismatch' | 'report missing';
  export function buildCodeBundle(files: { path: string; content: string }[]): string;
  export function codeHash(bundle: string): string;
  export function codeMessagePrefix(p: { repoUrl: string; commit: string; hunter: string }): string;
  export function checkRequestAgainstProgram(
    requestBody: string,
    program: { repo_url: string; commit: string; model_id: string; system_prompt_hash: string; code_hash: string },
    hunter: string,
  ): { ok: true; reason: null } | { ok: false; reason: DisputeReason };
}

declare module '@sealedbounty/shared/demo-data.mjs' {
  export const DEMO_TARGET: { repoUrl: string; commit: string };
  export const DEMO_HUNTER: string;
  export const DEMO_FRONTRUNNER: string;
  export const FAKE_CODE_BUNDLE: string;
  export const FAKE_CODE_REPORT: string;
}
