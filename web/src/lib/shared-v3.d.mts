// Types for the temporary v3 shim (shared-v3.mjs). Remove together with it after the rebase.
import type { DisputeReason } from '@sealedbounty/shared';

export type DisputeReasonV3 = DisputeReason | 'params tampered';
export interface JudgeParams {
  response_format?: unknown;
  chat_template_kwargs?: unknown;
  temperature?: unknown;
  max_tokens?: unknown;
}
export function canonicalJson(v: unknown): string;
export const JUDGE_PARAMS: Readonly<Required<JudgeParams>>;
export function paramsHash(req?: JudgeParams): string;
export function checkRequestAgainstProgram(
  requestBody: string,
  program: { repo_url: string; commit: string; model_id: string; system_prompt_hash: string; code_hash: string; params_hash?: string | null },
  hunter: string,
): { ok: true; reason: null } | { ok: false; reason: DisputeReasonV3 };
export function encryptForOwnerWithSecret(
  requestBody: string,
  ownerPubB64: string,
  opts?: { ephemeralSecret?: Uint8Array; nonce?: Uint8Array },
): { ciphertext: string; ephemeralSecretHex: string };
