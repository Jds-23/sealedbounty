// Claim status + reject reason texts (docs/INTERFACE.md v2 dispute reasons, v3 #1 #2 #6 #8).
import type { Claim } from './types';
import { nsToMs } from './format';

export type Tone = 'neutral' | 'ok' | 'warn' | 'bad' | 'info';

/** One-line explanation of each reject reason, plus which contract step produced it. */
const REASONS: Record<string, { source: string; why: string }> = {
  'code mismatch': {
    source: 'Rejected by owner dispute',
    why: 'The revealed request\'s CODE does not hash to program.code_hash: the TEE judged code the hunter invented, not the published bundle.',
  },
  'hunter mismatch': {
    source: 'Rejected by owner dispute',
    why: 'The revealed request\'s HUNTER line names another account: this claim copied someone else\'s pending submit_claim (front-run). req_hash is freed so the real hunter can resubmit.',
  },
  'system prompt tampered': { source: 'Rejected by owner dispute', why: 'The revealed request\'s system prompt differs from program.system_prompt_hash.' },
  'model mismatch': { source: 'Rejected by owner dispute', why: 'The revealed request was judged by another model.' },
  'report missing': { source: 'Rejected by owner dispute', why: 'The revealed request has no REPORT message.' },
  'params tampered': {
    source: 'Rejected by owner dispute',
    why: 'The revealed request\'s params (temperature, max_tokens, response_format) do not hash to program.params_hash: the hunter steered the judge, e.g. a schema that forces valid:true.',
  },
  'undecryptable report': {
    source: 'Rejected by the decryption challenge',
    why: 'The owner could not decrypt the ciphertext and flagged it; the hunter did not prove_ciphertext (reveal the ephemeral key that opens it to req_hash) before the deadline.',
  },
  'signer revoked': {
    source: 'Rejected at finalize',
    why: 'The admin revoked the TEE key that signed this verdict before it finalized; the payout and bond went back to the pool (the admin can block a payout, not redirect it).',
  },
};

export function rejectInfo(reason: string | null): { source: string; why: string } {
  return (reason && REASONS[reason]) || { source: 'Rejected', why: '' };
}

export const statusTone = (s: Claim['status']): Tone =>
  s === 'Paid' ? 'ok' : s === 'Rejected' || s === 'PayoutFailed' ? 'bad' : 'warn';

export interface StatusInfo {
  tone: Tone;
  headline: string;
  detail: string;
  /** ns timestamp to count down to (Challenged: challenge_deadline). */
  deadline?: string;
}

/** Headline + one-line detail for the v3 statuses shown on a claim card. */
export function claimStatusInfo(c: Claim, nowMs = Date.now()): StatusInfo {
  if (c.status === 'Challenged') {
    const d = c.challenge_deadline;
    const open = d !== null && nsToMs(d) > nowMs;
    return {
      tone: 'warn',
      headline: 'Challenged: hunter must reveal key',
      detail: open
        ? 'The owner flagged the ciphertext as undecryptable. The hunter must call prove_ciphertext with the ephemeral secret; the contract opens the box and checks sha256 == req_hash, then runs the dispute checks.'
        : 'The challenge deadline passed without a proof: finalize now rejects it with "undecryptable report".',
      deadline: d ?? undefined,
    };
  }
  if (c.status === 'PayoutFailed') {
    return {
      tone: 'bad',
      headline: 'Payout failed',
      detail: 'The transfer to the hunter failed (e.g. the account was deleted). on_payout put payout + bond back to the pool.',
    };
  }
  if (c.status === 'Rejected') {
    const r = rejectInfo(c.reject_reason);
    return { tone: 'bad', headline: `${r.source}: ${c.reject_reason ?? 'no reason given'}`, detail: r.why };
  }
  if (c.status === 'Paid') return { tone: 'ok', headline: 'Paid', detail: '' };
  return { tone: 'warn', headline: 'Pending', detail: '', deadline: c.finalize_after };
}

/** Owner inbox: what to do when a claim's ciphertext does not open with the owner key. */
export function undecryptableHint(c: Claim): string {
  if (c.status === 'Pending') return `UNDECRYPTABLE → \`sb flag-undecryptable --claim ${c.id}\``;
  if (c.status === 'Challenged') return 'UNDECRYPTABLE: already flagged; the hunter must prove_ciphertext before the deadline, else it is rejected.';
  if (c.status === 'Rejected') return `UNDECRYPTABLE: already rejected${c.reject_reason ? ` ("${c.reject_reason}")` : ''}.`;
  return `UNDECRYPTABLE: the claim is already ${c.status}; too late to flag.`;
}
