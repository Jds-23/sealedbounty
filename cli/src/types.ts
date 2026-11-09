// Mirrors docs/INTERFACE.md. Keep in sync with contracts/sealed-bounty.

export type Severity = 'none' | 'low' | 'medium' | 'high' | 'critical';
export type SigKind = 'provider_tee' | 'gateway';
/** "ed25519:<64 hex>" | "eth:0x<40 hex>" */
export type Signer = string;

export interface Verdict {
  valid: boolean;
  severity: Severity;
  cwe: string | null;
  confidence: number;
}

export interface Payouts {
  low: string;
  medium: string;
  high: string;
  critical: string;
}

export interface Program {
  id: number;
  owner: string;
  name: string;
  repo_url: string;
  commit: string;
  model_id: string;
  system_prompt_hash: string;
  /** v2: sha256hex of the published code bundle (buildCodeBundle). */
  code_hash: string;
  /** v3 #1: sha256hex(canonicalJson of the judge params) = shared.paramsHash(). */
  params_hash: string;
  /** v3 #3: signers accepted by this program (snapshot at creation; set_program_signers rotates it). */
  signers: Signer[];
  /** v3 #4: hunter stake (yocto U128) attached on top of storage to submit_claim. */
  bond: string;
  /** v3 #2: seconds the hunter has to prove_ciphertext after flag_undecryptable. */
  challenge_secs: number;
  payouts: Payouts;
  owner_enc_pubkey: string;
  dispute_secs: number;
  min_confidence: number;
  balance: string;
  reserved: string;
  open: boolean;
  created_at: string;
}

export type ClaimStatus = 'Pending' | 'Rejected' | 'Paid' | 'Challenged' | 'PayoutFailed';

export interface Claim {
  id: number;
  program_id: number;
  hunter: string;
  req_hash: string;
  resp_hash: string;
  verdict: Verdict;
  signer: Signer;
  kind: SigKind;
  signature: string;
  model: string;
  ciphertext: string;
  status: ClaimStatus;
  payout: string;
  submitted_at: string;
  finalize_after: string;
  reject_reason: string | null;
  /** v3 #4: paid back with the payout on Paid, forfeited to the pool on Rejected. */
  bond: string;
  /** v3 #2: ns deadline set by flag_undecryptable. */
  challenge_deadline: string | null;
}

export interface SignerMeta {
  kind: SigKind;
  model: string | null;
}

/**
 * A signed NEAR AI judge completion. Same shape as fixtures/live.*.json
 * (what spike/sign/record.mjs writes and what shared/judge.mjs `judge()` is expected to return).
 */
export interface JudgeRecord {
  model: string;
  request_body: string;
  response_body_b64: string;
  req_hash: string;
  resp_hash: string;
  chat_id?: string;
  signature: string;
  signing_address: string;
  signing_algo: 'ed25519' | 'ecdsa';
  signature_kind: SigKind;
  text: string;
  signer_in_attestation?: boolean;
  [k: string]: unknown;
}

/** [check name, ok, detail] */
export type CheckRow = [string, boolean, string];
