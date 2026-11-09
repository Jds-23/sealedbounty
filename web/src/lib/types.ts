// Mirrors docs/INTERFACE.md. Amounts are yoctoNEAR decimal strings; timestamps are ns strings.
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
  /** v2: sha256hex of the published code bundle. null for v1 programs (no code binding). */
  code_hash: string | null;
  /** v3 #1: sha256hex(canonicalJson(request params)). null before v3 (params not pinned). */
  params_hash: string | null;
  /** v3 #3: the program's own signer set (snapshot of the allowlist). null before v3 (global allowlist). */
  signers: Signer[] | null;
  /** v3 #4: hunter bond (yocto) attached to submit_claim. null before v3. */
  bond: string | null;
  /** v3 #2: seconds the hunter has to prove_ciphertext after a flag. null before v3. */
  challenge_secs: number | null;
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
  /** v3 #4: bond held by this claim. null before v3. */
  bond: string | null;
  /** v3 #2: set once the owner flags the ciphertext; the hunter must prove_ciphertext before it. */
  challenge_deadline: string | null;
  /**
   * Demo only: this attempt never reached the chain because submit_claim reverted (e.g. "verdict not payable").
   * Shown so the real TEE outputs for refused reports are visible; never set from RPC data.
   */
  refused_at_submit?: string;
  /**
   * Demo only: a claim built from a real fixture whose request body was changed offline (no NEAR AI call),
   * so there is no TEE signature over it. Explains what was changed; never set from RPC data.
   */
  synthetic?: string;
  /** Demo only: what happened to the claim, in order (flag, prove, finalize...). */
  history?: { at: string; event: string }[];
  /** Demo only: the ephemeral secret the hunter revealed with prove_ciphertext (a public tx arg). */
  proof_secret?: string;
}

export interface SignerMeta {
  kind: SigKind;
  model?: string | null;
}

export interface SignerEntry {
  signer: Signer;
  meta: SignerMeta;
}
