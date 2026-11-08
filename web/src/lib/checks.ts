// Builds the per-claim "Verified" checklist. Every item is either computed here, in the browser,
// or explicitly marked as not verifiable client-side.
import attestations from '../fixtures/attestation.summary.json';
import type { Claim, Program, SignerEntry } from './types';
import {
  b64ToBytes,
  findSigner,
  parseSigner,
  parseVerdict,
  quoteBindsSigner,
  sha256hex,
  signedText,
  strip0x,
  verifySignature,
} from './verify';

export type CheckStatus = 'pass' | 'fail' | 'offline' | 'na';
export interface Check {
  label: string;
  status: CheckStatus;
  detail: string;
}

type AttSummary = (typeof attestations)['ed25519'];

export function attestationFor(signer: string): AttSummary | undefined {
  try {
    const p = parseSigner(signer);
    const addr = p.algo === 'ed25519' ? p.pubkey : p.address;
    return Object.values(attestations).find(
      (a) => strip0x(a.model_attestation.signing_address).toLowerCase() === strip0x(addr),
    );
  } catch {
    return undefined;
  }
}

export interface CheckOptions {
  /** Raw response body, if known (demo mode). Onchain only resp_hash is stored. */
  respBodyB64?: string;
  signersSource: 'contract' | 'demo';
}

export function verifyClaim(claim: Claim, program: Program | undefined, signers: SignerEntry[] | null, opts: CheckOptions): Check[] {
  const checks: Check[] = [];
  const text = signedText(claim.kind, claim.model, claim.req_hash, claim.resp_hash);

  // 1. Model binding
  if (program) {
    const ok = claim.model === program.model_id;
    checks.push({ label: 'Signed model = program model', status: ok ? 'pass' : 'fail', detail: `${claim.model}${ok ? '' : ` ≠ ${program.model_id}`}` });
  }

  // 2. Signature
  const sig = verifySignature(claim.signer, text, claim.signature);
  checks.push({ label: `TEE signature over "model:req_hash:resp_hash"`, status: sig.ok ? 'pass' : 'fail', detail: sig.detail });

  // 3. Allowlist
  if (signers === null) {
    checks.push({ label: 'Signer allowlisted (get_signers)', status: 'na', detail: 'could not load get_signers from RPC' });
  } else {
    const e = findSigner(signers, claim.signer);
    const ok = !!e && e.meta.kind === claim.kind;
    const src = opts.signersSource === 'contract' ? 'contract get_signers' : 'demo allowlist = INTERFACE.md testnet signers';
    checks.push({
      label: 'Signer allowlisted (get_signers)',
      status: ok ? 'pass' : 'fail',
      detail: e ? (ok ? `${src}, kind ${e.meta.kind}` : `kind mismatch: ${e.meta.kind} vs ${claim.kind}`) : `not in ${src}`,
    });
  }

  // 4. Response body -> resp_hash -> verdict
  if (opts.respBodyB64) {
    const body = b64ToBytes(opts.respBodyB64);
    const h = sha256hex(body);
    let detail = `sha256(body) = ${h.slice(0, 12)}…`;
    let ok = h === claim.resp_hash.toLowerCase();
    if (ok) {
      try {
        const v = parseVerdict(body);
        ok = v.valid === claim.verdict.valid && v.severity === claim.verdict.severity;
        detail = `verdict in signed body: valid=${v.valid}, severity=${v.severity}, cwe=${v.cwe}`;
      } catch (e) {
        ok = false;
        detail = `verdict parse failed: ${(e as Error).message}`;
      }
    } else detail += ' ≠ resp_hash';
    checks.push({ label: 'Response body hashes to resp_hash, verdict matches', status: ok ? 'pass' : 'fail', detail });
  } else {
    checks.push({
      label: 'Verdict comes from the signed response',
      status: 'na',
      detail: 'Contract stores only resp_hash; it parsed the verdict from the body at submit_claim. Not re-checkable in the browser.',
    });
  }

  // 5. Attestation
  const att = attestationFor(claim.signer);
  if (!att) {
    checks.push({ label: 'Signer key attested in TEE', status: 'na', detail: 'no bundled attestation for this signer (signers rotate; re-run `attest`)' });
  } else {
    const m = att.model_attestation;
    const bind = quoteBindsSigner(m.intel_quote, m.signing_address, m.request_nonce);
    checks.push({ label: 'TDX quote report_data binds signer key + nonce', status: bind.ok ? 'pass' : 'fail', detail: `${bind.detail} (parsed in browser)` });
    const vs = att.verified_signers.find((s) => s.kind === 'model' && strip0x(s.signing_address).toLowerCase() === strip0x(m.signing_address).toLowerCase());
    const date = att.fetched_at.slice(0, 10);
    checks.push({
      label: 'Intel TDX DCAP + NVIDIA NRAS verdict',
      status: 'offline',
      detail: vs?.verified
        ? `verified offline by attest tool on ${date} (${Object.values(vs.checks).filter((c) => c.status === 'PASS').length} checks PASS). Quote cert chain / NRAS JWT not re-run in browser.`
        : `offline verifier did not mark this signer verified (${date})`,
    });
  }

  // 6. Report contents
  checks.push({ label: 'Report hashes to req_hash', status: 'na', detail: 'Encrypted to the program owner. Owner can check it in the Inbox.' });
  return checks;
}
