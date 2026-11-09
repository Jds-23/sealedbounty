// Builds the per-claim "Verified" checklist. Every item is either computed here, in the browser,
// or explicitly marked as not verifiable client-side.
import attestations from '../fixtures/attestation.summary.json';
import type { Claim, Program, SignerEntry } from './types';
import { b64ToBytes, findSigner, parseSigner, parseVerdict, quoteBindsSigner, sha256hex, signedText, strip0x, verifySignature } from './verify';

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
    return Object.values(attestations).find((a) => strip0x(a.model_attestation.signing_address).toLowerCase() === strip0x(addr));
  } catch {
    return undefined;
  }
}

export interface CheckOptions {
  /** Raw response body, if known (demo mode). Onchain only resp_hash is stored. */
  respBodyB64?: string;
  signersSource: 'contract' | 'demo';
  /** v3 #6: signers known to be revoked (is_signer_revoked). null/undefined = unknown. */
  revoked?: ReadonlySet<string> | null;
}

export function verifyClaim(claim: Claim, program: Program | undefined, signers: SignerEntry[] | null, opts: CheckOptions): Check[] {
  const checks: Check[] = [];
  const text = signedText(claim.kind, claim.model, claim.req_hash, claim.resp_hash);

  // 1. Model binding
  if (program) {
    const ok = claim.model === program.model_id;
    checks.push({
      label: 'Signed model = program model',
      status: ok ? 'pass' : 'fail',
      detail: `${claim.model}${ok ? '' : ` ≠ ${program.model_id}`}`,
    });
  }

  // 2. Signature
  if (claim.synthetic) {
    checks.push({ label: `TEE signature over "model:req_hash:resp_hash"`, status: 'na', detail: `synthetic demo claim: ${claim.synthetic}` });
  } else {
    const sig = verifySignature(claim.signer, text, claim.signature);
    checks.push({ label: `TEE signature over "model:req_hash:resp_hash"`, status: sig.ok ? 'pass' : 'fail', detail: sig.detail });
  }

  // 3. Signer set: v3 programs pin their own set (#3); before v3 only the global allowlist exists.
  const src = opts.signersSource === 'contract' ? 'contract get_signers' : 'demo allowlist = INTERFACE.md testnet signers';
  const entry = signers ? findSigner(signers, claim.signer) : undefined;
  if (program?.signers) {
    const inSet = program.signers.some((s) => s.toLowerCase() === claim.signer.toLowerCase());
    const kindOk = !entry || entry.meta.kind === claim.kind;
    let detail = `in program.signers (${program.signers.length}); submit_claim only accepts these`;
    if (!inSet) detail = `not in program.signers (${program.signers.length}): ${program.signers.map((s) => s.slice(0, 16) + '…').join(', ')}`;
    else if (!kindOk) detail = `kind mismatch: global allowlist says ${entry!.meta.kind}, claim ${claim.kind}`;
    else if (!entry) detail += signers ? '; no longer in the global allowlist (removed after submit)' : '; global allowlist not loaded';
    else detail += `; ${src}: kind ${entry.meta.kind}, model ${entry.meta.model ?? 'any'}`;
    checks.push({ label: 'Signer in PROGRAM set (program.signers)', status: inSet && kindOk ? 'pass' : 'fail', detail });

    const r = opts.revoked;
    const revoked = r?.has(claim.signer);
    checks.push({
      label: 'Signer not revoked (is_signer_revoked)',
      status: r == null ? 'na' : revoked ? 'fail' : 'pass',
      detail:
        r == null
          ? 'could not load is_signer_revoked from RPC'
          : revoked
            ? 'the admin revoked this key: finalize rejects the claim with "signer revoked" (payout + bond back to the pool)'
            : opts.signersSource === 'demo'
              ? 'demo: no signer revoked'
              : 'contract is_signer_revoked = false',
    });
  } else if (signers === null) {
    checks.push({ label: 'Signer allowlisted (get_signers)', status: 'na', detail: 'could not load get_signers from RPC' });
  } else {
    const e = entry;
    const kindOk = !!e && e.meta.kind === claim.kind;
    // A signer may be pinned to one model (SignerMeta.model); null/absent = any model.
    const modelOk = !!e && (e.meta.model == null || e.meta.model === claim.model);
    const ok = kindOk && modelOk;
    let detail = `not in ${src}`;
    if (e && !kindOk) detail = `kind mismatch: ${e.meta.kind} vs ${claim.kind}`;
    else if (e && !modelOk) detail = `signer pinned to ${e.meta.model}, claim model ${claim.model}`;
    else if (e) detail = `${src}, kind ${e.meta.kind}, model ${e.meta.model ?? 'any'}`;
    checks.push({ label: 'Signer allowlisted for this kind + model (get_signers)', status: ok ? 'pass' : 'fail', detail });
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
      label: 'Verdict bound via onchain resp_hash; body not stored',
      status: 'na',
      detail:
        'submit_claim hashed the response body, checked it against the signed resp_hash and parsed the verdict from it. Only resp_hash is stored, so the browser cannot re-parse the verdict.',
    });
  }

  // 5. Attestation
  const att = attestationFor(claim.signer);
  if (!att) {
    checks.push({
      label: 'Signer key attested in TEE',
      status: 'na',
      detail: 'no bundled attestation for this signer (signers rotate; re-run `attest`)',
    });
  } else {
    const m = att.model_attestation;
    const bind = quoteBindsSigner(m.intel_quote, m.signing_address, m.request_nonce);
    checks.push({
      label: 'TDX quote report_data binds signer key + nonce',
      status: bind.ok ? 'pass' : 'fail',
      detail: `${bind.detail} (bundled quote from ${att.fetched_at.slice(0, 10)}, parsed in browser)`,
    });
    const vs = att.verified_signers.find(
      (s) => s.kind === 'model' && strip0x(s.signing_address).toLowerCase() === strip0x(m.signing_address).toLowerCase(),
    );
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
  checks.push({
    label: 'Report hashes to req_hash',
    status: 'na',
    detail:
      program?.code_hash
        ? 'Encrypted to the program owner. The Inbox checks it against req_hash, the prompt, model, code_hash and this hunter.'
        : 'Encrypted to the program owner. Owner can check it in the Inbox.',
  });
  return checks;
}
