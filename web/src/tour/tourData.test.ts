// Guided tour data layer (docs/demo-app-spec.md §11): tx-args decoding, the gauntlet recompute for claims #1–#4,
// claim #0's clean audit + keyless decryption, and the RPC → snapshot fallback selector. All from the recorded
// public snapshot (src/fixtures/tour-v3-snapshot.json); no network.
import { describe, expect, it } from 'vitest';
import snap from '../fixtures/tour-v3-snapshot.json';
import { decodeTx } from '../lib/near';
import { sha256hex } from '../lib/verify';
import { auditRequest } from '../lib/requestChecks';
import { claimTxs, decryptClaim, recomputeReject, snapshotData, withFallback } from './tourData';

const raw = (method: string, claimId?: number) =>
  snap.txs.find((t) => t.method === method && t.ok && (claimId === undefined || decodeTx(t.raw).args?.claim_id === claimId))!;

describe('tx-args decoding', () => {
  it('decodes a dispute: claim_id + the revealed request_body', () => {
    const t = decodeTx(raw('dispute', 1).raw);
    expect(t.method).toBe('dispute');
    expect(t.signer).toBe('baldingsucks7993.testnet');
    expect(t.ok).toBe(true);
    expect(t.args).toMatchObject({ claim_id: 1 });
    expect(typeof t.args!.request_body).toBe('string');
    expect(JSON.parse(t.args!.request_body).model).toBe('Qwen/Qwen3.8-27B');
    expect(t.claimIds).toEqual([1]);
    expect(t.rejected).toEqual([{ claim_id: 1, reason: 'params tampered' }]);
  });

  it('decodes prove_ciphertext: the revealed 64-hex ephemeral secret', () => {
    const t = decodeTx(raw('prove_ciphertext').raw);
    expect(t.args).toMatchObject({ claim_id: 0 });
    expect(t.args!.ephemeral_secret).toMatch(/^[0-9a-f]{64}$/);
    expect(t.signer).toBe('hunter.baldingsucks7993.testnet');
  });

  it('decodes submit_claim: args + claim id from the claim_submitted event', () => {
    const rec = snap.txs.find((t) => t.hash.startsWith('GDUHZD4c'))!;
    const t = decodeTx(rec.raw);
    expect(t.method).toBe('submit_claim');
    expect(Object.keys(t.args!).sort()).toEqual(['ciphertext', 'kind', 'program_id', 'req_hash', 'resp_body', 'signature', 'signer']);
    expect(t.claimIds).toEqual([0]);
    const claim0 = snap.views.claims[0];
    expect(t.args!.req_hash).toBe(claim0.req_hash);
    expect(t.args!.ciphertext).toBe(claim0.ciphertext);
    // resp_body (base64) hashes to the stored resp_hash
    expect(sha256hex(Uint8Array.from(atob(t.args!.resp_body), (c) => c.charCodeAt(0)))).toBe(claim0.resp_hash);
  });

  it('reports a panicked tx with its panic text', () => {
    const rec = snap.txs.find((t) => t.hash.startsWith('6FHmjCg6'))!;
    const t = decodeTx(rec.raw);
    expect(t.ok).toBe(false);
    expect(t.failure).toMatch(/already claimed/);
    expect(t.claimIds).toEqual([]);
  });

  it('finds the finalize that paid claim 0 and the one that rejected claim 4', () => {
    const fin = snap.txs.filter((t) => t.method === 'finalize' && t.ok).map((t) => decodeTx(t.raw));
    expect(fin.find((t) => t.paidClaimIds.includes(0))!.hash).toMatch(/^ATvCo4xU/);
    expect(fin.find((t) => t.rejected.some((r) => r.claim_id === 4))!.rejected[0].reason).toBe('undecryptable report');
  });
});

describe('gauntlet recompute from snapshot data', () => {
  const d = snapshotData();
  const now = Date.now();
  const expected: Record<number, string> = { 1: 'params tampered', 2: 'code mismatch', 3: 'hunter mismatch', 4: 'undecryptable report' };

  for (const [id, reason] of Object.entries(expected)) {
    it(`claim #${id}: computed reason = onchain reject_reason = "${reason}"`, () => {
      const claim = d.claims.find((c) => c.id === Number(id))!;
      expect(claim.status).toBe('Rejected');
      expect(claim.reject_reason).toBe(reason);
      const r = recomputeReject(claim, d.program, claimTxs(d.txs, claim), now);
      expect(r.computed).toBe(reason);
      expect(r.onchain).toBe(reason);
      expect(r.match).toBe(true);
      expect(r.tx).toMatch(/^[1-9A-HJ-NP-Za-km-z]{43,44}$/);
    });
  }

  it('#3 front-run: the HUNTER line names the honest hunter, the claim came from frontrun', () => {
    const claim = d.claims.find((c) => c.id === 3)!;
    expect(claim.hunter).toBe('frontrun.baldingsucks7993.testnet');
    const txs = claimTxs(d.txs, claim);
    expect(JSON.parse(txs.dispute!.args!.request_body).messages[1].content).toContain('\nHUNTER hunter.baldingsucks7993.testnet\n');
    expect(txs.attempts).toEqual([]);
  });

  it('a replayed submit of claim #1 (same req_hash) panicked "already claimed"', () => {
    // 6FHmjCg6…: README lists it under the front-run row, but its args carry claim #1's req_hash.
    const txs = claimTxs(d.txs, d.claims.find((c) => c.id === 1)!);
    expect(txs.attempts.map((a) => [a.hash.slice(0, 8), /already claimed/.test(a.failure ?? '')])).toEqual([['6FHmjCg6', true]]);
  });

  it('#4: flagged, never proved, deadline passed', () => {
    const claim = d.claims.find((c) => c.id === 4)!;
    const txs = claimTxs(d.txs, claim);
    expect(txs.flag).toBeTruthy();
    expect(txs.prove).toBeNull();
    // before the deadline the same data does not yet compute a rejection
    const early = recomputeReject(claim, d.program, txs, Number(BigInt(claim.challenge_deadline!) / 1_000_000n) - 1000);
    expect(early.computed).toBeNull();
  });

  it('claim #0 audits clean and decrypts (keyless) to a report whose sha256 = req_hash', () => {
    const claim = d.claims.find((c) => c.id === 0)!;
    expect(claim.status).toBe('Paid');
    const txs = claimTxs(d.txs, claim);
    const dec = decryptClaim(claim, d.program, txs);
    expect(dec.ok).toBe(true);
    if (!dec.ok) return;
    expect(sha256hex(dec.plaintext)).toBe(claim.req_hash);
    const audit = auditRequest(dec.plaintext, d.program, claim.hunter);
    expect(audit.ok).toBe(true);
    expect(audit.checks.map((c) => c.ok)).toEqual([true, true, true, true, true, true]);
    expect(recomputeReject(claim, d.program, txs, now).computed).toBeNull();
    // the timeline: submitted -> flagged -> proven -> finalized (paid)
    expect([txs.submit, txs.flag, txs.prove, txs.finalize].every(Boolean)).toBe(true);
    expect(txs.finalize!.paidClaimIds).toContain(0);
  });
});

describe('fallback selector', () => {
  const SNAP = { v: 'snapshot' };

  it('returns live data when the call succeeds in time', async () => {
    const r = await withFallback(async () => ({ v: 'live' }), SNAP, 200);
    expect(r).toEqual({ data: { v: 'live' }, source: 'live', error: null });
  });

  it('an RPC failure returns the snapshot and the SNAPSHOT flag', async () => {
    const r = await withFallback(async () => {
      throw new Error('RPC HTTP 503');
    }, SNAP, 200);
    expect(r.data).toBe(SNAP);
    expect(r.source).toBe('snapshot');
    expect(r.error).toMatch(/503/);
  });

  it('a timeout returns the snapshot and the SNAPSHOT flag', async () => {
    const t0 = Date.now();
    const r = await withFallback(() => new Promise<never>(() => {}), SNAP, 50);
    expect(Date.now() - t0).toBeLessThan(1000);
    expect(r.source).toBe('snapshot');
    expect(r.data).toBe(SNAP);
    expect(r.error).toMatch(/timeout/i);
  });
});
