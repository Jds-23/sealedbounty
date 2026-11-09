// Step 6 — Owner decrypts → challenge → paid. 'Decrypt' takes the ephemeral secret the hunter revealed in claim #0's
// prove_ciphertext args and opens the onchain ciphertext (proveCiphertext), keyless; then the 6 dispute checks
// (auditRequest) and the tx timeline. Live lane: the full loop on program 2 through the helper.
import { useMemo, useState } from 'react';
import { fmtDate, nsToMs, yoctoToNear } from '../../lib/format';
import { auditRequest } from '../../lib/requestChecks';
import { LiveGate, StreamView, useHelperStream } from '../LiveLane';
import { useRestore, useTour, useTourAction } from '../TourContext';
import { claimTxs, decryptClaim } from '../tourData';
import { CheckList, ErrLine, Exhibit, Hash, HeroButton, KV, TxLink } from '../ui';

export const step6 = {
  kicker: 'Challenge, then payout',
  headline: 'Proven, then paid by the contract.',
  body: 'The owner can claim the report is unreadable. The hunter then reveals the encryption key onchain, and the contract decrypts it itself. Once the window closes, anyone can trigger the payout.',
  why: 'Neither side can stall or cheat the other.',
};

export function Step6() {
  const { data, setResult } = useTour();
  const claim = data.claims.find((c) => c.id === 0)!;
  const txs = useMemo(() => claimTxs(data.txs, claim), [data.txs, claim]);
  const [runId, setRunId] = useState(0);

  const res = useMemo(() => {
    if (!runId) return null;
    const dec = decryptClaim(claim, data.program, txs);
    if (!dec.ok) return { dec, audit: null, report: null };
    const audit = auditRequest(dec.plaintext, data.program, claim.hunter);
    let report: string | null = null;
    try {
      report = String(JSON.parse(dec.plaintext).messages?.[2]?.content ?? '').replace(/^REPORT\n/, '');
    } catch {
      /* shown raw */
    }
    return { dec, audit, report };
  }, [runId, claim, data.program, txs]);

  const decrypt = () => {
    setRunId((n) => n + 1);
    const dec = decryptClaim(claim, data.program, txs);
    setResult('decrypt', dec.ok, dec.ok ? 'Claim #0 decrypted keyless; sha256 = req_hash' : `Decryption failed (${dec.reason})`);
    if (dec.ok) {
      const a = auditRequest(dec.plaintext, data.program, claim.hunter);
      setResult('audit0', a.ok, a.ok ? 'All 6 dispute checks pass on claim #0' : `Dispute check failed: ${a.reason}`);
    }
  };
  useTourAction('decrypt', decrypt);
  useRestore('decrypt', decrypt);

  const paid = txs.finalize?.paidClaimIds.includes(claim.id);
  const total = claim.bond ? (BigInt(claim.payout) + BigInt(claim.bond)).toString() : claim.payout;
  const ts = (t: { blockTimestamp: string | null } | null) => (t?.blockTimestamp ? fmtDate(t.blockTimestamp) : '');
  const timeline = [
    { k: 'submitted', what: 'TEE signature verified onchain; payout reserved, bond held', tx: txs.submit, when: fmtDate(claim.submitted_at) },
    { k: 'flagged undecryptable', what: 'the owner challenged the ciphertext', tx: txs.flag, when: ts(txs.flag) },
    { k: 'proven', what: 'hunter revealed the key; the contract opened the box and re-ran the checks', tx: txs.prove, when: ts(txs.prove) },
    { k: 'finalized', what: 'anyone may call it once the window closes', tx: txs.finalize, when: ts(txs.finalize) },
  ];

  return (
    <div className="stack">
      <Exhibit label="claim #0 · decrypted from public tx data" meta={<TxLink hash={txs.prove?.hash} label="prove_ciphertext" />}>
        <div className="row-actions">
          <HeroButton onClick={decrypt} done={runId > 0}>
            {runId ? 'Decrypt again' : 'Decrypt'}
          </HeroButton>
          {res?.dec.ok && (
            <span className="readout readout-live">
              sha256(plaintext) = req_hash <span aria-hidden>✓</span>
            </span>
          )}
        </div>
        {!res ? (
          <p className="muted ghost-copy">No owner key needed: the hunter's revealed ephemeral secret is a public tx argument.</p>
        ) : !res.dec.ok ? (
          <ErrLine>decryption failed: {res.dec.reason}</ErrLine>
        ) : (
          <div className="reveal">
            <KV rows={[['ephemeral_secret', <Hash key="s" value={res.dec.secret!} />]]} />
            <div className="cap">the report, as the owner sees it</div>
            <pre className="pane-pre report-pre">{res.report ?? res.dec.plaintext}</pre>
            <details>
              <summary className="small muted">full judge request body ({res.dec.plaintext.length} chars)</summary>
              <pre className="pane-pre">{res.dec.plaintext}</pre>
            </details>
          </div>
        )}
      </Exhibit>

      {res?.audit && (
        <Exhibit label="6 dispute checks on the revealed request" tone={res.audit.ok ? 'ok' : 'bad'} meta={<span className="okc mono">{res.audit.ok ? 'nothing to dispute' : res.audit.reason}</span>}>
          <CheckList runId={runId} items={res.audit.checks.map((c) => ({ label: c.label, status: c.ok === null ? 'na' : c.ok ? 'pass' : 'fail', detail: c.detail }))} />
        </Exhibit>
      )}

      <Exhibit label="claim #0 · onchain timeline">
        <ol className="tline">
          {timeline.map((s) => (
            <li key={s.k} className={s.tx ? 'tline-on' : ''}>
              <span className="tline-dot" aria-hidden />
              <div>
                <div className="tline-k">{s.k}</div>
                <div className="tline-w">{s.what}</div>
              </div>
              <div className="tline-r">
                <span className="mono small muted">{s.when}</span>
                <TxLink hash={s.tx?.hash} />
              </div>
            </li>
          ))}
          <li className={`tline-on tline-paid ${paid ? '' : 'tline-pending'}`}>
            <span className="tline-dot" aria-hidden />
            <div>
              <div className="tline-k">{claim.status === 'Paid' ? 'Paid' : claim.status}</div>
              <div className="tline-w">
                {yoctoToNear(claim.payout, 2)} payout{claim.bond ? ` + ${yoctoToNear(claim.bond, 2)} bond` : ''} = <strong>{yoctoToNear(total, 2)} NEAR</strong> to{' '}
                <code>{claim.hunter}</code>
              </div>
            </div>
            <div className="tline-r">{paid ? <span className="okc mono small">claim_paid event</span> : null}</div>
          </li>
        </ol>
        {claim.challenge_deadline && txs.prove?.blockTimestamp && (
          <p className="muted small">
            Proven {Math.round((nsToMs(claim.challenge_deadline) - nsToMs(txs.prove.blockTimestamp)) / 1000)} s before the challenge deadline.
          </p>
        )}
      </Exhibit>

      <LiveLoop />
    </div>
  );
}

const LOOP_LABELS: Record<string, string> = {
  setup: 'setup',
  submit_claim: 'submit_claim (hunter)',
  flag_undecryptable: 'flag_undecryptable (owner)',
  prove_ciphertext: 'prove_ciphertext (hunter)',
  wait: 'wait for the window',
  finalize: 'finalize (anyone)',
};

function LiveLoop() {
  const { liveJudgement, setResult } = useTour();
  const s = useHelperStream();
  const run = async () => {
    try {
      const out = await s.start('/loop', { judgement: liveJudgement?.raw });
      setResult('live-loop', /paid/i.test(out ?? ''), `Live loop on program 2 → ${out}`);
    } catch (e) {
      setResult('live-loop', false, 'Live loop failed');
      throw e;
    }
  };
  useTourAction('live-loop', run);
  return (
    <LiveGate title="Run the full loop live">
      <div className="lane-row">
        <HeroButton kind="live" onClick={() => run().catch(() => {})} busy={s.running} disabled={!liveJudgement} done={!!s.outcome}>
          {s.running ? 'Running on testnet…' : 'Run the full loop live'}
        </HeroButton>
        {!liveJudgement && <span className="muted small">Judge a report live in step 4 first.</span>}
      </div>
      <StreamView st={s} labels={LOOP_LABELS} />
    </LiveGate>
  );
}
