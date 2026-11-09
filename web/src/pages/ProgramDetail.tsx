import { useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { useData } from '../data';
import { countdown, fmtDate, fmtSecs, nsToMs, yoctoToNear } from '../lib/format';
import { CONTRACT_ID, explorerAccount, explorerTx, findPaidTxs } from '../lib/near';
import type { Claim, Program } from '../lib/types';
import { Badge, Hash, StatusIcon } from '../components/ui';
import { DEMO_CODE_BUNDLE } from '../lib/demo';
import { sha256hex } from '../lib/verify';
import { VerifyPanel } from '../components/VerifyPanel';
import { claimStatusInfo, statusTone } from '../lib/status';
import { proveCiphertext } from '../lib/crypto';

function Countdown({ until, kind = 'dispute' }: { until: string; kind?: 'dispute' | 'challenge' }) {
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);
  return <span className="mono">{countdown(nsToMs(until) - now, kind)}</span>;
}

const payable = (c: Claim, min: number) => c.verdict.valid && c.verdict.severity !== 'none' && c.verdict.confidence >= min;

function usePaidTxs(enabled: boolean) {
  const [txs, setTxs] = useState<Record<number, string>>({});
  useEffect(() => {
    if (!enabled) return;
    let live = true;
    findPaidTxs().then((t) => live && setTxs(t));
    return () => {
      live = false;
    };
  }, [enabled]);
  return txs;
}

function Ext({ href, children }: { href: string; children: React.ReactNode }) {
  return (
    <a href={href} target="_blank" rel="noreferrer noopener">
      {children} ↗
    </a>
  );
}

function ClaimStatus({ c, program }: { c: Claim; program: Program }) {
  if (c.refused_at_submit)
    return (
      <div className="muted">
        Refused at submit: <code>submit_claim</code> reverts with &quot;{c.refused_at_submit}&quot;, so nothing is stored onchain. Shown here with its
        real TEE output.
      </div>
    );
  const info = claimStatusInfo(c);
  const proof = c.proof_secret ? proveCiphertext(c.ciphertext, program.owner_enc_pubkey, c.proof_secret, c.req_hash) : null;
  return (
    <>
      {c.status === 'Pending' && (
        <div className="pending">
          <Countdown until={c.finalize_after} />
        </div>
      )}
      {c.status === 'Challenged' && (
        <div className="challenged">
          <strong>{info.headline}</strong>
          {info.deadline && (
            <>
              {' · '}
              <Countdown until={info.deadline} kind="challenge" />
            </>
          )}
          <div className="small">{info.detail}</div>
        </div>
      )}
      {(c.status === 'Rejected' || c.status === 'PayoutFailed') && (
        <div className="rejected">
          <strong>{info.headline}</strong>
          {info.detail && <div className="small">{info.detail}</div>}
        </div>
      )}
      {proof && (
        <div className="row gap small">
          <StatusIcon status={proof.ok ? 'pass' : 'fail'} />
          <span>
            prove_ciphertext re-checked in your browser: the revealed ephemeral secret derives ciphertext[0..32], opens the box, and{' '}
            {proof.ok ? 'sha256(plaintext) = req_hash' : `fails (${proof.reason})`}. No owner key is needed.
          </span>
        </div>
      )}
    </>
  );
}

export function ProgramDetail() {
  const { id } = useParams();
  const { programs, claims, loading, isDemo } = useData();
  const paidTxs = usePaidTxs(!isDemo && !loading && claims.some((c) => c.status === 'Paid'));
  if (loading) return <p className="muted">Loading…</p>;
  const p = programs.find((x) => String(x.id) === id);
  if (!p)
    return (
      <p>
        Program {id} not found. <Link to="/programs">Back</Link>
      </p>
    );
  const bundleChecked = isDemo && p.code_hash === DEMO_CODE_BUNDLE.code_hash ? sha256hex(DEMO_CODE_BUNDLE.bundle) === p.code_hash : null;
  const list = claims.filter((c) => c.program_id === p.id).sort((a, b) => Number(BigInt(b.submitted_at) - BigInt(a.submitted_at)));

  return (
    <section>
      <Link to="/programs" className="muted small">
        ← all programs
      </Link>
      <div className="row between">
        <h1>{p.name}</h1>
        {p.open ? <Badge tone="ok">open</Badge> : <Badge>closed</Badge>}
      </div>
      <div className="card">
        <dl className="kv">
          <dt>Target</dt>
          <dd className="mono small">
            {p.repo_url}@{p.commit}
          </dd>
          <dt>Owner</dt>
          <dd className="mono small">{p.owner}</dd>
          <dt>Onchain</dt>
          <dd className="small">
            {isDemo ? (
              <span className="muted">mock program (demo mode), not onchain</span>
            ) : (
              <>
                program #{p.id} in <Ext href={explorerAccount(CONTRACT_ID)}>{CONTRACT_ID}</Ext> · created {fmtDate(p.created_at)}
              </>
            )}
          </dd>
          <dt>Pool</dt>
          <dd>
            {yoctoToNear(p.balance)} Ⓝ available · {yoctoToNear(p.reserved)} Ⓝ reserved
          </dd>
          <dt>Model</dt>
          <dd className="mono small">{p.model_id}</dd>
          <dt>Prompt hash</dt>
          <dd>
            <Hash value={p.system_prompt_hash} />
          </dd>
          <dt>Code hash</dt>
          <dd>
            {p.code_hash ? (
              <>
                <Hash value={p.code_hash} />
                <div className="small">
                  {/^https?:\/\//.test(p.repo_url) ? <Ext href={p.repo_url}>code bundle</Ext> : <span className="mono">{p.repo_url}</span>}
                  <span className="muted">
                    {' '}
                    · repo <code>fixtures/vuln-app</code>, sha256 of <code>bundle.txt</code>. Hunters must judge this exact bundle.
                  </span>
                  {bundleChecked !== null && (
                    <div className="row gap">
                      <StatusIcon status={bundleChecked ? 'pass' : 'fail'} /> bundled <code>bundle.txt</code> hashes to code_hash (checked in your browser)
                    </div>
                  )}
                </div>
              </>
            ) : (
              <span className="muted small">none (v1 program: requests are not bound to the code or the hunter)</span>
            )}
          </dd>
          <dt>Params hash</dt>
          <dd>
            {p.params_hash ? (
              <>
                <Hash value={p.params_hash} />
                <div className="small muted">sha256 of the canonical temperature, max_tokens, response_format and chat_template_kwargs. Other params are disputable.</div>
              </>
            ) : (
              <span className="muted small">none (pre-v3 program: request params are not pinned)</span>
            )}
          </dd>
          <dt>Signers</dt>
          <dd>
            {p.signers ? (
              <>
                {p.signers.map((s) => (
                  <div key={s}>
                    <Hash value={s} head={16} />
                  </div>
                ))}
                <div className="small muted">The program&apos;s own TEE key set. An admin add_signer does not change it.</div>
              </>
            ) : (
              <span className="muted small">global allowlist (pre-v3 program)</span>
            )}
          </dd>
          <dt>Rules</dt>
          <dd className="small">
            dispute window {fmtSecs(p.dispute_secs)} · min confidence {p.min_confidence} · first valid claim per request wins · the request must name the submitting hunter
            {p.bond !== null && (
              <>
                {' '}
                · hunter bond <strong>{yoctoToNear(p.bond)} Ⓝ</strong> (returned when paid, goes to the pool when rejected)
              </>
            )}
            {p.challenge_secs !== null && <> · {fmtSecs(p.challenge_secs)} to answer a decryption challenge</>}
          </dd>
        </dl>
      </div>

      <h2>Claims</h2>
      {list.length === 0 && <p className="muted">No claims yet.</p>}
      <ol className="timeline">
        {list.map((c) => (
          <li key={c.id} className="card claim">
            <div className="row between wrap">
              <div>
                <strong>{c.refused_at_submit ? 'Attempt (not onchain)' : `Claim #${c.id}`}</strong> <span className="muted">by</span>{' '}
                <span className="mono">{c.hunter}</span>
              </div>
              {c.refused_at_submit ? <Badge>refused at submit</Badge> : <Badge tone={statusTone(c.status)}>{c.status}</Badge>}
            </div>
            <div className="small muted">
              submitted {fmtDate(c.submitted_at)}
              {!isDemo && (
                <>
                  {' · '}
                  <Ext href={explorerAccount(CONTRACT_ID)}>contract on nearblocks</Ext> · hunter{' '}
                  <Ext href={explorerAccount(c.hunter)}>{c.hunter}</Ext>
                  {paidTxs[c.id] && (
                    <>
                      {' · '}
                      <Ext href={explorerTx(paidTxs[c.id])}>payout tx {paidTxs[c.id].slice(0, 8)}…</Ext>
                    </>
                  )}
                </>
              )}
            </div>
            <div className="claim-meta">
              <div>
                Verdict: <strong className={`sev sev-${c.verdict.severity}`}>{c.verdict.severity}</strong>
                {c.verdict.cwe && <span className="mono"> {c.verdict.cwe}</span>} · valid={String(c.verdict.valid)} ·{' '}
                <span title="Probability that this verdict is correct">{c.verdict.confidence}% confident in this verdict</span>
              </div>
              <div>
                {payable(c, p.min_confidence) && (c.status === 'Rejected' || c.status === 'PayoutFailed') ? (
                  <span className="muted">
                    Payout: <s>{yoctoToNear(c.payout)} Ⓝ</s> returned to the pool
                  </span>
                ) : payable(c, p.min_confidence) ? (
                  <>
                    Payout: <strong>{yoctoToNear(c.payout)} Ⓝ</strong>
                  </>
                ) : (
                  <span className="muted">Not payable (needs valid, severity ≠ none, confidence ≥ {p.min_confidence})</span>
                )}
                {c.bond !== null && !c.refused_at_submit && (
                  <span className="muted">
                    {' '}
                    · bond {yoctoToNear(c.bond)} Ⓝ{' '}
                    {c.status === 'Paid' ? 'returned' : c.status === 'Rejected' ? 'forfeited to the pool' : c.status === 'PayoutFailed' ? 'back to the pool' : 'held'}
                  </span>
                )}
              </div>
              <ClaimStatus c={c} program={p} />
              {c.synthetic && (
                <div className="muted small">
                  <strong>Synthetic demo claim:</strong> {c.synthetic}
                </div>
              )}
              {c.history && (
                <ol className="history small">
                  {c.history.map((h) => (
                    <li key={h.event}>
                      <span className="muted">{fmtDate(h.at)}</span> {h.event}
                    </li>
                  ))}
                </ol>
              )}
            </div>
            <div className="hashes small">
              <Hash label="req_hash" value={c.req_hash} />
              <Hash label="resp_hash" value={c.resp_hash} />
              <Hash label="signer" value={c.signer} head={14} />
              <Hash label="sig" value={c.signature} />
            </div>
            <VerifyPanel claim={c} program={p} />
          </li>
        ))}
      </ol>
    </section>
  );
}
