import { useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { useData } from '../data';
import { countdown, fmtDate, fmtSecs, nsToMs, yoctoToNear } from '../lib/format';
import { CONTRACT_ID, explorerAccount, explorerTx, findPaidTxs } from '../lib/near';
import type { Claim } from '../lib/types';
import { Badge, Hash } from '../components/ui';
import { VerifyPanel } from '../components/VerifyPanel';

function Countdown({ until }: { until: string }) {
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);
  return <span className="mono">{countdown(nsToMs(until) - now)}</span>;
}

const payable = (c: Claim, min: number) => c.verdict.valid && c.verdict.severity !== 'none' && c.verdict.confidence >= min;

const tone = (s: Claim['status']) => (s === 'Paid' ? 'ok' : s === 'Rejected' ? 'bad' : 'warn');

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

export function ProgramDetail() {
  const { id } = useParams();
  const { programs, claims, loading, isDemo } = useData();
  const paidTxs = usePaidTxs(!isDemo && !loading && claims.some((c) => c.status === 'Paid'));
  if (loading) return <p className="muted">Loading…</p>;
  const p = programs.find((x) => String(x.id) === id);
  if (!p)
    return (
      <p>
        Program {id} not found. <Link to="/">Back</Link>
      </p>
    );
  const list = claims.filter((c) => c.program_id === p.id).sort((a, b) => Number(BigInt(b.submitted_at) - BigInt(a.submitted_at)));

  return (
    <section>
      <Link to="/" className="muted small">
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
          <dt>Rules</dt>
          <dd className="small">
            dispute window {fmtSecs(p.dispute_secs)} · min confidence {p.min_confidence} · first valid claim per request wins
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
                <strong>Claim #{c.id}</strong> <span className="muted">by</span> <span className="mono">{c.hunter}</span>
              </div>
              <Badge tone={tone(c.status)}>{c.status}</Badge>
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
                {payable(c, p.min_confidence) ? (
                  <>
                    Payout: <strong>{yoctoToNear(c.payout)} Ⓝ</strong>
                  </>
                ) : (
                  <span className="muted">Not payable (needs valid, severity ≠ none, confidence ≥ {p.min_confidence})</span>
                )}
              </div>
              {c.status === 'Pending' && (
                <div className="pending">
                  <Countdown until={c.finalize_after} />
                </div>
              )}
              {c.status === 'Rejected' && <div className="rejected">Rejected: {c.reject_reason ?? 'no reason given'}</div>}
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
