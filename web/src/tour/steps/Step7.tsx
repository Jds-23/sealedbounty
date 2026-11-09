// Step 7 — The gauntlet. Each card recomputes claim #N's rejection locally from the claim plus its tx args
// (dispute request_body → auditRequest / shared requestParamsHash; challenge → deadline vs now) and compares it with
// the onchain reject_reason. Live lane: a real front-run on program 2 through the helper.
import { useMemo, useState } from 'react';
import { fmtDate, yoctoToNear } from '../../lib/format';
import type { ActionKey } from '../autoplay';
import { LiveGate, StreamView, useHelperStream } from '../LiveLane';
import { useRestore, useTour, useTourAction } from '../TourContext';
import { claimTxs, recomputeReject, type RejectRecompute } from '../tourData';
import { Exhibit, HeroButton, TxLink } from '../ui';

export const step7 = {
  kicker: 'The gauntlet',
  headline: 'We tried to cheat. Code said no.',
  body: 'Four real attacks against the live contract. Each was rejected onchain, and you can recompute every reason yourself.',
  why: "The rules are enforced by code, not by anyone's goodwill.",
};

const CARDS: { id: number; title: string; line: string }[] = [
  { id: 1, title: 'Params tampered', line: 'The real TEE called a fake report valid/critical once the schema was forced.' },
  { id: 2, title: 'Code mismatch', line: "An invented eval() RCE against code that doesn't exist." },
  { id: 3, title: 'Front-run', line: "Someone copied an honest hunter's signed verdict." },
  { id: 4, title: 'Undecryptable', line: 'Junk ciphertext, and the hunter never proved it.' },
];

export function Step7() {
  return (
    <div className="stack">
      <div className="gauntlet">
        {CARDS.map((c, i) => (
          <GauntletCard key={c.id} {...c} n={i + 1} />
        ))}
      </div>
      <LiveFrontrun />
    </div>
  );
}

function GauntletCard({ id, title, line, n }: { id: number; title: string; line: string; n: number }) {
  const { data, setResult } = useTour();
  const claim = data.claims.find((c) => c.id === id);
  const txs = useMemo(() => (claim ? claimTxs(data.txs, claim) : null), [data.txs, claim]);
  const [r, setR] = useState<RejectRecompute | null>(null);
  const [runId, setRunId] = useState(0);

  const run = () => {
    if (!claim || !txs) return;
    const out = recomputeReject(claim, data.program, txs, Date.now());
    setR(out);
    setRunId((k) => k + 1);
    setResult(`gauntlet-${id}`, out.match && out.computed !== null, `#${id} ${title}: recomputed "${out.computed}"`);
  };
  useTourAction(`gauntlet-${id}` as ActionKey, run);
  useRestore(`gauntlet-${id}`, run);
  if (!claim || !txs) return null;

  return (
    <Exhibit label={`attack ${n} · claim #${id} · ${claim.hunter.split('.')[0]}`} tone={r ? (r.match ? 'ok' : 'bad') : undefined} meta={<span className="badge badge-bad">{claim.status}</span>}>
      <h3 className="g-title">{title}</h3>
      <p className="g-line">{line}</p>
      <HeroButton onClick={run} done={!!r}>
        {r ? 'Run again' : 'Run check'}
      </HeroButton>
      {r && (
        <div className="g-res" key={runId}>
          <div className="g-cmp">
            <span>
              computed <code>{r.computed ?? 'none'}</code>
            </span>
            <span className={r.match ? 'okc' : 'bad'}>{r.match ? '✓ matches' : '✗ differs'}</span>
            <span>
              onchain <code>{r.onchain ?? 'none'}</code>
            </span>
          </div>
          <ul className="g-detail">
            {r.detail.map((d) => (
              <li key={d}>{d}</li>
            ))}
            {id === 3 && <li>on hunter mismatch the contract frees req_hash, so the real hunter can still resubmit the same verdict</li>}
            {id === 4 && claim.bond && <li>{yoctoToNear(claim.bond, 2)} NEAR bond forfeited to the pool</li>}
          </ul>
          <div className="g-tx">
            <TxLink hash={r.tx} label={r.via === 'dispute' ? 'dispute' : r.via === 'challenge' ? 'finalize' : 'tx'} />
            {id === 4 && txs.flag && <TxLink hash={txs.flag.hash} label="flag" />}
            {id === 4 && claim.challenge_deadline && <span className="mono small muted">deadline {fmtDate(claim.challenge_deadline)}</span>}
          </div>
        </div>
      )}
    </Exhibit>
  );
}

const FR_LABELS: Record<string, string> = {
  setup: 'setup',
  judge: 'fresh hunter-bound judgement (TEE)',
  submit_claim: 'submit_claim from frontrun.…',
  dispute: 'dispute (owner) with the request body',
  resubmit: 'real hunter resubmits',
};

function LiveFrontrun() {
  const { liveJudgement, setResult } = useTour();
  const s = useHelperStream();
  const run = async () => {
    try {
      const out = await s.start('/frontrun', liveJudgement ? { judgement: liveJudgement.raw } : {});
      setResult('live-frontrun', /hunter mismatch/i.test(out ?? ''), `Live front-run on program 2 → ${out}`);
    } catch (e) {
      setResult('live-frontrun', false, 'Live front-run failed');
      throw e;
    }
  };
  useTourAction('live-frontrun', run);
  return (
    <LiveGate title="Front-run live">
      <div className="lane-row">
        <HeroButton kind="live" onClick={() => run().catch(() => {})} busy={s.running} done={!!s.outcome}>
          {s.running ? 'Front-running on testnet…' : 'Front-run live'}
        </HeroButton>
        <span className="muted small">{liveJudgement ? 'copies the verdict judged in step 4' : 'the helper takes a fresh judgement first'}</span>
      </div>
      <StreamView st={s} labels={FR_LABELS} />
    </LiveGate>
  );
}
