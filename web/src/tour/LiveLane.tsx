// "Do it live" lane (steps 4, 6, 7): only rendered when GET localhost:8787/health answered ok within 1 s.
// Failures show inline in red mono; the recorded program-1 result above stays visible.
import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react';
import { getClaim } from '../lib/near';
import { countdown, nsToMs } from '../lib/format';
import type { Claim } from '../lib/types';
import { streamHelper, type HelperEvent } from './helper';
import { useTour } from './TourContext';
import { TOUR_RPC } from './tourData';
import { ErrLine, TxLink, useNow } from './ui';

export function LiveGate({ children, title }: { children: ReactNode; title: string }) {
  const { helper } = useTour();
  if (!helper) return null;
  if (!helper.ok)
    return (
      <div className="lane lane-off">
        <span className="lane-tag">● helper</span> demo-helper is running but not configured
        {helper.reason ? <span className="mono small"> ({helper.reason})</span> : null}. Set <code>DEMO_LIVE_PROGRAM_ID</code> and restart it to enable “{title}”.
      </div>
    );
  return (
    <section className="lane">
      <header className="lane-h">
        <span className="lane-tag">● do it live</span>
        <span className="lane-t">{title}</span>
        <span className="lane-p">program {helper.programId ?? '?'} · signed by the local helper</span>
      </header>
      {children}
    </section>
  );
}

export interface StreamState {
  events: HelperEvent[];
  running: boolean;
  error: string | null;
  outcome: string | null;
  claimId: number | null;
}

const EMPTY: StreamState = { events: [], running: false, error: null, outcome: null, claimId: null };

/** Runs one SSE helper action; resolves when it ends (rejects on error, after recording it). */
export function useHelperStream() {
  const [st, setSt] = useState<StreamState>(EMPTY);
  const busy = useRef(false);
  const start = useCallback(async (path: Parameters<typeof streamHelper>[0], body: unknown) => {
    if (busy.current) return;
    busy.current = true;
    setSt({ ...EMPTY, running: true });
    try {
      const end = await streamHelper(path, body, (e) =>
        setSt((s) => ({ ...s, events: [...s.events, e], claimId: Number.isInteger(e.claimId) ? (e.claimId as number) : s.claimId })),
      );
      const outcome = typeof end.outcome === 'string' ? end.outcome : JSON.stringify(end.outcome ?? 'done');
      setSt((s) => ({ ...s, running: false, outcome }));
      return outcome;
    } catch (e) {
      const msg = (e as Error).message;
      setSt((s) => ({ ...s, running: false, error: msg }));
      throw e;
    } finally {
      busy.current = false;
    }
  }, []);
  return { ...st, start };
}

/** Latest event per step, in first-seen order. */
function byStep(events: HelperEvent[]) {
  const order: string[] = [];
  const last = new Map<string, HelperEvent & { firstAt: number }>();
  events.forEach((e, i) => {
    if (!last.has(e.step)) order.push(e.step);
    const prev = last.get(e.step);
    last.set(e.step, { ...prev, ...e, tx: e.tx ?? prev?.tx, firstAt: prev?.firstAt ?? i });
  });
  return order.map((k) => last.get(k)!);
}

const STATUS_G: Record<string, string> = { pending: '◌', done: '✓', error: '✗' };

export function StreamView({ st, labels }: { st: StreamState; labels: Record<string, string> }) {
  const rows = byStep(st.events);
  const claim = useLiveClaim(st.claimId, st.running);
  const now = useNow(500);
  if (!st.running && !st.events.length && !st.error && !st.outcome) return null;
  return (
    <div className="stream">
      <ol className="stream-l">
        {rows.map((r) => (
          <li key={r.step} className={`stream-r stream-${r.status ?? 'pending'}`}>
            <span className="stream-g" aria-hidden>
              {STATUS_G[r.status ?? 'pending'] ?? '·'}
            </span>
            <span className="stream-s">{labels[r.step] ?? r.step}</span>
            <span className="stream-x">
              {r.step === 'wait' && r.status === 'pending' && typeof r.remaining === 'number'
                ? countdown(r.remaining * 1000)
                : r.message
                  ? <span className={r.status === 'error' ? 'bad mono' : 'muted'}>{r.message}</span>
                  : null}
            </span>
            {r.tx && <TxLink hash={r.tx} />}
          </li>
        ))}
        {st.running && !rows.some((r) => r.status === 'pending') && (
          <li className="stream-r stream-pending">
            <span className="stream-g">◌</span>
            <span className="stream-s muted">waiting for the helper…</span>
          </li>
        )}
      </ol>
      {claim && (
        <div className="stream-claim mono small">
          claim #{claim.id} onchain: <strong>{claim.status}</strong>
          {claim.reject_reason ? ` "${claim.reject_reason}"` : ''}
          {claim.status === 'Pending' && ` · ${countdown(nsToMs(claim.finalize_after) - now)}`}
          {claim.status === 'Challenged' && claim.challenge_deadline && ` · ${countdown(nsToMs(claim.challenge_deadline) - now, 'challenge')}`}
        </div>
      )}
      {st.outcome && <div className={`stream-out ${/reject/i.test(st.outcome) ? 'stream-out-bad' : ''}`}>outcome: {st.outcome}</div>}
      {st.error && <ErrLine>{st.error}</ErrLine>}
    </div>
  );
}

/** Polls get_claim (RPC only, no snapshot: program 2 is live-only) while a run is going, plus once after. */
function useLiveClaim(id: number | null, running: boolean) {
  const [c, setC] = useState<Claim | null>(null);
  useEffect(() => {
    if (id === null) return setC(null);
    let stop = false;
    const tick = () =>
      getClaim(id, TOUR_RPC)
        .then((x) => !stop && setC(x))
        .catch(() => {});
    tick();
    const t = running ? setInterval(tick, 3000) : null;
    return () => {
      stop = true;
      if (t) clearInterval(t);
    };
  }, [id, running]);
  return c;
}
