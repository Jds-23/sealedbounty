import { useEffect, useState, type ReactNode } from 'react';
import { Hash, StatusIcon } from '../components/ui';
import type { CheckStatus } from '../lib/checks';
import { explorerTx } from '../lib/near';

export { Hash, StatusIcon };

/** One proof block: a mono caption ("EXHIBIT"), optional right-side meta, then content. */
export function Exhibit({ label, meta, children, tone }: { label: string; meta?: ReactNode; children: ReactNode; tone?: 'ok' | 'bad' | 'live' }) {
  return (
    <section className={`exhibit ${tone ? `exhibit-${tone}` : ''}`}>
      <header className="exhibit-h">
        <span className="exhibit-l">{label}</span>
        {meta && <span className="exhibit-m">{meta}</span>}
      </header>
      {children}
    </section>
  );
}

export function TxLink({ hash, label }: { hash: string | null | undefined; label?: string }) {
  if (!hash) return <span className="muted mono">no tx</span>;
  return (
    <a className="txlink" href={explorerTx(hash)} target="_blank" rel="noreferrer noopener" title={hash}>
      {label && <span className="txlink-l">{label}</span>}
      <code>{hash.slice(0, 8)}…</code>
      <span aria-hidden>↗</span>
    </a>
  );
}

export interface CheckItem {
  label: string;
  status: CheckStatus;
  detail?: string;
}

/** Checks that tick in sequence (~120 ms stagger via CSS; no motion under prefers-reduced-motion). Re-keyed per run. */
export function CheckList({ items, runId }: { items: CheckItem[]; runId: number }) {
  return (
    <ul className="tchecks" key={runId}>
      {items.map((x, i) => (
        <li key={x.label} style={{ ['--i' as string]: i }} className={`tcheck tcheck-${x.status}`}>
          <StatusIcon status={x.status} />
          <div className="tcheck-b">
            <div className="tcheck-t">{x.label}</div>
            {x.detail && <div className="tcheck-d">{x.detail}</div>}
          </div>
        </li>
      ))}
    </ul>
  );
}

export function HeroButton({ onClick, busy, done, children, kind = 'primary', disabled }: { onClick: () => void; busy?: boolean; done?: boolean; children: ReactNode; kind?: 'primary' | 'ghost' | 'live'; disabled?: boolean }) {
  return (
    <button className={`hero hero-${kind} ${done ? 'hero-done' : ''}`} onClick={onClick} disabled={busy || disabled} aria-busy={busy}>
      <span className="hero-g" aria-hidden>
        {busy ? '◌' : done ? '↻' : '▸'}
      </span>
      {children}
    </button>
  );
}

export function ErrLine({ children }: { children: ReactNode }) {
  return (
    <div className="errline" role="alert">
      {children}
    </div>
  );
}

/** Seconds since `since` (ms epoch), ticking. */
export function useNow(intervalMs = 1000) {
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), intervalMs);
    return () => clearInterval(t);
  }, [intervalMs]);
  return now;
}

export function KV({ rows }: { rows: [ReactNode, ReactNode][] }) {
  return (
    <dl className="tkv">
      {rows.map(([k, v], i) => (
        <div key={i} className="tkv-r">
          <dt>{k}</dt>
          <dd>{v}</dd>
        </div>
      ))}
    </dl>
  );
}
