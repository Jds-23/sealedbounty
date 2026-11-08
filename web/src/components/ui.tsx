import { useState } from 'react';
import type { CheckStatus } from '../lib/checks';

export function Hash({ value, head = 10, tail = 6, label }: { value: string; head?: number; tail?: number; label?: string }) {
  const [copied, setCopied] = useState(false);
  const short = value.length > head + tail + 1 ? `${value.slice(0, head)}…${value.slice(-tail)}` : value;
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 1200);
    } catch {
      /* clipboard blocked */
    }
  };
  return (
    <span className="hash" title={value}>
      {label && <span className="muted">{label} </span>}
      <code>{short}</code>
      <button className="copy" onClick={copy} aria-label={`Copy ${label ?? 'value'}`}>
        {copied ? 'copied' : 'copy'}
      </button>
    </span>
  );
}

const ICON: Record<CheckStatus, string> = { pass: '✓', fail: '✗', offline: '◷', na: '–' };
const TITLE: Record<CheckStatus, string> = {
  pass: 'Verified in your browser',
  fail: 'Failed',
  offline: 'Verified offline, not re-run here',
  na: 'Not verifiable client-side',
};

export function StatusIcon({ status }: { status: CheckStatus }) {
  return (
    <span className={`icon icon-${status}`} title={TITLE[status]} aria-label={TITLE[status]}>
      {ICON[status]}
    </span>
  );
}

export function Badge({ children, tone = 'neutral' }: { children: React.ReactNode; tone?: 'neutral' | 'ok' | 'warn' | 'bad' | 'info' }) {
  return <span className={`badge badge-${tone}`}>{children}</span>;
}
