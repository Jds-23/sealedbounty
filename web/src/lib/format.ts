export function yoctoToNear(y: string, digits = 2): string {
  try {
    const v = BigInt(y);
    const whole = v / 10n ** 24n;
    const frac = (v % 10n ** 24n).toString().padStart(24, '0').slice(0, digits);
    return `${whole}${digits ? '.' + frac : ''}`;
  } catch {
    return y;
  }
}

export const nsToMs = (ns: string) => Number(BigInt(ns) / 1_000_000n);
export const fmtDate = (ns: string) => new Date(nsToMs(ns)).toLocaleString();

/** `dispute`: the owner's dispute window (finalize_after); `challenge`: the hunter's prove_ciphertext window (v3 #2). */
export function countdown(msLeft: number, kind: 'dispute' | 'challenge' = 'dispute'): string {
  if (msLeft <= 0)
    return kind === 'dispute' ? 'dispute window closed — anyone can finalize' : 'challenge expired — finalize rejects it as "undecryptable report"';
  const s = Math.floor(msLeft / 1000);
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const left = `${h}h ${String(m).padStart(2, '0')}m ${String(s % 60).padStart(2, '0')}s left`;
  return kind === 'dispute' ? `${left} to dispute` : `${left} for the hunter to prove_ciphertext`;
}

/** Human duration for contract `*_secs` fields (live program uses 90 s; demo uses 24 h). */
export function fmtSecs(secs: number): string {
  if (secs < 120) return `${secs}s`;
  if (secs < 7200) return `${Math.round(secs / 60)}m`;
  if (secs < 172800) return `${+(secs / 3600).toFixed(1)}h`;
  return `${+(secs / 86400).toFixed(1)}d`;
}
