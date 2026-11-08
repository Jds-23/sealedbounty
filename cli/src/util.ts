import { createHash } from 'node:crypto';
import type { CheckRow } from './types.js';

export const sha256hex = (data: string | Uint8Array) =>
  createHash('sha256').update(typeof data === 'string' ? Buffer.from(data, 'utf8') : data).digest('hex');

export const strip0x = (h: string) => (/^0x/i.test(h) ? h.slice(2) : h);

const YOCTO_PER_NEAR = 10n ** 24n;

/** Exact decimal NEAR string/number -> yoctoNEAR bigint. */
export function nearToYocto(near: string | number): bigint {
  const s = String(near).trim();
  if (!/^\d+(\.\d+)?$/.test(s)) throw new Error(`invalid NEAR amount: ${near}`);
  const [whole, frac = ''] = s.split('.');
  if (frac.length > 24) throw new Error(`too many decimals: ${near}`);
  return BigInt(whole) * YOCTO_PER_NEAR + BigInt(frac.padEnd(24, '0') || '0');
}

/** yoctoNEAR -> human NEAR string (trimmed, max 5 decimals). */
export function formatNear(yocto: string | bigint, decimals = 5): string {
  const y = BigInt(yocto);
  const whole = y / YOCTO_PER_NEAR;
  const frac = (y % YOCTO_PER_NEAR).toString().padStart(24, '0').slice(0, decimals).replace(/0+$/, '');
  return `${whole}${frac ? '.' + frac : ''} NEAR`;
}

/** Nanosecond U64 string -> ISO time. */
export const nsToIso = (ns: string | number) => new Date(Number(BigInt(ns) / 1_000_000n)).toISOString();

export function printChecks(title: string, rows: CheckRow[]): boolean {
  console.log(`\n${title}`);
  const w = Math.max(...rows.map((r) => r[0].length));
  for (const [name, ok, detail] of rows) console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${name.padEnd(w)}  ${detail}`);
  const allOk = rows.every((r) => r[1]);
  console.log(allOk ? '  => ALL PASS' : `  => ${rows.filter((r) => !r[1]).length} FAILED`);
  return allOk;
}

export function printKv(rows: [string, unknown][]): void {
  const w = Math.max(...rows.map((r) => r[0].length));
  for (const [k, v] of rows) console.log(`  ${k.padEnd(w)}  ${v}`);
}

export function printTable(headers: string[], rows: string[][]): void {
  const widths = headers.map((h, i) => Math.max(h.length, ...rows.map((r) => (r[i] ?? '').length)));
  const line = (cells: string[]) => cells.map((c, i) => (c ?? '').padEnd(widths[i])).join('  ');
  console.log(line(headers));
  console.log(widths.map((w) => '-'.repeat(w)).join('  '));
  for (const r of rows) console.log(line(r));
}

export const errMsg = (e: unknown) => (e instanceof Error ? e.message : String(e));

export const short = (s: string, n = 12) => (s.length > n * 2 + 1 ? `${s.slice(0, n)}…${s.slice(-6)}` : s);
