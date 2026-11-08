// Code bundle I/O (docs/INTERFACE.md v2). The bundle format itself lives in shared/judge.mjs.
import { readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { isAbsolute, join, relative, resolve, sep } from 'node:path';
import { shared } from './shared.js';

/** Files that buildBundleFromFiles writes; never bundled themselves. */
export const BUNDLE_OUTPUTS = ['bundle.txt', 'bundle.sha256'];

const hasGlob = (s: string) => /[*?{]/.test(s);

/** Minimal glob -> RegExp over `/`-separated relative paths: `**`, `*`, `?`, `{a,b}`. */
export function globToRegExp(glob: string): RegExp {
  let re = '';
  for (let i = 0; i < glob.length; i++) {
    const ch = glob[i];
    if (ch === '*' && glob[i + 1] === '*') {
      i++;
      if (glob[i + 1] === '/') {
        i++;
        re += '(?:.*/)?';
      } else re += '.*';
    } else if (ch === '*') re += '[^/]*';
    else if (ch === '?') re += '[^/]';
    else if (ch === '{') {
      const end = glob.indexOf('}', i);
      if (end < 0) throw new Error(`bad glob ${glob}`);
      re += '(?:' + glob.slice(i + 1, end).split(',').map((a) => a.replace(/[.+^$()|[\]\\]/g, '\\$&')).join('|') + ')';
      i = end;
    } else re += ch.replace(/[.+^$()|[\]\\]/g, '\\$&');
  }
  return new RegExp(`^${re}$`);
}

function globFiles(pattern: string, absRoot: string): string[] {
  const re = globToRegExp(pattern.replace(/^(\.\/)+/, ''));
  return (readdirSync(absRoot, { recursive: true }) as string[])
    .map((p) => p.split(sep).join('/'))
    .filter((p) => !/(^|\/)(node_modules|\.git)(\/|$)/.test(p) && re.test(p))
    .map((p) => resolve(absRoot, p));
}

/**
 * Resolve paths/globs under `root` to bundle entries. Paths in the bundle are relative to `root`
 * with forward slashes (e.g. `src/server.ts`), so pick `root` = the repo directory the program covers.
 */
export function collectCodeFiles(patterns: string[], root: string): { path: string; content: string }[] {
  const absRoot = resolve(root);
  const found = new Set<string>();
  for (const p of patterns) {
    const lit = resolve(absRoot, p);
    const isDir = !hasGlob(p) && !!statSync(lit, { throwIfNoEntry: false })?.isDirectory();
    const matches = hasGlob(p) || isDir ? globFiles(isDir ? `${relative(absRoot, lit).split(sep).join('/') || '.'}/**/*` : p, absRoot) : [lit];
    if (!matches.length) throw new Error(`--code-files: ${p} matched nothing under ${absRoot}`);
    for (const m of matches) {
      const st = statSync(m, { throwIfNoEntry: false });
      if (!st) throw new Error(`--code-files: ${m} does not exist`);
      if (st.isFile()) found.add(m);
    }
  }
  const files = [...found]
    .map((abs) => {
      const rel = relative(absRoot, abs);
      if (rel.startsWith('..') || isAbsolute(rel)) throw new Error(`--code-files: ${abs} is outside --code-root ${absRoot}`);
      return { abs, path: rel.split(sep).join('/') };
    })
    .filter((f) => !BUNDLE_OUTPUTS.includes(f.path));
  if (!files.length) throw new Error('--code-files: no files');
  return files.map((f) => ({ path: f.path, content: readFileSync(f.abs, 'utf8') }));
}

/** Build the bundle from files and write `<root>/bundle.txt` + `<root>/bundle.sha256` (no trailing newline). */
export function buildBundleFromFiles(patterns: string[], root: string) {
  const files = collectCodeFiles(patterns, root);
  const bundle = shared.buildCodeBundle(files);
  const hash = shared.codeHash(bundle);
  const outPath = join(resolve(root), 'bundle.txt');
  writeFileSync(outPath, bundle);
  writeFileSync(join(resolve(root), 'bundle.sha256'), hash);
  return { bundle, hash, outPath, paths: files.map((f) => f.path).sort() };
}

/** Read a published bundle file byte for byte (utf8). */
export function readBundle(file: string): string {
  return readFileSync(file, 'utf8');
}
