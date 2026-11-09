// Chain writes = the existing cli, run as `pnpm --dir <repo>/cli sb …`. All signing, tx sending,
// local pre-checks, owner-key loading (~/.sealedbounty/owner-<contract>-<id>.json), hunter
// ephemeral-secret saving (~/.sealedbounty/hunter-<contract>-<claim>.json) and ~/.near-credentials
// handling stay in cli/src. The helper only builds argv and parses the printed tx link / claim id.
import { spawn } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const TX_RE = /\/txns\/([1-9A-HJ-NP-Za-km-z]{32,64})/g;

export function parseSbOutput(out) {
  const txs = [...out.matchAll(TX_RE)].map((m) => m[1]);
  const claim = /^claim_id:\s*(\d+)\s*$/m.exec(out);
  const errs = [...out.matchAll(/^\s*(?:error|FAILED):\s*(.+?)\s*$/gm)].map((m) => m[1]);
  return { tx: txs.at(-1) ?? null, claimId: claim ? Number(claim[1]) : null, error: errs.at(-1) ?? null };
}

export function sbCommand(config, args) {
  return { cmd: 'pnpm', args: ['-s', '--dir', join(config.repoRoot, 'cli'), 'sb', '--contract', config.contractId, ...args] };
}

/**
 * The child loads the repo-root .env itself (cli/src/config.ts). NEARAI_API_KEY is pre-set to ''
 * so dotenv leaves it empty: no helper-driven command needs it (submit runs with --fixture).
 */
export function childEnv(env, config) {
  return { ...env, NEARAI_API_KEY: '', ESCROW_CONTRACT_ID: config.contractId, FORCE_COLOR: '0' };
}

export function defaultRunSb(config, { timeoutMs = 180_000 } = {}) {
  return (args) =>
    new Promise((resolve, reject) => {
      const { cmd, args: argv } = sbCommand(config, args);
      const child = spawn(cmd, argv, { env: childEnv(process.env, config), stdio: ['ignore', 'pipe', 'pipe'] });
      let stdout = '';
      let stderr = '';
      child.stdout.on('data', (d) => (stdout += d));
      child.stderr.on('data', (d) => (stderr += d));
      const t = setTimeout(() => child.kill('SIGTERM'), timeoutMs);
      child.on('error', (e) => {
        clearTimeout(t);
        reject(new Error(`could not run pnpm sb: ${e.message}`));
      });
      child.on('close', (code) => {
        clearTimeout(t);
        resolve({ code: code ?? 1, stdout, stderr });
      });
    });
}

const tail = (s, n = 3) =>
  s
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean)
    .slice(-n)
    .join(' | ');

/** @param {{config: {repoRoot: string, contractId: string, programId: number}, runSb?: (args: string[]) => Promise<{code: number, stdout: string, stderr: string}>}} o */
export function makeCliDeps({ config, runSb = defaultRunSb(config) }) {
  async function run(args) {
    const { code, stdout, stderr } = await runSb(args);
    const out = `${stdout}\n${stderr}`;
    const p = parseSbOutput(out);
    if (code !== 0) throw Object.assign(new Error(`sb ${args[0]} failed: ${p.error ?? (tail(out) || `exit ${code}`)}`), { tx: p.tx ?? undefined });
    if (!p.tx) throw new Error(`sb ${args[0]}: no transaction hash in its output (${tail(out) || 'empty'})`);
    return p;
  }
  const claimCmd = (cmd, extra = []) => async ({ claimId, account }) => {
    const p = await run([cmd, '--claim', String(claimId), '--account', account, ...extra]);
    return { tx: p.tx };
  };

  return {
    async submit({ record, account }) {
      const dir = await mkdtemp(join(tmpdir(), 'sb-demo-helper-'));
      const file = join(dir, 'judgement.json');
      try {
        await writeFile(file, JSON.stringify(record, null, 2) + '\n', { mode: 0o600 });
        const p = await run(['submit', '--program', String(config.programId), '--fixture', file, '--account', account]);
        if (p.claimId === null) throw Object.assign(new Error('sb submit: no claim_id in its output'), { tx: p.tx });
        return { tx: p.tx, claimId: p.claimId };
      } finally {
        await rm(dir, { recursive: true, force: true });
      }
    },
    // --force: the honest ciphertext DOES decrypt, so the cli's "[owner] ciphertext really is undecryptable"
    // pre-check fails by design here; the demo shows the owner stalling and the hunter proving it.
    flagUndecryptable: claimCmd('flag-undecryptable', ['--force']),
    proveCiphertext: claimCmd('prove-ciphertext'),
    finalize: claimCmd('finalize'),
    dispute: claimCmd('dispute'),
  };
}
