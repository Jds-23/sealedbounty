// The real (network) deps: RPC views, the NEAR AI TEE judge (shared/judge.mjs) and the cli writes.
// Not exercised by the tests (they inject fakes); see README "Live smoke test".
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { makeCliDeps } from './cli.mjs';

/** Read-only escrow view over JSON-RPC (no keys involved). */
export function makeViews({ rpcUrl, contractId, fetchImpl = fetch, timeoutMs = 8000 }) {
  async function view(method, args) {
    const res = await fetchImpl(rpcUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      signal: AbortSignal.timeout(timeoutMs),
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 'demo-helper',
        method: 'query',
        params: { request_type: 'call_function', finality: 'final', account_id: contractId, method_name: method, args_base64: Buffer.from(JSON.stringify(args)).toString('base64') },
      }),
    });
    const j = await res.json();
    if (j.error || j.result?.error) throw new Error(`rpc ${method}: ${JSON.stringify(j.error ?? j.result.error).slice(0, 300)}`);
    return JSON.parse(Buffer.from(j.result.result).toString('utf8'));
  }
  return {
    getProgram: (id) => view('get_program', { id }),
    getClaim: (id) => view('get_claim', { id }),
  };
}

export function makeLiveDeps(config) {
  const views = makeViews(config);
  const bundlePath = join(config.repoRoot, 'fixtures', 'vuln-app', 'bundle.txt');
  let shared;
  const loadShared = async () => (shared ??= await import(pathToFileURL(join(config.repoRoot, 'shared', 'judge.mjs')).href));

  return {
    ...views,
    ...makeCliDeps({ config }),
    now: () => Date.now(),
    sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
    defaultExploit: () => readFile(join(config.repoRoot, 'fixtures', 'exploits', 'sqli.md'), 'utf8'),
    /**
     * shared judge() against fixtures/vuln-app/bundle.txt, bound to the program-2 target read from the
     * chain (same repo_url/commit/code bundle as program 1) and HUNTER = the demo hunter.
     */
    async judge({ exploitMarkdown }) {
      if (!config.apiKey) throw new Error('NEARAI_API_KEY is not set in .env');
      const api = await loadShared();
      const program = await views.getProgram(config.programId);
      if (!program) throw new Error(`program ${config.programId} not found on ${config.contractId}`);
      const codeBundle = await readFile(bundlePath, 'utf8');
      if (api.codeHash(codeBundle) !== program.code_hash) throw new Error(`fixtures/vuln-app/bundle.txt does not hash to program ${config.programId}'s code_hash`);
      return api.judge({
        apiKey: config.apiKey,
        baseUrl: config.baseUrl,
        model: program.model_id,
        signingAlgo: config.signingAlgo,
        repoUrl: program.repo_url,
        commit: program.commit,
        hunter: config.hunter,
        codeBundle,
        report: exploitMarkdown,
      });
    },
  };
}
