// Demo constants shared by record-demo.mjs and demo-offline.mjs (browser-safe, no node:* imports).
import { buildCodeBundle } from './judge.mjs';

/** Demo program target (docs/INTERFACE.md v2). The code lives in fixtures/vuln-app. */
export const DEMO_TARGET = Object.freeze({
  repoUrl: 'https://github.com/sealedbounty/sealedbounty/tree/main/fixtures/vuln-app',
  commit: 'demo-commit-0001',
});

/** The hunter account bound into every demo request. */
export const DEMO_HUNTER = 'hunter.baldingsucks7993.testnet';

/** Front-runner used in the offline simulation (copies a pending claim's body). */
export const DEMO_FRONTRUNNER = 'frontrunner.testnet';

// Adversarial fixture: the hunter does NOT use the program's bundle and instead invents code with
// an eval() RCE endpoint, plus a matching report. The TEE judges what it is given, so it may well
// say valid; the contract's dispute rejects it with "code mismatch" (sha256(code) != code_hash).
const FAKE_SERVER_TS = `import express from 'express';
import { Pool } from 'pg';

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const app = express();
app.use(express.json());

app.get('/health', (_req, res) => {
  res.json({ ok: true, uptime: process.uptime() });
});

// Quick calculator used by the support dashboard.
app.get('/calc', (req, res) => {
  const expr = String(req.query.expr ?? '0');
  res.json({ result: eval(expr) });
});

app.listen(Number(process.env.PORT ?? 3000));
`;

/** Invented code bundle (NOT the program's bundle.txt). */
export const FAKE_CODE_BUNDLE = buildCodeBundle([{ path: 'src/server.ts', content: FAKE_SERVER_TS }]);

/** Report that matches the invented code. */
export const FAKE_CODE_REPORT = `# Remote code execution via eval() in GET /calc

**Endpoint:** \`GET /calc?expr=\` (no authentication required)

## Summary
The \`expr\` query parameter is passed directly to \`eval()\` in the /calc handler. There is no
authentication, validation or sandboxing.

## Reproduction
1. Send \`GET /calc?expr=require('child_process').execSync('id').toString()\` (URL-encoded).
2. The response contains the output of \`id\` run as the server process.

## Impact
Any unauthenticated attacker can execute arbitrary commands on the server, read DATABASE_URL and
take over the database.

## Fix
Remove eval(); parse arithmetic with a safe expression parser.`;
