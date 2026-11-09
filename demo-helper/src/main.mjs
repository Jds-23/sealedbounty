#!/usr/bin/env node
// pnpm --dir demo-helper start  ->  http://127.0.0.1:8787 (loopback only)
import { loadConfig } from './env.mjs';
import { makeLiveDeps } from './live.mjs';
import { createHelperServer } from './server.mjs';

const config = loadConfig();
const server = createHelperServer({ config, deps: makeLiveDeps(config) });

server.listen(config.port, '127.0.0.1', () => {
  console.error(`demo-helper on http://127.0.0.1:${config.port} (CORS: http://localhost:5173)`);
  console.error(`  contract ${config.contractId}, live program ${config.programId ?? 'NOT SET (DEMO_LIVE_PROGRAM_ID)'}`);
  console.error(`  hunter ${config.hunter}, front-runner ${config.frontrun}; NEAR AI key ${config.apiKey ? 'loaded' : 'MISSING (POST /judge will fail)'}`);
});
