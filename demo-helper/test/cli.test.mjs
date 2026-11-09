import assert from 'node:assert/strict';
import { existsSync, readFileSync, statSync } from 'node:fs';
import { describe, it } from 'node:test';
import { childEnv, makeCliDeps, parseSbOutput, sbCommand } from '../src/cli.mjs';
import { toJudgeRecord } from '../src/validate.mjs';
import { FAKE_API_KEY, makeJudgement } from './helpers.mjs';

const HUNTER = 'hunter.baldingsucks7993.testnet';
const OWNER = 'baldingsucks7993.testnet';
const TX = '9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin';
const config = { repoRoot: '/repo', contractId: 'sealedbounty-v3.testnet', programId: 2 };

const SUBMIT_OK = `Local verification\n  => ALL PASS\nephemeral secret saved to /h/.sealedbounty/hunter-pending-x.json (chmod 600) before sending

-> ${HUNTER} calls sealedbounty-v3.testnet.submit_claim  gas=100Tgas deposit=0.08 NEAR
   tx: https://testnet.nearblocks.io/txns/${TX}
   log: EVENT_JSON:{"event":"claim_submitted"}

claim_id: 12
ephemeral secret saved to /h/.sealedbounty/hunter-sealedbounty-v3.testnet-12.json (chmod 600).`;

const PANIC = `-> ${OWNER} calls sealedbounty-v3.testnet.dispute  gas=100Tgas deposit=0 NEAR
   tx: https://testnet.nearblocks.io/txns/${TX}
   FAILED: Smart contract panicked: dispute window closed`;

describe('parseSbOutput', () => {
  it('extracts the tx hash and claim id', () => {
    assert.deepEqual(parseSbOutput(SUBMIT_OK), { tx: TX, claimId: 12, error: null, fails: [] });
  });
  it('extracts the onchain panic', () => {
    assert.deepEqual(parseSbOutput(PANIC), { tx: TX, claimId: null, error: 'Smart contract panicked: dispute window closed', fails: [] });
  });
  it('extracts a CLI-level refusal (no tx)', () => {
    assert.deepEqual(parseSbOutput('foo\n\nerror: preconditions failed; not sending (use --force)\n'), {
      tx: null,
      claimId: null,
      error: 'preconditions failed; not sending (use --force)',
      fails: [],
    });
  });
});

describe('sbCommand / childEnv', () => {
  it('runs the cli through `pnpm --dir <repo>/cli sb --contract <id> …`', () => {
    const { cmd, args } = sbCommand(config, ['finalize', '--claim', '3']);
    assert.equal(cmd, 'pnpm');
    assert.deepEqual(args, ['-s', '--dir', '/repo/cli', 'sb', '--contract', 'sealedbounty-v3.testnet', 'finalize', '--claim', '3']);
  });
  it('never hands the NEAR AI key to the child process', () => {
    const e = childEnv({ PATH: '/bin', NEARAI_API_KEY: FAKE_API_KEY, HOME: '/h' }, config);
    assert.equal(e.NEARAI_API_KEY, '');
    assert.equal(e.PATH, '/bin');
    assert.equal(e.ESCROW_CONTRACT_ID, 'sealedbounty-v3.testnet');
  });
});

describe('makeCliDeps (each write = one `sb` command; signing stays in cli/)', () => {
  const record = toJudgeRecord(makeJudgement());
  const fake = (stdout, code = 0) => {
    const runs = [];
    const runSb = async (args) => {
      const i = args.indexOf('--fixture');
      runs.push({ args, fixture: i >= 0 ? { path: args[i + 1], body: readFileSync(args[i + 1], 'utf8'), mode: statSync(args[i + 1]).mode & 0o777 } : null });
      return { code, stdout, stderr: '' };
    };
    return { runs, deps: makeCliDeps({ config, runSb }) };
  };

  it('submit writes the record to a private temp fixture, passes --account, cleans up', async () => {
    const { runs, deps } = fake(SUBMIT_OK);
    assert.deepEqual(await deps.submit({ record, account: HUNTER }), { tx: TX, claimId: 12 });
    const { args, fixture } = runs[0];
    assert.deepEqual(args, ['submit', '--program', '2', '--fixture', fixture.path, '--account', HUNTER]);
    assert.deepEqual(JSON.parse(fixture.body), record);
    assert.equal(fixture.mode, 0o600);
    assert.equal(existsSync(fixture.path), false, 'temp fixture removed');
  });

  it('flag (owner, --force: the honest ciphertext does decrypt), prove, finalize, dispute', async () => {
    const { runs, deps } = fake(`   tx: https://testnet.nearblocks.io/txns/${TX}\n`);
    await deps.flagUndecryptable({ claimId: 12, account: OWNER });
    await deps.proveCiphertext({ claimId: 12, account: HUNTER });
    await deps.finalize({ claimId: 12, account: HUNTER });
    assert.deepEqual(await deps.dispute({ claimId: 12, account: OWNER }), { tx: TX });
    assert.deepEqual(
      runs.map((r) => r.args),
      [
        ['flag-undecryptable', '--claim', '12', '--account', OWNER, '--force'],
        ['prove-ciphertext', '--claim', '12', '--account', HUNTER],
        ['finalize', '--claim', '12', '--account', HUNTER],
        ['dispute', '--claim', '12', '--account', OWNER],
      ],
    );
  });

  it('a non-zero exit throws with the panic and keeps the tx hash', async () => {
    const { deps } = fake(PANIC, 1);
    await assert.rejects(deps.dispute({ claimId: 12, account: OWNER }), (e) => e.message.includes('dispute window closed') && e.tx === TX);
  });

  it('exit 0 without a tx hash is an error too', async () => {
    const { deps } = fake('nothing here');
    await assert.rejects(deps.finalize({ claimId: 1, account: HUNTER }), /no transaction/);
  });

  it('a submit without claim_id is an error', async () => {
    const { deps } = fake(`   tx: https://testnet.nearblocks.io/txns/${TX}\n`);
    await assert.rejects(deps.submit({ record, account: HUNTER }), /claim_id/);
  });
});
