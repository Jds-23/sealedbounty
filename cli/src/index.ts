#!/usr/bin/env node
import { Command } from 'commander';
import * as c from './commands.js';
import { loadEnv } from './config.js';

loadEnv();

const program = new Command()
  .name('sealedbounty')
  .description('SealedBounty CLI: TEE-judged, encrypted bug bounties on NEAR')
  .option('--contract <id>', 'escrow contract id (default $ESCROW_CONTRACT_ID or sealedbounty-v2.testnet)')
  .hook('preAction', (cmd) => {
    const contract = cmd.opts().contract;
    if (contract) process.env.ESCROW_CONTRACT_ID = contract;
  });

const run =
  <A extends unknown[]>(fn: (...a: A) => Promise<unknown>) =>
  async (...a: A) => {
    try {
      await fn(...a);
    } catch (e) {
      console.error(`\nerror: ${(e as Error).message}`);
      process.exitCode = 1;
    }
  };

program
  .command('attest')
  .description('Verify NEAR AI TEE attestation (Intel TDX + NVIDIA GPU) and print the add_signer args for every verified model signer')
  .option('--algo <algo>', 'ed25519 | ecdsa | both', 'both')
  .option('--model <model>', 'model to attest (default $NEARAI_MODEL)')
  .option('--out-dir <dir>', 'also write attestation.<algo>.json evidence files here')
  .option('--register', 'send add_signer for each verified model signer (admin account)')
  .option('--account <id>', 'admin account (default $NEAR_TESTNET_ACCOUNT_ID)')
  .action(run((o) => c.cmdAttest(o)));

program
  .command('create-program')
  .description('Create and fund a bounty program bound to a code bundle (code_hash); generates the owner encryption keypair (secret saved to ~/.sealedbounty/owner-<contract>-<id>.json)')
  .requiredOption('--name <name>', 'program name')
  .requiredOption('--repo <url>', 'repository URL')
  .requiredOption('--commit <sha>', 'commit under review')
  .requiredOption('--payout-low <NEAR>', 'payout for low severity')
  .requiredOption('--payout-medium <NEAR>', 'payout for medium severity')
  .requiredOption('--payout-high <NEAR>', 'payout for high severity')
  .requiredOption('--payout-critical <NEAR>', 'payout for critical severity')
  .requiredOption('--fund <NEAR>', 'initial pool (attached deposit; a 0.05 NEAR storage allowance is added)')
  .option('--dispute-secs <n>', 'dispute window in seconds', '86400')
  .option('--min-confidence <n>', 'minimum judge confidence 0-100', '70')
  .option('--code <file>', 'published code bundle file (e.g. fixtures/vuln-app/bundle.txt); code_hash = sha256(file)')
  .option('--code-files <paths...>', 'build the bundle from these files/globs (relative to --code-root) and write <code-root>/bundle.txt')
  .option('--code-root <dir>', 'base dir for --code-files; bundle paths are relative to it', '.')
  .option('--model <model>', 'judge model id (default $NEARAI_MODEL)')
  .option('--account <id>', 'owner account (default $NEAR_TESTNET_ACCOUNT_ID)')
  .option('--dry-run', 'print args without sending or saving the key (--code-files still writes bundle.txt)')
  .action(run((o) => c.cmdCreateProgram(o)));

program
  .command('programs')
  .description('List bounty programs')
  .option('--from <n>', 'from program id', '0')
  .option('--limit <n>', 'max rows', '50')
  .action(run((o) => c.cmdPrograms(o)));

program
  .command('program')
  .description('Show one program')
  .argument('<id>', 'program id')
  .action(run((id) => c.cmdProgram(id)));

program
  .command('claims')
  .description("List a program's claims")
  .argument('<programId>', 'program id')
  .option('--from <n>', 'skip the first n claims', '0')
  .option('--limit <n>', 'max rows', '50')
  .action(run((id, o) => c.cmdClaims(id, o)));

program
  .command('submit')
  .description('Judge a report on NEAR AI (TEE), verify it locally, encrypt it to the program owner and submit_claim')
  .requiredOption('--program <id>', 'program id')
  .option('--code <file>', "the program's code bundle (bundle.txt); must hash to program.code_hash")
  .option('--report <file>', 'exploit report file')
  .option('--fixture <file>', 'submit a pre-recorded signed judgement (no API key needed)')
  .option('--algo <algo>', 'NEAR AI signing algo ed25519|ecdsa (default $NEARAI_SIGNING_ALGO)')
  .option('--owner-pubkey <b64>', 'offline dry-run only: owner key to encrypt to')
  .option('--account <id>', 'hunter account = submit_claim signer, bound into the request (default $NEAR_TESTNET_ACCOUNT_ID)')
  .option('--dry-run', 'print verdict + args, do not send (with --fixture: no network at all; checks against the demo program)')
  .option('--full', 'print args without eliding long strings')
  .option('--force', 'send even if local pre-checks fail (code/request mismatch, payability)')
  .action(run((o) => c.cmdSubmit(o)));

program
  .command('inbox')
  .description('Program owner: decrypt every claim, check sha256(body) == req_hash and the request against the program (prompt, model, code, hunter, report)')
  .requiredOption('--program <id>', 'program id')
  .option('--status <s>', 'only Pending | Rejected | Paid')
  .action(run((o) => c.cmdInbox(o)));

program
  .command('dispute')
  .description('Program owner: reveal the decrypted request body on-chain to reject a claim that does not match the program')
  .requiredOption('--claim <id>', 'claim id')
  .option('--account <id>', 'owner account (default $NEAR_TESTNET_ACCOUNT_ID)')
  .option('--dry-run', 'print args, do not send')
  .option('--force', 'send even if the local checks say it will fail')
  .action(run((o) => c.cmdDispute(o)));

program
  .command('finalize')
  .description('Pay out a Pending claim after its dispute window (anyone can call)')
  .requiredOption('--claim <id>', 'claim id')
  .option('--account <id>', 'caller account (default $NEAR_TESTNET_ACCOUNT_ID)')
  .option('--dry-run', 'print args, do not send')
  .action(run((o) => c.cmdFinalize(o)));

program
  .command('verify-claim')
  .description("Re-verify an on-chain claim's TEE signature offline from its stored fields")
  .requiredOption('--claim <id>', 'claim id')
  .action(run((o) => c.cmdVerifyClaim(o)));

program
  .command('verify-fixture')
  .description('Offline check of a recorded judgement (fixtures/live.*.json)')
  .argument('<file>', 'fixture JSON')
  .option('--prompt-hash <hex>', 'also require the system prompt to hash to this')
  .action(run((f, o) => c.cmdVerifyFixture(f, o)));

await program.parseAsync(process.argv);
