import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  GAS,
  addSignerArgs,
  createProgramArgs,
  DISPUTE_INVALID_PANIC,
  codeHashRow,
  disputeArgs,
  disputeOutcome,
  estimateClaimStorageDeposit,
  finalizeArgs,
  payabilityChecks,
  splitRequest,
  submitClaimArgs,
  submitPrecheck,
} from './args.js';
import { buildBundleFromFiles, readBundle } from './bundle.js';
import { REPO_ROOT, config, nearaiApiKey } from './config.js';
import { finalizeOwnerKey, loadOwnerKey, savePendingOwnerKey, tryLoadOwnerKey } from './crypto.js';
import { shared as api, demo, verifySignerSig, type ProgramBinding } from './shared.js';
import { callContract, getSigners, listClaims, listPrograms, loadAccount, mustGetClaim, mustGetProgram } from './near.js';
import type { CheckRow, Claim, JudgeRecord, Program } from './types.js';
import { formatNear, nsToIso, printChecks, printKv, printTable, short } from './util.js';

const int = (name: string, v: string) => {
  if (!/^\d+$/.test(String(v))) throw new Error(`${name} must be a non-negative integer, got ${v}`);
  return Number(v);
};

/** Print args JSON with long strings elided (unless full). */
function showArgs(method: string, args: Record<string, unknown>, full = false) {
  const s = JSON.stringify(
    args,
    (_k, v) => (!full && typeof v === 'string' && v.length > 160 ? `${v.slice(0, 60)}…(${v.length} chars)…${v.slice(-20)}` : v),
    2,
  );
  console.log(`\n${method} args:\n${s}`);
}

// =============================================================== attest
export async function cmdAttest(o: { algo: string; model?: string; outDir?: string; register?: boolean; account?: string }) {
  const { runAttestation, dcapStatus } = await import('./attest.js');
  const cfg = config();
  const model = o.model ?? cfg.nearaiModel;
  const algos = (o.algo === 'both' ? ['ed25519', 'ecdsa'] : [o.algo]) as ('ed25519' | 'ecdsa')[];
  for (const a of algos) if (a !== 'ed25519' && a !== 'ecdsa') throw new Error(`--algo must be ed25519|ecdsa|both`);
  if (dcapStatus() !== 'loaded') console.warn(`WARNING: @phala/dcap-qvl-node ${dcapStatus()}; TDX checks will be SKIPPED and nothing will verify.`);

  const verified: { algo: 'ed25519' | 'ecdsa'; address: string }[] = [];
  let allOk = true;
  for (const a of algos) {
    try {
      const run = await runAttestation(a, { model, out: o.outDir ? join(o.outDir, `attestation.${a}.json`) : undefined });
      allOk &&= run.allModelSignersVerified;
      for (const s of run.signers) if (s.kind === 'model' && s.verified) verified.push({ algo: a, address: s.signing_address });
      const gw = run.signers.find((s) => s.kind === 'gateway');
      if (gw) console.log(`\n(gateway signer ${gw.signing_address} ${gw.verified ? 'verified' : 'NOT verified'}; not registered: claims must be provider_tee)`);
    } catch (e) {
      console.error(`\n[${a}] ERROR: ${(e as Error).message}`);
      allOk = false;
    }
  }

  console.log(`\n=== Verified model signers (${model}) ===`);
  if (!verified.length) console.log('  none');
  const toRegister = verified.map((v) => addSignerArgs(v.algo, v.address, 'provider_tee', model));
  for (const args of toRegister) {
    console.log(`  ${args.signer}`);
    console.log(`    near call ${cfg.contractId} add_signer '${JSON.stringify(args)}' --accountId <admin>`);
  }
  console.log(`\nOVERALL: ${allOk ? 'all model signers VERIFIED' : 'NOT all model signers verified'}`);

  if (o.register) {
    if (!toRegister.length) throw new Error('nothing verified; refusing to register');
    const account = loadAccount(o.account);
    const existing = new Map((await getSigners()).map(([s, m]) => [s, m]));
    for (const args of toRegister) {
      const prev = existing.get(args.signer);
      if (prev && prev.kind === args.meta.kind) {
        console.log(`\n${args.signer} already allowlisted (${prev.kind}); skipping`);
        continue;
      }
      const r = await callContract(account, 'add_signer', args, { gas: GAS.addSigner });
      if (!r.ok) process.exitCode = 1;
    }
  }
  if (!allOk) process.exitCode = 1;
}

// =============================================================== create-program
export async function cmdCreateProgram(o: {
  name: string;
  repo: string;
  commit: string;
  payoutLow: string;
  payoutMedium: string;
  payoutHigh: string;
  payoutCritical: string;
  fund: string;
  disputeSecs: string;
  minConfidence: string;
  model?: string;
  code?: string;
  codeFiles?: string[];
  codeRoot?: string;
  account?: string;
  dryRun?: boolean;
}) {
  const cfg = config();
  if (!!o.code === !!o.codeFiles?.length) throw new Error('pass exactly one of --code <bundle file> or --code-files <paths/globs...>');
  let bundle: string;
  if (o.code) {
    bundle = readBundle(o.code);
    console.log(`code bundle: ${o.code} (${Buffer.byteLength(bundle)} B)`);
  } else {
    const b = buildBundleFromFiles(o.codeFiles!, o.codeRoot ?? '.');
    bundle = b.bundle;
    console.log(`code bundle: ${b.paths.length} file(s) [${b.paths.join(', ')}] -> wrote ${b.outPath} (${Buffer.byteLength(bundle)} B)`);
    console.log('publish bundle.txt with the program: hunters must judge against it byte for byte.');
  }
  const kp = api.generateOwnerKeypair();
  const { args, deposit } = createProgramArgs({
    name: o.name,
    repoUrl: o.repo,
    commit: o.commit,
    modelId: o.model ?? cfg.nearaiModel,
    systemPromptHash: api.systemPromptHash(),
    codeHash: api.codeHash(bundle),
    payoutsNear: { low: o.payoutLow, medium: o.payoutMedium, high: o.payoutHigh, critical: o.payoutCritical },
    ownerEncPubkey: kp.publicKey,
    disputeSecs: int('dispute-secs', o.disputeSecs),
    minConfidence: int('min-confidence', o.minConfidence),
    fundNear: o.fund,
  });
  showArgs('create_program', args, true);
  console.log(`deposit: ${formatNear(deposit)} (fund ${o.fund} NEAR + storage allowance; the unused allowance stays in the pool)`);
  if (o.dryRun) {
    console.log('\n--dry-run: not sent; owner key NOT saved.');
    return;
  }
  const account = loadAccount(o.account);
  const pending = savePendingOwnerKey(kp, cfg.contractId, cfg.network);
  const r = await callContract(account, 'create_program', args, { gas: GAS.createProgram, deposit });
  if (!r.ok) {
    console.log(`owner key left at ${pending} (unused)`);
    process.exitCode = 1;
    return;
  }
  const id = Number(r.value);
  const path = finalizeOwnerKey(pending, id);
  console.log(`\nprogram_id: ${id}`);
  console.log(`owner secret key saved to ${path} (chmod 600). Back it up: without it you cannot read reports.`);
}

// =============================================================== views
export async function cmdPrograms(o: { from?: string; limit?: string }) {
  const ps = await listPrograms(Number(o.from ?? 0), Number(o.limit ?? 50));
  console.log(`contract: ${config().contractId}\n`);
  if (!ps.length) return console.log('no programs');
  printTable(
    ['id', 'name', 'owner', 'open', 'balance', 'reserved', 'min_conf', 'dispute_s', 'payouts L/M/H/C (NEAR)'],
    ps.map((p) => [
      String(p.id),
      p.name,
      p.owner,
      p.open ? 'yes' : 'no',
      formatNear(p.balance),
      formatNear(p.reserved),
      String(p.min_confidence),
      String(p.dispute_secs),
      [p.payouts.low, p.payouts.medium, p.payouts.high, p.payouts.critical].map((x) => formatNear(x).replace(' NEAR', '')).join('/'),
    ]),
  );
}

export function printProgram(p: Program) {
  printKv([
    ['id', p.id],
    ['name', p.name],
    ['owner', p.owner],
    ['target', `${p.repo_url}@${p.commit}`],
    ['model_id', p.model_id],
    ['system_prompt_hash', p.system_prompt_hash],
    ['code_hash', p.code_hash ?? '(missing: v1 contract?)'],
    ['owner_enc_pubkey', p.owner_enc_pubkey],
    ['payouts', `low ${formatNear(p.payouts.low)} | medium ${formatNear(p.payouts.medium)} | high ${formatNear(p.payouts.high)} | critical ${formatNear(p.payouts.critical)}`],
    ['balance', formatNear(p.balance)],
    ['reserved', formatNear(p.reserved)],
    ['min_confidence', p.min_confidence],
    ['dispute_secs', p.dispute_secs],
    ['open', p.open],
    ['created_at', nsToIso(p.created_at)],
  ]);
}

export async function cmdProgram(id: string) {
  const p = await mustGetProgram(int('id', id));
  printProgram(p);
  const local = api.systemPromptHash();
  console.log(`\n  prompt hash ${p.system_prompt_hash === local ? 'matches' : 'DIFFERS FROM'} the local shared/system-prompt.txt (${short(local)})`);
  if (!p.code_hash) console.log('  no code_hash: this looks like a v1 contract (set --contract / $ESCROW_CONTRACT_ID to the v2 escrow)');
  console.log(`  owner key on this machine: ${tryLoadOwnerKey(p.id) ? 'yes' : 'no'}`);
}

export async function cmdClaims(programId: string, o: { from?: string; limit?: string }) {
  const cs = await listClaims(int('programId', programId), Number(o.from ?? 0), Number(o.limit ?? 50));
  if (!cs.length) return console.log('no claims');
  const now = Date.now() * 1e6;
  printTable(
    ['id', 'hunter', 'status', 'severity', 'conf', 'cwe', 'payout', 'finalize_after', 'signer'],
    cs.map((c) => [
      String(c.id),
      c.hunter,
      c.status === 'Pending' && Number(c.finalize_after) <= now ? 'Pending (finalizable)' : c.status + (c.reject_reason ? ` (${c.reject_reason})` : ''),
      c.verdict.severity,
      String(c.verdict.confidence),
      c.verdict.cwe ?? '-',
      formatNear(c.payout),
      nsToIso(c.finalize_after),
      short(c.signer, 14),
    ]),
  );
}

// =============================================================== submit
/** Published demo bundle, used as the assumed program code in an offline dry-run. */
export const DEMO_BUNDLE_PATH = join(REPO_ROOT, 'fixtures', 'vuln-app', 'bundle.txt');

/**
 * What an offline dry-run checks against when the program cannot be fetched: the demo program
 * (shared/demo-data.mjs target, local system prompt, $NEARAI_MODEL) with code_hash from --code or
 * fixtures/vuln-app/bundle.txt.
 */
export function offlineProgramBinding(model: string, codeBundle?: string): ProgramBinding {
  return {
    repo_url: demo.DEMO_TARGET.repoUrl,
    commit: demo.DEMO_TARGET.commit,
    model_id: model,
    system_prompt_hash: api.systemPromptHash(),
    code_hash: api.codeHash(codeBundle ?? readBundle(DEMO_BUNDLE_PATH)),
  };
}

export async function cmdSubmit(o: {
  program: string;
  code?: string;
  report?: string;
  fixture?: string;
  dryRun?: boolean;
  account?: string;
  ownerPubkey?: string;
  algo?: string;
  force?: boolean;
  full?: boolean;
}) {
  const cfg = config();
  const programId = int('program', o.program);
  const offline = !!(o.dryRun && o.fixture);
  const refuse = (msg: string) => {
    if (!o.force) throw new Error(`${msg}; not sending (use --force to override)`);
    console.warn(`WARNING (--force): ${msg}`);
  };

  let program: Program | undefined;
  if (!offline) program = await mustGetProgram(programId);
  const codeBundle = o.code ? readBundle(o.code) : undefined;
  const binding: ProgramBinding = program ?? offlineProgramBinding(cfg.nearaiModel, codeBundle);
  if (!program) {
    console.log(`offline dry-run: program ${programId} not fetched; checking against the demo program`);
    console.log(`  target ${binding.repo_url}@${binding.commit}, model ${binding.model_id}, code_hash ${short(binding.code_hash)} (${o.code ?? 'fixtures/vuln-app/bundle.txt'})`);
  }

  // 0. the hunter = the account that signs submit_claim (bound into the request's HUNTER line)
  const account = o.dryRun ? undefined : loadAccount(o.account);
  let hunter = account?.accountId ?? o.account ?? cfg.accountId;

  // 1. the code bundle must be the program's, byte for byte
  if (codeBundle !== undefined) {
    const row = codeHashRow(codeBundle, binding.code_hash);
    if (!printChecks('Code bundle', [row])) refuse(`code mismatch: --code ${o.code} does not hash to program.code_hash`);
  }

  // 2. obtain a signed judge record
  let record: JudgeRecord;
  if (o.fixture) {
    record = JSON.parse(readFileSync(o.fixture, 'utf8'));
    console.log(`using pre-recorded fixture ${o.fixture} (chat_id ${record.chat_id}, ${record.signing_algo})`);
    if (!hunter) {
      hunter = splitRequest(record.request_body).hunter;
      if (!hunter) throw new Error('no hunter account: pass --account or set NEAR_TESTNET_ACCOUNT_ID');
      console.log(`(no --account / NEAR_TESTNET_ACCOUNT_ID: pre-checking as the fixture's own hunter ${hunter})`);
    }
  } else {
    if (!codeBundle || !o.report) throw new Error('need --code <program bundle> and --report (or --fixture)');
    if (!hunter) throw new Error('no hunter account: pass --account or set NEAR_TESTNET_ACCOUNT_ID');
    const inputs = { repoUrl: binding.repo_url, commit: binding.commit, hunter, codeBundle, report: readFileSync(o.report, 'utf8') };
    // Pre-check the exact body before spending a NEAR AI call on it.
    const pre = submitPrecheck(api.buildRequestBody({ model: binding.model_id, ...inputs }), binding, hunter, false);
    if (pre.refuse) refuse(pre.refuse);
    const apiKey = nearaiApiKey();
    if (!apiKey) throw new Error('NEARAI_API_KEY not set (use --fixture to submit a pre-recorded judgement)');
    const algo = (o.algo ?? cfg.nearaiAlgo) as 'ed25519' | 'ecdsa';
    console.log(`judging on NEAR AI (${binding.model_id}, ${algo}) as hunter ${hunter}…`);
    record = await api.judge({ apiKey, baseUrl: cfg.nearaiBaseUrl, model: binding.model_id, ...inputs, signingAlgo: algo });
  }

  // 3. verify locally
  const v = api.verifyFixture(record, { systemPromptHash: binding.system_prompt_hash });
  const rows: CheckRow[] = v.checks.map((c) => [c.name, c.ok, c.detail]);
  if (program) rows.push(['request model == program.model_id', record.model === program.model_id, record.model]);
  const verOk = printChecks('Local verification', rows);
  if (!v.verdict) throw new Error('verdict did not parse');
  console.log(`\nverdict: ${JSON.stringify(v.verdict)}`);

  // 4. request vs program (exactly what the owner's dispute checks)
  const pre = submitPrecheck(record.request_body, binding, hunter, !!o.fixture);
  printChecks(`Request vs program (v2 dispute rules, hunter ${hunter})`, [
    ['checkRequestAgainstProgram', pre.check.ok, pre.check.ok ? 'ok: a dispute would fail' : pre.check.reason],
  ]);
  if (pre.warn) console.warn(`WARNING: ${pre.warn}`);
  if (pre.refuse) refuse(pre.refuse);

  let payOk = true;
  if (program) {
    payOk = printChecks('Contract pre-checks (mirrors submit_claim)', payabilityChecks(v.verdict, program));
    const signer = api.signerId(record);
    const allow = new Map(await getSigners());
    const meta = allow.get(signer);
    payOk = printChecks('Signer allowlist', [['signer allowlisted with matching kind', meta?.kind === record.signature_kind, meta ? meta.kind : `${signer} not in get_signers`]]) && payOk;
  } else {
    console.log('\n(offline dry-run: payability and allowlist not checked)');
    printChecks('Offline hints', [
      ['verdict payable (valid && severity != none)', v.verdict.valid && v.verdict.severity !== 'none', `valid=${v.verdict.valid} severity=${v.verdict.severity}; needs program.min_confidence <= ${v.verdict.confidence}`],
    ]);
  }

  // 5. encrypt the exact request body to the owner
  let ownerPub: string;
  let ownerPubSrc: string;
  if (program) {
    if (o.ownerPubkey && o.ownerPubkey !== program.owner_enc_pubkey) throw new Error('--owner-pubkey differs from program.owner_enc_pubkey');
    ownerPub = program.owner_enc_pubkey;
    ownerPubSrc = 'program.owner_enc_pubkey';
  } else if (o.ownerPubkey) {
    ownerPub = o.ownerPubkey;
    ownerPubSrc = '--owner-pubkey';
  } else if (tryLoadOwnerKey(programId)) {
    ownerPub = tryLoadOwnerKey(programId)!.publicKey;
    ownerPubSrc = `local ~/.sealedbounty/owner-${programId}.json`;
  } else {
    ownerPub = api.generateOwnerKeypair().publicKey;
    ownerPubSrc = 'THROWAWAY key (offline dry-run; ciphertext size is exact, content unreadable)';
  }
  const ciphertext = api.encryptForOwner(record.request_body, ownerPub);
  const args = submitClaimArgs(programId, record, ciphertext);
  const { bytes, deposit } = estimateClaimStorageDeposit(ciphertext);
  console.log(`\nencrypted request body (${Buffer.byteLength(record.request_body)} B) to ${ownerPubSrc}`);
  showArgs('submit_claim', args, o.full);
  console.log(`storage deposit: ${formatNear(deposit)} (~${bytes} B x 1e19 yocto + 0.01 NEAR margin; unused part refunded)`);
  console.log(`gas: ${GAS.submitClaim / 10n ** 12n} Tgas`);

  if (o.dryRun) {
    console.log(`\n--dry-run: not sent (would be signed by ${hunter}).`);
    return { args, check: pre.check, hunter };
  }
  if ((!verOk || !payOk) && !o.force) throw new Error('pre-checks failed; not sending (use --force to send anyway)');
  const r = await callContract(account!, 'submit_claim', args, { gas: GAS.submitClaim, deposit });
  if (!r.ok) {
    process.exitCode = 1;
    return;
  }
  console.log(`\nclaim_id: ${r.value}`);
}

// =============================================================== inbox / dispute / finalize
function decryptClaim(c: Claim, secret: string) {
  const body = api.decryptAsOwner(c.ciphertext, secret);
  return { body, hashOk: api.sha256hex(body) === c.req_hash };
}

export async function cmdInbox(o: { program: string; status?: string }) {
  const programId = int('program', o.program);
  const key = loadOwnerKey(programId);
  const program = await mustGetProgram(programId);
  if (key.publicKey !== program.owner_enc_pubkey) console.warn('WARNING: local owner key does not match program.owner_enc_pubkey');
  let claims = await listClaims(programId, 0, 1000);
  if (o.status) claims = claims.filter((c) => c.status.toLowerCase() === o.status!.toLowerCase());
  if (!claims.length) return console.log('inbox empty');
  for (const c of claims) {
    console.log(`\n${'='.repeat(78)}\nclaim ${c.id}  ${c.status}${c.reject_reason ? ` (${c.reject_reason})` : ''}  hunter ${c.hunter}`);
    console.log(`verdict ${c.verdict.severity} conf=${c.verdict.confidence} cwe=${c.verdict.cwe ?? '-'}  payout ${formatNear(c.payout)}  finalize_after ${nsToIso(c.finalize_after)}`);
    let body: string;
    try {
      const d = decryptClaim(c, key.secretKey);
      body = d.body;
      console.log(`sha256(request_body) == req_hash: ${d.hashOk ? 'PASS' : 'FAIL'}`);
    } catch (e) {
      console.log(`decrypt FAILED: ${(e as Error).message}`);
      continue;
    }
    const check = api.checkRequestAgainstProgram(body, program, c.hunter);
    if (check.ok) {
      console.log('request vs program: OK (prompt, model, code bundle, hunter, report all match; a dispute would fail)');
    } else {
      console.log(`request vs program: MISMATCH -> ${check.reason}`);
      console.log(
        c.status === 'Pending'
          ? `  dispute it: sealedbounty dispute --claim ${c.id}   (${disputeOutcome(check)})`
          : `  (claim is ${c.status}; only Pending claims can be disputed)`,
      );
    }
    const u = splitRequest(body);
    if (u.target) {
      const codeOk = api.codeHash(u.code!) === program.code_hash;
      console.log(`\n-- TARGET ${u.target}\n-- HUNTER ${u.hunter}`);
      console.log(`-- CODE ${Buffer.byteLength(u.code!)} B, sha256 ${short(api.codeHash(u.code!))} ${codeOk ? '(== program.code_hash; not shown)' : 'DIFFERS from program.code_hash:'}`);
      if (!codeOk) console.log(u.code);
      console.log(`-- REPORT\n${u.report ?? '(missing)'}`);
    } else {
      console.log(`\n-- USER MESSAGES (non-canonical format)\n${u.raw}`);
    }
  }
}

export async function cmdDispute(o: { claim: string; account?: string; dryRun?: boolean; force?: boolean }) {
  const c = await mustGetClaim(int('claim', o.claim));
  const program = await mustGetProgram(c.program_id);
  const key = loadOwnerKey(c.program_id);
  const { body, hashOk } = decryptClaim(c, key.secretKey);
  const rows: CheckRow[] = [
    ['claim is Pending', c.status === 'Pending', c.status],
    ['dispute window open', Date.now() * 1e6 < Number(c.finalize_after), `until ${nsToIso(c.finalize_after)}`],
    ['sha256(decrypted body) == req_hash', hashOk, short(c.req_hash)],
  ];
  printChecks('Dispute preconditions', rows);
  const check = api.checkRequestAgainstProgram(body, program, c.hunter);
  printChecks(`Request vs program (a dispute succeeds only if this FAILS; hunter ${c.hunter})`, [
    ['checkRequestAgainstProgram', check.ok, check.ok ? 'ok' : check.reason],
  ]);
  console.log(`\nexpected: ${disputeOutcome(check)}`);
  const args = disputeArgs(c.id, body);
  showArgs('dispute', args);
  if (o.dryRun) return console.log('\n--dry-run: not sent.');
  if (!rows.every((r) => r[1]) && !o.force) throw new Error('preconditions failed; not sending (use --force)');
  if (check.ok && !o.force) throw new Error(`request matches the program: the contract would panic "${DISPUTE_INVALID_PANIC}" (use --force)`);
  const r = await callContract(loadAccount(o.account), 'dispute', args, { gas: GAS.dispute });
  if (!r.ok) {
    process.exitCode = 1;
    return;
  }
  const after = await mustGetClaim(c.id);
  console.log(`\nclaim ${c.id}: ${after.status}${after.reject_reason ? ` (reason "${after.reject_reason}")` : ''}${check.ok ? '' : `; expected "${check.reason}"`}`);
}

export async function cmdFinalize(o: { claim: string; account?: string; dryRun?: boolean }) {
  const c = await mustGetClaim(int('claim', o.claim));
  const ready = c.status === 'Pending' && Date.now() * 1e6 >= Number(c.finalize_after);
  console.log(`claim ${c.id}: ${c.status}, payout ${formatNear(c.payout)} to ${c.hunter}, finalize_after ${nsToIso(c.finalize_after)}${ready ? ' (ready)' : ' (NOT ready)'}`);
  const args = finalizeArgs(c.id);
  showArgs('finalize', args);
  if (o.dryRun) return console.log('\n--dry-run: not sent.');
  const r = await callContract(loadAccount(o.account), 'finalize', args, { gas: GAS.finalize });
  if (!r.ok) process.exitCode = 1;
}

// =============================================================== verify-claim
export async function verifyClaimChecks(c: Claim, program: Program, allowlist: Map<string, { kind: string }>): Promise<CheckRow[]> {
  const hex64 = /^[0-9a-f]{64}$/;
  const text = c.kind === 'provider_tee' ? `${c.model}:${c.req_hash}:${c.resp_hash}` : `${c.req_hash}:${c.resp_hash}`;
  let sigOk = false;
  let sigDetail = c.signer;
  try {
    sigOk = verifySignerSig(c.signer, c.signature, text);
  } catch (e) {
    sigDetail = (e as Error).message;
  }
  const meta = allowlist.get(c.signer);
  return [
    ['req_hash is 64 hex', hex64.test(c.req_hash), short(c.req_hash)],
    ['resp_hash is 64 hex', hex64.test(c.resp_hash), short(c.resp_hash)],
    ['kind is provider_tee', c.kind === 'provider_tee', c.kind],
    ['claim.model == program.model_id', c.model === program.model_id, c.model],
    [`signature over "${c.kind === 'provider_tee' ? 'model:req_hash:resp_hash' : 'req_hash:resp_hash'}"`, sigOk, sigDetail],
    ['signer currently allowlisted (same kind)', meta?.kind === c.kind, meta ? meta.kind : 'not in get_signers'],
  ];
}

export async function cmdVerifyClaim(o: { claim: string }) {
  const c = await mustGetClaim(int('claim', o.claim));
  const program = await mustGetProgram(c.program_id);
  const allow = new Map(await getSigners());
  console.log(`claim ${c.id} (program ${c.program_id}, ${c.status}) verdict ${JSON.stringify(c.verdict)}`);
  const rows = await verifyClaimChecks(c, program, allow);
  const key = tryLoadOwnerKey(c.program_id);
  if (key) {
    try {
      const { body, hashOk } = decryptClaim(c, key.secretKey);
      rows.push(['[owner] sha256(decrypted body) == req_hash', hashOk, '']);
      const check = api.checkRequestAgainstProgram(body, program, c.hunter);
      rows.push(['[owner] request matches program (v2 dispute rules)', check.ok, check.ok ? 'ok' : `${check.reason}: dispute it`]);
    } catch (e) {
      rows.push(['[owner] decrypt ciphertext', false, (e as Error).message]);
    }
  }
  const ok = printChecks(`verify-claim ${c.id} (offline signature check from on-chain fields)`, rows);
  if (!ok) process.exitCode = 1;
}

export async function cmdVerifyFixture(file: string, o: { promptHash?: string }) {
  const r: JudgeRecord = JSON.parse(readFileSync(file, 'utf8'));
  const v = api.verifyFixture(r, o.promptHash ? { systemPromptHash: o.promptHash } : {});
  const ok = printChecks(`verify-fixture ${file}`, v.checks.map((c) => [c.name, c.ok, c.detail]));
  console.log(`verdict: ${JSON.stringify(v.verdict)}  signer: ${v.signer}`);
  if (!ok) process.exitCode = 1;
}
