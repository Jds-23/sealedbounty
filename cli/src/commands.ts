import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  DEFAULT_BOND_NEAR,
  DEFAULT_CHALLENGE_SECS,
  GAS,
  addSignerArgs,
  attestRotationHint,
  claimStatusLabel,
  createProgramArgs,
  DISPUTE_INVALID_PANIC,
  codeHashRow,
  disputeArgs,
  disputeOutcome,
  finalizeArgs,
  finalizeOutcome,
  flagUndecryptableArgs,
  parseSigners,
  payabilityChecks,
  proveCiphertextArgs,
  revokeSignerArgs,
  setProgramSignersArgs,
  splitRequest,
  submitClaimArgs,
  submitDeposit,
  submitPrecheck,
} from './args.js';
import { buildBundleFromFiles, readBundle } from './bundle.js';
import { REPO_ROOT, config, nearaiApiKey } from './config.js';
import {
  finalizeHunterSecret,
  finalizeOwnerKey,
  loadHunterSecret,
  loadOwnerKey,
  openWithEphemeral,
  ownerKeyPath,
  savePendingHunterSecret,
  savePendingOwnerKey,
  tryLoadOwnerKey,
} from './crypto.js';
import { shared as api, demo, verifySignerSig, type ProgramBinding, type RequestCheck } from './shared.js';
import { callContract, getSigners, isSignerRevoked, listClaims, listPrograms, loadAccount, mustGetClaim, mustGetProgram } from './near.js';
import type { CheckRow, Claim, JudgeRecord, Program } from './types.js';
import { formatNear, nearToYocto, nsToIso, printChecks, printKv, printTable, short } from './util.js';

const int = (name: string, v: string) => {
  if (!/^\d+$/.test(String(v))) throw new Error(`${name} must be a non-negative integer, got ${v}`);
  return Number(v);
};
const nowNs = () => BigInt(Date.now()) * 1_000_000n;

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
export function cmdAttestRegisterHint() {
  console.log(`\n${attestRotationHint()}`);
}

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
    cmdAttestRegisterHint();
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
  bond?: string;
  challengeSecs?: string;
  signers?: string[];
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
  const signers = o.signers ? parseSigners(o.signers) : [];
  const kp = api.generateOwnerKeypair();
  const { args, deposit } = createProgramArgs({
    name: o.name,
    repoUrl: o.repo,
    commit: o.commit,
    modelId: o.model ?? cfg.nearaiModel,
    systemPromptHash: api.systemPromptHash(),
    codeHash: api.codeHash(bundle),
    paramsHash: api.paramsHash(),
    payoutsNear: { low: o.payoutLow, medium: o.payoutMedium, high: o.payoutHigh, critical: o.payoutCritical },
    ownerEncPubkey: kp.publicKey,
    disputeSecs: int('dispute-secs', o.disputeSecs),
    minConfidence: int('min-confidence', o.minConfidence),
    fundNear: o.fund,
    bondNear: o.bond ?? DEFAULT_BOND_NEAR,
    challengeSecs: int('challenge-secs', o.challengeSecs ?? String(DEFAULT_CHALLENGE_SECS)),
    signers,
  });
  showArgs('create_program', args, true);
  console.log(`deposit: ${formatNear(deposit)} (fund ${o.fund} NEAR + storage allowance; the unused allowance stays in the pool)`);
  console.log(`hunter bond: ${formatNear(args.bond)} per claim (returned on Paid, forfeited to the pool on Rejected)`);
  console.log(
    args.signers
      ? `signers: ${args.signers.length} explicit (each must be allowlisted for ${args.model_id})`
      : `signers: none given -> the contract snapshots every allowlisted signer for ${args.model_id}`,
  );
  if (o.dryRun) {
    console.log('\n--dry-run: not sent; owner key NOT saved.');
    return { args, deposit };
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
  return { args, deposit, id };
}

// =============================================================== views
export async function cmdPrograms(o: { from?: string; limit?: string }) {
  const ps = await listPrograms(Number(o.from ?? 0), Number(o.limit ?? 50));
  console.log(`contract: ${config().contractId}\n`);
  if (!ps.length) return console.log('no programs');
  printTable(
    ['id', 'name', 'owner', 'open', 'balance', 'reserved', 'bond', 'min_conf', 'dispute_s', 'challenge_s', 'signers', 'payouts L/M/H/C (NEAR)'],
    ps.map((p) => [
      String(p.id),
      p.name,
      p.owner,
      p.open ? 'yes' : 'no',
      formatNear(p.balance),
      formatNear(p.reserved),
      p.bond != null ? formatNear(p.bond) : '-',
      String(p.min_confidence),
      String(p.dispute_secs),
      p.challenge_secs != null ? String(p.challenge_secs) : '-',
      p.signers ? String(p.signers.length) : '-',
      [p.payouts.low, p.payouts.medium, p.payouts.high, p.payouts.critical].map((x) => formatNear(x).replace(' NEAR', '')).join('/'),
    ]),
  );
}

export function printProgram(p: Program) {
  const missing = '(missing: pre-v3 contract?)';
  printKv([
    ['id', p.id],
    ['name', p.name],
    ['owner', p.owner],
    ['target', `${p.repo_url}@${p.commit}`],
    ['model_id', p.model_id],
    ['system_prompt_hash', p.system_prompt_hash],
    ['code_hash', p.code_hash ?? '(missing: v1 contract?)'],
    ['params_hash', p.params_hash ?? missing],
    ['signers', p.signers ? (p.signers.length ? p.signers.join(', ') : '(none)') : missing],
    ['owner_enc_pubkey', p.owner_enc_pubkey],
    ['payouts', `low ${formatNear(p.payouts.low)} | medium ${formatNear(p.payouts.medium)} | high ${formatNear(p.payouts.high)} | critical ${formatNear(p.payouts.critical)}`],
    ['bond', p.bond != null ? formatNear(p.bond) : missing],
    ['balance', formatNear(p.balance)],
    ['reserved', formatNear(p.reserved)],
    ['min_confidence', p.min_confidence],
    ['dispute_secs', p.dispute_secs],
    ['challenge_secs', p.challenge_secs ?? missing],
    ['open', p.open],
    ['created_at', nsToIso(p.created_at)],
  ]);
}

export async function cmdProgram(id: string) {
  const p = await mustGetProgram(int('id', id));
  printProgram(p);
  const local = api.systemPromptHash();
  console.log(`\n  prompt hash ${p.system_prompt_hash === local ? 'matches' : 'DIFFERS FROM'} the local shared/system-prompt.txt (${short(local)})`);
  if (p.params_hash) {
    const lp = api.paramsHash();
    console.log(`  params hash ${p.params_hash === lp ? 'matches' : 'DIFFERS FROM'} the local canonical judge params (${short(lp)})`);
  }
  if (!p.code_hash) console.log('  no code_hash: this looks like a v1 contract (set --contract / $ESCROW_CONTRACT_ID to the v3 escrow)');
  else if (!p.params_hash) console.log('  no params_hash: this looks like a v2 contract (set --contract / $ESCROW_CONTRACT_ID to the v3 escrow)');
  console.log(`  owner key on this machine: ${tryLoadOwnerKey(p.id) ? 'yes' : 'no'}`);
}

export async function cmdClaims(programId: string, o: { from?: string; limit?: string }) {
  const cs = await listClaims(int('programId', programId), Number(o.from ?? 0), Number(o.limit ?? 50));
  if (!cs.length) return console.log('no claims');
  const now = nowNs();
  printTable(
    ['id', 'hunter', 'status', 'severity', 'conf', 'cwe', 'payout', 'bond', 'finalize_after', 'signer'],
    cs.map((c) => [
      String(c.id),
      c.hunter,
      claimStatusLabel(c, now),
      c.verdict.severity,
      String(c.verdict.confidence),
      c.verdict.cwe ?? '-',
      formatNear(c.payout),
      c.bond != null ? formatNear(c.bond) : '-',
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
 * (shared/demo-data.mjs target, local system prompt, canonical params, $NEARAI_MODEL) with code_hash
 * from --code or fixtures/vuln-app/bundle.txt.
 */
export function offlineProgramBinding(model: string, codeBundle?: string): ProgramBinding {
  return {
    repo_url: demo.DEMO_TARGET.repoUrl,
    commit: demo.DEMO_TARGET.commit,
    model_id: model,
    system_prompt_hash: api.systemPromptHash(),
    code_hash: api.codeHash(codeBundle ?? readBundle(DEMO_BUNDLE_PATH)),
    params_hash: api.paramsHash(),
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

  // 4. request vs program (exactly what the owner's dispute checks, incl. v3 params_hash)
  const pre = submitPrecheck(record.request_body, binding, hunter, !!o.fixture);
  printChecks(`Request vs program (v3 dispute rules, hunter ${hunter})`, [
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
    const signerRows: CheckRow[] = [['signer allowlisted with matching kind', meta?.kind === record.signature_kind, meta ? meta.kind : `${signer} not in get_signers`]];
    if (program.signers) {
      signerRows.push(['signer in program.signers', program.signers.includes(signer), program.signers.includes(signer) ? short(signer) : `${short(signer)} not in the program's ${program.signers.length} signer(s)`]);
    }
    try {
      const revoked = await isSignerRevoked(signer);
      signerRows.push(['signer not revoked', !revoked, revoked ? 'revoked: finalize would reject "signer revoked"' : 'ok']);
    } catch {
      /* pre-v3 contract: no is_signer_revoked view */
    }
    payOk = printChecks('Signer', signerRows) && payOk;
  } else {
    console.log('\n(offline dry-run: payability and allowlist not checked)');
    printChecks('Offline hints', [
      ['verdict payable (valid && severity != none)', v.verdict.valid && v.verdict.severity !== 'none', `valid=${v.verdict.valid} severity=${v.verdict.severity}; needs program.min_confidence <= ${v.verdict.confidence}`],
    ]);
  }

  // 5. encrypt the exact request body to the owner; keep the ephemeral secret for prove_ciphertext
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
    ownerPubSrc = `local ${ownerKeyPath(programId)}`;
  } else {
    ownerPub = api.generateOwnerKeypair().publicKey;
    ownerPubSrc = 'THROWAWAY key (offline dry-run; ciphertext size is exact, content unreadable)';
  }
  const { ciphertext, ephemeralSecretHex } = api.encryptForOwnerWithSecret(record.request_body, ownerPub);
  const args = submitClaimArgs(programId, record, ciphertext);
  const bond = program ? program.bond : nearToYocto(DEFAULT_BOND_NEAR).toString();
  const dep = submitDeposit(ciphertext, bond);
  console.log(`\nencrypted request body (${Buffer.byteLength(record.request_body)} B) to ${ownerPubSrc}`);
  showArgs('submit_claim', args, o.full);
  console.log(`storage deposit: ${formatNear(dep.storage)} (~${dep.bytes} B x 1e19 yocto + 0.01 NEAR margin; unused part refunded)`);
  console.log(`bond: ${formatNear(dep.bond)} (${program ? 'program.bond' : `offline: assumed default ${DEFAULT_BOND_NEAR} NEAR`}; returned on Paid, forfeited on Rejected)`);
  console.log(`attached: ${formatNear(dep.deposit)} = storage + bond`);
  console.log(`gas: ${GAS.submitClaim / 10n ** 12n} Tgas`);

  if (o.dryRun) {
    console.log(`\n--dry-run: not sent (would be signed by ${hunter}); ephemeral secret NOT saved.`);
    return { args, check: pre.check, hunter, deposit: dep.deposit };
  }
  if ((!verOk || !payOk) && !o.force) throw new Error('pre-checks failed; not sending (use --force to send anyway)');
  // Save the ephemeral secret BEFORE sending: without it the hunter cannot answer flag_undecryptable.
  const pending = savePendingHunterSecret({ ephemeralSecretHex, req_hash: record.req_hash, contract: cfg.contractId, program_id: programId });
  console.log(`ephemeral secret saved to ${pending} (chmod 600) before sending`);
  const r = await callContract(account!, 'submit_claim', args, { gas: GAS.submitClaim, deposit: dep.deposit });
  if (!r.ok) {
    console.log(`ephemeral secret left at ${pending} (unused)`);
    process.exitCode = 1;
    return;
  }
  const claimId = Number(r.value);
  const path = finalizeHunterSecret(pending, claimId);
  console.log(`\nclaim_id: ${claimId}`);
  console.log(`ephemeral secret saved to ${path} (chmod 600). Keep it until the claim is Paid: prove-ciphertext needs it.`);
  return { args, check: pre.check, hunter, deposit: dep.deposit, claimId };
}

// =============================================================== inbox / dispute / finalize
function decryptClaim(c: Claim, secret: string) {
  const body = api.decryptAsOwner(c.ciphertext, secret);
  return { body, hashOk: api.sha256hex(body) === c.req_hash };
}

export type InboxDecrypt = { ok: true; body: string; check: RequestCheck; error?: undefined; hint?: undefined } | { ok: false; error: string; hint: string };

/** Owner-side decrypt of one claim. A ciphertext that fails to open, or opens to a body whose hash != req_hash, is UNDECRYPTABLE (v3 #2). */
export function inboxDecrypt(c: Claim, program: ProgramBinding, ownerSecret: string): InboxDecrypt {
  const hint = `UNDECRYPTABLE → run \`sb flag-undecryptable --claim ${c.id}\``;
  let d: { body: string; hashOk: boolean };
  try {
    d = decryptClaim(c, ownerSecret);
  } catch (e) {
    return { ok: false, error: `decrypt failed: ${(e as Error).message}`, hint };
  }
  if (!d.hashOk) return { ok: false, error: 'decrypts, but sha256(body) != req_hash', hint };
  return { ok: true, body: d.body, check: api.checkRequestAgainstProgram(d.body, program, c.hunter) };
}

export async function cmdInbox(o: { program: string; status?: string }) {
  const programId = int('program', o.program);
  const key = loadOwnerKey(programId);
  const program = await mustGetProgram(programId);
  if (key.publicKey !== program.owner_enc_pubkey) console.warn('WARNING: local owner key does not match program.owner_enc_pubkey');
  let claims = await listClaims(programId, 0, 1000);
  if (o.status) claims = claims.filter((c) => c.status.toLowerCase() === o.status!.toLowerCase());
  if (!claims.length) return console.log('inbox empty');
  const now = nowNs();
  for (const c of claims) {
    console.log(`\n${'='.repeat(78)}\nclaim ${c.id}  ${claimStatusLabel(c, now)}  hunter ${c.hunter}`);
    console.log(
      `verdict ${c.verdict.severity} conf=${c.verdict.confidence} cwe=${c.verdict.cwe ?? '-'}  payout ${formatNear(c.payout)}  bond ${c.bond != null ? formatNear(c.bond) : '-'}  finalize_after ${nsToIso(c.finalize_after)}`,
    );
    const d = inboxDecrypt(c, program, key.secretKey);
    if (!d.ok) {
      console.log(d.error);
      if (c.status === 'Pending') console.log(d.hint);
      else if (c.status === 'Challenged') console.log('(already challenged: the hunter must prove_ciphertext before the deadline, else finalize rejects it)');
      else console.log(`UNDECRYPTABLE (claim is ${c.status}; only Pending claims can be flagged)`);
      continue;
    }
    console.log('sha256(request_body) == req_hash: PASS');
    const { body, check } = d;
    if (check.ok) {
      console.log('request vs program: OK (prompt, model, params, code bundle, hunter, report all match; a dispute would fail)');
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
    ['claim is Pending', c.status === 'Pending', c.status === 'Challenged' ? 'Challenged: contract panics "claim not pending"' : c.status],
    ['dispute window open', Date.now() * 1e6 < Number(c.finalize_after), `until ${nsToIso(c.finalize_after)}`],
    ['sha256(decrypted body) == req_hash', hashOk, hashOk ? short(c.req_hash) : `${short(c.req_hash)} (use flag-undecryptable instead)`],
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

export async function cmdFinalize(o: { claim: string; account?: string; dryRun?: boolean; force?: boolean }) {
  const c = await mustGetClaim(int('claim', o.claim));
  const now = nowNs();
  let expect: string;
  let ready: boolean;
  if (c.status === 'Challenged') {
    ready = !!c.challenge_deadline && now >= BigInt(c.challenge_deadline);
    expect = ready
      ? 'challenge deadline passed: finalize rejects the claim "undecryptable report" (bond to the pool)'
      : `challenge open until ${c.challenge_deadline ? nsToIso(c.challenge_deadline) : '?'}: contract would panic "challenge open"`;
  } else {
    ready = c.status === 'Pending' && now >= BigInt(c.finalize_after);
    expect = ready ? `pays ${formatNear(c.payout)} + bond ${formatNear(c.bond ?? '0')} to ${c.hunter}` : `NOT ready (${claimStatusLabel(c, now)})`;
    if (ready) {
      try {
        if (await isSignerRevoked(c.signer)) expect = 'signer revoked: finalize rejects the claim "signer revoked"';
      } catch {
        /* pre-v3 contract */
      }
    }
  }
  console.log(`claim ${c.id}: ${claimStatusLabel(c, now)}, payout ${formatNear(c.payout)}, finalize_after ${nsToIso(c.finalize_after)}`);
  console.log(`expected: ${expect}`);
  const args = finalizeArgs(c.id);
  showArgs('finalize', args);
  if (o.dryRun) return console.log('\n--dry-run: not sent.');
  if (!ready && !o.force) throw new Error('claim is not finalizable yet; not sending (use --force)');
  const r = await callContract(loadAccount(o.account), 'finalize', args, { gas: GAS.finalize });
  if (!r.ok) {
    process.exitCode = 1;
    return;
  }
  let after: Claim | null = null;
  try {
    after = await mustGetClaim(c.id);
  } catch {
    /* outcome from logs only */
  }
  const out = finalizeOutcome(r.logs, after);
  console.log(`\noutcome: ${out.text}`);
  if (out.status === 'PayoutFailed') process.exitCode = 1;
}

// =============================================================== v3 #2: decryption challenge
export async function cmdFlagUndecryptable(o: { claim: string; account?: string; dryRun?: boolean; force?: boolean }) {
  const cfg = config();
  const c = await mustGetClaim(int('claim', o.claim));
  const program = await mustGetProgram(c.program_id);
  const caller = o.account ?? cfg.accountId;
  const rows: CheckRow[] = [
    ['claim is Pending', c.status === 'Pending', c.status],
    ['dispute window open', nowNs() < BigInt(c.finalize_after), `until ${nsToIso(c.finalize_after)}`],
  ];
  if (caller) rows.push(['caller is the program owner', caller === program.owner, `${caller} (owner ${program.owner})`]);
  const key = tryLoadOwnerKey(c.program_id);
  if (key) {
    const d = inboxDecrypt(c, program, key.secretKey);
    rows.push(['[owner] ciphertext really is undecryptable', !d.ok, d.ok ? 'it decrypts and hashes to req_hash: use dispute instead' : d.error]);
  } else {
    console.log(`(no local owner key for program ${c.program_id}: cannot confirm the ciphertext is undecryptable)`);
  }
  const ok = printChecks('flag-undecryptable preconditions', rows);
  console.log(
    `\nexpected: claim -> Challenged; ${c.hunter} then has ${program.challenge_secs ?? '?'} s to prove_ciphertext, else finalize rejects it "undecryptable report"`,
  );
  const args = flagUndecryptableArgs(c.id);
  showArgs('flag_undecryptable', args);
  if (o.dryRun) return console.log('\n--dry-run: not sent.');
  if (!ok && !o.force) throw new Error('preconditions failed; not sending (use --force)');
  const r = await callContract(loadAccount(o.account), 'flag_undecryptable', args, { gas: GAS.flagUndecryptable });
  if (!r.ok) {
    process.exitCode = 1;
    return;
  }
  try {
    const after = await mustGetClaim(c.id);
    console.log(`\nclaim ${c.id}: ${claimStatusLabel(after)}`);
  } catch {
    /* view failed; tx already printed */
  }
}

/** Local mirror of prove_ciphertext: open with the ephemeral secret, hash == req_hash, then the full dispute checks. */
export function proveCheck(c: Claim, program: ProgramBinding & { owner_enc_pubkey: string }, ephemeralSecretHex: string) {
  const rows: CheckRow[] = [];
  let reason: string | null = null;
  let body: string | undefined;
  try {
    body = openWithEphemeral(c.ciphertext, program.owner_enc_pubkey, ephemeralSecretHex);
    rows.push(['box opens with the saved ephemeral secret', true, `${Buffer.byteLength(body)} B plaintext`]);
  } catch (e) {
    rows.push(['box opens with the saved ephemeral secret', false, (e as Error).message]);
    reason = 'undecryptable report';
  }
  if (body !== undefined) {
    const h = api.sha256hex(body);
    rows.push(['sha256(plaintext) == req_hash', h === c.req_hash, short(h)]);
    if (h !== c.req_hash) reason = 'undecryptable report';
    else {
      const check = api.checkRequestAgainstProgram(body, program, c.hunter);
      rows.push(['request matches program (dispute rules)', check.ok, check.ok ? 'ok' : check.reason]);
      if (!check.ok) reason = check.reason;
    }
  }
  const outcome =
    reason === null
      ? `claim -> back to Pending with finalize_after = now (finalizable: sealedbounty finalize --claim ${c.id})`
      : `claim -> Rejected, reason "${reason}"; bond forfeited to the pool`;
  return { rows, reason, outcome };
}

export async function cmdProveCiphertext(o: { claim: string; account?: string; dryRun?: boolean; force?: boolean }) {
  const cfg = config();
  const c = await mustGetClaim(int('claim', o.claim));
  const program = await mustGetProgram(c.program_id);
  const secret = loadHunterSecret(c.id, undefined, cfg.contractId);
  const now = nowNs();
  const pre: CheckRow[] = [
    ['claim is Challenged', c.status === 'Challenged', claimStatusLabel(c, now)],
    ['challenge window open', !!c.challenge_deadline && now < BigInt(c.challenge_deadline), c.challenge_deadline ? `until ${nsToIso(c.challenge_deadline)}` : 'no deadline'],
    ['saved secret is for this claim (req_hash)', secret.req_hash === c.req_hash, short(secret.req_hash)],
  ];
  const caller = o.account ?? cfg.accountId;
  if (caller) pre.push(['caller is the claim hunter', caller === c.hunter, `${caller} (hunter ${c.hunter})`]);
  const preOk = printChecks('prove-ciphertext preconditions', pre);
  const pc = proveCheck(c, program, secret.ephemeralSecretHex);
  printChecks('Local decryption check (mirrors prove_ciphertext)', pc.rows);
  console.log(`\nexpected: ${pc.outcome}`);
  const args = proveCiphertextArgs(c.id, secret.ephemeralSecretHex);
  showArgs('prove_ciphertext', { ...args, ephemeral_secret: `${args.ephemeral_secret.slice(0, 8)}… (from ${secret.contract} claim ${secret.claim_id})` });
  if (o.dryRun) return console.log('\n--dry-run: not sent.');
  if (!preOk && !o.force) throw new Error('preconditions failed; not sending (use --force)');
  if (pc.reason && !o.force) throw new Error(`the contract would reject the claim "${pc.reason}"; not sending (use --force)`);
  const r = await callContract(loadAccount(o.account), 'prove_ciphertext', args, { gas: GAS.proveCiphertext });
  if (!r.ok) {
    process.exitCode = 1;
    return;
  }
  try {
    const after = await mustGetClaim(c.id);
    console.log(`\nclaim ${c.id}: ${claimStatusLabel(after)}${after.reject_reason ? ` (reason "${after.reject_reason}")` : ''}`);
  } catch {
    /* view failed */
  }
}

// =============================================================== v3 #3 / #6: signers
export async function cmdSetProgramSigners(o: { program: string; signers: string[]; account?: string; dryRun?: boolean; force?: boolean }) {
  const programId = int('program', o.program);
  const program = await mustGetProgram(programId);
  const signers = parseSigners(o.signers);
  const allow = new Map(await getSigners());
  const rows: CheckRow[] = signers.map((s) => {
    const m = allow.get(s);
    return [`${short(s)} allowlisted for ${program.model_id}`, m?.model === program.model_id, m ? `model ${m.model ?? 'null'}` : 'not in get_signers'];
  });
  const ok = printChecks('Signers (contract: each must be allowlisted with model == program.model_id)', rows);
  console.log(`\ncurrent: ${program.signers?.join(', ') || '(none)'}\nnew:     ${signers.join(', ')}`);
  console.log('applies to future submit_claim calls only; existing claims keep their signer.');
  const args = setProgramSignersArgs(programId, signers);
  showArgs('set_program_signers', args);
  if (o.dryRun) return console.log('\n--dry-run: not sent.');
  if (!ok && !o.force) throw new Error('a signer is not allowlisted for this model: the contract would panic "signer not allowlisted" (use --force)');
  // Payable for storage growth; the contract refunds the unused part.
  const r = await callContract(loadAccount(o.account), 'set_program_signers', args, { gas: GAS.setProgramSigners, deposit: nearToYocto('0.01') });
  if (!r.ok) process.exitCode = 1;
}

export async function cmdRevokeSigner(signer: string, o: { account?: string; dryRun?: boolean }) {
  const args = revokeSignerArgs(signer);
  console.log(`revoke_signer ${args.signer}: removes it from the allowlist and marks it revoked.`);
  console.log('Pending claims signed by it are Rejected at finalize ("signer revoked"); new submissions with it fail.');
  showArgs('revoke_signer', args);
  if (o.dryRun) return console.log('\n--dry-run: not sent.');
  const r = await callContract(loadAccount(o.account), 'revoke_signer', args, { gas: GAS.revokeSigner });
  if (!r.ok) {
    process.exitCode = 1;
    return;
  }
  console.log(r.value === false ? `\n${args.signer} was already revoked` : `\n${args.signer} revoked`);
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
  const rows: CheckRow[] = [
    ['req_hash is 64 hex', hex64.test(c.req_hash), short(c.req_hash)],
    ['resp_hash is 64 hex', hex64.test(c.resp_hash), short(c.resp_hash)],
    ['kind is provider_tee', c.kind === 'provider_tee', c.kind],
    ['claim.model == program.model_id', c.model === program.model_id, c.model],
    [`signature over "${c.kind === 'provider_tee' ? 'model:req_hash:resp_hash' : 'req_hash:resp_hash'}"`, sigOk, sigDetail],
    ['signer currently allowlisted (same kind)', meta?.kind === c.kind, meta ? meta.kind : 'not in get_signers'],
  ];
  if (program.signers) rows.push(['signer in program.signers (now)', program.signers.includes(c.signer), short(c.signer)]);
  return rows;
}

export async function cmdVerifyClaim(o: { claim: string }) {
  const c = await mustGetClaim(int('claim', o.claim));
  const program = await mustGetProgram(c.program_id);
  const allow = new Map(await getSigners());
  console.log(`claim ${c.id} (program ${c.program_id}, ${claimStatusLabel(c)}) verdict ${JSON.stringify(c.verdict)}`);
  const rows = await verifyClaimChecks(c, program, allow);
  const key = tryLoadOwnerKey(c.program_id);
  if (key) {
    const d = inboxDecrypt(c, program, key.secretKey);
    if (d.ok) {
      rows.push(['[owner] sha256(decrypted body) == req_hash', true, '']);
      rows.push(['[owner] request matches program (v3 dispute rules)', d.check.ok, d.check.ok ? 'ok' : `${d.check.reason}: dispute it`]);
    } else {
      rows.push(['[owner] decrypt ciphertext', false, `${d.error}; ${d.hint}`]);
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
