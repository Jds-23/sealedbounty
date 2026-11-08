import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  GAS,
  addSignerArgs,
  createProgramArgs,
  disputeArgs,
  estimateClaimStorageDeposit,
  finalizeArgs,
  payabilityChecks,
  promptBindingChecks,
  splitUserMessage,
  submitClaimArgs,
} from './args.js';
import { config, nearaiApiKey } from './config.js';
import { finalizeOwnerKey, loadOwnerKey, savePendingOwnerKey, tryLoadOwnerKey } from './crypto.js';
import { shared as api, verifySignerSig } from './shared.js';
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
  account?: string;
  dryRun?: boolean;
}) {
  const cfg = config();
  const kp = api.generateOwnerKeypair();
  const { args, deposit } = createProgramArgs({
    name: o.name,
    repoUrl: o.repo,
    commit: o.commit,
    modelId: o.model ?? cfg.nearaiModel,
    systemPromptHash: api.systemPromptHash(),
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

  let program: Program | undefined;
  if (!offline) program = await mustGetProgram(programId);

  // 1. obtain a signed judge record
  let record: JudgeRecord;
  if (o.fixture) {
    record = JSON.parse(readFileSync(o.fixture, 'utf8'));
    console.log(`using pre-recorded fixture ${o.fixture} (chat_id ${record.chat_id}, ${record.signing_algo})`);
  } else {
    if (!o.code || !o.report) throw new Error('need --code and --report (or --fixture)');
    const apiKey = nearaiApiKey();
    if (!apiKey) throw new Error('NEARAI_API_KEY not set (use --fixture to submit a pre-recorded judgement)');
    const algo = (o.algo ?? cfg.nearaiAlgo) as 'ed25519' | 'ecdsa';
    console.log(`judging on NEAR AI (${program!.model_id}, ${algo})…`);
    record = await api.judge({
      apiKey,
      baseUrl: cfg.nearaiBaseUrl,
      model: program!.model_id,
      repoUrl: program!.repo_url,
      commit: program!.commit,
      codeExcerpt: readFileSync(o.code, 'utf8'),
      report: readFileSync(o.report, 'utf8'),
      signingAlgo: algo,
    });
  }

  // 2. verify locally
  const v = api.verifyFixture(record, program ? { systemPromptHash: program.system_prompt_hash } : {});
  const rows: CheckRow[] = v.checks.map((c) => [c.name, c.ok, c.detail]);
  if (program) rows.push(['request model == program.model_id', record.model === program.model_id, record.model]);
  const verOk = printChecks('Local verification', rows);
  if (!v.verdict) throw new Error('verdict did not parse');
  console.log(`\nverdict: ${JSON.stringify(v.verdict)}`);

  let payOk = true;
  if (program) {
    payOk = printChecks('Contract pre-checks (mirrors submit_claim)', payabilityChecks(v.verdict, program));
    const signer = api.signerId(record);
    const allow = new Map(await getSigners());
    const meta = allow.get(signer);
    payOk = printChecks('Signer allowlist', [['signer allowlisted with matching kind', meta?.kind === record.signature_kind, meta ? meta.kind : `${signer} not in get_signers`]]) && payOk;
  } else {
    console.log('\n(offline dry-run: program not fetched; payability and allowlist not checked)');
    const offlineRows = promptBindingChecks(record.request_body, { model_id: record.model, system_prompt_hash: api.systemPromptHash() }, api.sha256hex)
      .filter((r) => r[0].startsWith('sha256'))
      .map(([, ok, d]) => ['system prompt == shared/system-prompt.txt (what create-program registers)', ok, d] as CheckRow);
    printChecks('Offline hints', [
      ...offlineRows,
      ['verdict payable (valid && severity != none)', v.verdict.valid && v.verdict.severity !== 'none', `valid=${v.verdict.valid} severity=${v.verdict.severity}; needs program.min_confidence <= ${v.verdict.confidence}`],
    ]);
  }

  // 3. encrypt the exact request body to the owner
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
    console.log('\n--dry-run: not sent.');
    return;
  }
  if ((!verOk || !payOk) && !o.force) throw new Error('pre-checks failed; not sending (use --force to send anyway)');
  const account = loadAccount(o.account);
  const r = await callContract(account, 'submit_claim', args, { gas: GAS.submitClaim, deposit });
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
    const binding = promptBindingChecks(body, program, api.sha256hex);
    const tampered = binding.filter((b) => !b[1]);
    console.log(`prompt/model binding: ${tampered.length ? 'TAMPERED -> dispute with `sealedbounty dispute --claim ' + c.id + '`' : 'PASS (matches program)'}`);
    for (const t of tampered) console.log(`  FAIL ${t[0]}: ${t[2]}`);
    const u = splitUserMessage(body);
    if (u.target) {
      console.log(`\n-- TARGET ${u.target}\n-- CODE\n${u.code}\n-- REPORT\n${u.report}`);
    } else {
      console.log(`\n-- USER MESSAGE (non-canonical format)\n${u.raw}`);
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
  const binding = promptBindingChecks(body, program, api.sha256hex);
  const bindingOk = printChecks('Prompt/model binding (a dispute succeeds only if one of these FAILS)', binding);
  const args = disputeArgs(c.id, body);
  showArgs('dispute', args);
  if (o.dryRun) return console.log('\n--dry-run: not sent.');
  if (!rows.every((r) => r[1]) && !o.force) throw new Error('preconditions failed; not sending (use --force)');
  if (bindingOk && !o.force) throw new Error('request matches the program prompt and model: the contract would panic "dispute invalid: prompt matches" (use --force)');
  const r = await callContract(loadAccount(o.account), 'dispute', args, { gas: GAS.dispute });
  if (!r.ok) process.exitCode = 1;
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
      rows.push(...promptBindingChecks(body, program, api.sha256hex).map(([n, ok, d]) => [`[owner] ${n}`, ok, d] as CheckRow));
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
