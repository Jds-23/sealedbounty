// The two live-lane flows (spec §5 steps 6 and 7). Pure sequencing over injected deps, so the tests
// drive them against a fake chain. Every event is {step, status:'pending'|'done'|'error', tx?, claimId?,
// message?, remaining?}; the last one is {step:'end', outcome, claimId?, message?}.
//
// deps: submit({record, account}) -> {tx, claimId}; flagUndecryptable / proveCiphertext / finalize /
//       dispute({claimId, account}) -> {tx}; getProgram(id); getClaim(id); judge({exploitMarkdown});
//       defaultExploit(); now() ms; sleep(ms)
import { judgeResponse, toJudgeRecord } from './validate.mjs';

class StepError extends Error {
  constructor(message, tx) {
    super(message);
    this.tx = tx;
  }
}

const errText = (e) => (e instanceof Error ? e.message : String(e));

/** Runs one step: pending -> fn -> done (or error). Returns fn's result. */
async function step(emit, name, base, message, fn, { pending = true } = {}) {
  if (pending) emit({ step: name, status: 'pending', ...base, ...(message ? { message } : {}) });
  try {
    const r = (await fn()) ?? {};
    emit({ step: name, status: 'done', ...base, ...r.event });
    return r;
  } catch (e) {
    emit({ step: name, status: 'error', ...base, ...(e?.tx ? { tx: e.tx } : {}), message: errText(e) });
    throw Object.assign(e instanceof Error ? e : new Error(String(e)), { emitted: true });
  }
}

async function expectStatus(deps, claimId, want, tx) {
  const c = await deps.getClaim(claimId);
  if (!c) throw new StepError(`claim ${claimId} not found after the tx`, tx);
  if (c.status !== want) throw new StepError(`claim ${claimId} is ${c.status}${c.reject_reason ? ` (${c.reject_reason})` : ''}, expected ${want}`, tx);
  return c;
}

const outcomeOf = (c) => (c.status === 'Rejected' ? `Rejected: ${c.reject_reason ?? '?'}` : c.status);

async function guarded(emit, body) {
  const ctx = { claimId: undefined };
  try {
    return await body(ctx);
  } catch (e) {
    if (!e?.emitted) emit({ step: 'setup', status: 'error', message: errText(e) });
    emit({ step: 'end', outcome: 'error', ...(ctx.claimId !== undefined ? { claimId: ctx.claimId } : {}), message: errText(e) });
    return 'error';
  }
}

/**
 * Honest loop: submit_claim (hunter) -> flag_undecryptable (owner) -> prove_ciphertext (hunter)
 * -> wait until finalize_after (countdown) -> finalize -> end (Paid).
 */
export function runLoop({ record, programId, hunter, deps, emit, marginMs = 2000 }) {
  return guarded(emit, async (ctx) => {
    const program = await deps.getProgram(programId);
    if (!program) throw new Error(`program ${programId} not found`);
    const owner = program.owner;

    const sub = await step(emit, 'submit_claim', {}, `${hunter} submits the sealed report to program ${programId}`, async () => {
      const r = await deps.submit({ record, account: hunter });
      ctx.claimId = r.claimId;
      await expectStatus(deps, r.claimId, 'Pending', r.tx);
      return { event: { tx: r.tx, claimId: r.claimId } };
    });
    const claimId = sub.event.claimId;
    const base = { claimId };

    await step(emit, 'flag_undecryptable', base, `owner ${owner} claims the report is unreadable`, async () => {
      const r = await deps.flagUndecryptable({ claimId, account: owner });
      await expectStatus(deps, claimId, 'Challenged', r.tx);
      return { event: { tx: r.tx } };
    });

    await step(emit, 'prove_ciphertext', base, `${hunter} reveals the ephemeral key; the contract decrypts the report`, async () => {
      const r = await deps.proveCiphertext({ claimId, account: hunter });
      await expectStatus(deps, claimId, 'Pending', r.tx);
      return { event: { tx: r.tx } };
    });

    await step(emit, 'wait', base, undefined, async () => {
      const c = await deps.getClaim(claimId);
      const target = Number(BigInt(c.finalize_after) / 1_000_000n) + marginMs;
      let last;
      for (;;) {
        const left = target - deps.now();
        if (left <= 0) break;
        const s = Math.ceil(left / 1000);
        if (s !== last) emit({ step: 'wait', status: 'pending', ...base, remaining: s, message: `finalizable in ${s} s` });
        last = s;
        await deps.sleep(Math.min(1000, left - (s - 1) * 1000));
      }
      return { event: { remaining: 0, message: 'dispute window closed' } };
    }, { pending: false }); // the countdown events are the pending ones

    let final;
    await step(emit, 'finalize', base, 'anyone settles the claim', async () => {
      const r = await deps.finalize({ claimId, account: hunter });
      final = await deps.getClaim(claimId);
      if (!final) throw new StepError(`claim ${claimId} not found after finalize`, r.tx);
      return { event: { tx: r.tx, message: outcomeOf(final) } };
    });
    const outcome = outcomeOf(final);
    emit({ step: 'end', outcome, claimId });
    return outcome;
  });
}

/**
 * Front-run: (fresh hunter-bound judgement) -> submit_claim from the front-runner -> owner dispute
 * (reveals the request body; HUNTER line != claim.hunter) -> Rejected "hunter mismatch"
 * -> optionally the real hunter resubmits the same judgement (req_hash was released).
 */
export function runFrontrun({ record, resubmit = false, programId, hunter, frontrun, deps, emit }) {
  return guarded(emit, async (ctx) => {
    const program = await deps.getProgram(programId);
    if (!program) throw new Error(`program ${programId} not found`);
    const owner = program.owner;

    if (!record) {
      await step(emit, 'judge', {}, `fresh TEE judgement bound to HUNTER ${hunter}`, async () => {
        const j = judgeResponse(await deps.judge({ exploitMarkdown: await deps.defaultExploit() }));
        record = toJudgeRecord(j, { attested: true });
        return { event: { message: j.verdict ? `${j.verdict.valid ? 'valid' : 'invalid'} ${j.verdict.severity} (${j.verdict.confidence})` : 'judged', chat_id: j.chat_id } };
      });
    }

    const sub = await step(emit, 'submit_claim', {}, `${frontrun} copies the signed verdict and submits it`, async () => {
      const r = await deps.submit({ record, account: frontrun });
      ctx.claimId = r.claimId;
      await expectStatus(deps, r.claimId, 'Pending', r.tx);
      return { event: { tx: r.tx, claimId: r.claimId } };
    });
    const claimId = sub.event.claimId;

    let rejected;
    await step(emit, 'dispute', { claimId }, `owner ${owner} reveals the request body onchain`, async () => {
      const r = await deps.dispute({ claimId, account: owner });
      rejected = await expectStatus(deps, claimId, 'Rejected', r.tx);
      if (rejected.reject_reason !== 'hunter mismatch') throw new StepError(`rejected "${rejected.reject_reason}", expected "hunter mismatch"`, r.tx);
      return { event: { tx: r.tx, message: outcomeOf(rejected) } };
    });
    const outcome = outcomeOf(rejected);

    if (resubmit) {
      await step(emit, 'resubmit', {}, `the real hunter ${hunter} resubmits the same judgement`, async () => {
        const r = await deps.submit({ record, account: hunter });
        await expectStatus(deps, r.claimId, 'Pending', r.tx);
        return { event: { tx: r.tx, claimId: r.claimId } };
      });
    }
    emit({ step: 'end', outcome, claimId });
    return outcome;
  });
}
