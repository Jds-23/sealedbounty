import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { runFrontrun, runLoop } from '../src/flows.mjs';
import { toJudgeRecord } from '../src/validate.mjs';
import { FAKE_PRIVATE_KEY, fakeChain, makeJudgement } from './helpers.mjs';

const HUNTER = 'hunter.baldingsucks7993.testnet';
const FRONTRUN = 'frontrun.baldingsucks7993.testnet';
const OWNER = 'baldingsucks7993.testnet';
const seq = (events) => events.map((e) => `${e.step}:${e.status ?? e.outcome}`);
const collect = () => {
  const events = [];
  return { events, emit: (e) => events.push(e) };
};

describe('runLoop (honest loop on program 2)', () => {
  it('submit (hunter) -> flag (owner) -> prove (hunter) -> countdown -> finalize -> Paid', async () => {
    const deps = fakeChain();
    const { events, emit } = collect();
    const record = toJudgeRecord(makeJudgement());
    const out = await runLoop({ record, programId: 2, hunter: HUNTER, deps, emit, marginMs: 0 });

    assert.equal(out, 'Paid');
    assert.deepEqual(
      deps.calls.map((c) => c.slice(0, 2)),
      [
        ['submit', HUNTER],
        ['flag', OWNER],
        ['prove', HUNTER],
        ['finalize', HUNTER],
      ],
    );
    assert.deepEqual(seq(events), [
      'submit_claim:pending',
      'submit_claim:done',
      'flag_undecryptable:pending',
      'flag_undecryptable:done',
      'prove_ciphertext:pending',
      'prove_ciphertext:done',
      'wait:pending',
      'wait:pending',
      'wait:pending',
      'wait:pending',
      'wait:pending',
      'wait:done',
      'finalize:pending',
      'finalize:done',
      'end:Paid',
    ]);
    // countdown 5..1 s, every done event of a write carries its tx hash, all carry the claim id
    assert.deepEqual(events.filter((e) => e.step === 'wait' && e.status === 'pending').map((e) => e.remaining), [5, 4, 3, 2, 1]);
    for (const e of events.filter((e) => e.status === 'done' && e.step !== 'wait')) assert.match(e.tx, /^Tx1+\d+$/, e.step);
    assert.ok(events.filter((e) => e.step !== 'submit_claim' || e.status === 'done').every((e) => e.claimId === 7));
    assert.equal(events.at(-1).claimId, 7);
  });

  it('a failing step emits error then end:error and stops', async () => {
    const deps = fakeChain();
    deps.flagUndecryptable = async () => {
      throw new Error(`dispute window closed ${FAKE_PRIVATE_KEY}`);
    };
    const { events, emit } = collect();
    const out = await runLoop({ record: toJudgeRecord(makeJudgement()), programId: 2, hunter: HUNTER, deps, emit, marginMs: 0 });
    assert.equal(out, 'error');
    assert.deepEqual(seq(events), ['submit_claim:pending', 'submit_claim:done', 'flag_undecryptable:pending', 'flag_undecryptable:error', 'end:error']);
    assert.match(events.at(-2).message, /dispute window closed/);
    assert.ok(!deps.calls.some((c) => c[0] === 'prove'));
  });

  it('a write that lands but leaves the wrong onchain status is an error', async () => {
    const deps = fakeChain();
    const flag = deps.flagUndecryptable;
    deps.flagUndecryptable = async (a) => {
      const r = await flag(a);
      deps.claims.get(a.claimId).status = 'Pending';
      return r;
    };
    const { events, emit } = collect();
    assert.equal(await runLoop({ record: toJudgeRecord(makeJudgement()), programId: 2, hunter: HUNTER, deps, emit, marginMs: 0 }), 'error');
    const err = events.find((e) => e.status === 'error');
    assert.equal(err.step, 'flag_undecryptable');
    assert.match(err.message, /expected Challenged/);
    assert.ok(err.tx, 'the landed tx is still reported');
  });

  it('the finalize outcome is whatever the chain says (e.g. Rejected)', async () => {
    const deps = fakeChain();
    deps.finalize = async ({ claimId }) => {
      Object.assign(deps.claims.get(claimId), { status: 'Rejected', reject_reason: 'signer revoked' });
      return { tx: 'TxF' };
    };
    const { events, emit } = collect();
    const out = await runLoop({ record: toJudgeRecord(makeJudgement()), programId: 2, hunter: HUNTER, deps, emit, marginMs: 0 });
    assert.equal(out, 'Rejected: signer revoked');
    assert.equal(events.at(-1).outcome, 'Rejected: signer revoked');
  });
});

describe('runFrontrun', () => {
  it('fresh judgement -> submit from frontrun -> owner dispute -> Rejected hunter mismatch', async () => {
    const deps = fakeChain();
    const { events, emit } = collect();
    const out = await runFrontrun({ programId: 2, hunter: HUNTER, frontrun: FRONTRUN, deps, emit });
    assert.equal(out, 'Rejected: hunter mismatch');
    assert.deepEqual(
      deps.calls.map((c) => c.slice(0, 2)),
      [
        ['judge', '# SQLi in /users'],
        ['submit', FRONTRUN],
        ['dispute', OWNER],
      ],
    );
    assert.deepEqual(seq(events), ['judge:pending', 'judge:done', 'submit_claim:pending', 'submit_claim:done', 'dispute:pending', 'dispute:done', 'end:Rejected: hunter mismatch']);
    assert.ok(events.find((e) => e.step === 'dispute' && e.status === 'done').tx);
  });

  it('uses a given judgement (no judge call) and with resubmit the real hunter resubmits the same req_hash', async () => {
    const deps = fakeChain();
    const { events, emit } = collect();
    const record = toJudgeRecord(makeJudgement());
    const out = await runFrontrun({ record, resubmit: true, programId: 2, hunter: HUNTER, frontrun: FRONTRUN, deps, emit });
    assert.equal(out, 'Rejected: hunter mismatch');
    assert.deepEqual(
      deps.calls.map((c) => c.slice(0, 2)),
      [
        ['submit', FRONTRUN],
        ['dispute', OWNER],
        ['submit', HUNTER],
      ],
    );
    assert.equal(deps.calls[0][2], deps.calls[2][2], 'same req_hash resubmitted');
    assert.deepEqual(seq(events), ['submit_claim:pending', 'submit_claim:done', 'dispute:pending', 'dispute:done', 'resubmit:pending', 'resubmit:done', 'end:Rejected: hunter mismatch']);
    const re = events.find((e) => e.step === 'resubmit' && e.status === 'done');
    assert.equal(re.claimId, 8);
    assert.ok(re.tx);
  });

  it('a dispute that does not end in hunter mismatch is an error', async () => {
    const deps = fakeChain();
    deps.dispute = async () => {
      throw new Error('request matches the program');
    };
    const { events, emit } = collect();
    assert.equal(await runFrontrun({ record: toJudgeRecord(makeJudgement()), programId: 2, hunter: HUNTER, frontrun: FRONTRUN, deps, emit }), 'error');
    assert.deepEqual(seq(events).slice(-2), ['dispute:error', 'end:error']);
  });
});
