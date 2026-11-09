// Live judgement reuse across steps 4 → 6 → 7. A judgement's req_hash is consumed by the first submit_claim that
// lands (the contract dedupes req_hash per program and a Paid claim never releases it), so a second submit of the
// same judgement panics "already claimed". These tests pin the consumed-state transitions and what the browser sends
// to the helper's /loop and /frontrun (fetch + SSE mocked).
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  consumesJudgement,
  frontrunBody,
  JudgementUnavailableError,
  judgementReducer,
  NO_JUDGEMENT,
  runLiveFrontrun,
  runLiveLoop,
  type HelperEvent,
  type Judgement,
  type LiveJudgementState,
} from './helper';

const judgement = (tag: string): Judgement => ({
  verdict: { valid: true, severity: 'critical', cwe: 'CWE-89', confidence: 100 },
  signature: `sig-${tag}`,
  chat_id: `chat-${tag}`,
  request_body: `{"tag":"${tag}"}`,
  response_body_b64: 'e30=',
  req_hash: tag.padEnd(64, '0'),
  signer: 'ed25519:' + 'a'.repeat(64),
  kind: 'provider_tee',
  raw: { tag, signature: `sig-${tag}` },
});

const J1 = judgement('one');
const judged: LiveJudgementState = judgementReducer(NO_JUDGEMENT, { type: 'judged', judgement: J1, markdown: '# sqli' });
const ev = (step: string, status: string, extra: Partial<HelperEvent> = {}): HelperEvent => ({ step, status, ...extra });

describe('consumed-state transitions', () => {
  it('starts with no judgement, not consumed', () => {
    expect(NO_JUDGEMENT).toEqual({ judgement: null, markdown: null, consumed: false });
  });

  it('a new judgement is fresh (not consumed) and remembers its markdown', () => {
    expect(judged).toEqual({ judgement: J1, markdown: '# sqli', consumed: false });
  });

  it('submit_claim done consumes it (from /loop or /frontrun)', () => {
    expect(consumesJudgement(ev('submit_claim', 'done', { tx: 'T', claimId: 8 }))).toBe(true);
    expect(judgementReducer(judged, { type: 'event', event: ev('submit_claim', 'done', { claimId: 8 }) }).consumed).toBe(true);
  });

  it('pending/error submit_claim and other steps do not consume it', () => {
    for (const e of [ev('submit_claim', 'pending'), ev('submit_claim', 'error', { message: 'already claimed' }), ev('setup', 'done'), ev('judge', 'done'), ev('finalize', 'done')]) {
      expect(consumesJudgement(e)).toBe(false);
      expect(judgementReducer(judged, { type: 'event', event: e })).toBe(judged);
    }
  });

  it('judging again resets consumed', () => {
    const used = judgementReducer(judged, { type: 'event', event: ev('submit_claim', 'done') });
    const J2 = judgement('two');
    expect(judgementReducer(used, { type: 'judged', judgement: J2, markdown: '# idor' })).toEqual({ judgement: J2, markdown: '# idor', consumed: false });
  });

  it('events with no judgement held change nothing', () => {
    expect(judgementReducer(NO_JUDGEMENT, { type: 'event', event: ev('submit_claim', 'done') })).toBe(NO_JUDGEMENT);
  });
});

describe('/frontrun request body', () => {
  it('sends the step-4 judgement while it is unused', () => {
    expect(frontrunBody(judged)).toEqual({ judgement: J1.raw });
  });
  it('sends {} once consumed (the helper judges fresh with a run trailer)', () => {
    expect(frontrunBody({ ...judged, consumed: true })).toEqual({});
  });
  it('sends {} with no judgement', () => {
    expect(frontrunBody(NO_JUDGEMENT)).toEqual({});
  });
});

// ---- mocked helper: JSON for /judge, SSE for /loop and /frontrun ----

const sse = (events: object[]) => events.map((e) => `data: ${JSON.stringify(e)}\n\n`).join('');

function mockHelper(streams: Record<string, object[]>, judgeAnswer: Record<string, unknown> = { ...J1.raw }) {
  const calls: { path: string; body: any }[] = [];
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string, init: RequestInit) => {
      const path = new URL(url).pathname;
      const body = init.body ? JSON.parse(String(init.body)) : null;
      calls.push({ path, body });
      if (path === '/judge') return new Response(JSON.stringify(judgeAnswer), { status: 200, headers: { 'content-type': 'application/json' } });
      return new Response(sse(streams[path] ?? []), { status: 200, headers: { 'content-type': 'text/event-stream' } });
    }),
  );
  return calls;
}

afterEach(() => vi.unstubAllGlobals());

describe('step 6 → step 7 against a mocked helper', () => {
  const LOOP = [ev('submit_claim', 'pending'), ev('submit_claim', 'done', { tx: 'SUB', claimId: 8 }), ev('finalize', 'done', { tx: 'FIN' }), { step: 'end', outcome: 'Paid' }];
  const FR = [ev('judge', 'done'), ev('submit_claim', 'done', { tx: 'FR', claimId: 9 }), ev('dispute', 'done'), { step: 'end', outcome: 'Rejected: hunter mismatch' }];

  it('the loop submits the step-4 judgement and marks it consumed; the front-run then sends {}', async () => {
    const calls = mockHelper({ '/loop': LOOP, '/frontrun': FR });
    let state = judged;
    const track = (a: Parameters<typeof judgementReducer>[1]) => (state = judgementReducer(state, a));

    const loopEnd = await runLiveLoop(state, () => {}, track);
    expect(loopEnd.outcome).toBe('Paid');
    expect(calls[0]).toEqual({ path: '/loop', body: { judgement: J1.raw } });
    expect(state.consumed).toBe(true);

    const frEnd = await runLiveFrontrun(state, () => {}, track);
    expect(frEnd.outcome).toMatch(/hunter mismatch/);
    expect(calls[1]).toEqual({ path: '/frontrun', body: {} });
  });

  it('a front-run with an unused judgement copies it, and consumes it', async () => {
    const calls = mockHelper({ '/frontrun': FR });
    let state = judged;
    await runLiveFrontrun(state, () => {}, (a) => (state = judgementReducer(state, a)));
    expect(calls).toEqual([{ path: '/frontrun', body: { judgement: J1.raw } }]);
    expect(state.consumed).toBe(true);
  });

  it('a failed front-run submit ("already claimed") does not consume the judgement', async () => {
    mockHelper({ '/frontrun': [ev('submit_claim', 'error', { message: 'already claimed' }), { step: 'end', outcome: 'error' }] });
    let state = judged;
    await runLiveFrontrun(state, () => {}, (a) => (state = judgementReducer(state, a)));
    expect(state.consumed).toBe(false);
  });

  it('the loop refuses a consumed judgement without calling the helper', async () => {
    const calls = mockHelper({ '/loop': LOOP });
    const used = { ...judged, consumed: true };
    await expect(runLiveLoop(used, () => {}, () => {})).rejects.toBeInstanceOf(JudgementUnavailableError);
    await expect(runLiveLoop(used, () => {}, () => {})).rejects.toThrow(/already submitted/);
    expect(calls).toEqual([]);
  });

  it('the loop refuses when nothing was judged', async () => {
    mockHelper({ '/loop': LOOP });
    await expect(runLiveLoop(NO_JUDGEMENT, () => {}, () => {})).rejects.toBeInstanceOf(JudgementUnavailableError);
  });

  it('autoFresh (autoplay &live=1): judges again with the same markdown, then submits the fresh one', async () => {
    const J2 = judgement('two');
    const calls = mockHelper({ '/loop': LOOP }, { ...J2.raw, signature: J2.signature });
    let state: LiveJudgementState = { ...judged, consumed: true };
    const seen: HelperEvent[] = [];
    await runLiveLoop(state, (e) => seen.push(e), (a) => (state = judgementReducer(state, a)), { autoFresh: true, fallbackMarkdown: '# fallback' });
    expect(calls.map((c) => c.path)).toEqual(['/judge', '/loop']);
    expect(calls[0].body).toEqual({ exploitMarkdown: '# sqli' });
    expect(calls[1].body).toEqual({ judgement: { ...J2.raw, signature: J2.signature } });
    expect(seen.filter((e) => e.step === 'judge').map((e) => e.status)).toEqual(['pending', 'done']);
    // the fresh judgement is now the held one, and the loop consumed it
    expect(state.judgement?.signature).toBe(J2.signature);
    expect(state.consumed).toBe(true);
  });

  it('autoFresh with nothing judged yet uses the fallback markdown', async () => {
    const calls = mockHelper({ '/loop': LOOP });
    await runLiveLoop(NO_JUDGEMENT, () => {}, () => {}, { autoFresh: true, fallbackMarkdown: '# fallback' });
    expect(calls[0]).toEqual({ path: '/judge', body: { exploitMarkdown: '# fallback' } });
  });
});
