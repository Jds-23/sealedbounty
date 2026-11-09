// Client for the optional local demo-helper (docs/demo-app-spec.md §4, §8). Local only: it holds the NEAR AI key and
// the testnet keys; the browser only ever sees verdicts, signatures and tx hashes. Every call is tolerant of missing
// or extra fields: the helper is built in parallel to this contract.
//   GET  /health            -> {ok:true, programId}
//   POST /judge {exploitMarkdown} -> {verdict, signature, chat_id, request_body, response_body_b64, req_hash, signer, kind}
//   POST /loop {judgement}  -> SSE {step, status:'pending'|'done'|'error', tx?, claimId?, message?} ... {step:'end', outcome}
//   POST /frontrun {judgement?} -> SSE (same)

export const HELPER_URL: string = (import.meta.env.VITE_DEMO_HELPER as string | undefined) || 'http://localhost:8787';

export interface HelperHealth {
  /** false = the helper answers but is not configured (e.g. DEMO_LIVE_PROGRAM_ID unset): live lanes stay hidden. */
  ok: boolean;
  programId: number | null;
  contractId: string | null;
  reason: string | null;
}

export interface Judgement {
  verdict: { valid: boolean; severity: string; cwe: string | null; confidence: number } | null;
  signature: string;
  chat_id: string | null;
  request_body: string | null;
  response_body_b64: string | null;
  req_hash: string | null;
  signer: string | null;
  kind: string | null;
  /** The raw helper answer, passed back verbatim to /loop and /frontrun. */
  raw: Record<string, unknown>;
}

export interface HelperEvent {
  step: string;
  status?: 'pending' | 'done' | 'error' | string;
  tx?: string;
  claimId?: number;
  message?: string;
  outcome?: unknown;
  /** wait step: seconds left until finalize */
  remaining?: number;
  [k: string]: unknown;
}

/**
 * GET /health within 1 s. null = no helper (absent, slow, not JSON). {ok:false, reason} = present but not configured.
 */
export async function probeHelper(timeoutMs = 1000): Promise<HelperHealth | null> {
  try {
    const r = await fetch(`${HELPER_URL}/health`, { signal: AbortSignal.timeout(timeoutMs) });
    const j = await r.json().catch(() => null);
    if (!j || typeof j !== 'object') return null;
    const pid = Number(j.programId ?? j.program_id);
    const ok = j.ok === true && r.ok;
    return {
      ok,
      programId: Number.isInteger(pid) && j.programId != null ? pid : null,
      contractId: typeof j.contractId === 'string' ? j.contractId : null,
      reason: ok ? null : String(j.reason ?? j.error ?? `HTTP ${r.status}`),
    };
  } catch {
    return null;
  }
}

const errText = async (r: Response) => {
  if (r.status === 409) return 'helper busy: another live write is running, try again when it ends';
  const t = await r.text().catch(() => '');
  try {
    const j = JSON.parse(t);
    return String(j.error ?? j.message ?? t);
  } catch {
    return t || `HTTP ${r.status}`;
  }
};

const s = (v: unknown) => (typeof v === 'string' ? v : null);

export async function judgeLive(exploitMarkdown: string, signal?: AbortSignal): Promise<Judgement> {
  const r = await fetch(`${HELPER_URL}/judge`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ exploitMarkdown }),
    signal: signal ?? AbortSignal.timeout(180_000),
  });
  if (!r.ok) throw new Error(`helper /judge: ${(await errText(r)).slice(0, 300)}`);
  const j = (await r.json()) as Record<string, any>;
  const v = j.verdict ?? null;
  if (!s(j.signature)) throw new Error('helper /judge: no signature in the answer');
  return {
    verdict: v && typeof v === 'object' ? { valid: !!v.valid, severity: String(v.severity ?? 'none'), cwe: v.cwe ?? null, confidence: Number(v.confidence ?? 0) } : null,
    signature: j.signature,
    chat_id: s(j.chat_id) ?? s(j.chatId),
    request_body: s(j.request_body),
    response_body_b64: s(j.response_body_b64),
    req_hash: s(j.req_hash),
    signer: s(j.signer) ?? s(j.signing_address),
    kind: s(j.kind) ?? s(j.signature_kind),
    raw: j,
  };
}

/**
 * Incremental SSE parser: returns the complete events in `buf` and the unparsed tail. Accepts `data:` lines
 * (multi-line data joined), bare JSON lines, CRLF; ignores comments, `event:`/`id:`/`retry:` and junk.
 */
export function parseSSE(buf: string): { events: HelperEvent[]; rest: string } {
  const text = buf.replace(/\r\n?/g, '\n');
  const cut = text.lastIndexOf('\n');
  const complete = cut < 0 ? '' : text.slice(0, cut + 1);
  const rest = cut < 0 ? text : text.slice(cut + 1);
  const events: HelperEvent[] = [];
  let data: string[] = [];
  const flush = () => {
    if (!data.length) return;
    const payload = data.join('\n');
    data = [];
    try {
      const ev = JSON.parse(payload);
      if (ev && typeof ev === 'object' && typeof ev.step === 'string') events.push(ev);
    } catch {
      /* junk */
    }
  };
  for (const line of complete.split('\n')) {
    if (line === '') flush();
    else if (line.startsWith('data:')) data.push(line.slice(5).replace(/^ /, ''));
    else if (line.startsWith(':') || /^(event|id|retry):/.test(line)) continue;
    else if (line.trimStart().startsWith('{')) {
      flush();
      data.push(line);
      flush();
    }
  }
  // a data: block whose blank separator hasn't arrived yet stays in the tail
  const pending = data.length ? data.map((d) => `data: ${d}\n`).join('') : '';
  return { events, rest: pending + rest };
}

/** POST an SSE endpoint; calls onEvent for each event; resolves with the final {step:'end'} event. */
export async function streamHelper(path: '/loop' | '/frontrun' | '/frontrun?resubmit=1', body: unknown, onEvent: (e: HelperEvent) => void, signal?: AbortSignal): Promise<HelperEvent> {
  const r = await fetch(`${HELPER_URL}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'text/event-stream' },
    body: JSON.stringify(body ?? {}),
    signal,
  });
  if (!r.ok || !r.body) throw new Error(`helper ${path}: ${(await errText(r)).slice(0, 300)}`);
  const reader = r.body.getReader();
  const dec = new TextDecoder();
  let buf = '';
  let end: HelperEvent | null = null;
  let lastErr: HelperEvent | null = null;
  for (;;) {
    const { value, done } = await reader.read();
    buf += done ? '\n\n' : dec.decode(value, { stream: true });
    const { events, rest } = parseSSE(buf);
    buf = rest;
    for (const e of events) {
      if (e.step === 'end') end = e;
      else {
        if (e.status === 'error') lastErr = e;
        onEvent(e);
      }
    }
    if (end || done) break;
  }
  reader.cancel().catch(() => {});
  if (end) return end;
  throw new Error(`helper ${path}: stream ended without an end event${lastErr?.message ? ` (${lastErr.message})` : ''}`);
}

// ---- the session's live judgement (step 4) and its reuse in steps 6 and 7 ----
// The contract dedupes req_hash per program and a Paid claim never releases it, so a judgement is single-use: the
// first submit_claim that lands consumes it, and a second submit panics "already claimed".

export interface LiveJudgementState {
  judgement: Judgement | null;
  /** The report it judged, so a consumed judgement can be re-judged (the helper adds a run-unique trailer). */
  markdown: string | null;
  /** A submit_claim with this judgement landed (/loop or /frontrun). */
  consumed: boolean;
}

export const NO_JUDGEMENT: LiveJudgementState = { judgement: null, markdown: null, consumed: false };

export type JudgementAction = { type: 'judged'; judgement: Judgement; markdown: string } | { type: 'event'; event: HelperEvent };

export const consumesJudgement = (e: HelperEvent) => e.step === 'submit_claim' && e.status === 'done';

export function judgementReducer(s: LiveJudgementState, a: JudgementAction): LiveJudgementState {
  if (a.type === 'judged') return { judgement: a.judgement, markdown: a.markdown, consumed: false };
  if (!s.judgement || s.consumed || !consumesJudgement(a.event)) return s;
  return { ...s, consumed: true };
}

const usable = (s: LiveJudgementState) => (s.judgement && !s.consumed ? s.judgement : null);

/** /frontrun copies the step-4 judgement while it is unused; otherwise {} and the helper judges fresh. */
export const frontrunBody = (s: LiveJudgementState): { judgement?: Record<string, unknown> } => {
  const j = usable(s);
  return j ? { judgement: j.raw } : {};
};

export class JudgementUnavailableError extends Error {
  constructor(readonly reason: 'consumed' | 'absent') {
    super(reason === 'consumed' ? 'this judgement was already submitted: judge again in step 4' : 'judge a report live in step 4 first');
  }
}

type Track = (a: JudgementAction) => void;
const tracked = (onEvent: (e: HelperEvent) => void, track: Track) => (e: HelperEvent) => {
  onEvent(e);
  track({ type: 'event', event: e });
};

export function runLiveFrontrun(s: LiveJudgementState, onEvent: (e: HelperEvent) => void, track: Track, signal?: AbortSignal): Promise<HelperEvent> {
  return streamHelper('/frontrun', frontrunBody(s), tracked(onEvent, track), signal);
}

/**
 * /loop with the session judgement. A consumed (or missing) one is refused, unless `autoFresh` (autoplay &live=1):
 * then it judges the same report again first (fresh req_hash) and submits that.
 */
export async function runLiveLoop(
  s: LiveJudgementState,
  onEvent: (e: HelperEvent) => void,
  track: Track,
  opts: { autoFresh?: boolean; fallbackMarkdown?: string; signal?: AbortSignal } = {},
): Promise<HelperEvent> {
  let j = usable(s);
  if (!j) {
    const md = s.markdown ?? opts.fallbackMarkdown;
    if (!opts.autoFresh || !md) throw new JudgementUnavailableError(s.consumed ? 'consumed' : 'absent');
    onEvent({ step: 'judge', status: 'pending', message: s.consumed ? 'the last judgement was already submitted: judging again' : 'judging the report in the TEE' });
    try {
      j = await judgeLive(md, opts.signal);
    } catch (e) {
      onEvent({ step: 'judge', status: 'error', message: (e as Error).message });
      throw e;
    }
    track({ type: 'judged', judgement: j, markdown: md });
    onEvent({ step: 'judge', status: 'done' });
  }
  return streamHelper('/loop', { judgement: j.raw }, tracked(onEvent, track), opts.signal);
}
