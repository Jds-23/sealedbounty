// The local-only demo helper (docs/demo-app-spec.md §8): plain node:http, CORS for the tour origin
// only, one request at a time, no secret ever sent (free text redacted, signed data scanned, never rewritten).
//   GET  /health                -> {ok:true, programId, contractId} | {ok:false, reason}
//   POST /judge {exploitMarkdown} -> judgement JSON (see validate.mjs)
//   POST /loop {judgement}      -> SSE: submit_claim, flag_undecryptable, prove_ciphertext, wait, finalize, end
//   POST /frontrun {judgement?} -> SSE: [judge], submit_claim, dispute, [resubmit (?resubmit=1)], end
import { createServer } from 'node:http';
import { PREFLIGHT_HEADERS, corsHeaders, originAllowed } from './cors.mjs';
import { runFrontrun, runLoop } from './flows.mjs';
import { createMutex } from './mutex.mjs';
import { makeRedactor, makeSecretScanner, secretsFromEnv } from './redact.mjs';
import { openSse } from './sse.mjs';
import { judgeResponse, toJudgeRecord, validateJudgeRequest, validateJudgement, withRunTrailer } from './validate.mjs';

export const MAX_BODY_BYTES = 1024 * 1024;
const ROUTES = { '/health': 'GET', '/judge': 'POST', '/loop': 'POST', '/frontrun': 'POST' };
const errText = (e) => (e instanceof Error ? e.message : String(e));

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size <= MAX_BODY_BYTES) chunks.push(c); // keep draining so the 413 reaches the client
    });
    req.on('end', () => {
      if (size > MAX_BODY_BYTES) return reject(new HttpError(413, `body over ${MAX_BODY_BYTES} bytes`));
      const text = Buffer.concat(chunks).toString('utf8');
      if (!text.trim()) return resolve(undefined);
      try {
        resolve(JSON.parse(text));
      } catch {
        reject(new HttpError(400, 'body is not valid JSON'));
      }
    });
    req.on('error', reject);
  });
}

/**
 * @param {{config: {programId: number|null, contractId: string, apiKey?: string, env?: object, hunter: string, frontrun: string, marginMs?: number},
 *          deps: object, log?: (...a: unknown[]) => void}} o
 */
export function createHelperServer({ config, deps, log = console.error }) {
  // Redaction policy: free text (error/message fields, logs) is pattern + literal redacted. Structured
  // success data (judgements, tx hashes) is never rewritten, because it is signed and hashed; it is only
  // scanned for the literal secrets, and a payload containing one is refused.
  const secrets = [config.apiKey, ...secretsFromEnv(config.env ?? {})].filter(Boolean);
  const redact = makeRedactor(secrets);
  const hasSecret = makeSecretScanner(secrets);
  const REFUSED = 'refused: payload contained a configured secret (not sent)';
  const say = (...a) => log(redact(a.map((x) => (typeof x === 'string' ? x : JSON.stringify(x))).join(' ')));
  const mutex = createMutex();
  /** req_hashes this process judged (shared judge() checked the signer against a fresh attestation). */
  const attested = new Set();
  const remember = (h) => {
    attested.add(h);
    if (attested.size > 100) attested.delete(attested.values().next().value);
  };

  function sendJson(res, status, body, headers) {
    if (status >= 400) body = { error: redact(body?.error ?? 'error') };
    else if (hasSecret(body)) {
      say(REFUSED);
      status = 500;
      body = { error: REFUSED };
    }
    const text = JSON.stringify(body);
    res.writeHead(status, { ...headers, 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
    res.end(text);
  }

  function lock(name) {
    const release = mutex.tryAcquire(name);
    if (!release) throw new HttpError(409, `busy: ${mutex.holder()} is running; one request at a time`);
    return release;
  }

  function judgementRecord(j) {
    const v = validateJudgement(j);
    if (!v.ok) throw new HttpError(400, v.error);
    const record = toJudgeRecord(j, { attested: attested.has(j.req_hash) });
    if (!record.signer_in_attestation) throw new HttpError(400, 'judgement is not attested (signer_in_attestation): judge it with POST /judge on this helper first');
    return record;
  }

  /** SSE: only `message` is free text; every other field passes through untouched, or the event is refused. */
  function safeEvent(e) {
    const { message, ...data } = e;
    if (hasSecret(data)) {
      say(REFUSED);
      return { step: e.step, status: 'error', message: REFUSED };
    }
    return message === undefined ? data : { ...data, message: redact(message) };
  }

  async function stream(res, cors, name, run) {
    const release = lock(name);
    const sse = openSse(res, { headers: cors, transform: safeEvent });
    const emit = (e) => {
      sse.send(e);
      if (e.status === 'error' || e.step === 'end') say(`[${name}]`, e);
    };
    try {
      await run(emit);
    } finally {
      release();
      sse.end();
    }
  }

  async function handle(req, res) {
    const url = new URL(req.url ?? '/', 'http://localhost');
    const origin = req.headers.origin;
    if (!originAllowed(origin)) {
      req.resume();
      return sendJson(res, 403, { error: 'origin not allowed' }, { Vary: 'Origin' });
    }
    const cors = corsHeaders(origin);
    if (req.method === 'OPTIONS') {
      res.writeHead(204, { ...cors, ...PREFLIGHT_HEADERS });
      return res.end();
    }
    const method = ROUTES[url.pathname];
    if (!method) return sendJson(res, 404, { error: 'not found' }, cors);
    if (req.method !== method) return sendJson(res, 405, { error: `use ${method}` }, { ...cors, Allow: `${method}, OPTIONS` });

    if (url.pathname === '/health') {
      return sendJson(
        res,
        200,
        config.programId === null
          ? { ok: false, reason: 'DEMO_LIVE_PROGRAM_ID is not set in .env (see demo-helper/README.md, program 2 setup)', contractId: config.contractId }
          : { ok: true, programId: config.programId, contractId: config.contractId },
        cors,
      );
    }

    const body = await readBody(req);
    if (config.programId === null) throw new HttpError(503, 'DEMO_LIVE_PROGRAM_ID is not set in .env');
    const programId = config.programId;

    if (url.pathname === '/judge') {
      const v = validateJudgeRequest(body);
      if (!v.ok) throw new HttpError(400, v.error);
      const release = lock('judge');
      try {
        const { report, runId } = withRunTrailer(v.value.exploitMarkdown);
        const out = judgeResponse(await deps.judge({ exploitMarkdown: report }));
        if (out.signer_in_attestation) remember(out.req_hash);
        return sendJson(res, 200, { ...out, runId }, cors);
      } catch (e) {
        throw new HttpError(502, `judge failed: ${errText(e)}`);
      } finally {
        release();
      }
    }

    if (url.pathname === '/loop') {
      if (!body || typeof body !== 'object') throw new HttpError(400, 'body must be {judgement}');
      const record = judgementRecord(body.judgement);
      return stream(res, cors, 'loop', (emit) => runLoop({ record, programId, hunter: config.hunter, deps, emit, marginMs: config.marginMs ?? 2000 }));
    }

    // /frontrun
    const b = body ?? {};
    if (typeof b !== 'object' || Array.isArray(b)) throw new HttpError(400, 'body must be {judgement?}');
    const record = b.judgement === undefined || b.judgement === null ? undefined : judgementRecord(b.judgement);
    const resubmit = url.searchParams.get('resubmit') === '1' || b.resubmit === true;
    return stream(res, cors, 'frontrun', (emit) => runFrontrun({ record, resubmit, programId, hunter: config.hunter, frontrun: config.frontrun, deps, emit }));
  }

  return createServer((req, res) => {
    const started = Date.now();
    res.on('finish', () => say(`${req.method} ${req.url} -> ${res.statusCode} (${Date.now() - started} ms)`));
    handle(req, res).catch((e) => {
      const status = e instanceof HttpError ? e.status : 500;
      if (status >= 500) say(`error: ${errText(e)}`);
      if (res.headersSent) return res.end();
      sendJson(res, status, { error: errText(e) }, corsHeaders(req.headers.origin));
    });
  });
}
