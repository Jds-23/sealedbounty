// Request validation and the judgement <-> cli JudgeRecord mapping.
// The API shape (what POST /judge returns and /loop, /frontrun accept) is
//   {verdict, signature, chat_id, request_body, response_body_b64, req_hash, signer, kind}
// plus the optional extras resp_hash, model, signer_in_attestation.
// The cli's `sb submit --fixture` wants a JudgeRecord (fixtures/live.*.json shape); every extra field
// of it is derived from the API fields, and the cli re-verifies the signature itself before sending.
import { createHash, randomBytes } from 'node:crypto';

/**
 * The judge request is deterministic (temperature 0, same bundle, report and HUNTER), and the contract
 * dedupes req_hash per program ("already claimed"). So every live run appends a run-unique trailer to the
 * REPORT. It is hunter-controlled report text, so the code/params/hunter binding is untouched.
 * @returns {{report: string, runId: string}}
 */
export function withRunTrailer(markdown, { now = new Date(), rand = randomBytes(3).toString('hex') } = {}) {
  return { report: `${markdown}\n\n---\nDemo run: ${now.toISOString()} #${rand}`, runId: rand };
}

export const MAX_EXPLOIT_BYTES = 64 * 1024;
const MAX_REQUEST_BODY = 512 * 1024;

const sha256hex = (d) => createHash('sha256').update(d).digest('hex');
const HEX64 = /^[0-9a-f]{64}$/;
const SIGNER = /^(?:ed25519:[0-9a-f]{64}|eth:0x[0-9a-fA-F]{40})$/;
const SIG = /^(?:0x)?[0-9a-fA-F]{128,130}$/;
const B64 = /^[A-Za-z0-9+/]+={0,2}$/;
const isObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);
const bad = (error) => ({ ok: false, error });

export function validateJudgeRequest(body) {
  if (!isObj(body)) return bad('body must be a JSON object {exploitMarkdown}');
  const m = body.exploitMarkdown;
  if (typeof m !== 'string' || !m.trim()) return bad('exploitMarkdown must be a non-empty string');
  if (Buffer.byteLength(m) > MAX_EXPLOIT_BYTES) return bad(`exploitMarkdown is over ${MAX_EXPLOIT_BYTES} bytes`);
  return { ok: true, value: { exploitMarkdown: m } };
}

export function validateJudgement(j) {
  if (!isObj(j)) return bad('judgement must be an object (the POST /judge response)');
  const { request_body: rb, req_hash: rh, response_body_b64: b64, signature, signer, kind, chat_id: chat, verdict } = j;
  if (typeof rb !== 'string' || !rb) return bad('judgement.request_body must be a non-empty string');
  if (Buffer.byteLength(rb) > MAX_REQUEST_BODY) return bad('judgement.request_body is too large');
  if (typeof rh !== 'string' || !HEX64.test(rh)) return bad('judgement.req_hash must be 64 lowercase hex');
  if (sha256hex(rb) !== rh) return bad('judgement.req_hash != sha256(request_body)');
  let model;
  try {
    model = JSON.parse(rb).model;
  } catch {
    return bad('judgement.request_body is not JSON');
  }
  if (typeof model !== 'string' || !model) return bad('judgement.request_body has no model');
  if (typeof b64 !== 'string' || !b64 || b64.length % 4 !== 0 || !B64.test(b64)) return bad('judgement.response_body_b64 must be base64');
  if (typeof signature !== 'string' || !SIG.test(signature)) return bad('judgement.signature must be hex');
  if (typeof signer !== 'string' || !SIGNER.test(signer)) return bad('judgement.signer must be ed25519:<64 hex> or eth:0x<40 hex>');
  if (kind !== 'provider_tee' && kind !== 'gateway') return bad('judgement.kind must be provider_tee or gateway');
  if (typeof chat !== 'string' || !chat) return bad('judgement.chat_id must be a non-empty string');
  if (verdict !== undefined && !isObj(verdict)) return bad('judgement.verdict must be an object');
  return { ok: true, value: j };
}

/** Same as shared/judge.mjs expectedText (the string NEAR AI signs). */
const expectedText = (kind, model, reqHash, respHash) => (kind === 'provider_tee' ? `${model}:${reqHash}:${respHash}` : `${reqHash}:${respHash}`);

/**
 * API judgement -> cli JudgeRecord. `attested` = this helper ran the judgement itself (shared judge()
 * checks the signer against a fresh attestation report before returning).
 */
export function toJudgeRecord(j, { attested = false } = {}) {
  const model = JSON.parse(j.request_body).model;
  const resp_hash = sha256hex(Buffer.from(j.response_body_b64, 'base64'));
  const ecdsa = j.signer.startsWith('eth:');
  return {
    model,
    request_body: j.request_body,
    response_body_b64: j.response_body_b64,
    req_hash: j.req_hash,
    resp_hash,
    chat_id: j.chat_id,
    signature: j.signature,
    signing_address: ecdsa ? j.signer.slice(4) : j.signer.slice('ed25519:'.length),
    signing_algo: ecdsa ? 'ecdsa' : 'ed25519',
    signature_kind: j.kind,
    text: expectedText(j.kind, model, j.req_hash, resp_hash),
    signer_in_attestation: j.signer_in_attestation === true || attested,
  };
}

/** A shared judge() result (JudgeRecord + verdict + signer) -> the API judgement. Whitelists fields. */
export function judgeResponse(r) {
  const signer = r.signer ?? (r.signing_algo === 'ecdsa' ? `eth:0x${String(r.signing_address).replace(/^0x/i, '').toLowerCase()}` : `ed25519:${String(r.signing_address).toLowerCase()}`);
  return {
    verdict: r.verdict,
    signature: r.signature,
    chat_id: r.chat_id,
    request_body: r.request_body,
    response_body_b64: r.response_body_b64,
    req_hash: r.req_hash,
    signer,
    kind: r.kind ?? r.signature_kind,
    resp_hash: r.resp_hash ?? sha256hex(Buffer.from(r.response_body_b64, 'base64')),
    model: r.model ?? JSON.parse(r.request_body).model,
    signer_in_attestation: r.signer_in_attestation === true,
  };
}
