// SealedBounty shared judge library (ESM, isomorphic: Node >= 22 and browsers, no node:* imports).
//
// Stable API used by cli/ and web/. Spec: docs/INTERFACE.md ("v2": code bundle + hunter bound into
// the request; "Canonical judge request v2").
// Recording/verification logic is ported from spike/sign/{lib,record}.mjs (Phase 0, proven live).
//
// Never logs or returns the API key. Error messages have the key redacted.

import nacl from 'tweetnacl';
import {
  sha256 as ethSha256,
  toUtf8Bytes,
  toUtf8String,
  encodeBase64,
  decodeBase64,
  getBytes,
  hexlify,
  verifyMessage,
} from 'ethers';
import { SYSTEM_PROMPT, SYSTEM_PROMPT_SHA256 } from './system-prompt.mjs';

export { SYSTEM_PROMPT };

/** Default NEAR AI Cloud endpoint. */
export const DEFAULT_BASE_URL = 'https://cloud-api.near.ai/v1';
/** Phase 0 proven model (provider_tee signatures). */
export const DEFAULT_MODEL = 'Qwen/Qwen3.8-27B';

/**
 * Strict json_schema for the verdict. Property order = generation order.
 * Matches contract `Verdict {valid, severity, cwe: Option<String>, confidence: u8}`.
 */
export const VERDICT_RESPONSE_FORMAT = Object.freeze({
  type: 'json_schema',
  json_schema: {
    name: 'verdict',
    strict: true,
    schema: {
      type: 'object',
      properties: {
        valid: { type: 'boolean' },
        severity: { type: 'string', enum: ['none', 'low', 'medium', 'high', 'critical'] },
        cwe: { type: ['string', 'null'] },
        confidence: { type: 'integer', minimum: 0, maximum: 100 },
      },
      required: ['valid', 'severity', 'cwe', 'confidence'],
      additionalProperties: false,
    },
  },
});

// ---------------------------------------------------------------- byte helpers

const strip0x = (h) => (h.startsWith('0x') || h.startsWith('0X') ? h.slice(2) : h);
const hexBytes = (h) => getBytes('0x' + strip0x(String(h)));
const utf8 = (s) => toUtf8Bytes(s);

/**
 * Lowercase sha256 hex (no 0x) of a string (hashed as utf8) or bytes.
 * @param {string|Uint8Array} data
 * @returns {string}
 */
export function sha256hex(data) {
  const bytes = typeof data === 'string' ? utf8(data) : data;
  return strip0x(ethSha256(bytes));
}

/**
 * sha256 hex of the frozen system prompt (== Program.system_prompt_hash).
 * @returns {string} 64 lowercase hex chars
 */
export function systemPromptHash() {
  return SYSTEM_PROMPT_SHA256;
}

// ---------------------------------------------------------------- code bundle (v2)

/**
 * Build the canonical code bundle the program owner publishes (docs/INTERFACE.md v2).
 * Files are sorted by path in utf8 byte order; each entry is
 * `// file: <path>\n<content>` with a trailing `\n` appended to content if missing; entries are
 * concatenated with no separator.
 * @param {{path: string, content: string}[]} files
 * @returns {string} bundle; Program.code_hash = codeHash(bundle)
 */
export function buildCodeBundle(files) {
  if (!Array.isArray(files) || files.length === 0) throw new Error('buildCodeBundle: files must be a non-empty array');
  const enc = (s) => utf8(s);
  const cmp = (a, b) => {
    const x = enc(a), y = enc(b);
    for (let i = 0; i < Math.min(x.length, y.length); i++) if (x[i] !== y[i]) return x[i] - y[i];
    return x.length - y.length;
  };
  const seen = new Set();
  for (const f of files) {
    if (typeof f?.path !== 'string' || !f.path || typeof f.content !== 'string') throw new Error('buildCodeBundle: each file needs string path and content');
    if (seen.has(f.path)) throw new Error(`buildCodeBundle: duplicate path ${f.path}`);
    seen.add(f.path);
  }
  return [...files]
    .sort((a, b) => cmp(a.path, b.path))
    .map((f) => `// file: ${f.path}\n${f.content.endsWith('\n') ? f.content : f.content + '\n'}`)
    .join('');
}

/**
 * Program.code_hash: sha256hex(utf8(bundle)).
 * @param {string} bundle output of buildCodeBundle
 * @returns {string} 64 lowercase hex chars
 */
export function codeHash(bundle) {
  if (typeof bundle !== 'string') throw new Error('codeHash: bundle must be a string');
  return sha256hex(bundle);
}

/**
 * Exact prefix of messages[1].content before the code bundle (what the contract's dispute checks).
 * @param {{repoUrl: string, commit: string, hunter: string}} p
 * @returns {string} `TARGET <repoUrl>@<commit>\nHUNTER <hunter>\n\nCODE\n`
 */
export function codeMessagePrefix({ repoUrl, commit, hunter }) {
  return `TARGET ${repoUrl}@${commit}\nHUNTER ${hunter}\n\nCODE\n`;
}

// ---------------------------------------------------------------- request body

/**
 * Build the canonical v2 judge request body (exact string that is sent AND hashed).
 * messages = [system prompt, user `TARGET..\nHUNTER..\n\nCODE\n<codeBundle>`, user `REPORT\n<report>`].
 * Key order and content are fixed by docs/INTERFACE.md (v2); do not re-serialize the result.
 * @param {{model: string, repoUrl: string, commit: string, hunter: string, codeBundle: string, report: string}} p
 *   hunter = the NEAR account that will call submit_claim; codeBundle = the program's published bundle, byte for byte
 * @returns {string} JSON string; req_hash = sha256hex(this string)
 */
export function buildRequestBody({ model, repoUrl, commit, hunter, codeBundle, report, ...rest }) {
  if ('codeExcerpt' in rest && codeBundle === undefined) {
    throw new Error('buildRequestBody: v1 codeExcerpt is gone; pass hunter + codeBundle (v2) or use buildRequestBodyV1');
  }
  for (const [k, v] of Object.entries({ model, repoUrl, commit, hunter, codeBundle, report })) {
    if (typeof v !== 'string' || v.length === 0) throw new Error(`buildRequestBody: ${k} must be a non-empty string`);
  }
  if (/\s/.test(hunter)) throw new Error('buildRequestBody: hunter must not contain whitespace');
  return JSON.stringify({
    model,
    messages: [
      { role: 'system', content: SYSTEM_PROMPT },
      { role: 'user', content: codeMessagePrefix({ repoUrl, commit, hunter }) + codeBundle },
      { role: 'user', content: `REPORT\n${report}` },
    ],
    response_format: VERDICT_RESPONSE_FORMAT,
    chat_template_kwargs: { enable_thinking: false },
    temperature: 0,
    max_tokens: 400,
  });
}

/**
 * LEGACY v1 body (single user message, hunter-supplied excerpt). Only for re-verifying v1 records;
 * a v2 contract rejects these on dispute ("code mismatch").
 * @deprecated use buildRequestBody (v2)
 * @param {{model: string, repoUrl: string, commit: string, codeExcerpt: string, report: string}} p
 * @returns {string}
 */
export function buildRequestBodyV1({ model, repoUrl, commit, codeExcerpt, report }) {
  for (const [k, v] of Object.entries({ model, repoUrl, commit, codeExcerpt, report })) {
    if (typeof v !== 'string' || v.length === 0) throw new Error(`buildRequestBodyV1: ${k} must be a non-empty string`);
  }
  return JSON.stringify({
    model,
    messages: [
      { role: 'system', content: SYSTEM_PROMPT },
      { role: 'user', content: `TARGET ${repoUrl}@${commit}\n\n${codeExcerpt}\n\nREPORT\n${report}` },
    ],
    response_format: VERDICT_RESPONSE_FORMAT,
    chat_template_kwargs: { enable_thinking: false },
    temperature: 0,
    max_tokens: 400,
  });
}

/**
 * Pre-check a request body against a program the way the v2 contract's `dispute` does (after its
 * sha256 == req_hash check), returning the FIRST failing reason in contract order:
 * 1 "system prompt tampered" (unparsable JSON, messages[0] not system / hash != system_prompt_hash,
 *   or more than 3 messages), 2 "model mismatch", 3 "code mismatch" (messages[1] not user, TARGET line,
 *   malformed HUNTER/CODE header, or sha256(code) != code_hash), 4 "hunter mismatch" (only the HUNTER
 *   line differs from `hunter`: front-running), 5 "report missing" (messages[2] missing / not user /
 *   not starting with "REPORT\n").
 * ok:true means a dispute would fail with "dispute invalid: request matches program".
 * @param {string} requestBody exact request body
 * @param {{repo_url: string, commit: string, model_id: string, system_prompt_hash: string, code_hash: string}} program
 *   contract Program view (snake_case, as returned by get_program)
 * @param {string} hunter the account that submits (or submitted) the claim
 * @returns {{ok: boolean, reason: null|'system prompt tampered'|'model mismatch'|'code mismatch'|'hunter mismatch'|'report missing'}}
 */
export function checkRequestAgainstProgram(requestBody, program, hunter) {
  const fail = (reason) => ({ ok: false, reason });
  let req;
  try { req = JSON.parse(requestBody); } catch { return fail('system prompt tampered'); }
  if (req === null || typeof req !== 'object' || typeof req.model !== 'string' || !Array.isArray(req.messages)) {
    return fail('system prompt tampered');
  }
  const msgs = req.messages;
  const isMsg = (m) => m !== null && typeof m === 'object' && typeof m.role === 'string' && 'content' in m;
  if (!msgs.every(isMsg)) return fail('system prompt tampered'); // contract: messages fail to deserialize
  const m0 = msgs[0];
  if (!m0 || m0.role !== 'system' || typeof m0.content !== 'string' || sha256hex(m0.content) !== program.system_prompt_hash) {
    return fail('system prompt tampered');
  }
  if (msgs.length > 3) return fail('system prompt tampered');
  if (req.model !== program.model_id) return fail('model mismatch');

  const m1 = msgs[1];
  if (!m1 || m1.role !== 'user' || typeof m1.content !== 'string') return fail('code mismatch');
  const target = `TARGET ${program.repo_url}@${program.commit}\n`;
  if (!m1.content.startsWith(target)) return fail('code mismatch');
  const afterTarget = m1.content.slice(target.length);
  if (!afterTarget.startsWith('HUNTER ')) return fail('code mismatch');
  const nl = afterTarget.indexOf('\n');
  if (nl < 0) return fail('code mismatch');
  const claimedHunter = afterTarget.slice('HUNTER '.length, nl);
  const codeHdr = '\n\nCODE\n';
  if (!afterTarget.startsWith(codeHdr, nl)) return fail('code mismatch');
  const code = afterTarget.slice(nl + codeHdr.length);
  if (sha256hex(code) !== program.code_hash) return fail('code mismatch');
  if (claimedHunter !== String(hunter)) return fail('hunter mismatch');

  const m2 = msgs[2];
  if (!m2 || m2.role !== 'user' || typeof m2.content !== 'string' || !m2.content.startsWith('REPORT\n')) {
    return fail('report missing');
  }
  return { ok: true, reason: null };
}

// ---------------------------------------------------------------- verdict + signatures

/**
 * Parse a verdict from a chat completion body. Mirrors contract `parse_verdict`
 * (strips ``` fences; falls back to the outermost {...}).
 * @param {string|Uint8Array} responseBody raw completion JSON
 * @returns {{valid: boolean, severity: 'none'|'low'|'medium'|'high'|'critical', cwe: string|null, confidence: number}}
 */
export function parseVerdict(responseBody) {
  const txt = typeof responseBody === 'string' ? responseBody : toUtf8String(responseBody);
  const content = JSON.parse(txt)?.choices?.[0]?.message?.content;
  if (typeof content !== 'string') throw new Error('missing choices[0].message.content');
  let body = content.trim();
  if (body.startsWith('```')) {
    const nl = body.indexOf('\n');
    body = (nl >= 0 ? body.slice(nl + 1) : body.slice(3)).trimEnd();
    if (body.endsWith('```')) body = body.slice(0, -3);
    body = body.trim();
  }
  let v;
  try { v = JSON.parse(body); } catch {
    const a = body.indexOf('{'), b = body.lastIndexOf('}');
    if (a < 0 || b <= a) throw new Error('bad verdict json');
    v = JSON.parse(body.slice(a, b + 1));
  }
  const sev = ['none', 'low', 'medium', 'high', 'critical'];
  if (typeof v?.valid !== 'boolean' || !sev.includes(v.severity) || !Number.isInteger(v.confidence) ||
      v.confidence < 0 || v.confidence > 255 || !(v.cwe == null || typeof v.cwe === 'string')) {
    throw new Error('bad verdict json: wrong shape');
  }
  return { valid: v.valid, severity: v.severity, cwe: v.cwe ?? null, confidence: v.confidence };
}

/** @param {string} text @returns {'provider_tee'|'gateway'} */
export function inferKind(text) {
  return text.split(':').length >= 3 ? 'provider_tee' : 'gateway';
}

/**
 * The exact text the TEE signs.
 * @param {'provider_tee'|'gateway'} kind
 */
export function expectedText(kind, model, reqHash, respHash) {
  return kind === 'provider_tee' ? `${model}:${reqHash}:${respHash}` : `${reqHash}:${respHash}`;
}

/**
 * Verify a NEAR AI signature over `text`.
 * @param {{text: string, signature: string, signing_address: string, signing_algo: 'ed25519'|'ecdsa'}} s
 * @returns {boolean}
 */
export function verifySig({ text, signature, signing_address, signing_algo }) {
  if (signing_algo === 'ed25519') {
    const pk = hexBytes(signing_address), sig = hexBytes(signature);
    if (pk.length !== 32 || sig.length !== 64) return false;
    return nacl.sign.detached.verify(utf8(text), sig, pk);
  }
  if (signing_algo === 'ecdsa') {
    try {
      return verifyMessage(text, '0x' + strip0x(signature)).toLowerCase() === '0x' + strip0x(signing_address).toLowerCase();
    } catch { return false; }
  }
  throw new Error(`unknown signing_algo ${signing_algo}`);
}

/**
 * Contract `Signer` encoding for a record: "ed25519:<64 hex>" or "eth:0x<40 hex>".
 * @param {{signing_address: string, signing_algo: 'ed25519'|'ecdsa'}} r
 * @returns {string}
 */
export function signerId({ signing_address, signing_algo }) {
  const h = strip0x(String(signing_address)).toLowerCase();
  return signing_algo === 'ecdsa' ? `eth:0x${h}` : `ed25519:${h}`;
}

// ---------------------------------------------------------------- network

const redactor = (key) => (s) => (key ? String(s).split(key).join('[REDACTED]') : String(s));
const trimBase = (u) => String(u || DEFAULT_BASE_URL).replace(/\/$/, '');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * Fetch the TEE signature for a completion (retries 404 while it is being produced).
 * @param {{apiKey: string, baseUrl?: string, model: string, chatId: string, algo?: 'ed25519'|'ecdsa', fetchImpl?: typeof fetch, retries?: number}} p
 * @returns {Promise<{text: string, signature: string, signing_address: string, signing_algo: string, signature_kind?: string}>}
 */
export async function fetchSignature({ apiKey, baseUrl, model, chatId, algo = 'ed25519', fetchImpl = fetch, retries = 7 }) {
  const redact = redactor(apiKey);
  const url = `${trimBase(baseUrl)}/signature/${encodeURIComponent(chatId)}?model=${encodeURIComponent(model)}&signing_algo=${algo}`;
  for (let i = 0; i < retries; i++) {
    const res = await fetchImpl(url, { headers: { Authorization: `Bearer ${apiKey}` } });
    const txt = await res.text();
    if (res.status === 404 && i < retries - 1) { await sleep(1000); continue; }
    if (res.status !== 200) throw new Error(`signature HTTP ${res.status}: ${redact(txt).slice(0, 300)}`);
    const j = JSON.parse(txt);
    if (j.error_code || !j.signature) throw new Error(`signature unavailable: ${redact(txt).slice(0, 300)}`);
    return j;
  }
  throw new Error('signature: retries exhausted');
}

/**
 * Fetch a fresh attestation report (random nonce) and check that `signingAddress` is one of the
 * attested signers (model_attestations for provider_tee, gateway_attestation for gateway).
 * @returns {Promise<{nonce: string, signer_in_attestation: boolean, attested: string[]}>}
 */
export async function checkSignerInAttestation({ apiKey, baseUrl, model, algo = 'ed25519', kind = 'provider_tee', signingAddress, fetchImpl = fetch }) {
  const redact = redactor(apiKey);
  const nonce = hexlify(nacl.randomBytes(32)).slice(2);
  const url = `${trimBase(baseUrl)}/attestation/report?model=${encodeURIComponent(model)}&provider=near&signing_algo=${algo}&nonce=${nonce}`;
  const res = await fetchImpl(url, { headers: { Authorization: `Bearer ${apiKey}`, 'x-no-aliasing': 'true' } });
  const txt = await res.text();
  if (res.status !== 200) throw new Error(`attestation HTTP ${res.status}: ${redact(txt).slice(0, 300)}`);
  const att = JSON.parse(txt);
  const attested = (kind === 'provider_tee'
    ? (att.model_attestations || []).map((a) => a.signing_address)
    : [att.gateway_attestation?.signing_address]).filter(Boolean).map((a) => strip0x(a).toLowerCase());
  return { nonce, attested, signer_in_attestation: attested.includes(strip0x(signingAddress).toLowerCase()) };
}

/**
 * @typedef {Object} JudgeRecord
 * @property {string} model
 * @property {string} request_body       exact bytes sent (utf8)
 * @property {string} response_body_b64  exact response bytes, base64
 * @property {string} req_hash           sha256hex(request_body)
 * @property {string} resp_hash          sha256hex(response bytes)
 * @property {string} chat_id
 * @property {string} signature          hex
 * @property {string} signing_address    ed25519 pubkey hex or eth address
 * @property {'ed25519'|'ecdsa'} signing_algo
 * @property {'provider_tee'|'gateway'} signature_kind
 * @property {string} text               signed text
 * @property {string} [attestation_nonce]
 * @property {boolean} [signer_in_attestation]
 * @property {string} recorded_at        ISO time
 * @property {{valid:boolean,severity:string,cwe:string|null,confidence:number}} verdict  (derived, convenience)
 * @property {string} signer             contract Signer encoding (derived, convenience)
 */

/**
 * Attach a (re)fetched signature to a completion and verify it locally. Throws on any mismatch.
 * Use with algo:'ecdsa' to get the second signature for an existing record.
 * @param {{apiKey: string, baseUrl?: string, record: {model: string, request_body: string, response_body_b64: string, chat_id: string}, algo?: 'ed25519'|'ecdsa', checkAttestation?: boolean, fetchImpl?: typeof fetch}} p
 * @returns {Promise<JudgeRecord>}
 */
export async function signRecord({ apiKey, baseUrl, record, algo = 'ed25519', checkAttestation = true, fetchImpl = fetch }) {
  const { model, request_body, response_body_b64, chat_id } = record;
  const respBytes = decodeBase64(response_body_b64);
  const req_hash = sha256hex(request_body);
  const resp_hash = sha256hex(respBytes);
  const sig = await fetchSignature({ apiKey, baseUrl, model, chatId: chat_id, algo, fetchImpl });
  const signature_kind = sig.signature_kind || inferKind(sig.text);
  const exp = expectedText(signature_kind, model, req_hash, resp_hash);
  if (sig.text !== exp) throw new Error(`signed text mismatch: got ${sig.text} expected ${exp}`);
  const out = {
    model, request_body, response_body_b64, req_hash, resp_hash, chat_id,
    signature: sig.signature, signing_address: sig.signing_address, signing_algo: algo,
    signature_kind, text: sig.text,
  };
  if (!verifySig(out)) throw new Error(`${algo} signature does not verify locally`);
  if (checkAttestation) {
    const a = await checkSignerInAttestation({ apiKey, baseUrl, model, algo, kind: signature_kind, signingAddress: sig.signing_address, fetchImpl });
    if (!a.signer_in_attestation) throw new Error(`signer ${sig.signing_address} not in fresh attestation (${a.attested.length} attested)`);
    out.attestation_nonce = a.nonce;
    out.signer_in_attestation = true;
  }
  out.recorded_at = new Date().toISOString();
  out.verdict = parseVerdict(respBytes);
  out.signer = signerId(out);
  return out;
}

/**
 * Run one judge completion on NEAR AI Cloud, fetch its TEE signature, verify everything locally.
 * Throws on HTTP errors, unparsable verdicts, signature/text mismatch or (by default) a signer that
 * is not in a fresh attestation report.
 * The request is the v2 body from buildRequestBody (hunter + program code bundle bound in).
 * @param {{apiKey: string, baseUrl?: string, model?: string, repoUrl: string, commit: string, hunter: string, codeBundle: string, report: string, signingAlgo?: 'ed25519'|'ecdsa', checkAttestation?: boolean, fetchImpl?: typeof fetch}} p
 * @returns {Promise<JudgeRecord>}
 */
export async function judge({ apiKey, baseUrl, model = DEFAULT_MODEL, repoUrl, commit, hunter, codeBundle, report, signingAlgo = 'ed25519', checkAttestation = true, fetchImpl = fetch }) {
  if (!apiKey) throw new Error('judge: apiKey required');
  const redact = redactor(apiKey);
  const request_body = buildRequestBody({ model, repoUrl, commit, hunter, codeBundle, report });
  const res = await fetchImpl(`${trimBase(baseUrl)}/chat/completions`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
      'x-no-aliasing': 'true',
      'Accept-Encoding': 'identity',
    },
    body: request_body,
  });
  const respBytes = new Uint8Array(await res.arrayBuffer()); // exact raw bytes
  if (res.status !== 200) throw new Error(`completion HTTP ${res.status}: ${redact(toUtf8String(respBytes)).slice(0, 400)}`);
  parseVerdict(respBytes); // refuse to sign/record an unparsable verdict
  const chat_id = JSON.parse(toUtf8String(respBytes)).id;
  return signRecord({
    apiKey, baseUrl, algo: signingAlgo, checkAttestation, fetchImpl,
    record: { model, request_body, response_body_b64: encodeBase64(respBytes), chat_id },
  });
}

// ---------------------------------------------------------------- offline verification

/**
 * Offline re-verification of a recorded judge result (no network, no key).
 * If `obj.inputs` is present, also checks that the inputs rebuild request_body byte for byte:
 * - v2 inputs {repoUrl, commit, hunter, report, codeBundle?}: codeBundle comes from inputs, else
 *   opts.codeBundle, else it is taken from the body's CODE section (structure is still checked).
 * - legacy v1 inputs {repoUrl, commit, codeExcerpt, report}: rebuilt with buildRequestBodyV1.
 * Whether the CODE matches a program is NOT checked here; use checkRequestAgainstProgram (or opts.codeHash).
 * @param {JudgeRecord & {spec?: string, inputs?: {repoUrl: string, commit: string, hunter?: string, codeBundle?: string, codeExcerpt?: string, report: string}}} obj
 * @param {{systemPromptHash?: string, codeBundle?: string, codeHash?: string}} [opts]
 *   systemPromptHash: messages[0].content must hash to it; codeHash: the body's CODE section must hash to it
 * @returns {{ok: boolean, checks: {name: string, ok: boolean, detail: string}[], verdict: object|null, signer: string|null}}
 */
export function verifyFixture(obj, opts = {}) {
  const checks = [];
  const add = (name, ok, detail = '') => checks.push({ name, ok: !!ok, detail: String(detail) });
  let verdict = null, signer = null;
  try {
    const respBytes = decodeBase64(obj.response_body_b64);
    const reqHash = sha256hex(obj.request_body);
    const respHash = sha256hex(respBytes);
    const req = JSON.parse(obj.request_body);
    add('req_hash == sha256(request_body)', reqHash === obj.req_hash, reqHash);
    add('resp_hash == sha256(response bytes)', respHash === obj.resp_hash, respHash);
    add('request model == record model', req.model === obj.model, req.model);
    let respId = null; try { respId = JSON.parse(toUtf8String(respBytes)).id; } catch {}
    add('chat_id == response id', respId === obj.chat_id, respId);
    add('kind consistent with signed text', inferKind(obj.text) === obj.signature_kind, obj.signature_kind);
    const exp = expectedText(obj.signature_kind, obj.model, reqHash, respHash);
    add('signed text == expected from hashes', obj.text === exp, exp);
    let sigOk = false, sigErr = '';
    try { sigOk = verifySig(obj); } catch (e) { sigErr = e.message; }
    add(`${obj.signing_algo} signature verifies`, sigOk, sigErr || obj.signing_address);
    add('signer_in_attestation (recorded)', obj.signer_in_attestation === true, obj.signer_in_attestation);
    signer = signerId(obj);
    try { verdict = parseVerdict(respBytes); add('verdict parses', true, JSON.stringify(verdict)); }
    catch (e) { add('verdict parses', false, e.message); }
    if (opts.systemPromptHash) {
      const h = req.messages?.[0]?.role === 'system' ? sha256hex(req.messages[0].content) : 'no system message';
      add('system prompt hash matches', h === opts.systemPromptHash, h);
    }
    const bodyCode = () => {
      const c = req.messages?.[1]?.content;
      const i = typeof c === 'string' ? c.indexOf('\n\nCODE\n') : -1;
      return i < 0 ? null : c.slice(i + '\n\nCODE\n'.length);
    };
    if (obj.inputs) {
      const { codeExcerpt, codeBundle, ...rest } = obj.inputs;
      let rebuilt;
      if (codeExcerpt !== undefined && rest.hunter === undefined) {
        rebuilt = buildRequestBodyV1({ model: obj.model, ...obj.inputs });
      } else {
        const cb = codeBundle ?? opts.codeBundle ?? bodyCode();
        rebuilt = cb == null ? null : buildRequestBody({ model: obj.model, ...rest, codeBundle: cb });
      }
      add('inputs rebuild request_body exactly', rebuilt === obj.request_body);
    }
    if (opts.codeHash) {
      const c = bodyCode();
      const h = c == null ? 'no CODE section' : sha256hex(c);
      add('code hash matches', h === opts.codeHash, h);
    }
  } catch (e) {
    add('fixture well-formed', false, e.message);
  }
  return { ok: checks.every((c) => c.ok), checks, verdict, signer };
}

// ---------------------------------------------------------------- owner encryption

/**
 * Encrypt the request body for the program owner.
 * Ciphertext (base64) = ephemeralPub(32) || nonce(24) || nacl.box(utf8(requestBody), nonce, ownerPub, ephemeralSecret).
 * @param {string} requestBody
 * @param {string} ownerPubB64 base64 x25519 public key (Program.owner_enc_pubkey)
 * @returns {string} base64 ciphertext
 */
export function encryptForOwner(requestBody, ownerPubB64) {
  const ownerPub = decodeBase64(ownerPubB64);
  if (ownerPub.length !== nacl.box.publicKeyLength) throw new Error('owner pubkey must be 32 bytes');
  const eph = nacl.box.keyPair();
  const nonce = nacl.randomBytes(nacl.box.nonceLength);
  const boxed = nacl.box(utf8(requestBody), nonce, ownerPub, eph.secretKey);
  const out = new Uint8Array(32 + 24 + boxed.length);
  out.set(eph.publicKey, 0); out.set(nonce, 32); out.set(boxed, 56);
  return encodeBase64(out);
}

/**
 * Decrypt a ciphertext produced by encryptForOwner.
 * @param {string} ciphertextB64
 * @param {string} ownerSecretB64 base64 x25519 secret key (32 bytes)
 * @returns {string} the request body
 */
export function decryptAsOwner(ciphertextB64, ownerSecretB64) {
  const buf = decodeBase64(ciphertextB64);
  const sk = decodeBase64(ownerSecretB64);
  if (sk.length !== nacl.box.secretKeyLength) throw new Error('owner secret must be 32 bytes');
  if (buf.length < 56 + nacl.box.overheadLength) throw new Error('ciphertext too short');
  const opened = nacl.box.open(buf.subarray(56), buf.subarray(32, 56), buf.subarray(0, 32), sk);
  if (!opened) throw new Error('decryption failed');
  return toUtf8String(opened);
}

/**
 * Generate an owner x25519 keypair (base64). Store the secret at ~/.sealedbounty/owner-<id>.json.
 * @returns {{publicKey: string, secretKey: string}}
 */
export function generateOwnerKeypair() {
  const kp = nacl.box.keyPair();
  return { publicKey: encodeBase64(kp.publicKey), secretKey: encodeBase64(kp.secretKey) };
}
