// SealedBounty shared judge library (ESM, isomorphic: Node >= 22 and browsers, no node:* imports).
//
// Stable API used by cli/ and web/. Spec: docs/INTERFACE.md ("Canonical judge request body").
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

// ---------------------------------------------------------------- request body

/**
 * Build the canonical judge request body (exact string that is sent AND hashed).
 * Key order and content are fixed by docs/INTERFACE.md; do not re-serialize the result.
 * @param {{model: string, repoUrl: string, commit: string, codeExcerpt: string, report: string}} p
 * @returns {string} JSON string; req_hash = sha256hex(this string)
 */
export function buildRequestBody({ model, repoUrl, commit, codeExcerpt, report }) {
  for (const [k, v] of Object.entries({ model, repoUrl, commit, codeExcerpt, report })) {
    if (typeof v !== 'string' || v.length === 0) throw new Error(`buildRequestBody: ${k} must be a non-empty string`);
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
 * @param {{apiKey: string, baseUrl?: string, model?: string, repoUrl: string, commit: string, codeExcerpt: string, report: string, signingAlgo?: 'ed25519'|'ecdsa', checkAttestation?: boolean, fetchImpl?: typeof fetch}} p
 * @returns {Promise<JudgeRecord>}
 */
export async function judge({ apiKey, baseUrl, model = DEFAULT_MODEL, repoUrl, commit, codeExcerpt, report, signingAlgo = 'ed25519', checkAttestation = true, fetchImpl = fetch }) {
  if (!apiKey) throw new Error('judge: apiKey required');
  const redact = redactor(apiKey);
  const request_body = buildRequestBody({ model, repoUrl, commit, codeExcerpt, report });
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
 * If `obj.inputs` ({repoUrl, commit, codeExcerpt, report}) is present, also checks that
 * buildRequestBody(inputs) reproduces request_body byte for byte.
 * @param {JudgeRecord & {inputs?: {repoUrl: string, commit: string, codeExcerpt: string, report: string}}} obj
 * @param {{systemPromptHash?: string}} [opts] when set, messages[0].content must hash to it
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
    if (obj.inputs) {
      const rebuilt = buildRequestBody({ model: obj.model, ...obj.inputs });
      add('inputs rebuild request_body exactly', rebuilt === obj.request_body);
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
