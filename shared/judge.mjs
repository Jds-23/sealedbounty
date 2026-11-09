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

// ---------------------------------------------------------------- params pinning (v3 #1)

/** utf8 byte-order string compare (== Rust String Ord; JS `<` compares UTF-16 code units). */
const utf8Cmp = (a, b) => {
  const x = utf8(a), y = utf8(b);
  for (let i = 0; i < Math.min(x.length, y.length); i++) if (x[i] !== y[i]) return x[i] - y[i];
  return x.length - y.length;
};

// Numbers (#15). The deployed v3 contract parses the body with serde_json 1.0.154 (no
// `arbitrary_precision`, no `float_roundtrip`) into `serde_json::Value` and prints it back, so a
// number's canonical form depends on its source TOKEN, not just its value:
//   - an integer token that fits u64 (or i64 if negative) stays an integer: `0`, `400`,
//     `18446744073709551615`, `-9223372036854775808` (exact; JS Number would lose precision);
//   - anything else (`.`, `e`/`E`, `-0`, out of u64/i64 range) becomes an f64, parsed with
//     serde_json's fast (NOT always correctly rounded) algorithm and printed with zmij:
//     `0.0`→`0.0`, `-0`→`-0.0`, `1.50`→`1.5`, `1e2`/`1E+2`→`100.0`, `1e-5`→`0.00001`,
//     `0.000001`→`1e-6`, `1e16`→`1e+16`, `2.2250738585072011e-308`→`2.2250738585072014e-308`;
//   - an f64 that overflows (`1e400`) is a parse error: the contract rejects the request.
// The helpers below replay that algorithm exactly (vectors: contracts/sealed-bounty/tests/fixtures/
// canonical-vectors.json, checked by shared/test/canonical-vectors.test.mjs).

const U64_MAX = (1n << 64n) - 1n;
const I32_MAX = 2 ** 31 - 1;
const I32_MIN = -(2 ** 31);
/** serde_json's POW10 table: the f64 literals 1e0..1e308. */
const POW10 = Array.from({ length: 309 }, (_, i) => Number(`1e${i}`));

/**
 * A JSON number kept as its exact source token (what {@link parseJsonLossless} returns for numbers).
 * {@link canonicalJson} prints it the way the contract does.
 */
export class JsonNumber {
  /** @param {string} token a JSON number token, e.g. "0.0" */
  constructor(token) {
    this.token = token;
    Object.freeze(this);
  }
}

/**
 * Parse a JSON number token exactly like serde_json 1.0.154 `deserialize_any` (default features).
 * @param {string} token
 * @returns {{u64: bigint} | {i64: bigint} | {f64: number}}
 * @throws {RangeError} out of f64 range (serde_json "number out of range")
 */
function serdeParseNumber(token) {
  const s = token;
  let i = 0;
  const isDigit = () => s[i] >= '0' && s[i] <= '9';
  const bad = () => new SyntaxError(`not a JSON number: ${token}`);
  const oor = () => new RangeError(`number out of range: ${token}`);
  let positive = true;
  if (s[i] === '-') { positive = false; i++; }

  const fromParts = (sig, exponent) => { // f64_from_parts (not float_roundtrip)
    let f = Number(sig); // u64 as f64: round to nearest, ties to even
    for (;;) {
      const idx = Math.abs(exponent);
      if (idx < POW10.length) {
        if (exponent >= 0) {
          f *= POW10[idx];
          if (!Number.isFinite(f)) throw oor();
        } else {
          f /= POW10[idx];
        }
        break;
      }
      if (f === 0) break;
      if (exponent >= 0) throw oor();
      f /= 1e308;
      exponent += 308;
    }
    return positive ? f : -f;
  };
  const parseExponent = (sig, startingExp) => {
    i++; // e | E
    let positiveExp = true;
    if (s[i] === '+') i++;
    else if (s[i] === '-') { positiveExp = false; i++; }
    if (!isDigit()) throw bad();
    let exp = s.charCodeAt(i++) - 48;
    while (isDigit()) {
      const d = s.charCodeAt(i++) - 48;
      if (exp * 10 + d > I32_MAX) { // parse_exponent_overflow
        if (sig !== 0n && positiveExp) throw oor();
        while (isDigit()) i++;
        return positive ? 0 : -0;
      }
      exp = exp * 10 + d;
    }
    const finalExp = Math.min(I32_MAX, Math.max(I32_MIN, positiveExp ? startingExp + exp : startingExp - exp));
    return fromParts(sig, finalExp);
  };
  const afterDigits = (sig, exponent) =>
    s[i] === 'e' || s[i] === 'E' ? parseExponent(sig, exponent) : fromParts(sig, exponent);
  const parseDecimal = (sig, expBefore) => {
    i++; // '.'
    let expAfter = 0;
    while (isDigit()) {
      const d = BigInt(s.charCodeAt(i) - 48);
      if (sig * 10n + d > U64_MAX) { // parse_decimal_overflow: ignore all further digits
        while (isDigit()) i++;
        return afterDigits(sig, expBefore + expAfter);
      }
      i++;
      sig = sig * 10n + d;
      expAfter--;
    }
    if (expAfter === 0) throw bad();
    return afterDigits(sig, expBefore + expAfter);
  };
  const parseLongInteger = (sig) => {
    let exponent = 0;
    while (isDigit()) { i++; exponent++; }
    return s[i] === '.' ? parseDecimal(sig, exponent) : afterDigits(sig, exponent);
  };
  const parseNumber = (sig) => {
    if (s[i] === '.') return { f64: parseDecimal(sig, 0) };
    if (s[i] === 'e' || s[i] === 'E') return { f64: parseExponent(sig, 0) };
    if (positive) return { u64: sig };
    // (sig as i64).wrapping_neg() >= 0, i.e. -0 or below i64::MIN, becomes an f64
    if (sig === 0n || sig > 1n << 63n) return { f64: -Number(sig) };
    return { i64: -sig };
  };

  let out;
  if (s[i] === '0') {
    i++;
    if (isDigit()) throw bad();
    out = parseNumber(0n);
  } else if (isDigit()) {
    let sig = BigInt(s.charCodeAt(i++) - 48);
    out = null;
    while (isDigit()) {
      const d = BigInt(s.charCodeAt(i) - 48);
      if (sig * 10n + d > U64_MAX) { out = { f64: parseLongInteger(sig) }; break; }
      i++;
      sig = sig * 10n + d;
    }
    out ??= parseNumber(sig);
  } else {
    throw bad();
  }
  if (i !== s.length) throw bad();
  return out;
}

/**
 * Print a finite f64 like serde_json 1.0.154 (zmij 1.0.23): shortest round-trip digits, fixed
 * notation with a mandatory fraction (`100.0`, `0.00001`) when the decimal exponent is in -5..=15,
 * else `d[.ddd]e±x` (`1e+16`, `1e-6`, `1.5e-7`).
 * @param {number} x
 * @returns {string}
 */
function serdeFormatF64(x) {
  if (x === 0) return Object.is(x, -0) ? '-0.0' : '0.0';
  const sign = x < 0 ? '-' : '';
  // shortest round-trip digits (same digit choice as zmij), from Number#toString
  const m = /^(\d+)(?:\.(\d+))?(?:e([+-]\d+))?$/.exec(String(Math.abs(x)));
  let digits = m[1] + (m[2] ?? '');
  let exp = Number(m[3] ?? 0) + m[1].length - 1; // decimal exponent of digits[0]
  const lead = digits.match(/^0*/)[0].length;
  digits = digits.slice(lead).replace(/0+$/, '');
  exp -= lead;
  if (exp >= -5 && exp <= 15) {
    if (digits.length - 1 <= exp) return `${sign}${digits}${'0'.repeat(exp - digits.length + 1)}.0`;
    if (exp >= 0) return `${sign}${digits.slice(0, exp + 1)}.${digits.slice(exp + 1)}`;
    return `${sign}0.${'0'.repeat(-exp - 1)}${digits}`;
  }
  const mant = digits.length > 1 ? `${digits[0]}.${digits.slice(1)}` : digits;
  return `${sign}${mant}e${exp < 0 ? '-' : '+'}${Math.abs(exp)}`;
}

/**
 * The contract's canonical form of a JSON number token.
 * @param {string} token
 * @returns {string}
 * @throws {RangeError} if the contract would reject the token (out of f64 range)
 */
function canonicalNumber(token) {
  const n = serdeParseNumber(token);
  return 'f64' in n ? serdeFormatF64(n.f64) : String(n.u64 ?? n.i64);
}

/**
 * Canonical JSON (docs/INTERFACE.md v3 #1): object keys sorted recursively in utf8 byte order,
 * no whitespace, standard JSON.stringify escapes, numbers printed as the contract's
 * `canonical_json` prints them (#15). Equal to what the contract computes for the JSON text:
 * - {@link JsonNumber} (from {@link parseJsonLossless}): canonicalized from its exact token, so
 *   `0.0` stays `0.0` and `0` stays `0`, as in the contract;
 * - a plain JS number or bigint: canonicalized from its JSON.stringify token, i.e. what the
 *   contract computes for a body built with JSON.stringify (`0` → `0`, `1.5` → `1.5`,
 *   `1e21` → `1e+21`); a non-finite number is `null`, as JSON.stringify writes it.
 * @param {unknown} v JSON value
 * @returns {string}
 * @throws {RangeError} a number token the contract rejects (e.g. `1e400`)
 */
export function canonicalJson(v) {
  if (v instanceof JsonNumber) return canonicalNumber(v.token);
  if (typeof v === 'number') return Number.isFinite(v) ? canonicalNumber(JSON.stringify(v)) : 'null';
  if (typeof v === 'bigint') return canonicalNumber(v.toString());
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(',')}]`;
  if (v !== null && typeof v === 'object') {
    return `{${Object.keys(v).sort(utf8Cmp).map((k) => `${JSON.stringify(k)}:${canonicalJson(v[k])}`).join(',')}}`;
  }
  const s = JSON.stringify(v);
  if (s === undefined) throw new Error(`canonicalJson: not a JSON value (${typeof v})`);
  return s;
}

/** The canonical judge request params (what buildRequestBody sends besides model + messages). */
export const JUDGE_PARAMS = Object.freeze({
  response_format: VERDICT_RESPONSE_FORMAT,
  chat_template_kwargs: Object.freeze({ enable_thinking: false }),
  temperature: 0,
  max_tokens: 400,
});

/** Exact top-level keys of a judge request; each message is exactly {role, content}. */
const REQUEST_KEYS = ['model', 'messages', 'response_format', 'chat_template_kwargs', 'temperature', 'max_tokens'];

/**
 * Program.params_hash: sha256hex(canonicalJson({chat_template_kwargs, max_tokens, response_format, temperature})).
 * To check a request body against a program use {@link requestParamsHash} (exact number tokens):
 * `paramsHash(JSON.parse(body))` re-reads `0.0` as `0` and so differs from the contract for bodies
 * with non-integer number tokens; `paramsHash(parseJsonLossless(body))` does not.
 * @param {{chat_template_kwargs?: unknown, max_tokens?: unknown, response_format?: unknown, temperature?: unknown}} [req]
 *   a parsed request (or just its params); defaults to the canonical JUDGE_PARAMS
 * @returns {string} 64 lowercase hex chars
 * @throws {RangeError} a number token the contract rejects (e.g. `1e400`)
 */
export function paramsHash(req = JUDGE_PARAMS) {
  const { chat_template_kwargs, max_tokens, response_format, temperature } = req;
  return sha256hex(canonicalJson({ chat_template_kwargs, max_tokens, response_format, temperature }));
}

/**
 * Lossless JSON parse: like JSON.parse, but every number is a {@link JsonNumber} holding its exact
 * source token, objects have a null prototype, and the paths of duplicated object keys are
 * reported (the last copy wins, as in JSON.parse; the contract rejects duplicates).
 * @param {string} text
 * @returns {{value: unknown, dups: (string|number)[][]}} dups e.g. [['temperature'], ['messages', 2, 'role']]
 * @throws {SyntaxError} invalid JSON
 */
function parseLossless(text) {
  JSON.parse(text); // validate; the scanner below assumes valid JSON
  const dups = [];
  let i = 0;
  const ws = () => { while (text[i] === ' ' || text[i] === '\t' || text[i] === '\n' || text[i] === '\r') i++; };
  const str = () => {
    const m = /"(?:[^"\\]|\\.)*"/y; m.lastIndex = i;
    const s = m.exec(text)[0]; i += s.length;
    return JSON.parse(s);
  };
  const value = (path) => {
    ws();
    const c = text[i];
    if (c === '{') {
      i++; ws();
      const obj = Object.create(null);
      if (text[i] === '}') { i++; return obj; }
      for (;;) {
        ws(); const k = str(); ws(); i++; // ':'
        if (Object.hasOwn(obj, k)) dups.push([...path, k]);
        obj[k] = value([...path, k]); ws();
        if (text[i++] === '}') return obj; // else ','
      }
    }
    if (c === '[') {
      i++; ws();
      const arr = [];
      if (text[i] === ']') { i++; return arr; }
      for (let n = 0; ; n++) {
        arr.push(value([...path, n])); ws();
        if (text[i++] === ']') return arr;
      }
    }
    if (c === '"') return str();
    const m = /-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|true|false|null/y; m.lastIndex = i;
    const tok = m.exec(text)[0];
    i += tok.length;
    if (tok === 'true') return true;
    if (tok === 'false') return false;
    if (tok === 'null') return null;
    return new JsonNumber(tok);
  };
  const v = value([]);
  return { value: v, dups };
}

/**
 * Parse JSON keeping every number's exact token (as {@link JsonNumber}), so that
 * `canonicalJson(parseJsonLossless(text))` is exactly the contract's canonical JSON of `text`.
 * Objects have a null prototype. Duplicate keys: the last copy wins.
 * @param {string} text
 * @returns {unknown}
 * @throws {SyntaxError} invalid JSON
 */
export function parseJsonLossless(text) {
  return parseLossless(text).value;
}

/** True if any number in `v` (a parseJsonLossless value) would make the contract's parse fail. */
const hasRejectedNumber = (v) => {
  if (v instanceof JsonNumber) {
    try { serdeParseNumber(v.token); return false; } catch { return true; }
  }
  if (v !== null && typeof v === 'object') return Object.values(v).some(hasRejectedNumber);
  return false;
};

/** {value, dups} if `body` has exactly the canonical request shape (object form), else null. */
function strictRequest(body) {
  let p;
  try { p = parseLossless(body); } catch { return null; }
  const req = p.value;
  const isObj = (o) => o !== null && typeof o === 'object' && !Array.isArray(o) && !(o instanceof JsonNumber);
  if (!isObj(req) || p.dups.length) return null;
  const keys = Object.keys(req);
  if (keys.length !== REQUEST_KEYS.length || !REQUEST_KEYS.every((k) => Object.hasOwn(req, k))) return null;
  const msgs = req.messages;
  const isMsg = (m) => isObj(m) && Object.keys(m).length === 2 && Object.hasOwn(m, 'role') && Object.hasOwn(m, 'content');
  if (!Array.isArray(msgs) || !msgs.every(isMsg)) return null;
  if (hasRejectedNumber(req)) return null;
  return req;
}

/**
 * The contract's `request_params_hash(request_body)` (#15: computed from the exact number tokens of
 * the body): the params hash if the body has exactly the canonical request shape (exactly
 * model/messages/response_format/chat_template_kwargs/temperature/max_tokens, each message exactly
 * {role, content}, no duplicate key anywhere, every number in f64 range), else null.
 * @param {string} requestBody exact request body
 * @returns {string|null} 64 lowercase hex chars, or null
 */
export function requestParamsHash(requestBody) {
  const req = strictRequest(requestBody);
  return req ? paramsHash(req) : null;
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
 * Pre-check a request body against a program the way the v3 contract's `dispute` does (after its
 * sha256 == req_hash check), returning the FIRST failing reason in contract order:
 * 1 "system prompt tampered" (unparsable JSON, messages[0] not system / hash != system_prompt_hash,
 *   or more than 3 messages), 2 "model mismatch", 3 "params tampered" (top-level keys not exactly
 *   model/messages/response_format/chat_template_kwargs/temperature/max_tokens, a message that is not
 *   exactly {role, content}, a duplicate key anywhere, or paramsHash(req) != params_hash; skipped when
 *   the program has no params_hash, i.e. a v2 contract), 4 "code mismatch" (messages[1] not user, TARGET
 *   line, malformed HUNTER/CODE header, or sha256(code) != code_hash), 5 "hunter mismatch" (only the
 *   HUNTER line differs from `hunter`: front-running), 6 "report missing" (messages[2] missing / not
 *   user / not starting with "REPORT\n").
 * ok:true means a dispute would fail with "dispute invalid: request matches program".
 * @param {string} requestBody exact request body
 * @param {{repo_url: string, commit: string, model_id: string, system_prompt_hash: string, code_hash: string, params_hash?: string}} program
 *   contract Program view (snake_case, as returned by get_program)
 * @param {string} hunter the account that submits (or submitted) the claim
 * @returns {{ok: boolean, reason: null|'system prompt tampered'|'model mismatch'|'params tampered'|'code mismatch'|'hunter mismatch'|'report missing'}}
 */
export function checkRequestAgainstProgram(requestBody, program, hunter) {
  const fail = (reason) => ({ ok: false, reason });
  let parsed;
  try { parsed = parseLossless(requestBody); } catch { return fail('system prompt tampered'); }
  const { value: req, dups } = parsed;
  if (req === null || typeof req !== 'object' || req instanceof JsonNumber || typeof req.model !== 'string' ||
    !Array.isArray(req.messages)) {
    return fail('system prompt tampered');
  }
  const msgs = req.messages;
  const isMsg = (m) => m !== null && typeof m === 'object' && typeof m.role === 'string' && 'content' in m;
  if (!msgs.every(isMsg)) return fail('system prompt tampered'); // contract: messages fail to deserialize
  // The contract's lenient serde structs reject a repeated `model`/`messages` key or a repeated
  // `role`/`content` key in a message; any other duplicate is caught at the params step.
  const structDup = (p) => (p.length === 1 && (p[0] === 'model' || p[0] === 'messages')) ||
    (p.length === 3 && p[0] === 'messages' && (p[2] === 'role' || p[2] === 'content'));
  if (dups.some(structDup)) return fail('system prompt tampered');
  // message content is a serde_json::Value there: an out-of-range number in it fails the parse
  if (msgs.some((m) => hasRejectedNumber(m.content))) return fail('system prompt tampered');
  const m0 = msgs[0];
  if (!m0 || m0.role !== 'system' || typeof m0.content !== 'string' || sha256hex(m0.content) !== program.system_prompt_hash) {
    return fail('system prompt tampered');
  }
  if (msgs.length > 3) return fail('system prompt tampered');
  if (req.model !== program.model_id) return fail('model mismatch');

  // v3 #1: exact request shape, no duplicate keys, params hash pinned. A v2 program (no
  // params_hash) skips this step, as the v2 contract does.
  if (program.params_hash != null && requestParamsHash(requestBody) !== program.params_hash) {
    return fail('params tampered');
  }

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
  return encryptForOwnerWithSecret(requestBody, ownerPubB64).ciphertext;
}

/**
 * Same as encryptForOwner, but also returns the ephemeral x25519 secret (hex). The hunter keeps
 * it (CLI: ~/.sealedbounty/hunter-<contract>-<claim>.json) to answer a decryption challenge with
 * `prove_ciphertext(claim_id, ephemeral_secret)` (INTERFACE.md v3 #2).
 * @param {string} requestBody
 * @param {string} ownerPubB64 base64 x25519 public key (Program.owner_enc_pubkey)
 * @param {{ephemeralSecret?: Uint8Array, nonce?: Uint8Array}} [opts] fixed inputs (tests only)
 * @returns {{ciphertext: string, ephemeralSecretHex: string}}
 */
export function encryptForOwnerWithSecret(requestBody, ownerPubB64, opts = {}) {
  const ownerPub = decodeBase64(ownerPubB64);
  if (ownerPub.length !== nacl.box.publicKeyLength) throw new Error('owner pubkey must be 32 bytes');
  const eph = opts.ephemeralSecret
    ? nacl.box.keyPair.fromSecretKey(opts.ephemeralSecret)
    : nacl.box.keyPair();
  const nonce = opts.nonce ?? nacl.randomBytes(nacl.box.nonceLength);
  if (nonce.length !== nacl.box.nonceLength) throw new Error('nonce must be 24 bytes');
  const boxed = nacl.box(utf8(requestBody), nonce, ownerPub, eph.secretKey);
  const out = new Uint8Array(32 + 24 + boxed.length);
  out.set(eph.publicKey, 0); out.set(nonce, 32); out.set(boxed, 56);
  return { ciphertext: encodeBase64(out), ephemeralSecretHex: hexlify(eph.secretKey).slice(2) };
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
