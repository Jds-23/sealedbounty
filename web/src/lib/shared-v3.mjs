// TEMPORARY SHIM: local copies of the v3 shared/judge.mjs exports (fix/1-params-pinning,
// fix/2-decryption-challenge) until this branch is rebased onto integrate/v3. Remove after rebase
// and import these names from '@sealedbounty/shared' instead.
import nacl from 'tweetnacl';
import * as shared from '@sealedbounty/shared';

const enc = new TextEncoder();
const utf8Cmp = (a, b) => {
  const x = enc.encode(a), y = enc.encode(b);
  for (let i = 0; i < Math.min(x.length, y.length); i++) if (x[i] !== y[i]) return x[i] - y[i];
  return x.length - y.length;
};

/** Canonical JSON (INTERFACE.md v3 #1): keys sorted recursively (utf8 byte order), no whitespace. */
export function canonicalJson(v) {
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(',')}]`;
  if (v !== null && typeof v === 'object') {
    return `{${Object.keys(v).sort(utf8Cmp).map((k) => `${JSON.stringify(k)}:${canonicalJson(v[k])}`).join(',')}}`;
  }
  const s = JSON.stringify(v);
  if (s === undefined) throw new Error(`canonicalJson: not a JSON value (${typeof v})`);
  return s;
}

export const JUDGE_PARAMS = Object.freeze({
  response_format: shared.VERDICT_RESPONSE_FORMAT,
  chat_template_kwargs: Object.freeze({ enable_thinking: false }),
  temperature: 0,
  max_tokens: 400,
});

const REQUEST_KEYS = ['model', 'messages', 'response_format', 'chat_template_kwargs', 'temperature', 'max_tokens'];

export function paramsHash(req = JUDGE_PARAMS) {
  const { chat_template_kwargs, max_tokens, response_format, temperature } = req;
  return shared.sha256hex(canonicalJson({ chat_template_kwargs, max_tokens, response_format, temperature }));
}

/**
 * v3 dispute pre-check: prompt -> model -> params -> code -> hunter -> report. Wraps the v2 shared
 * check and inserts the params step (skipped for programs without params_hash). The upstream
 * version also rejects duplicate JSON keys; this shim does not.
 */
export function checkRequestAgainstProgram(requestBody, program, hunter) {
  const v2 = shared.checkRequestAgainstProgram(requestBody, program, hunter);
  if (program.params_hash == null) return v2;
  if (v2.reason === 'system prompt tampered' || v2.reason === 'model mismatch') return v2;
  const req = JSON.parse(requestBody);
  const keys = Object.keys(req);
  const exact = keys.length === REQUEST_KEYS.length && REQUEST_KEYS.every((k) => Object.hasOwn(req, k)) &&
    req.messages.every((m) => Object.keys(m).length === 2);
  if (!exact || paramsHash(req) !== program.params_hash) return { ok: false, reason: 'params tampered' };
  return v2;
}

/** encryptForOwner that also returns the ephemeral x25519 secret (hex), for prove_ciphertext (v3 #2). */
export function encryptForOwnerWithSecret(requestBody, ownerPubB64, opts = {}) {
  const ownerPub = Uint8Array.from(atob(ownerPubB64), (c) => c.charCodeAt(0));
  if (ownerPub.length !== 32) throw new Error('owner pubkey must be 32 bytes');
  const eph = opts.ephemeralSecret ? nacl.box.keyPair.fromSecretKey(opts.ephemeralSecret) : nacl.box.keyPair();
  const nonce = opts.nonce ?? nacl.randomBytes(24);
  const boxed = nacl.box(enc.encode(requestBody), nonce, ownerPub, eph.secretKey);
  const out = new Uint8Array(56 + boxed.length);
  out.set(eph.publicKey, 0); out.set(nonce, 32); out.set(boxed, 56);
  const b64 = btoa(String.fromCharCode(...out));
  const hex = Array.from(eph.secretKey, (b) => b.toString(16).padStart(2, '0')).join('');
  return { ciphertext: b64, ephemeralSecretHex: hex };
}
