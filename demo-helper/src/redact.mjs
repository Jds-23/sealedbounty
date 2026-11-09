// Everything the helper sends (JSON, SSE) or logs goes through a redactor: the NEAR AI key and any
// NEAR private key must never leave the process, even inside an upstream error message.

const R = '[REDACTED]';
const SECRET_NAME = /(KEY|SECRET|PRIVATE|TOKEN|PASSWORD)/i;
/** Values of these names are public even though they match SECRET_NAME. */
const PUBLIC_NAMES = new Set(['NEAR_MAINNET_PAYOUT_ACCOUNT']);

const PATTERNS = [
  // NEAR secret keys: ed25519:/secp256k1: + base58 of 64 bytes (~88 chars). Public keys are ~44 chars and stay.
  [/\b(ed25519|secp256k1):[1-9A-HJ-NP-Za-km-z]{70,}/g, `$1:${R}`],
  // JSON fields holding secrets (credentials files, owner/hunter secret files)
  [/("(?:private_key|secret_key|secretKey|ephemeralSecretHex|ephemeral_secret|api_key|apiKey)"\s*:\s*")[^"]*(")/g, `$1${R}$2`],
  [/\bBearer\s+[^\s"']+/gi, `Bearer ${R}`],
  // NEAR AI style keys
  [/\bsk-[A-Za-z0-9_-]{16,}/g, R],
];

/** Env values that look secret by name (NEARAI_API_KEY, *_SECRET, …). */
export function secretsFromEnv(env) {
  return Object.entries(env)
    .filter(([k, v]) => SECRET_NAME.test(k) && !PUBLIC_NAMES.has(k) && typeof v === 'string' && v.length >= 8)
    .map(([, v]) => v);
}

/** @param {string[]} secrets literal values to scrub (short ones are ignored to avoid shredding text) */
export function makeRedactor(secrets = []) {
  const lits = [...new Set(secrets.filter((s) => typeof s === 'string' && s.length >= 8))].sort((a, b) => b.length - a.length);
  return (input) => {
    let s = String(input);
    for (const lit of lits) s = s.split(lit).join(R);
    for (const [re, rep] of PATTERNS) s = s.replace(re, rep);
    return s;
  };
}

export function redactDeep(value, redact) {
  if (typeof value === 'string') return redact(value);
  if (Array.isArray(value)) return value.map((v) => redactDeep(v, redact));
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, redactDeep(v, redact)]));
  return value;
}

/**
 * Success payloads carry signed data (request_body, response_body_b64, tx hashes) that must stay byte
 * for byte, so they are never rewritten. They are only scanned for the literal secrets; the caller
 * refuses to send a payload that contains one.
 * @returns {(value: unknown) => boolean}
 */
export function makeSecretScanner(secrets = []) {
  const lits = [...new Set(secrets.filter((s) => typeof s === 'string' && s.length >= 8))];
  const scan = (v) => {
    if (typeof v === 'string') return lits.some((l) => v.includes(l));
    if (Array.isArray(v)) return v.some(scan);
    if (v && typeof v === 'object') return Object.entries(v).some(([k, x]) => scan(k) || scan(x));
    return false;
  };
  return scan;
}
