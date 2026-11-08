/**
 * Spike A (SealedBounty): verify that NEAR AI Cloud model attestations come from a TEE
 * and extract the signing identities a contract can allowlist.
 *
 * Adapted from (credit):
 *   - nearai/nearai-cloud-verifier  ts/model_verifier.ts
 *     (fetchReport, checkTdxQuote, checkReportData, signingAddressPadded32, showCompose, checkGpu)
 *   - near-examples/nearai-cloud-verification-example  utils/model-attestation.js
 *     (NRAS response decoding / eat_nonce check)
 *
 * Copied from spike/attest/src/attest.ts and turned into a library for `sealedbounty attest`.
 */
import { createHash, randomBytes } from 'node:crypto';
import { createRequire } from 'node:module';
import { writeFileSync } from 'node:fs';
import { decodeJwt, jwtVerify, createRemoteJWKSet, decodeProtectedHeader } from 'jose';
import { keccak_256 } from '@noble/hashes/sha3.js';

const require = createRequire(import.meta.url);

const API_BASE = 'https://cloud-api.near.ai';
let MODEL = 'Qwen/Qwen3.8-27B';
const PCCS_URL = 'https://api.trustedservices.intel.com/tdx/certification/v4';
const NRAS_URL = 'https://nras.attestation.nvidia.com/v3/attest/gpu';
const NRAS_JWKS_URL = 'https://nras.attestation.nvidia.com/.well-known/jwks.json';

// ---------- types ----------
type Status = 'PASS' | 'FAIL' | 'SKIPPED' | 'N/A';
interface Check { status: Status; detail?: string }
type Checks = Record<string, Check>;

interface Attestation {
  model_name?: string;
  intel_quote: string;
  event_log?: string;
  request_nonce?: string;
  report_data?: string;
  signing_address: string;
  signing_algo: string;
  signing_public_key?: string;
  tls_cert_fingerprint?: string;
  nvidia_payload?: string;
  info?: { tcb_info?: string | { app_compose?: string } };
  [k: string]: unknown;
}

// ---------- helpers ----------
const pass = (detail?: string): Check => ({ status: 'PASS', detail });
const fail = (detail?: string): Check => ({ status: 'FAIL', detail });
const skip = (detail: string): Check => ({ status: 'SKIPPED', detail });
const na = (detail: string): Check => ({ status: 'N/A', detail });
const strip0x = (h: string) => h.replace(/^0x/i, '').toLowerCase();
const sha256 = (b: Buffer | string) => createHash('sha256').update(b).digest();
const errMsg = (e: unknown) => (e instanceof Error ? e.message : String(e));

function loadApiKey(): string | undefined {
  return process.env.NEARAI_API_KEY || undefined; // .env already loaded by the CLI
}

async function fetchReport(algo: string, nonce: string): Promise<any> {
  const url = `${API_BASE}/v1/attestation/report?model=${encodeURIComponent(MODEL)}&provider=near&signing_algo=${algo}&nonce=${nonce}`;
  const doFetch = (auth?: string) =>
    fetch(url, {
      headers: { 'x-no-aliasing': 'true', Accept: 'application/json', ...(auth ? { Authorization: `Bearer ${auth}` } : {}) },
      signal: AbortSignal.timeout(60_000),
    });
  let res = await doFetch();
  if (res.status === 429) {
    const key = loadApiKey();
    if (key) res = await doFetch(key);
  }
  if (!res.ok) throw new Error(`attestation report HTTP ${res.status}: ${(await res.text()).slice(0, 300)}`);
  return res.json();
}

// ---------- TDX quote (DCAP) ----------
interface TdxResult { status: string; reportData: Buffer; mrConfigId: string; tdAttributes: string; advisories: string[] }

let dcap: { js_verify: Function; js_get_collateral: Function } | null = null;
let dcapLoadError: string | null = null;
try {
  dcap = require('@phala/dcap-qvl-node');
} catch (e) {
  dcapLoadError = errMsg(e);
}

async function verifyTdx(quoteHex: string): Promise<TdxResult> {
  if (!dcap) throw new Error(`dcap-qvl unavailable: ${dcapLoadError}`);
  const raw = Buffer.from(strip0x(quoteHex), 'hex');
  const collateral = await dcap.js_get_collateral(PCCS_URL, raw);
  const r: any = dcap.js_verify(raw, collateral, BigInt(Math.floor(Date.now() / 1000)));
  const td = r?.report?.TD10 ?? r?.report?.TD15;
  if (!td) throw new Error(`unexpected verify result: ${JSON.stringify(r).slice(0, 200)}`);
  return {
    status: r.status,
    reportData: Buffer.from(td.report_data, 'hex'),
    mrConfigId: String(td.mr_config_id).toLowerCase(),
    tdAttributes: String(td.td_attributes).toLowerCase(),
    advisories: r.advisory_ids ?? [],
  };
}

// ---------- report_data binding (from model_verifier.ts checkReportData / signingAddressPadded32) ----------
function identityBytes(att: Attestation): Buffer {
  return Buffer.from(strip0x(att.signing_address), 'hex');
}

function checkReportData(att: Attestation, nonce: string, rd: Buffer): { signer: Check; nonce: Check } {
  const first = rd.subarray(0, 32);
  const second = rd.subarray(32, 64);
  const id = identityBytes(att);
  let expected: Buffer;
  let mode: string;
  if (att.tls_cert_fingerprint) {
    expected = sha256(Buffer.concat([id, Buffer.from(strip0x(att.tls_cert_fingerprint), 'hex')]));
    mode = 'sha256(identity||tls_fp)';
  } else {
    if (id.length > 32) return { signer: fail(`identity too long (${id.length}B)`), nonce: fail('n/a') };
    expected = Buffer.concat([id, Buffer.alloc(32 - id.length)]);
    mode = 'padded identity';
  }
  const signer = first.equals(expected)
    ? pass(mode)
    : fail(`${mode}: expected ${expected.toString('hex')} got ${first.toString('hex')}`);
  const nonceOk = second.equals(Buffer.from(nonce, 'hex'));
  return { signer, nonce: nonceOk ? pass() : fail(`got ${second.toString('hex')}`) };
}

// ---------- app compose / MRCONFIGID (from model_verifier.ts showCompose) ----------
function appCompose(att: Attestation): string | undefined {
  const tcb = att.info?.tcb_info;
  if (!tcb) return undefined;
  const obj = typeof tcb === 'string' ? JSON.parse(tcb) : tcb;
  return obj.app_compose;
}

function checkMrConfig(att: Attestation, mrConfigId: string): { check: Check; composeHash?: string } {
  const compose = appCompose(att);
  if (!compose) return { check: fail('no info.tcb_info.app_compose') };
  const h = sha256(compose).toString('hex');
  const expected = ('01' + h).padEnd(96, '0'); // MRCONFIGID is 48 bytes: 0x01 || sha256 || zeros
  return { check: mrConfigId === expected ? pass(`compose sha256 ${h}`) : fail(`expected ${expected} got ${mrConfigId}`), composeHash: h };
}

// ---------- GPU via NVIDIA NRAS (from model_verifier.ts checkGpu + example decodeNvidiaAttestation) ----------
const nrasJwks = createRemoteJWKSet(new URL(NRAS_JWKS_URL));

async function checkGpu(att: Attestation, nonce: string): Promise<Checks> {
  if (!att.nvidia_payload) {
    const r = na('no nvidia_payload (gateway is CPU-only)');
    return { gpu_payload_nonce: r, gpu_nras_verdict: r, gpu_eat_nonce: r, gpu_jwt_signature: r };
  }
  const payload = JSON.parse(att.nvidia_payload);
  const out: Checks = {};
  out.gpu_payload_nonce = strip0x(payload.nonce ?? '') === nonce ? pass() : fail(`payload nonce ${payload.nonce}`);
  let body: any;
  try {
    const res = await fetch(NRAS_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(60_000),
    });
    const text = await res.text();
    if (!res.ok) throw new Error(`NRAS HTTP ${res.status}: ${text.slice(0, 200)}`);
    body = JSON.parse(text);
  } catch (e) {
    const s = skip(`NRAS call failed: ${errMsg(e)}`);
    return { ...out, gpu_nras_verdict: s, gpu_eat_nonce: s, gpu_jwt_signature: s };
  }
  const jwt: string = body?.[0]?.[1];
  if (typeof jwt !== 'string') {
    const f = fail('unexpected NRAS response shape');
    return { ...out, gpu_nras_verdict: f, gpu_eat_nonce: f, gpu_jwt_signature: f };
  }
  const claims: any = decodeJwt(jwt);
  out.gpu_nras_verdict = claims['x-nvidia-overall-att-result'] === true ? pass() : fail(`verdict=${claims['x-nvidia-overall-att-result']}`);
  out.gpu_eat_nonce = strip0x(String(claims.eat_nonce ?? '')) === nonce ? pass() : fail(`eat_nonce=${claims.eat_nonce}`);
  // Extra: verify the NRAS JWT signature against NVIDIA's JWKS (overall token + per-GPU tokens).
  try {
    const tokens: string[] = [jwt, ...Object.values((body?.[1] ?? {}) as Record<string, string>)];
    for (const t of tokens) await jwtVerify(t, nrasJwks, { algorithms: [decodeProtectedHeader(t).alg!] });
    out.gpu_jwt_signature = pass(`${tokens.length} token(s) signed by NRAS JWKS`);
  } catch (e) {
    const m = errMsg(e);
    out.gpu_jwt_signature = /fetch|network|timeout|JWKS/i.test(m) ? skip(`JWKS: ${m}`) : fail(m);
  }
  return out;
}

// ---------- identity consistency ----------
function checkPubkey(att: Attestation): Check {
  const pk = att.signing_public_key;
  if (!pk) return na('no signing_public_key field');
  const algo = att.signing_algo.toLowerCase();
  if (algo === 'ed25519') {
    return strip0x(pk) === strip0x(att.signing_address) && strip0x(pk).length === 64
      ? pass('pubkey == signing_address')
      : fail(`pubkey ${pk} vs address ${att.signing_address}`);
  }
  // ecdsa: eth address = keccak256(uncompressed_pubkey[1:] (64B))[12:]
  let raw = Buffer.from(strip0x(pk), 'hex');
  if (raw.length === 65 && raw[0] === 0x04) raw = raw.subarray(1);
  if (raw.length !== 64) return fail(`unexpected ecdsa pubkey length ${raw.length}`);
  const addr = Buffer.from(keccak_256(raw)).subarray(12).toString('hex');
  return addr === strip0x(att.signing_address) ? pass('keccak(pubkey) == address') : fail(`derived 0x${addr}`);
}

function checkTdAttributes(tdAttrHex: string): Check {
  // TD_ATTRIBUTES is a little-endian u64; bit 0 = DEBUG.
  const b0 = Buffer.from(tdAttrHex, 'hex')[0];
  return (b0 & 1) === 0 ? pass(`td_attributes=${tdAttrHex}`) : fail(`DEBUG TD (td_attributes=${tdAttrHex})`);
}

// ---------- per-entry verification ----------
async function verifyEntry(att: Attestation, kind: 'model' | 'gateway', nonce: string, algo: string): Promise<Checks> {
  const c: Checks = {};
  c.signing_algo = att.signing_algo?.toLowerCase() === algo ? pass() : fail(`got ${att.signing_algo}`);
  c.request_nonce_echo = att.request_nonce === undefined ? na('field absent') : strip0x(att.request_nonce) === nonce ? pass() : fail(att.request_nonce);
  if (kind === 'model') c.model_name = att.model_name === MODEL ? pass() : fail(`got ${att.model_name}`);

  let tdx: TdxResult | undefined;
  try {
    tdx = await verifyTdx(att.intel_quote);
    c.tdx_quote_dcap = ['UpToDate', 'OutOfDate', 'SWHardeningNeeded', 'ConfigurationAndSWHardeningNeeded'].includes(tdx.status)
      ? pass(`status=${tdx.status}${tdx.advisories.length ? ` advisories=${tdx.advisories.join(',')}` : ''}`)
      : fail(`status=${tdx.status}`);
  } catch (e) {
    const m = errMsg(e);
    c.tdx_quote_dcap = m.startsWith('dcap-qvl unavailable') ? skip(m) : fail(m);
  }

  if (tdx) {
    c.td_not_debug = checkTdAttributes(tdx.tdAttributes);
    const rd = checkReportData(att, nonce, tdx.reportData);
    c.report_data_signer = rd.signer;
    c.report_data_nonce = rd.nonce;
    if (att.report_data !== undefined) {
      c.report_data_field_matches_quote = strip0x(att.report_data) === tdx.reportData.toString('hex') ? pass() : fail('json report_data != quote');
    }
    c.mrconfigid_app_compose = checkMrConfig(att, tdx.mrConfigId).check;
  } else {
    const s = skip('TDX quote not verified');
    Object.assign(c, { td_not_debug: s, report_data_signer: s, report_data_nonce: s, mrconfigid_app_compose: s });
  }

  c.signing_pubkey_consistency = checkPubkey(att);
  Object.assign(c, await checkGpu(att, nonce));
  return c;
}

// A signer is verified only if nothing FAILED and every hard requirement is PASS (SKIPPED != PASS).
const REQUIRED_MODEL = ['tdx_quote_dcap', 'td_not_debug', 'report_data_signer', 'report_data_nonce', 'mrconfigid_app_compose', 'gpu_nras_verdict', 'gpu_eat_nonce'];
const REQUIRED_GATEWAY = ['tdx_quote_dcap', 'td_not_debug', 'report_data_signer', 'report_data_nonce', 'mrconfigid_app_compose'];
function isVerified(kind: string, c: Checks): boolean {
  if (Object.values(c).some((x) => x.status === 'FAIL')) return false;
  return (kind === 'model' ? REQUIRED_MODEL : REQUIRED_GATEWAY).every((k) => c[k]?.status === 'PASS');
}

// ---------- output ----------
function printTable(title: string, rows: { label: string; checks: Checks }[]) {
  const names = [...new Set(rows.flatMap((r) => Object.keys(r.checks)))];
  const w0 = Math.max(...names.map((n) => n.length), 5);
  console.log(`\n=== ${title} ===`);
  for (const r of rows) {
    console.log(`\n-- ${r.label}`);
    for (const n of names) {
      const ch = r.checks[n];
      if (!ch) continue;
      const d = ch.detail ? `  ${ch.detail.length > 110 ? ch.detail.slice(0, 107) + '...' : ch.detail}` : '';
      console.log(`  ${n.padEnd(w0)}  ${ch.status.padEnd(7)}${d}`);
    }
  }
}

export interface AttestedSigner {
  signing_algo: 'ed25519' | 'ecdsa';
  signing_address: string;
  signing_public_key?: string;
  kind: 'model' | 'gateway';
  label: string;
  verified: boolean;
  checks: Checks;
}

export interface AttestationRun {
  algo: 'ed25519' | 'ecdsa';
  nonce: string;
  fetched_at: string;
  model: string;
  signers: AttestedSigner[];
  allModelSignersVerified: boolean;
}

export const dcapStatus = () => (dcap ? 'loaded' : `unavailable: ${dcapLoadError}`);

export async function runAttestation(algo: 'ed25519' | 'ecdsa', opts: { model: string; out?: string; quiet?: boolean }): Promise<AttestationRun> {
  MODEL = opts.model;
  const nonce = randomBytes(32).toString('hex');
  const fetched_at = new Date().toISOString();
  const raw = await fetchReport(algo, nonce);

  const entries: { att: Attestation; kind: 'model' | 'gateway'; label: string }[] = [];
  if (raw.gateway_attestation) entries.push({ att: raw.gateway_attestation, kind: 'gateway', label: 'gateway' });
  (raw.model_attestations ?? []).forEach((a: Attestation, i: number) => entries.push({ att: a, kind: 'model', label: `model[${i}] ${a.model_name}` }));

  const signers: AttestedSigner[] = [];
  for (const e of entries) {
    const checks = await verifyEntry(e.att, e.kind, nonce, algo);
    const addr = strip0x(e.att.signing_address);
    signers.push({
      signing_algo: algo,
      signing_address: algo === 'ecdsa' ? `0x${addr}` : addr,
      ...(e.att.signing_public_key ? { signing_public_key: strip0x(e.att.signing_public_key) } : {}),
      kind: e.kind,
      label: e.label,
      verified: isVerified(e.kind, checks),
      checks,
    });
  }
  if (!opts.quiet) {
    printTable(`${algo}  nonce=${nonce}`, signers.map((r) => ({ label: `${r.label}  signer=${r.signing_address}  => ${r.verified ? 'VERIFIED' : 'NOT VERIFIED'}`, checks: r.checks })));
  }
  if (opts.out) {
    writeFileSync(opts.out, JSON.stringify({
      nonce, fetched_at, model: MODEL,
      policy: { pccs_url: PCCS_URL, nras_url: NRAS_URL, required_model_checks: REQUIRED_MODEL, required_gateway_checks: REQUIRED_GATEWAY,
        note: 'verified=true only if no check FAILED and all required checks PASSED (SKIPPED never counts as pass).' },
      raw_response: raw,
      verified_signers: signers.map(({ label, ...r }) => r),
    }, null, 2) + '\n');
    console.log(`\nwrote ${opts.out}`);
  }
  const models = signers.filter((r) => r.kind === 'model');
  return { algo, nonce, fetched_at, model: MODEL, signers, allModelSignersVerified: models.length > 0 && models.every((r) => r.verified) };
}
