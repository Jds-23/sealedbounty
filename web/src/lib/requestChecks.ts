// Owner-side audit of a decrypted judge request against the program, mirroring the v3 contract's
// `dispute` (docs/INTERFACE.md "v3": prompt -> model -> params -> code -> hunter -> report). The
// overall verdict comes from the shared checkRequestAgainstProgram (same code the CLI uses); the
// per-check breakdown below explains it.
import { sha256hex } from '@sealedbounty/shared';
import { canonicalJson, checkRequestAgainstProgram, JUDGE_PARAMS, paramsHash, type DisputeReasonV3 as DisputeReason } from './shared-v3.mjs';
import type { Program } from './types';

export type { DisputeReason };
export type ReqCheckKey = 'prompt' | 'model' | 'params' | 'code' | 'hunter' | 'report';
export interface ReqCheck {
  key: ReqCheckKey;
  label: string;
  /** null = not applicable (v1 program without code_hash, or v2 without params_hash) */
  ok: boolean | null;
  detail: string;
}
export interface RequestAudit {
  /** true: a dispute would fail ("request matches program"). */
  ok: boolean;
  /** First failing reason in contract order (what `dispute` would reject with). */
  reason: DisputeReason | null;
  /** Program has no code_hash (v1 contract): only prompt + model can be checked. */
  v1: boolean;
  checks: ReqCheck[];
}

const short = (h: string) => `${h.slice(0, 10)}…`;

interface Msg {
  role?: unknown;
  content?: unknown;
}

export function auditRequest(body: string, program: Program, hunter: string): RequestAudit {
  let req: Record<string, unknown> | null = null;
  try {
    const j = JSON.parse(body);
    if (j && typeof j === 'object') req = j;
  } catch {
    /* handled below */
  }
  const msgs: Msg[] = Array.isArray(req?.messages) ? (req!.messages as Msg[]).filter((m) => m && typeof m === 'object') : [];
  const str = (m: Msg | undefined) => (typeof m?.content === 'string' ? m.content : null);

  // 1. system prompt
  const m0 = msgs[0];
  let prompt: ReqCheck;
  if (!req) prompt = { key: 'prompt', label: 'System prompt', ok: false, detail: 'request is not JSON' };
  else if (m0?.role !== 'system' || str(m0) === null) prompt = { key: 'prompt', label: 'System prompt', ok: false, detail: 'messages[0] is not a system message' };
  else {
    const h = sha256hex(str(m0)!);
    const extra = program.code_hash !== null && msgs.length > 3;
    prompt = {
      key: 'prompt',
      label: 'System prompt',
      ok: h === program.system_prompt_hash && !extra,
      detail:
        h !== program.system_prompt_hash
          ? `sha256 ${short(h)} ≠ program.system_prompt_hash ${short(program.system_prompt_hash)}`
          : extra
            ? `${msgs.length} messages; only system + CODE + REPORT are allowed`
            : `sha256 = program.system_prompt_hash (${short(h)})`,
    };
  }

  // 2. model
  const model: ReqCheck = {
    key: 'model',
    label: 'Model',
    ok: req?.model === program.model_id,
    detail: req?.model === program.model_id ? String(req.model) : `request ${JSON.stringify(req?.model ?? null)} ≠ program ${program.model_id}`,
  };

  if (program.code_hash === null) {
    const na = (key: ReqCheckKey, label: string): ReqCheck => ({
      key,
      label,
      ok: null,
      detail: 'v1 program: no code_hash onchain, so the request is not bound to the code or the hunter',
    });
    const reason: DisputeReason | null = !prompt.ok ? 'system prompt tampered' : !model.ok ? 'model mismatch' : null;
    return {
      ok: reason === null,
      reason,
      v1: true,
      checks: [prompt, model, na('params', 'Params'), na('code', 'Code bundle'), na('hunter', 'Hunter'), na('report', 'Report')],
    };
  }

  // 3. params (v3 #1)
  const params = req ? checkParams(req, program.params_hash) : { key: 'params' as const, label: 'Params', ok: false, detail: 'request is not JSON' };

  // 3 + 4. code bundle and hunter, both in messages[1]
  const m1 = msgs[1];
  const c1 = m1?.role === 'user' ? str(m1) : null;
  const target = `TARGET ${program.repo_url}@${program.commit}\n`;
  let code: ReqCheck;
  let hunterCheck: ReqCheck;
  const hunterFail = (detail: string): ReqCheck => ({ key: 'hunter', label: 'Hunter', ok: false, detail });
  if (c1 === null) {
    code = { key: 'code', label: 'Code bundle', ok: false, detail: 'messages[1] is not a user message' };
    hunterCheck = hunterFail('no HUNTER line');
  } else if (!c1.startsWith(target)) {
    const got = c1.split('\n')[0];
    code = { key: 'code', label: 'Code bundle', ok: false, detail: `TARGET line "${got.slice(0, 120)}" ≠ program repo@commit` };
    hunterCheck = hunterFail('no HUNTER line after the program TARGET');
  } else {
    const after = c1.slice(target.length);
    const nl = after.indexOf('\n');
    const claimed = after.startsWith('HUNTER ') && nl > 0 ? after.slice(7, nl) : null;
    const hdr = '\n\nCODE\n';
    if (claimed === null || !after.startsWith(hdr, nl)) {
      code = { key: 'code', label: 'Code bundle', ok: false, detail: 'malformed HUNTER / CODE header' };
      hunterCheck = claimed === null ? hunterFail('no HUNTER line') : checkHunter(claimed, hunter);
    } else {
      const h = sha256hex(after.slice(nl + hdr.length));
      code = {
        key: 'code',
        label: 'Code bundle',
        ok: h === program.code_hash,
        detail:
          h === program.code_hash
            ? `sha256(CODE) = program.code_hash (${short(h)})`
            : `sha256(CODE) ${short(h)} ≠ program.code_hash ${short(program.code_hash)}: the hunter did not judge the published code`,
      };
      hunterCheck = checkHunter(claimed, hunter);
    }
  }

  // 5. report
  const m2 = msgs[2];
  const c2 = m2?.role === 'user' ? str(m2) : null;
  const report: ReqCheck = {
    key: 'report',
    label: 'Report',
    ok: c2 !== null && c2.startsWith('REPORT\n'),
    detail: c2 === null ? 'messages[2] missing or not a user message' : c2.startsWith('REPORT\n') ? `${c2.length - 7} chars after "REPORT"` : 'messages[2] does not start with "REPORT"',
  };

  const overall = checkRequestAgainstProgram(body, { ...program, code_hash: program.code_hash }, hunter);
  return { ok: overall.ok, reason: overall.reason, v1: false, checks: [prompt, model, params, code, hunterCheck, report] };
}

const REQUEST_KEYS = ['model', 'messages', 'response_format', 'chat_template_kwargs', 'temperature', 'max_tokens'];
const PARAM_KEYS = ['response_format', 'chat_template_kwargs', 'temperature', 'max_tokens'] as const;

/** Explains the params step: which keys are extra / missing / differ from the canonical judge params. */
function checkParams(req: Record<string, unknown>, pinned: string | null): ReqCheck {
  const label = 'Params';
  if (pinned === null) return { key: 'params', label, ok: null, detail: 'v2 program: no params_hash onchain, so temperature, max_tokens and response_format are not pinned' };
  let h: string | null = null;
  try {
    h = paramsHash(req);
  } catch {
    /* a param is missing: canonicalJson has nothing to hash */
  }
  const extra = Object.keys(req).filter((k) => !REQUEST_KEYS.includes(k));
  const missing = REQUEST_KEYS.filter((k) => !Object.hasOwn(req, k));
  const msgExtra = Array.isArray(req.messages) && (req.messages as object[]).some((m) => m && typeof m === 'object' && Object.keys(m).length !== 2);
  const differ = PARAM_KEYS.filter((k) => Object.hasOwn(req, k) && canonicalJson(req[k]) !== canonicalJson(JUDGE_PARAMS[k]));
  const ok = h === pinned && !extra.length && !missing.length && !msgExtra;
  if (ok) return { key: 'params', label, ok, detail: `sha256(canonical params) = program.params_hash (${short(pinned)})` };
  const why = [
    extra.length && `extra key ${extra.join(', ')}`,
    missing.length && `missing ${missing.join(', ')}`,
    msgExtra && 'a message has fields besides role/content',
    differ.length && `${differ.map((k) => (k === 'temperature' || k === 'max_tokens' ? `${k}=${JSON.stringify(req[k])}` : k)).join(', ')} differs from the canonical judge params`,
  ].filter(Boolean);
  return {
    key: 'params',
    label,
    ok: false,
    detail: `${why.length ? why.join('; ') + ': ' : ''}${h ? `sha256 ${short(h)} ≠ ` : 'cannot match '}program.params_hash ${short(pinned)}`,
  };
}

function checkHunter(claimed: string, hunter: string): ReqCheck {
  const ok = claimed === hunter;
  return {
    key: 'hunter',
    label: 'Hunter',
    ok,
    detail: ok ? `HUNTER line = claim.hunter (${hunter})` : `request was judged for ${claimed}, but ${hunter} submitted the claim (front-run)`,
  };
}

/** Short contract-style text for a dispute reason. */
export const REASON_TEXT: Record<DisputeReason, string> = {
  'system prompt tampered': 'the system prompt differs from the program',
  'model mismatch': 'the model differs from the program',
  'params tampered': 'temperature, max_tokens or response_format differ from program.params_hash',
  'code mismatch': 'the CODE section is not the program code bundle',
  'hunter mismatch': 'the HUNTER line names another account (front-run)',
  'report missing': 'the REPORT message is missing',
};
