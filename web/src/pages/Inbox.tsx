import { useMemo, useState } from 'react';
import { useData } from '../data';
import { decryptReport, parseOwnerSecret, reportMatchesHash } from '../lib/crypto';
import { DEMO_OWNER_SECRET } from '../lib/demo';
import { sha256hex } from '../lib/verify';
import { auditRequest, REASON_TEXT, type RequestAudit } from '../lib/requestChecks';
import type { Claim, Program } from '../lib/types';
import { Badge, Hash, StatusIcon } from '../components/ui';

interface Decrypted {
  claim: Claim;
  program?: Program;
  plaintext?: string;
  error?: string;
}

/** Splits a decrypted request into report text and the TARGET/HUNTER/CODE part (v2: separate messages; v1: one). */
function splitRequest(pt: string): { report: string; targetAndCode: string | null } {
  let req: { messages?: { role: string; content: string }[] } | null = null;
  try {
    req = JSON.parse(pt);
  } catch {
    return { report: pt, targetAndCode: null };
  }
  const users = (req?.messages ?? []).filter((m) => m?.role === 'user' && typeof m.content === 'string');
  if (users.length >= 2 && users[1].content.startsWith('REPORT\n')) return { report: users[1].content.slice(7), targetAndCode: users[0].content };
  const u = users[0]?.content ?? '';
  const cut = u.lastIndexOf('\n\nREPORT\n');
  return cut >= 0 ? { report: u.slice(cut + 9), targetAndCode: u.slice(0, cut) } : { report: u || pt, targetAndCode: null };
}

function DisputeHint({ claim, audit }: { claim: Claim; audit: RequestAudit }) {
  if (audit.ok) {
    return (
      <div className="dispute-hint ok small">
        Request matches the program{audit.v1 ? ' (v1: prompt + model only)' : ''}. A dispute would fail, so this claim pays out after the window.
      </div>
    );
  }
  const why = audit.reason ? REASON_TEXT[audit.reason] : '';
  if (claim.status === 'Pending') {
    return (
      <div className="dispute-hint">
        <strong>
          Disputable: run <code>sb dispute --claim {claim.id}</code>
        </strong>{' '}
        before the window closes. The contract will reject it with &quot;{audit.reason}&quot; ({why}).
      </div>
    );
  }
  if (claim.status === 'Rejected') {
    return (
      <div className="dispute-hint">
        Already rejected onchain{claim.reject_reason ? <> with &quot;{claim.reject_reason}&quot;</> : null}. This is what{' '}
        <code>sb dispute --claim {claim.id}</code> proves: {why}.
      </div>
    );
  }
  return (
    <div className="dispute-hint">
      Would have been disputable (&quot;{audit.reason}&quot;: {why}), but the claim is already {claim.status}.
    </div>
  );
}

function Report({ d }: { d: Decrypted }) {
  const { claim, program, plaintext, error } = d;
  if (error) {
    return (
      <div className="card">
        <strong>Claim #{claim.id}</strong> <span className="bad">{error}</span>
      </div>
    );
  }
  const pt = plaintext!;
  const hashOk = reportMatchesHash(pt, claim.req_hash);
  const audit = program ? auditRequest(pt, program, claim.hunter) : null;
  const { report, targetAndCode } = splitRequest(pt);
  return (
    <div className="card">
      <div className="row between wrap">
        <strong>
          Claim #{claim.id} · {program?.name ?? `program ${claim.program_id}`} · <span className="mono small">{claim.hunter}</span>
        </strong>
        <Badge tone={claim.status === 'Pending' ? 'warn' : claim.status === 'Paid' ? 'ok' : 'bad'}>{claim.status}</Badge>
      </div>
      <ul className="checks">
        <li>
          <StatusIcon status={hashOk ? 'pass' : 'fail'} />
          <div>
            sha256(decrypted) == req_hash <Hash value={claim.req_hash} />
          </div>
        </li>
        {audit?.checks.map((x) => (
          <li key={x.key}>
            <StatusIcon status={x.ok === null ? 'na' : x.ok ? 'pass' : 'fail'} />
            <div>
              <div className={x.ok === false ? 'check-bad' : undefined}>{x.label}</div>
              <div className="muted small mono-wrap">{x.detail}</div>
            </div>
          </li>
        ))}
      </ul>
      {hashOk && audit && <DisputeHint claim={claim} audit={audit} />}
      {!hashOk && <div className="dispute-hint small">Decrypted text does not hash to req_hash: this ciphertext is not the judged request.</div>}
      <h3>Report</h3>
      <pre className="report">{report}</pre>
      {targetAndCode && (
        <details>
          <summary className="small">Target, hunter and code sent to the judge</summary>
          <pre className="report small">{targetAndCode}</pre>
        </details>
      )}
      <details>
        <summary className="small">Full request body (exact bytes hashed to req_hash)</summary>
        <pre className="report small">{pt}</pre>
      </details>
    </div>
  );
}

export function Inbox() {
  const { claims, programs, isDemo } = useData();
  const [secretText, setSecretText] = useState('');
  const [manualCt, setManualCt] = useState('');

  const parsed = useMemo(() => {
    if (!secretText.trim()) return null;
    try {
      return { ok: parseOwnerSecret(secretText) };
    } catch (e) {
      return { err: (e as Error).message };
    }
  }, [secretText]);

  const results: Decrypted[] = useMemo(() => {
    if (!parsed?.ok) return [];
    const { secretKey, publicKeyB64 } = parsed.ok;
    const mine = programs.filter((p) => p.owner_enc_pubkey === publicKeyB64);
    const out: Decrypted[] = claims
      .filter((c) => !c.refused_at_submit && mine.some((p) => p.id === c.program_id))
      .map((claim) => {
        const program = mine.find((p) => p.id === claim.program_id);
        try {
          return { claim, program, plaintext: decryptReport(claim.ciphertext, secretKey) };
        } catch (e) {
          return { claim, program, error: (e as Error).message };
        }
      });
    return out;
  }, [parsed, claims, programs]);

  const manual = useMemo(() => {
    if (!parsed?.ok || !manualCt.trim()) return null;
    try {
      return { text: decryptReport(manualCt, parsed.ok.secretKey) };
    } catch (e) {
      return { err: (e as Error).message };
    }
  }, [parsed, manualCt]);

  const onFile = async (f?: File) => {
    if (f) setSecretText(await f.text());
  };

  return (
    <section>
      <h1>Owner inbox</h1>
      <div className="notice">
        <strong>Your secret never leaves this tab.</strong> Decryption runs locally with tweetnacl. Nothing is uploaded, stored, or sent over the
        network. This page has no backend, and the only network calls are read-only NEAR RPC views.
      </div>
      <div className="card">
        <label className="field">
          <span>Owner secret: paste <code>~/.sealedbounty/owner-&lt;contract&gt;-&lt;id&gt;.json</code> or the base64 box secret key</span>
          <textarea
            rows={4}
            className="mono"
            value={secretText}
            onChange={(e) => setSecretText(e.target.value)}
            placeholder='{"program_id": 0, "public_key": "…", "secret_key": "…base64…"}'
            spellCheck={false}
            autoComplete="off"
          />
        </label>
        <div className="row wrap gap">
          <input type="file" accept=".json,application/json,text/plain" onChange={(e) => onFile(e.target.files?.[0])} />
          {isDemo && (
            <button onClick={() => setSecretText(DEMO_OWNER_SECRET)}>Load demo owner key</button>
          )}
          {secretText && <button onClick={() => setSecretText('')}>Forget key</button>}
        </div>
        {parsed?.err && <p className="bad small">{parsed.err}</p>}
        {parsed?.ok && (
          <p className="small">
            Public key derived from the secret: <Hash value={parsed.ok.publicKeyB64} />. It matches{' '}
            {programs.filter((p) => p.owner_enc_pubkey === parsed.ok!.publicKeyB64).length} program(s).
          </p>
        )}
      </div>

      {parsed?.ok && (
        <>
          <h2>Claims for your programs ({results.length})</h2>
          {results.length === 0 && <p className="muted">No claims in programs that use this key.</p>}
          {results.map((d) => (
            <Report key={d.claim.id} d={d} />
          ))}
          <details className="card">
            <summary>Decrypt a raw ciphertext</summary>
            <textarea rows={3} className="mono" value={manualCt} onChange={(e) => setManualCt(e.target.value)} placeholder="base64 ciphertext" />
            {manual?.err && <p className="bad small">{manual.err}</p>}
            {manual?.text && (
              <>
                <p className="small">
                  sha256: <Hash value={sha256hex(manual.text)} />
                </p>
                <pre className="report">{manual.text}</pre>
              </>
            )}
          </details>
        </>
      )}
    </section>
  );
}
