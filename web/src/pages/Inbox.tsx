import { useMemo, useState } from 'react';
import { useData } from '../data';
import { decryptReport, parseOwnerSecret, reportMatchesHash } from '../lib/crypto';
import { DEMO_OWNER_SECRET } from '../lib/demo';
import { sha256hex } from '../lib/verify';
import type { Claim, Program } from '../lib/types';
import { Badge, Hash, StatusIcon } from '../components/ui';

interface Decrypted {
  claim: Claim;
  program?: Program;
  plaintext?: string;
  error?: string;
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
  let req: { model?: string; messages?: { role: string; content: string }[] } | null = null;
  try {
    req = JSON.parse(pt);
  } catch {
    /* not JSON */
  }
  const sys = req?.messages?.[0];
  const user = req?.messages?.find((m) => m.role === 'user');
  const sysOk = !!(sys && sys.role === 'system' && program && sha256hex(sys.content) === program.system_prompt_hash);
  const modelOk = !!(req && program && req.model === program.model_id);
  const userMsg = user?.content ?? '';
  const cut = userMsg.lastIndexOf('\n\nREPORT\n');
  const reportText = cut >= 0 ? userMsg.slice(cut + 9) : userMsg || pt;
  const targetAndCode = cut >= 0 ? userMsg.slice(0, cut) : null;
  return (
    <div className="card">
      <div className="row between wrap">
        <strong>
          Claim #{claim.id} · {program?.name ?? `program ${claim.program_id}`}
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
        <li>
          <StatusIcon status={sysOk ? 'pass' : 'fail'} />
          <div>
            System prompt matches program.system_prompt_hash
            {!sysOk && claim.status === 'Pending' && (
              <div className="small bad">Mismatch: you can `dispute` this claim with the CLI before the window closes.</div>
            )}
          </div>
        </li>
        <li>
          <StatusIcon status={modelOk ? 'pass' : 'fail'} />
          <div>Request model == program model ({req?.model ?? '?'})</div>
        </li>
      </ul>
      <h3>Report</h3>
      <pre className="report">{reportText}</pre>
      {targetAndCode && (
        <details>
          <summary className="small">Target and code excerpt sent to the judge</summary>
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
      .filter((c) => mine.some((p) => p.id === c.program_id))
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
          <span>Owner secret: paste <code>~/.sealedbounty/owner-&lt;id&gt;.json</code> or the base64 box secret key</span>
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
