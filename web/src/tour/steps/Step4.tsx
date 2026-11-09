// Step 4 — Hunter submits. Encrypt fixtures/exploits/sqli.md to program 1's owner_enc_pubkey (encryptReport), and show
// claim #0's onchain verdict + hashes, read from the claim plus its submit_claim tx args (resp_body).
// Live lane: judge a preset/edited report in the real TEE through the local helper.
import { useMemo, useState } from 'react';
import { decodeBase64 } from 'ethers';
import sqli from '../../../../fixtures/exploits/sqli.md?raw';
import idor from '../../../../fixtures/exploits/idor.md?raw';
import bogus from '../../../../fixtures/exploits/bogus.md?raw';
import injection from '../../../../fixtures/exploits/injection.md?raw';
import { encryptReport } from '../../lib/crypto';
import { parseVerdict } from '../../lib/verify';
import { judgeLive } from '../helper';
import { LiveGate } from '../LiveLane';
import { useRestore, useTour, useTourAction } from '../TourContext';
import { claimTxs } from '../tourData';
import { ErrLine, Exhibit, Hash, HeroButton, KV, TxLink } from '../ui';

export const step4 = {
  kicker: 'Hunter submits',
  headline: 'The exploit stays sealed.',
  body: "The hunter's report is encrypted so only the program owner can read it. The AI judges it inside the enclave and returns a signed verdict.",
  why: 'The hunter never has to reveal first.',
};

export const PRESETS = { sqli, idor, bogus, injection } as const;

export function Step4() {
  const { data, setResult } = useTour();
  const [ct, setCt] = useState<string | null>(null);
  const claim = data.claims.find((c) => c.id === 0)!;
  const txs = useMemo(() => claimTxs(data.txs, claim), [data.txs, claim]);
  const respBody = txs.submit?.args?.resp_body as string | undefined;
  const bodyVerdict = useMemo(() => {
    try {
      return respBody ? parseVerdict(decodeBase64(respBody)) : null;
    } catch {
      return null;
    }
  }, [respBody]);

  const encrypt = () => {
    const out = encryptReport(sqli, decodeBase64(data.program.owner_enc_pubkey));
    setCt(out);
    setResult('encrypt', true, 'Encrypted a report to the program owner key');
  };
  useTourAction('encrypt', encrypt);
  useRestore('encrypt', encrypt);

  return (
    <div className="stack">
      <Exhibit label="hunter side · nacl box to program.owner_enc_pubkey" meta={<Hash value={data.program.owner_enc_pubkey} head={8} tail={4} label="owner key" />}>
        <div className="row-actions">
          <HeroButton onClick={encrypt} done={!!ct}>
            {ct ? 'Encrypt again (fresh ephemeral key)' : 'Encrypt report'}
          </HeroButton>
        </div>
        <div className="split2">
          <div>
            <div className="cap">plaintext · fixtures/exploits/sqli.md</div>
            <pre className="pane-pre">{sqli}</pre>
          </div>
          <div>
            <div className="cap">ciphertext (base64) · {ct ? `${Math.floor((ct.length * 3) / 4)} bytes` : 'not yet'}</div>
            <pre className={`pane-pre cipher ${ct ? 'cipher-on' : ''}`} key={ct ?? 'none'}>
              {ct ?? 'ephemeralPub ‖ nonce ‖ box(report)'}
            </pre>
          </div>
        </div>
      </Exhibit>

      <Exhibit label="claim #0 · what the enclave signed" meta={<TxLink hash={txs.submit?.hash} label="submit_claim" />}>
        <div className="verdict">
          <span className={`vchip ${claim.verdict.valid ? 'vchip-ok' : 'vchip-bad'}`}>{claim.verdict.valid ? 'valid' : 'invalid'}</span>
          <span className={`sev sev-${claim.verdict.severity}`}>{claim.verdict.severity}</span>
          <span className="mono">{claim.verdict.cwe ?? '—'}</span>
          <span className="mono muted">confidence {claim.verdict.confidence}</span>
        </div>
        <KV
          rows={[
            ['req_hash', <Hash key="r" value={claim.req_hash} />],
            ['resp_hash', <Hash key="p" value={claim.resp_hash} />],
            ['signer', <Hash key="s" value={claim.signer} head={14} tail={6} />],
            ['signature', <Hash key="g" value={claim.signature} head={14} tail={6} />],
            [
              'resp_body',
              bodyVerdict ? (
                <span key="b" className="mono small">
                  {respBody!.length} b64 chars in the tx args → {JSON.stringify(bodyVerdict)}
                </span>
              ) : (
                <span key="b" className="muted small">tx args not loaded</span>
              ),
            ],
          ]}
        />
      </Exhibit>

      <LiveJudge />
    </div>
  );
}

function LiveJudge() {
  const { liveJudgement, setLiveJudgement, setResult } = useTour();
  const [preset, setPreset] = useState<keyof typeof PRESETS>('sqli');
  const [text, setText] = useState<string>(PRESETS.sqli);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [ms, setMs] = useState<number | null>(null);

  const run = async (md = text) => {
    setBusy(true);
    setErr(null);
    const start = Date.now();
    try {
      const j = await judgeLive(md);
      setLiveJudgement(j);
      setMs(Date.now() - start);
      setResult('live-judge', true, `Judged live in the TEE (${j.verdict?.severity ?? '?'})`);
    } catch (e) {
      setErr((e as Error).message);
      setResult('live-judge', false, 'Live TEE judgement failed');
      throw e;
    } finally {
      setBusy(false);
    }
  };
  useTourAction('live-judge', () => {
    setPreset('sqli');
    setText(PRESETS.sqli);
    return run(PRESETS.sqli);
  });

  return (
    <LiveGate title="Judge live in TEE">
      <div className="lane-row">
        <label className="lane-pick">
          preset
          <select
            value={preset}
            onChange={(e) => {
              const k = e.target.value as keyof typeof PRESETS;
              setPreset(k);
              setText(PRESETS[k]);
            }}
          >
            {Object.keys(PRESETS).map((k) => (
              <option key={k} value={k}>
                {k}.md
              </option>
            ))}
          </select>
        </label>
        <HeroButton kind="live" onClick={() => run().catch(() => {})} busy={busy} done={!!liveJudgement}>
          {busy ? 'Judging in the enclave…' : 'Judge live in TEE'}
        </HeroButton>
      </div>
      <textarea className="lane-text mono" value={text} onChange={(e) => setText(e.target.value)} rows={6} spellCheck={false} aria-label="Exploit report" />
      {err && <ErrLine>{err}</ErrLine>}
      {liveJudgement && !busy && (
        <div className="lane-out">
          <div className="verdict">
            {liveJudgement.verdict ? (
              <>
                <span className={`vchip ${liveJudgement.verdict.valid ? 'vchip-ok' : 'vchip-bad'}`}>{liveJudgement.verdict.valid ? 'valid' : 'invalid'}</span>
                <span className={`sev sev-${liveJudgement.verdict.severity}`}>{liveJudgement.verdict.severity}</span>
                <span className="mono">{liveJudgement.verdict.cwe ?? '—'}</span>
                <span className="mono muted">confidence {liveJudgement.verdict.confidence}</span>
              </>
            ) : (
              <span className="muted">no verdict field</span>
            )}
            {ms !== null && <span className="mono muted">· {(ms / 1000).toFixed(1)} s</span>}
          </div>
          <KV
            rows={[
              ['signature', <Hash key="s" value={liveJudgement.signature} head={14} tail={6} />],
              ['chat_id', <code key="c">{liveJudgement.chat_id ?? '—'}</code>],
              ['req_hash', liveJudgement.req_hash ? <Hash key="r" value={liveJudgement.req_hash} /> : '—'],
            ]}
          />
          <p className="muted small">Kept for this session: steps 6 and 7 can submit it on program 2.</p>
        </div>
      )}
    </LiveGate>
  );
}
