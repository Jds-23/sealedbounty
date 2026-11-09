// Step 5 — Contract verifies. 'Verify in browser' runs verifyClaim (lib/checks.ts: signature, program signer set,
// revocation, TDX quote binding, attestation summary) on claim #0 with the resp_body from its submit_claim args.
// 'Ask the contract' (spec §5) sends the same submit_claim args to the deployed contract as a free RPC view
// (verify_tee_response): it returns its own Verdict, or panics "bad signature". 'Flip 1 byte' flips one byte of
// resp_body (confidence 100 → 101) and re-runs both: the signature no longer verifies in the browser or onchain.
import { useMemo, useRef, useState } from 'react';
import { decodeBase64, encodeBase64 } from 'ethers';
import { verifyClaim, type Check } from '../../lib/checks';
import { CONTRACT_ID } from '../../lib/near';
import { sha256hex } from '../../lib/verify';
import { useRestore, useTour, useTourAction } from '../TourContext';
import { askContract, askContractArgs, claimTxs, type AskResult } from '../tourData';
import { CheckList, Exhibit, HeroButton, TxLink, type CheckItem } from '../ui';

export const step5 = {
  kicker: 'Contract verifies',
  headline: 'The contract checks the TEE itself.',
  body: "No server decides. The contract checks the enclave's signature and that the signer belongs to this program. Run the same check in your browser, then ask the contract.",
  why: 'Change one byte and the payout is refused.',
};

/** Index of the byte to flip: the last digit of the confidence value (100 → 101), else the middle byte. */
export function flipIndex(body: Uint8Array): number {
  const text = new TextDecoder().decode(body);
  const m = /confidence\\?"\s*:\s*\d+/.exec(text);
  if (m) return new TextEncoder().encode(text.slice(0, m.index + m[0].length - 1)).length;
  return Math.floor(body.length / 2);
}

const KEEP = /^(Signed model|TEE signature|Signer in PROGRAM|Signer not revoked|Response body|TDX quote|Intel TDX)/;
const SHORT: Record<string, string> = {
  'Signed model = program model': 'Signed model = program model',
  'TEE signature over "model:req_hash:resp_hash"': 'Enclave signature (ed25519) over model:req_hash:resp_hash',
  'Signer in PROGRAM set (program.signers)': 'Signer is in the program signer set',
  'Signer not revoked (is_signer_revoked)': 'Signer not revoked',
  'Response body hashes to resp_hash, verdict matches': 'resp_body hashes to resp_hash; verdict inside matches',
  'TDX quote report_data binds signer key + nonce': 'Intel TDX quote binds the signing key',
  'Intel TDX DCAP + NVIDIA NRAS verdict': 'Attestation summary (DCAP + NRAS)',
};

type Ask = (AskResult & { flipped: boolean }) | null;

export function Step5() {
  const { data, setResult } = useTour();
  const claim = data.claims.find((c) => c.id === 0)!;
  const txs = useMemo(() => claimTxs(data.txs, claim), [data.txs, claim]);
  const respB64 = txs.submit?.args?.resp_body as string | undefined;
  const [runId, setRunId] = useState(0);
  const [flipped, setFlipped] = useState(false);
  const [ask, setAsk] = useState<Ask>(null);
  const [asking, setAsking] = useState(false);
  const askSeq = useRef(0);

  const flip = useMemo(() => {
    if (!respB64) return null;
    const body = decodeBase64(respB64);
    const i = flipIndex(body);
    const t = Uint8Array.from(body);
    t[i] ^= 0x01;
    const dec = new TextDecoder();
    return { i, from: dec.decode(body.slice(i, i + 1)), to: dec.decode(t.slice(i, i + 1)), b64: encodeBase64(t), hash: sha256hex(t) };
  }, [respB64]);

  const checks: Check[] = useMemo(() => {
    if (runId === 0) return [];
    const c = flipped && flip ? { ...claim, resp_hash: flip.hash } : claim;
    return verifyClaim(c, data.program, data.signers, {
      respBodyB64: flipped && flip ? flip.b64 : respB64,
      signersSource: 'contract',
      revoked: data.revoked,
    }).filter((x) => KEEP.test(x.label));
  }, [runId, flipped, flip, claim, data, respB64]);

  const failed = checks.some((x) => x.status === 'fail');
  const verify = () => {
    setRunId((n) => n + 1);
    const res = verifyClaim(claim, data.program, data.signers, { respBodyB64: respB64, signersSource: 'contract', revoked: data.revoked });
    setResult('verify-browser', !res.some((x) => x.status === 'fail'), 'TEE signature + signer set re-verified in your browser');
  };

  /** RPC call_function verify_tee_response with claim #0's submit_claim args (flipped body when the switch is on). */
  const askNow = async (withFlip: boolean) => {
    if (!txs.submit) return;
    const seq = ++askSeq.current;
    setAsking(true);
    const r = await askContract(askContractArgs(claim, txs.submit, withFlip && flip ? flip.b64 : undefined));
    if (seq !== askSeq.current) return; // a newer ask (flip toggled) superseded this one
    setAsk({ ...r, flipped: withFlip });
    setAsking(false);
    if (!withFlip) setResult('ask-contract', r.ok, r.ok ? `The contract itself returned claim #0's verdict (${r.verdict.severity}, free view)` : `The contract refused claim #0: ${r.error}`);
    else if (!r.ok) setResult('flip-contract', true, `The contract refused the 1-byte edit: "${r.error}"`);
  };
  const askClick = () => askNow(flipped);

  const setFlip = (on: boolean) => {
    setFlipped(on);
    setRunId((n) => n + 1);
    if (on) setResult('flip-byte', true, 'A 1-byte edit broke the signature in your browser');
    if (ask || asking) void askNow(on); // keep the contract's answer in step with the body it was asked about
  };
  useTourAction('verify-browser', verify);
  useTourAction('ask-contract', askClick);
  useTourAction('flip-on', () => setFlip(true));
  useTourAction('flip-off', () => setFlip(false));
  useRestore('verify-browser', verify);
  useRestore('ask-contract', askClick);

  const items: CheckItem[] = checks.map((x) => ({ label: SHORT[x.label] ?? x.label, status: x.status, detail: x.detail }));
  const contractBad = ask ? !ask.ok : false;

  return (
    <div className="stack">
      <Exhibit
        label="claim #0 · re-verified in this browser"
        tone={runId ? (failed ? 'bad' : 'ok') : undefined}
        meta={runId ? <span className={failed ? 'bad mono' : 'okc mono'}>{failed ? 'REFUSED' : 'VALID'}</span> : null}
      >
        <div className="row-actions">
          <HeroButton onClick={verify} done={runId > 0}>
            {runId ? 'Verify again' : 'Verify in browser'}
          </HeroButton>
          <label className={`flip ${flipped ? 'flip-on' : ''}`}>
            <input type="checkbox" checked={flipped} onChange={(e) => setFlip(e.target.checked)} disabled={!flip} />
            <span className="flip-k" aria-hidden />
            Flip 1 byte
            {flip && (
              <span className="mono small muted">
                {' '}
                resp_body[{flip.i}] “{flip.from}” → “{flip.to}”
              </span>
            )}
          </label>
        </div>
        {runId > 0 ? <CheckList items={items} runId={runId} /> : <p className="muted ghost-copy">Runs the same checks the contract runs, with tweetnacl and the bundled TDX quote. No server involved.</p>}
      </Exhibit>

      <Exhibit
        label={`ask the contract · ${CONTRACT_ID}`}
        tone={ask ? (contractBad ? 'bad' : 'ok') : undefined}
        meta={ask ? <span className={contractBad ? 'bad mono' : 'okc mono'}>{contractBad ? 'REFUSED' : 'VALID'}</span> : null}
      >
        <div className="row-actions">
          <HeroButton onClick={askClick} busy={asking} done={!!ask && !asking} disabled={!txs.submit}>
            {ask ? 'Ask again' : 'Ask the contract'}
          </HeroButton>
          <span className="mono small muted">
            free RPC view: <code>verify_tee_response</code>
            {flipped ? ' · flipped resp_body' : ''}
          </span>
        </div>
        <div className="askcmp">
          <div className={`askcol ${runId ? (failed ? 'askcol-bad' : 'askcol-ok') : ''}`}>
            <p className="cap">your browser</p>
            {runId ? (
              <span className={`vchip ${failed ? 'vchip-bad' : 'vchip-ok'}`}>{failed ? 'signature fails' : 'signature valid'}</span>
            ) : (
              <span className="muted small">not run yet</span>
            )}
          </div>
          <div className={`askcol ${ask ? (contractBad ? 'askcol-bad' : 'askcol-ok') : ''}`} data-testid="contract-verdict">
            <p className="cap">the contract</p>
            {asking && !ask ? (
              <span className="muted small">asking…</span>
            ) : ask?.ok ? (
              <span className="verdict">
                <span className="vchip vchip-ok">valid</span>
                <span className="mono small">
                  {ask.verdict.severity} · {ask.verdict.cwe ?? 'no CWE'} · confidence {ask.verdict.confidence}
                </span>
              </span>
            ) : ask ? (
              <span className="verdict">
                <span className="vchip vchip-bad">panic</span>
                <span className="mono small bad">“{ask.error}”</span>
              </span>
            ) : (
              <span className="muted small">not asked yet</span>
            )}
            {ask?.source === 'snapshot' && (
              <p className="readout readout-snap" title={ask.rpcError ?? ''}>
                SNAPSHOT · RPC unreachable, showing the recorded answer
              </p>
            )}
          </div>
        </div>
        {ask && !ask.ok ? (
          <p className="small muted">submit_claim runs this exact check first, so the same panic would refuse the claim: nothing is reserved and the deposit is refunded.</p>
        ) : (
          <div className="onchain-ok">
            <span className="icon icon-pass">✓</span>
            <span>
              <code>submit_claim</code> ran the same check onchain and stored claim <code>0</code>
            </span>
            <TxLink hash={txs.submit?.hash} />
          </div>
        )}
      </Exhibit>
    </div>
  );
}
