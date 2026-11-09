// Step 5 — Contract verifies. 'Verify in browser' runs verifyClaim (lib/checks.ts: signature, program signer set,
// revocation, TDX quote binding, attestation summary) on claim #0 with the resp_body from its submit_claim args.
// 'Flip 1 byte' flips one byte of resp_body (confidence 100 → 101) and re-runs: the contract would recompute
// resp_hash from the body, so the signature no longer verifies.
//
// 'Ask the contract' (spec §5): verify_tee_response cannot run as an RPC view on the deployed wasm — it calls
// env::used_gas(), which NEAR prohibits in views (RPC: ProhibitedInView { method_name: "used_gas" }). The pane says so
// and points at the submit_claim receipt, where the contract ran the same signature check itself.
import { useMemo, useState } from 'react';
import { decodeBase64, encodeBase64 } from 'ethers';
import { verifyClaim, type Check } from '../../lib/checks';
import { CONTRACT_ID } from '../../lib/near';
import { sha256hex } from '../../lib/verify';
import { useRestore, useTour, useTourAction } from '../TourContext';
import { claimTxs } from '../tourData';
import { CheckList, Exhibit, HeroButton, TxLink, type CheckItem } from '../ui';

export const step5 = {
  kicker: 'Contract verifies',
  headline: 'The contract checks the TEE itself.',
  body: "No server decides. The contract checks the enclave's signature and that the signer belongs to this program. You can run the same check right here.",
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

export function Step5() {
  const { data, setResult } = useTour();
  const claim = data.claims.find((c) => c.id === 0)!;
  const txs = useMemo(() => claimTxs(data.txs, claim), [data.txs, claim]);
  const respB64 = txs.submit?.args?.resp_body as string | undefined;
  const [runId, setRunId] = useState(0);
  const [flipped, setFlipped] = useState(false);

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
  const setFlip = (on: boolean) => {
    setFlipped(on);
    setRunId((n) => n + 1);
    if (on) setResult('flip-byte', true, 'A 1-byte edit broke the signature (payout refused)');
  };
  useTourAction('verify-browser', verify);
  useTourAction('flip-on', () => setFlip(true));
  useTourAction('flip-off', () => setFlip(false));
  useRestore('verify-browser', verify);

  const items: CheckItem[] = checks.map((x) => ({ label: SHORT[x.label] ?? x.label, status: x.status, detail: x.detail }));

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

      <Exhibit label={`ask the contract · ${CONTRACT_ID}`}>
        <p className="small">
          <code>verify_tee_response</code> can't be called as a free view on the deployed contract: it reads <code>env::used_gas()</code>, which NEAR forbids in
          views (the RPC answers <code>ProhibitedInView</code>). The contract already ran this exact signature check onchain when it accepted claim #0 and
          stored it:
        </p>
        <div className="onchain-ok">
          <span className="icon icon-pass">✓</span>
          <span>
            <code>submit_claim</code> verified the signature and returned claim id <code>0</code>
          </span>
          <TxLink hash={txs.submit?.hash} />
        </div>
        {flipped && (
          <p className="small bad mono">With the flipped byte, the same call would panic: “bad signature”. Nothing is reserved, and the deposit is refunded.</p>
        )}
      </Exhibit>
    </div>
  );
}
