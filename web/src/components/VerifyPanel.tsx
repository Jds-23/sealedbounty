import { useMemo, useState } from 'react';
import type { Claim, Program } from '../lib/types';
import { verifyClaim } from '../lib/checks';
import { DEMO_RESP_BODIES } from '../lib/demo';
import { useData } from '../data';
import { StatusIcon } from './ui';

/** Flip one hex nibble: used by the dev "tamper" toggle to prove the check can fail. */
const flip = (h: string) => h.slice(0, 8) + (h[8] === '0' ? '1' : '0') + h.slice(9);

export function VerifyPanel({ claim, program }: { claim: Claim; program?: Program }) {
  const { isDemo, signers } = useData();
  const [tamper, setTamper] = useState(false);
  const checks = useMemo(() => {
    const c = tamper ? { ...claim, resp_hash: flip(claim.resp_hash) } : claim;
    return verifyClaim(c, program, signers, {
      respBodyB64: isDemo && !tamper ? DEMO_RESP_BODIES[claim.id] : undefined,
      signersSource: isDemo ? 'demo' : 'contract',
    });
  }, [claim, program, signers, isDemo, tamper]);
  const failed = checks.some((x) => x.status === 'fail');
  return (
    <div className={`verify ${failed ? 'verify-bad' : 'verify-ok'}`}>
      <div className="verify-head">
        <strong>{failed ? 'Verification FAILED' : 'Verified in your browser'}</strong>
        {(import.meta.env.DEV || isDemo) && (
          <label className="tamper">
            <input type="checkbox" checked={tamper} onChange={(e) => setTamper(e.target.checked)} /> tamper 1 byte of resp_hash
          </label>
        )}
      </div>
      <ul className="checks">
        {checks.map((x) => (
          <li key={x.label}>
            <StatusIcon status={x.status} />
            <div>
              <div>{x.label}</div>
              <div className="muted small mono-wrap">{x.detail}</div>
            </div>
          </li>
        ))}
      </ul>
      <div className="legend muted small">
        <StatusIcon status="pass" /> checked here · <StatusIcon status="offline" /> checked offline, not re-run · <StatusIcon status="na" /> not verifiable client-side ·{' '}
        <StatusIcon status="fail" /> failed
      </div>
    </div>
  );
}
