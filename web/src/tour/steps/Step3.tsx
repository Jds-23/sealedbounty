// Step 3 — Live program. 'Load live' runs getProgram(1) + getSigners() + getRevoked() (snapshot fallback).
import { useState } from 'react';
import { CONTRACT_ID, explorerAccount } from '../../lib/near';
import { fmtSecs, yoctoToNear } from '../../lib/format';
import { useTour, useTourAction } from '../TourContext';
import { SNAPSHOT_RECORDED_AT, TOUR_PROGRAM_ID } from '../tourData';
import { Exhibit, Hash, HeroButton, KV } from '../ui';

export const step3 = {
  kicker: 'Live program',
  headline: 'A real bounty, live on testnet.',
  body: 'Program 1 escrows real testnet NEAR. Payouts are fixed by severity. Hunters post a bond, and the owner has a window to dispute.',
  why: 'The rules are fixed before anyone submits.',
};

/** Exact seconds for short windows (150 s, not "3m"); fmtSecs for long ones. */
const secs = (s: number) => (s < 600 ? `${s} s` : fmtSecs(s));

export function Step3() {
  const { programRead, loadProgram, setResult } = useTour();
  const [busy, setBusy] = useState(false);

  const load = async () => {
    setBusy(true);
    try {
      const live = await loadProgram();
      setResult('load-program', true, live ? 'Read program 1 from live testnet' : 'Read program 1 (snapshot: RPC unreachable)');
    } finally {
      setBusy(false);
    }
  };
  useTourAction('load-program', load);

  const view = programRead?.view ?? null;
  const p = view?.program;
  return (
    <div className="stack">
      <div className="row-actions">
        <HeroButton onClick={load} busy={busy} done={!!programRead}>
          {programRead ? 'Reload from testnet' : 'Load live'}
        </HeroButton>
        {programRead && (
          <span className={`readout ${programRead.source === 'live' ? 'readout-live' : 'readout-snap'}`}>
            {programRead.source === 'live'
              ? `get_program · get_signers · is_signer_revoked → ${programRead.ms} ms`
              : `RPC unreachable → snapshot ${SNAPSHOT_RECORDED_AT.slice(0, 10)}`}
          </span>
        )}
      </div>

      {!p ? (
        <Exhibit label={`program ${TOUR_PROGRAM_ID} · ${CONTRACT_ID}`}>
          <p className="muted ghost-copy">
            Press <strong>Load live</strong> to read the program straight from the contract. Nothing is cached; the values below come from three RPC views.
          </p>
          <div className="skeleton" aria-hidden>
            <span />
            <span />
            <span />
          </div>
        </Exhibit>
      ) : (
        <>
          <Exhibit
            label={`program ${p.id} · "${p.name}"`}
            meta={
              <a href={explorerAccount(CONTRACT_ID)} target="_blank" rel="noreferrer noopener">
                {CONTRACT_ID} ↗
              </a>
            }
          >
            <div className="pool">
              <div>
                <div className="pool-n">{yoctoToNear(p.balance, 3)}</div>
                <div className="pool-l">NEAR in escrow</div>
              </div>
              <div>
                <div className="pool-n dim">{yoctoToNear(p.reserved, 3)}</div>
                <div className="pool-l">reserved for open claims</div>
              </div>
              <div>
                <div className="pool-n dim">{p.open ? 'open' : 'closed'}</div>
                <div className="pool-l">status</div>
              </div>
            </div>
            <table className="payout-t">
              <thead>
                <tr>
                  <th>severity</th>
                  <th>low</th>
                  <th>medium</th>
                  <th>high</th>
                  <th>critical</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>payout (NEAR)</td>
                  {(['low', 'medium', 'high', 'critical'] as const).map((k) => (
                    <td key={k}>{yoctoToNear(p.payouts[k], 2)}</td>
                  ))}
                </tr>
              </tbody>
            </table>
            <KV
              rows={[
                ['hunter bond', p.bond ? `${yoctoToNear(p.bond, 2)} NEAR` : '—'],
                ['dispute window', secs(p.dispute_secs)],
                ['challenge window', p.challenge_secs != null ? secs(p.challenge_secs) : '—'],
                ['min_confidence', String(p.min_confidence)],
                ['model', <code key="m">{p.model_id}</code>],
              ]}
            />
          </Exhibit>
          <Exhibit label="pinned hashes · what a judgement must match">
            <KV
              rows={[
                ['code_hash', p.code_hash ? <Hash value={p.code_hash} /> : '—'],
                ['params_hash', p.params_hash ? <Hash value={p.params_hash} /> : '—'],
                ['system_prompt_hash', <Hash key="s" value={p.system_prompt_hash} />],
              ]}
            />
          </Exhibit>
          <Exhibit label={`program signer set · ${p.signers?.length ?? 0} attested NEAR AI keys`}>
            <ul className="signers">
              {(p.signers ?? []).map((s) => {
                const meta = view!.signers.find((e) => e.signer.toLowerCase() === s.toLowerCase())?.meta;
                const revoked = view!.revoked.has(s);
                return (
                  <li key={s}>
                    <Hash value={s} head={16} tail={6} />
                    <span className="muted small">{meta ? `${meta.kind}` : 'not in global allowlist'}</span>
                    <span className={revoked ? 'bad small' : 'okc small'}>{revoked ? 'revoked' : 'not revoked'}</span>
                  </li>
                );
              })}
            </ul>
          </Exhibit>
        </>
      )}
    </div>
  );
}
