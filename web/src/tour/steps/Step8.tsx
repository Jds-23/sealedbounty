// Step 8 — Recap: a scorecard of the checks this session actually ran, with jump-back links.
import { Link, useLocation } from 'react-router-dom';
import { CONTRACT_ID, explorerAccount } from '../../lib/near';
import { useTour } from '../TourContext';
import { StatusIcon } from '../ui';

export const step8 = {
  kicker: 'Recap',
  headline: 'You just verified it yourself.',
  body: 'Everything you saw was checked in your browser against live testnet: signatures, attestation, decryption, payout and four rejections.',
  why: 'Private bounties that pay out without trusting anyone.',
};

const REPO = 'https://github.com/Jds-23/sealedbounty';

const SCORE: { key: string; label: string; step: number; live?: boolean }[] = [
  { key: 'load-program', label: 'Program 1 read from testnet', step: 3 },
  { key: 'encrypt', label: 'Report encrypted to the owner key', step: 4 },
  { key: 'verify-browser', label: 'TEE signature re-verified in your browser', step: 5 },
  { key: 'ask-contract', label: 'The contract re-verified claim #0 (free view)', step: 5 },
  { key: 'flip-byte', label: 'A 1-byte edit refused in your browser', step: 5 },
  { key: 'flip-contract', label: 'A 1-byte edit refused by the contract', step: 5 },
  { key: 'decrypt', label: 'Claim #0 decrypted; hash matches', step: 6 },
  { key: 'audit0', label: 'Six dispute checks pass on claim #0', step: 6 },
  { key: 'gauntlet-1', label: '#1 params tampered, recomputed', step: 7 },
  { key: 'gauntlet-2', label: '#2 code mismatch, recomputed', step: 7 },
  { key: 'gauntlet-3', label: '#3 hunter mismatch, recomputed', step: 7 },
  { key: 'gauntlet-4', label: '#4 undecryptable report, recomputed', step: 7 },
  { key: 'live-judge', label: 'Fresh TEE judgement (helper)', step: 4, live: true },
  { key: 'live-loop', label: 'Program 2 loop reached Paid (helper)', step: 6, live: true },
  { key: 'live-frontrun', label: 'Live front-run rejected (helper)', step: 7, live: true },
];

export function Step8() {
  const { results, helper, badge } = useTour();
  const { search } = useLocation();
  const rows = SCORE.filter((s) => !s.live || (helper?.ok ?? false) || results[s.key]);
  const done = rows.filter((s) => results[s.key]?.ok).length;
  return (
    <div className="stack">
      <section className="score">
        <header className="score-h">
          <span className="score-n">
            {done}
            <span className="dim">/{rows.length}</span>
          </span>
          <span className="score-l">checks you ran this session · data {badge === 'live' ? 'from live testnet' : badge === 'snapshot' ? 'from the snapshot' : 'loading'}</span>
        </header>
        <ul className="score-l2">
          {rows.map((s, i) => {
            const r = results[s.key];
            return (
              <li key={s.key} style={{ ['--i' as string]: i }}>
                <StatusIcon status={r ? (r.ok ? 'pass' : 'fail') : 'na'} />
                <span className={r ? '' : 'muted'}>{r?.label ?? s.label}</span>
                {!r && (
                  <Link className="jump" to={`/tour/${s.step}${search}`}>
                    not run · step {s.step} ←
                  </Link>
                )}
              </li>
            );
          })}
        </ul>
      </section>
      <nav className="links">
        <a href={REPO} target="_blank" rel="noreferrer noopener">
          Source code <span>github ↗</span>
        </a>
        <a href={explorerAccount(CONTRACT_ID)} target="_blank" rel="noreferrer noopener">
          Contract <span>{CONTRACT_ID} ↗</span>
        </a>
        <a href={`${REPO}#live-on-testnet-v3`} target="_blank" rel="noreferrer noopener">
          Every tx of this run <span>README testnet table ↗</span>
        </a>
        <Link to="/programs">
          Explore programs and claims <span>#/programs →</span>
        </Link>
      </nav>
    </div>
  );
}
