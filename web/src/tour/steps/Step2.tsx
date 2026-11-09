// Step 2 — Idea. Flow diagram hunter → TEE → contract → owner; one pulse travels the arrows on entry; hover/click a
// node for one line about it. Inline SVG, a horizontal and a vertical variant (narrow screens).
import { useEffect, useRef, useState } from 'react';
import { useTour, useTourAction } from '../TourContext';
import { snapshotData } from '../tourData';

export const step2 = {
  kicker: 'The idea',
  headline: 'An attested AI judges. The contract checks.',
  body: 'The exploit goes to an AI model running inside verified hardware. The hardware signs the verdict. A NEAR contract checks that signature itself and pays from escrow.',
  why: 'The payout depends on math, not on a server.',
};

type NodeKey = 'hunter' | 'tee' | 'contract' | 'owner';
const NODES: { key: NodeKey; title: string; sub: string; line: string }[] = [
  { key: 'hunter', title: 'Hunter', sub: 'encrypted report', line: 'Sends the exploit to the enclave and an encrypted copy (nacl box) to the chain. Never reveals it in public.' },
  { key: 'tee', title: 'TEE judge', sub: 'Intel TDX + NVIDIA GPU', line: '' },
  { key: 'contract', title: 'NEAR contract', sub: 'sealedbounty-v3', line: 'Verifies the ed25519 / ecdsa signature onchain, checks the signer is in the program set, escrows the payout by severity.' },
  { key: 'owner', title: 'Owner', sub: 'decrypts, may dispute', line: 'Decrypts the report. Can dispute a tampered request or flag an unreadable one, but cannot block an honest payout.' },
];

export function Step2() {
  const { data } = useTour();
  const model = data.program.model_id || snapshotData().program.model_id;
  const [sel, setSel] = useState<NodeKey | null>(null);
  const timers = useRef<number[]>([]);
  const nodes = NODES.map((n) => (n.key === 'tee' ? { ...n, line: `Runs ${model} inside an attested enclave and signs model:sha256(request):sha256(response) with a key bound to its TDX quote.` } : n));

  const cycle = () => {
    timers.current.forEach(clearTimeout);
    timers.current = NODES.map((n, i) => window.setTimeout(() => setSel(n.key), i * 2200));
  };
  useTourAction('diagram-tour', cycle);
  useEffect(() => () => timers.current.forEach(clearTimeout), []);

  const active = nodes.find((n) => n.key === sel);
  const nodeProps = (k: NodeKey) => ({
    className: `fnode ${sel === k ? 'fnode-on' : ''}`,
    tabIndex: 0,
    role: 'button',
    'aria-pressed': sel === k,
    'aria-label': nodes.find((n) => n.key === k)!.title,
    onMouseEnter: () => setSel(k),
    onFocus: () => setSel(k),
    onClick: () => setSel(k),
    onKeyDown: (e: React.KeyboardEvent) => (e.key === 'Enter' || e.key === ' ') && (e.preventDefault(), setSel(k)),
  });

  return (
    <div className="flow">
      <svg className="flow-h" viewBox="0 0 720 240" aria-label="Flow: hunter to TEE to contract to owner">
        <defs>
          <marker id="ah" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
            <path d="M0 0L10 5L0 10z" className="arrowfill" />
          </marker>
        </defs>
        <path className="fedge" d="M142 96H197" markerEnd="url(#ah)" />
        <path className="fedge" d="M372 96H447" markerEnd="url(#ah)" />
        <path className="fedge" d="M602 96H630Q650 96 650 116V141" markerEnd="url(#ah)" />
        <path className="fedge dashed" d="M525 138V194H75V140" markerEnd="url(#ah)" />
        <text className="fedge-t" x="300" y="214" textAnchor="middle">
          payout + bond, after the dispute window
        </text>
        <text className="fedge-t" x="170" y="86" textAnchor="middle">
          report
        </text>
        <text className="fedge-t" x="410" y="72" textAnchor="middle">
          signed
        </text>
        <text className="fedge-t" x="410" y="86" textAnchor="middle">
          verdict
        </text>
        {[
          ['hunter', 10, 56, 130],
          ['tee', 200, 56, 170],
          ['contract', 450, 56, 150],
          ['owner', 550, 145, 160],
        ].map(([k, x, y, w]) => {
          const n = nodes.find((m) => m.key === k)!;
          return (
            <g key={k as string} transform={`translate(${x} ${y})`} {...nodeProps(k as NodeKey)}>
              <rect width={w} height="80" rx="8" />
              <text className="fnode-t" x="16" y="34">
                {n.title}
              </text>
              <text className="fnode-s" x="16" y="56">
                {n.sub}
              </text>
            </g>
          );
        })}
        <circle className="pulse" r="5">
          <animateMotion dur="2.4s" begin="0.4s" fill="freeze" path="M142 96H200M370 96H450M600 96H630Q650 96 650 116V145" />
          <animate attributeName="opacity" values="0;1;1;0" keyTimes="0;0.08;0.9;1" dur="2.4s" begin="0.4s" fill="freeze" />
        </circle>
      </svg>

      <div className="flow-v" aria-label="Flow: hunter to TEE to contract to owner">
        {nodes.map((n, i) => (
          <div key={n.key} className="flow-v-row" style={{ ['--i' as string]: i }}>
            <div {...nodeProps(n.key)} className={`fnode-v ${sel === n.key ? 'fnode-on' : ''}`}>
              <strong>{n.title}</strong>
              <span>{n.sub}</span>
            </div>
            {i < nodes.length - 1 && <div className="flow-v-edge" aria-hidden />}
          </div>
        ))}
      </div>

      <p className={`flow-line ${active ? 'flow-line-on' : ''}`} aria-live="polite" key={sel ?? 'none'}>
        {active ? (
          <>
            <strong>{active.title}.</strong> {active.line}
          </>
        ) : (
          <span className="muted">Hover or tap a node.</span>
        )}
      </p>
    </div>
  );
}
