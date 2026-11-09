// Step 1 — Problem. Three panels: reveal-before-pay, spam inbox, fake AI verdict. Static SVG + CSS.
export const step1 = {
  kicker: 'The problem',
  headline: 'Bug bounties run on trust.',
  body: "Hunters must reveal an exploit before they're paid. Owners drown in spam. And an 'AI judge' on someone's server can be faked.",
  why: 'No one should have to trust the other side.',
};

export function Step1() {
  return (
    <div className="problem">
      <figure className="panel" style={{ ['--i' as string]: 0 }}>
        <svg viewBox="0 0 200 140" role="img" aria-label="A hunter hands over the exploit; the payment never arrives">
          <rect className="ln" x="18" y="30" width="54" height="70" rx="4" />
          <path className="ln dim" d="M28 46h34M28 56h34M28 66h22" />
          <path className="ln bad" d="M28 80l10 8 16-18" />
          <path className="ln arrow" d="M82 64h48" />
          <path className="ln arrow" d="M124 58l8 6-8 6" />
          <circle className="ln" cx="162" cy="64" r="22" />
          <text className="glyph" x="162" y="72" textAnchor="middle">
            ?
          </text>
        </svg>
        <figcaption>
          <span className="panel-n">01</span> Reveal first, maybe get paid
        </figcaption>
      </figure>
      <figure className="panel" style={{ ['--i' as string]: 1 }}>
        <svg viewBox="0 0 200 140" role="img" aria-label="An inbox overflowing with reports">
          {[0, 1, 2, 3, 4].map((k) => (
            <g key={k} transform={`translate(${36 + k * 6} ${24 + k * 12})`}>
              <rect className={`ln ${k < 4 ? 'dim' : ''}`} width="110" height="40" rx="4" />
              <path className={`ln ${k < 4 ? 'dim' : ''}`} d="M0 2l55 22 55-22" />
            </g>
          ))}
          <rect className="pill-bg" x="140" y="10" width="48" height="20" rx="10" />
          <text className="pill-t" x="164" y="24" textAnchor="middle">
            412
          </text>
        </svg>
        <figcaption>
          <span className="panel-n">02</span> Owners drown in spam
        </figcaption>
      </figure>
      <figure className="panel" style={{ ['--i' as string]: 2 }}>
        <svg viewBox="0 0 200 140" role="img" aria-label="A server prints a verdict nobody can check">
          <rect className="ln" x="20" y="40" width="56" height="64" rx="4" />
          <path className="ln dim" d="M30 56h36M30 68h36M30 80h36" />
          <circle className="dot" cx="66" cy="94" r="2.5" />
          <path className="ln" d="M92 40h86a6 6 0 0 1 6 6v34a6 6 0 0 1-6 6h-56l-14 12v-12h-16a6 6 0 0 1-6-6v-34a6 6 0 0 1 6-6z" />
          <text className="mono-t" x="138" y="60" textAnchor="middle">
            valid: true
          </text>
          <text className="mono-t" x="138" y="76" textAnchor="middle">
            sev: critical
          </text>
          <g className="stamp" transform="rotate(-12 150 112)">
            <rect x="104" y="102" width="92" height="22" rx="3" />
            <text x="150" y="117" textAnchor="middle">
              UNVERIFIABLE
            </text>
          </g>
        </svg>
        <figcaption>
          <span className="panel-n">03</span> An AI verdict anyone could fake
        </figcaption>
      </figure>
    </div>
  );
}
