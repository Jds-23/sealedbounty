// The guided tour shell (docs/demo-app-spec.md §6–§8): split slide, 8-segment progress bar, Back/Next, ←/→,
// deep links #/tour/1..8, LIVE/SNAPSHOT + helper badges, and the ?autoplay=1 (&live=1) runner.
import { useCallback, useEffect, useRef, useState, type ComponentType } from 'react';
import { Link, Navigate, useLocation, useNavigate, useParams } from 'react-router-dom';
import { CONTRACT_ID } from '../lib/near';
import { canAdvance, dueActions, LIVE_ERROR_HOLD_MS, LIVE_HOLD_MS, planFor, totalMs, type TimelineStep } from './autoplay';
import { TourProvider, useTour } from './TourContext';
import { SNAPSHOT_RECORDED_AT } from './tourData';
import { Step1, step1 } from './steps/Step1';
import { Step2, step2 } from './steps/Step2';
import { Step3, step3 } from './steps/Step3';
import { Step4, step4 } from './steps/Step4';
import { Step5, step5 } from './steps/Step5';
import { Step6, step6 } from './steps/Step6';
import { Step7, step7 } from './steps/Step7';
import { Step8, step8 } from './steps/Step8';
import './tour.css';

interface StepDef {
  kicker: string;
  headline: string;
  body: string;
  why: string;
  Proof: ComponentType;
}

export const STEPS: StepDef[] = [
  { ...step1, Proof: Step1 },
  { ...step2, Proof: Step2 },
  { ...step3, Proof: Step3 },
  { ...step4, Proof: Step4 },
  { ...step5, Proof: Step5 },
  { ...step6, Proof: Step6 },
  { ...step7, Proof: Step7 },
  { ...step8, Proof: Step8 },
];

export function Tour() {
  const { step } = useParams();
  const { search } = useLocation();
  const n = Number(step);
  if (!Number.isInteger(n) || n < 1 || n > STEPS.length) return <Navigate to={`/tour/1${search}`} replace />;
  return (
    <TourProvider>
      <TourShell n={n} />
    </TourProvider>
  );
}

type Theme = 'dark' | 'light';
function useTourTheme(): [Theme, () => void] {
  const [theme, setTheme] = useState<Theme>(() => {
    try {
      return localStorage.getItem('sb-theme') === 'light' ? 'light' : 'dark';
    } catch {
      return 'dark';
    }
  });
  useEffect(() => {
    const root = document.documentElement;
    const prev = root.getAttribute('data-theme');
    root.setAttribute('data-theme', theme);
    try {
      localStorage.setItem('sb-theme', theme);
    } catch {
      /* ignore */
    }
    return () => {
      if (prev === null) root.removeAttribute('data-theme');
      else root.setAttribute('data-theme', prev);
    };
  }, [theme]);
  return [theme, () => setTheme((t) => (t === 'dark' ? 'light' : 'dark'))];
}

interface AutoState {
  on: boolean;
  paused: boolean;
  live: boolean;
  startedAt: number;
  finishedMs: number | null;
}

function TourShell({ n }: { n: number }) {
  const navigate = useNavigate();
  const { search } = useLocation();
  const params = new URLSearchParams(search);
  const tour = useTour();
  const [theme, toggleTheme] = useTourTheme();
  const wantLive = params.get('live') === '1';
  const [auto, setAuto] = useState<AutoState>(() => ({ on: params.get('autoplay') === '1', paused: false, live: false, startedAt: Date.now(), finishedMs: null }));

  const go = useCallback(
    (to: number, manual = true) => {
      const t = Math.min(STEPS.length, Math.max(1, to));
      if (manual) setAuto((a) => (a.on && !a.paused ? { ...a, paused: true } : a));
      navigate(`/tour/${t}${search}`);
    },
    [navigate, search],
  );

  // &live=1: decide once the helper probe answered (≤1 s).
  useEffect(() => {
    if (!auto.on || !wantLive || !tour.helperChecked) return;
    if (tour.helper?.ok) setAuto((a) => ({ ...a, live: true }));
    else tour.showToast(tour.helper ? `helper not configured (${tour.helper.reason}) — keyless mode` : 'helper not running — keyless mode');
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tour.helperChecked]);

  // keyboard
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const el = e.target as HTMLElement;
      if (el && (el.tagName === 'TEXTAREA' || el.tagName === 'INPUT' || el.tagName === 'SELECT' || el.isContentEditable)) return;
      if (e.metaKey || e.ctrlKey || e.altKey) return;
      if (e.key === 'ArrowRight') go(n + 1);
      else if (e.key === 'ArrowLeft') go(n - 1);
      else if (e.key === ' ' && auto.on) {
        e.preventDefault();
        setAuto((a) => ({ ...a, paused: !a.paused }));
      } else if (e.key === 'Escape' && auto.on) setAuto((a) => ({ ...a, on: false }));
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [go, n, auto.on]);

  // autoplay runner: 100 ms ticks; elapsed only advances while playing
  const runner = useRef({ step: 0, elapsed: 0, pending: 0, hold: 0 });
  const plan = useRef<TimelineStep[]>(planFor(false));
  plan.current = planFor(auto.live);
  useEffect(() => {
    if (!auto.on) return;
    const r = runner.current;
    if (r.step !== n) {
      // entering a step (programmatic advance, or the viewer navigated while paused): restart its clock
      r.step = n;
      r.elapsed = -1;
      r.pending = 0;
      r.hold = 0;
    }
    if (auto.paused) return;
    let last = performance.now();
    const t = setInterval(() => {
      const now = performance.now();
      const dt = now - last;
      last = now;
      const st = plan.current.find((s) => s.step === n);
      if (!st) return;
      const prev = r.elapsed;
      r.elapsed = Math.max(0, r.elapsed) + dt;
      for (const a of dueActions(st, prev, r.elapsed)) {
        if (a.live) {
          r.pending++;
          tour
            .run(a.action)
            .then(
              () => (r.hold = r.elapsed + LIVE_HOLD_MS),
              () => (r.hold = r.elapsed + LIVE_ERROR_HOLD_MS),
            )
            .finally(() => r.pending--);
        } else tour.run(a.action).catch(() => {});
      }
      if (canAdvance(st, r.elapsed, r.pending, r.hold)) {
        if (n < STEPS.length) go(n + 1, false);
        else {
          clearInterval(t);
          setAuto((a) => ({ ...a, on: false, finishedMs: Date.now() - a.startedAt }));
        }
      }
    }, 100);
    return () => clearInterval(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [auto.on, auto.paused, auto.live, n]);

  useEffect(() => {
    (window as any).__tourAutoplay = { on: auto.on, paused: auto.paused, live: auto.live, startedAt: auto.startedAt, finishedMs: auto.finishedMs, plannedMs: totalMs(plan.current) };
  }, [auto]);

  useEffect(() => {
    if (!tour.toast) return;
    const t = setTimeout(() => tour.showToast(null), 6000);
    return () => clearTimeout(t);
  }, [tour.toast, tour]);

  const s = STEPS[n - 1];
  const Proof = s.Proof;
  const badgeTitle = tour.badge === 'snapshot' ? `RPC unreachable for some reads; showing tour-v3-snapshot.json. ${tour.fallbackErrors.join(' · ')}` : `${CONTRACT_ID} via RPC`;

  return (
    <div className="tour">
      <header className="tbar">
        <Link to="/tour/1" className="tbrand" aria-label="SealedBounty tour start">
          <svg viewBox="0 0 16 16" aria-hidden>
            <rect x="3" y="7" width="10" height="7" rx="1.5" />
            <path d="M5.5 7V5a2.5 2.5 0 0 1 5 0v2" />
          </svg>
          SealedBounty
        </Link>
        <nav className="tprog" aria-label="Tour steps">
          {STEPS.map((x, i) => (
            <button
              key={i}
              className={`tseg ${i + 1 === n ? 'tseg-on' : ''} ${i + 1 < n ? 'tseg-past' : ''}`}
              onClick={() => go(i + 1)}
              aria-label={`Step ${i + 1}: ${x.kicker}`}
              aria-current={i + 1 === n ? 'step' : undefined}
              title={`${i + 1} · ${x.kicker}`}
            >
              <span />
            </button>
          ))}
        </nav>
        <div className="tbadges">
          <span className={`dbadge dbadge-${tour.badge}`} title={badgeTitle} data-testid="data-badge">
            {tour.badge === 'live' ? (
              <>
                LIVE <span className="dot" aria-hidden>●</span>
              </>
            ) : tour.badge === 'snapshot' ? (
              <>SNAPSHOT {SNAPSHOT_RECORDED_AT.slice(0, 10)}</>
            ) : (
              <>connecting…</>
            )}
          </span>
          {tour.helper?.ok && (
            <span className="dbadge dbadge-helper" title={`demo-helper on localhost:8787 · program ${tour.helper.programId}`}>
              ● helper
            </span>
          )}
          <Link className="tlink" to="/programs">
            Explorer
          </Link>
          <button className="ttheme" onClick={toggleTheme} aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`}>
            {theme === 'dark' ? '○' : '●'}
          </button>
        </div>
      </header>

      <main className="slide" key={n}>
        <article className="narr">
          <div className="narr-k">
            <span className="narr-n">
              {String(n).padStart(2, '0')}
              <span className="dim"> / {String(STEPS.length).padStart(2, '0')}</span>
            </span>
            <span className="narr-kick">{s.kicker}</span>
          </div>
          <h1 className="narr-h">{s.headline}</h1>
          <p className="narr-b">{s.body}</p>
          <p className="narr-w">
            <span className="narr-wl">Why it matters</span>
            {s.why}
          </p>
        </article>
        <section className="proof" aria-label="Proof">
          <Proof />
        </section>
      </main>

      <footer className="tfoot">
        <button className="tnav" onClick={() => go(n - 1)} disabled={n === 1}>
          ← Back
        </button>
        <div className="tauto" aria-live="polite">
          {auto.on ? (
            <>
              <span className={`apill ${auto.paused ? 'apill-paused' : ''}`}>
                {auto.paused ? 'paused' : 'autoplay'}
                {auto.live ? ' · live' : ''}
              </span>
              <span className="muted small hide-sm">Space {auto.paused ? 'resume' : 'pause'} · Esc exit</span>
            </>
          ) : auto.finishedMs !== null ? (
            <span className="muted small">autoplay finished in {Math.round(auto.finishedMs / 1000)} s</span>
          ) : (
            <span className="muted small hide-sm">← → to move</span>
          )}
        </div>
        <button className="tnav tnav-next" onClick={() => go(n + 1)} disabled={n === STEPS.length}>
          Next →
        </button>
      </footer>
      {tour.toast && (
        <div className="toast" role="status">
          {tour.toast}
        </div>
      )}
    </div>
  );
}
