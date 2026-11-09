import { useEffect, useState } from 'react';
import { HashRouter, Navigate, NavLink, Outlet, Route, Routes, useLocation } from 'react-router-dom';
import { Tour } from './tour/Tour';
import { DataProvider, useData, type Mode } from './data';
import { CONTRACT_ID, explorerAccount } from './lib/near';
import { Programs } from './pages/Programs';
import { ProgramDetail } from './pages/ProgramDetail';
import { Inbox } from './pages/Inbox';
import { HowItWorks } from './pages/HowItWorks';

type Theme = 'system' | 'light' | 'dark';

function ThemeToggle() {
  const [theme, setTheme] = useState<Theme>(() => {
    try {
      return (localStorage.getItem('sb-theme') as Theme) || 'system';
    } catch {
      return 'system';
    }
  });
  useEffect(() => {
    const root = document.documentElement;
    if (theme === 'system') root.removeAttribute('data-theme');
    else root.setAttribute('data-theme', theme);
    try {
      localStorage.setItem('sb-theme', theme);
    } catch {
      /* ignore */
    }
  }, [theme]);
  const next: Record<Theme, Theme> = { system: 'dark', dark: 'light', light: 'system' };
  return (
    <button className="ghost" onClick={() => setTheme(next[theme])} title="Toggle theme">
      {theme === 'system' ? '◐ auto' : theme === 'dark' ? '● dark' : '○ light'}
    </button>
  );
}

function ModeBar() {
  const { mode, setMode, isDemo, demoReason, reload, loading, rpcError } = useData();
  return (
    <>
      {rpcError && !/CodeDoesNotExist/.test(rpcError) && (
        <div className="rpc-alert" role="alert">
          <strong>Live RPC unreachable</strong>
          {mode === 'auto' ? ' → showing demo data.' : '. No live data loaded.'} <span className="mono small">{rpcError.slice(0, 120)}</span>{' '}
          <button className="ghost" onClick={reload}>
            retry
          </button>
        </div>
      )}
      <div className={`modebar ${isDemo ? 'modebar-demo' : ''}`}>
        <span>
          {isDemo ? (
            <>
              <strong>DEMO</strong> · {demoReason}. Program and claims are mock data. Signatures and attestation are the <strong>real</strong>{' '}
              recorded TEE outputs from <code>fixtures/demo.*.json</code>.
            </>
          ) : loading ? (
            <>
              Connecting to <code>{CONTRACT_ID}</code>…
            </>
          ) : (
            <>
              Live · <code>{CONTRACT_ID}</code> on testnet ·{' '}
              <a href={explorerAccount(CONTRACT_ID)} target="_blank" rel="noreferrer noopener">
                nearblocks ↗
              </a>
            </>
          )}
        </span>
        <span className="row gap">
          <select value={mode} onChange={(e) => setMode(e.target.value as Mode)} aria-label="Data source">
            <option value="auto">auto</option>
            <option value="live">live</option>
            <option value="demo">demo</option>
          </select>
          {!isDemo && (
            <button className="ghost" onClick={reload}>
              reload
            </button>
          )}
        </span>
      </div>
    </>
  );
}

/** The explorer (programs, claims, inbox, how): its own data provider, so the tour never triggers its RPC loads. */
function ExplorerLayout() {
  return (
    <DataProvider>
      <header className="top">
        <div className="brand">
          <span className="lock">🔒</span> SealedBounty
        </div>
        <nav>
          <NavLink to="/tour/1">Tour</NavLink>
          <NavLink to="/programs">Programs</NavLink>
          <NavLink to="/inbox">Owner inbox</NavLink>
          <NavLink to="/how">How it works</NavLink>
        </nav>
        <ThemeToggle />
      </header>
      <ModeBar />
      <main>
        <Outlet />
      </main>
      <footer className="muted small">Read-only. No wallet, no backend. Writes happen through the SealedBounty CLI.</footer>
    </DataProvider>
  );
}

/** `#/?autoplay=1` keeps its query on the way to `#/tour/1`. */
function ToTour() {
  const { search } = useLocation();
  return <Navigate to={`/tour/1${search}`} replace />;
}

export function App() {
  return (
    <HashRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
      <Routes>
        <Route path="/" element={<ToTour />} />
        <Route path="/tour" element={<ToTour />} />
        <Route path="/tour/:step" element={<Tour />} />
        <Route element={<ExplorerLayout />}>
          <Route path="/programs" element={<Programs />} />
          <Route path="/program/:id" element={<ProgramDetail />} />
          <Route path="/inbox" element={<Inbox />} />
          <Route path="/how" element={<HowItWorks />} />
        </Route>
        <Route path="*" element={<ToTour />} />
      </Routes>
    </HashRouter>
  );
}
