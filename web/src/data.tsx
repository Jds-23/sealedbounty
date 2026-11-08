import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';
import type { Claim, Program, SignerEntry } from './lib/types';
import { getSigners, listClaims, listPrograms } from './lib/near';
import { buildDemo, DEMO_SIGNERS } from './lib/demo';

export type Mode = 'auto' | 'demo' | 'live';

interface DataState {
  mode: Mode;
  setMode: (m: Mode) => void;
  isDemo: boolean;
  demoReason: string | null;
  loading: boolean;
  programs: Program[];
  claims: Claim[];
  signers: SignerEntry[] | null;
  reload: () => void;
}

const Ctx = createContext<DataState | null>(null);

const readMode = (): Mode => {
  try {
    const m = localStorage.getItem('sb-mode');
    return m === 'demo' || m === 'live' ? m : 'auto';
  } catch {
    return 'auto';
  }
};

export function DataProvider({ children }: { children: ReactNode }) {
  const [mode, setModeState] = useState<Mode>(readMode);
  const [loading, setLoading] = useState(true);
  const [live, setLive] = useState<{ programs: Program[]; claims: Claim[]; signers: SignerEntry[] | null; error: string | null }>({
    programs: [],
    claims: [],
    signers: null,
    error: null,
  });
  const [tick, setTick] = useState(0);
  const demo = useMemo(() => buildDemo(), []);

  const setMode = (m: Mode) => {
    setModeState(m);
    try {
      localStorage.setItem('sb-mode', m);
    } catch {
      /* ignore */
    }
  };

  useEffect(() => {
    if (mode === 'demo') {
      setLoading(false);
      return;
    }
    let cancelled = false;
    setLoading(true);
    (async () => {
      try {
        const [programs, signers] = await Promise.all([listPrograms(), getSigners().catch(() => null)]);
        const claims = (await Promise.all(programs.map((p) => listClaims(p.id)))).flat();
        if (!cancelled) setLive({ programs, claims, signers, error: null });
      } catch (e) {
        if (!cancelled) setLive({ programs: [], claims: [], signers: null, error: (e as Error).message });
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [mode, tick]);

  const reload = useCallback(() => setTick((t) => t + 1), []);

  let demoReason: string | null = null;
  if (mode === 'demo') demoReason = 'Demo mode on';
  else if (mode === 'auto' && !loading) {
    if (live.error) demoReason = /CodeDoesNotExist/.test(live.error) ? 'Contract not deployed yet' : `RPC failed (${live.error.slice(0, 80)})`;
    else if (live.programs.length === 0) demoReason = 'Contract has no programs yet';
  }
  const isDemo = demoReason !== null;

  const value: DataState = {
    mode,
    setMode,
    isDemo,
    demoReason,
    loading: loading && mode !== 'demo',
    programs: isDemo ? demo.programs : live.programs,
    claims: isDemo ? demo.claims : live.claims,
    signers: isDemo ? DEMO_SIGNERS : live.signers,
    reload,
  };
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useData() {
  const v = useContext(Ctx);
  if (!v) throw new Error('useData outside provider');
  return v;
}
