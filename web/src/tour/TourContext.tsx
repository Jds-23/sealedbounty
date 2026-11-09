// Tour session state (React context, no localStorage): the data (live with per-datum snapshot fallback), the results
// of the hero actions the viewer ran (step 8 scorecard), the helper probe, and an action registry autoplay fires.
import { createContext, useCallback, useContext, useEffect, useMemo, useReducer, useRef, useState, type ReactNode } from 'react';
import type { ActionKey } from './autoplay';
import { judgementReducer, NO_JUDGEMENT, probeHelper, type HelperHealth, type Judgement, type JudgementAction, type LiveJudgementState } from './helper';
import { loadClaims, loadProgramView, loadTxs, snapshotData, type ProgramView, type Source, type TourData } from './tourData';

export interface ResultEntry {
  ok: boolean;
  label: string;
  at: number;
}

export type Badge = 'loading' | 'live' | 'snapshot';

interface TourState {
  data: TourData;
  badge: Badge;
  /** Why something fell back to the snapshot (shown in the badge tooltip). */
  fallbackErrors: string[];
  /** Step 3 'Load live' result: what was read, from where, how long it took. */
  programRead: { view: ProgramView; source: Source; ms: number; at: number } | null;
  loadProgram: () => Promise<boolean>;
  results: Partial<Record<string, ResultEntry>>;
  setResult: (key: string, ok: boolean, label: string) => void;
  register: (key: ActionKey, fn: () => Promise<unknown> | unknown) => () => void;
  run: (key: ActionKey) => Promise<void>;
  helper: HelperHealth | null;
  helperChecked: boolean;
  liveJudgement: Judgement | null;
  /** The step-4 judgement plus whether a submit_claim already consumed its req_hash (steps 6, 7). */
  judgementState: LiveJudgementState;
  trackJudgement: (a: JudgementAction) => void;
  toast: string | null;
  showToast: (t: string | null) => void;
}

const Ctx = createContext<TourState | null>(null);

export function TourProvider({ children }: { children: ReactNode }) {
  const [data, setData] = useState<TourData>(snapshotData);
  const [sources, setSources] = useState<Record<string, Source | 'loading'>>({ program: 'loading', claims: 'loading', txs: 'loading' });
  const [fallbackErrors, setFallbackErrors] = useState<string[]>([]);
  const [programRead, setProgramRead] = useState<TourState['programRead']>(null);
  const [results, setResults] = useState<TourState['results']>({});
  const [helper, setHelper] = useState<HelperHealth | null>(null);
  const [helperChecked, setHelperChecked] = useState(false);
  const [judgementState, trackJudgement] = useReducer(judgementReducer, NO_JUDGEMENT);
  const liveJudgement = judgementState.judgement;
  const [toast, setToast] = useState<string | null>(null);
  const actions = useRef(new Map<ActionKey, () => Promise<unknown> | unknown>());

  const noteErrors = (errs: string[]) => errs.length && setFallbackErrors((e) => [...new Set([...e, ...errs])].slice(-6));

  const loadProgram = useCallback(async () => {
    const t0 = performance.now();
    const r = await loadProgramView();
    setProgramRead({ view: r.data, source: r.source, ms: Math.round(performance.now() - t0), at: Date.now() });
    setData((d) => ({ ...d, ...r.data }));
    setSources((s) => ({ ...s, program: r.source }));
    noteErrors(r.errors);
    return r.source === 'live';
  }, []);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      const [p, c] = await Promise.all([loadProgramView(), loadClaims()]);
      if (cancelled) return;
      setData((d) => ({ ...d, ...p.data, claims: c.data }));
      setSources((s) => ({ ...s, program: p.source, claims: c.source }));
      noteErrors([...p.errors, ...c.errors]);
      const t = await loadTxs(c.data);
      if (cancelled) return;
      setData((d) => ({ ...d, txs: t.data }));
      setSources((s) => ({ ...s, txs: t.source }));
      noteErrors(t.errors);
    })();
    probeHelper(1000).then((h) => {
      if (cancelled) return;
      setHelper(h);
      setHelperChecked(true);
    });
    return () => {
      cancelled = true;
    };
  }, []);

  const setResult = useCallback((key: string, ok: boolean, label: string) => setResults((r) => ({ ...r, [key]: { ok, label, at: Date.now() } })), []);

  const register = useCallback((key: ActionKey, fn: () => Promise<unknown> | unknown) => {
    actions.current.set(key, fn);
    return () => {
      if (actions.current.get(key) === fn) actions.current.delete(key);
    };
  }, []);

  const run = useCallback(async (key: ActionKey) => {
    const fn = actions.current.get(key);
    if (fn) await fn();
  }, []);

  const vals = Object.values(sources);
  const badge: Badge = vals.includes('snapshot') ? 'snapshot' : vals.includes('loading') ? 'loading' : 'live';

  const value = useMemo<TourState>(
    () => ({
      data,
      badge,
      fallbackErrors,
      programRead,
      loadProgram,
      results,
      setResult,
      register,
      run,
      helper,
      helperChecked,
      liveJudgement,
      judgementState,
      trackJudgement,
      toast,
      showToast: setToast,
    }),
    [data, badge, fallbackErrors, programRead, loadProgram, results, setResult, register, run, helper, helperChecked, liveJudgement, judgementState, toast],
  );
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useTour() {
  const v = useContext(Ctx);
  if (!v) throw new Error('useTour outside TourProvider');
  return v;
}

/**
 * Results persist across steps: when a step mounts and its action already ran this session, re-run it (pure,
 * idempotent recomputes) so the proof pane shows the result again instead of an empty state.
 */
export function useRestore(key: string, fn: () => unknown) {
  const { results } = useTour();
  const had = useRef(!!results[key]);
  useEffect(() => {
    if (had.current) fn();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
}

/** Registers a step's hero action for autoplay (always calls the latest closure). */
export function useTourAction(key: ActionKey, fn: () => Promise<unknown> | unknown) {
  const { register } = useTour();
  const ref = useRef(fn);
  ref.current = fn;
  useEffect(() => register(key, () => ref.current()), [key, register]);
}
