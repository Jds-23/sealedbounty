// `?autoplay=1` timeline (docs/demo-app-spec.md §6): one data table, tune it here. Keyless total = 120 s.
// `&live=1` also fires the helper actions (live: true); the step then waits for their completion event instead of
// the fixed dwell (a failed live action continues after 5 s).

export type ActionKey =
  | 'diagram-tour'
  | 'load-program'
  | 'encrypt'
  | 'verify-browser'
  | 'ask-contract'
  | 'flip-on'
  | 'flip-off'
  | 'decrypt'
  | 'gauntlet-1'
  | 'gauntlet-2'
  | 'gauntlet-3'
  | 'gauntlet-4'
  | 'live-judge'
  | 'live-loop'
  | 'live-frontrun';

export interface TimelineAction {
  /** ms after the step opens */
  at: number;
  action: ActionKey;
  /** Helper action: only with &live=1 (and a reachable helper); the step waits for it to finish. */
  live?: boolean;
}

export interface TimelineStep {
  step: number;
  /** ms on this step before advancing (keyless), or the minimum when live actions are awaited */
  dwell: number;
  actions: TimelineAction[];
}

export const TIMELINE: TimelineStep[] = [
  { step: 1, dwell: 12_000, actions: [] },
  { step: 2, dwell: 14_000, actions: [{ at: 4_500, action: 'diagram-tour' }] },
  { step: 3, dwell: 14_000, actions: [{ at: 2_500, action: 'load-program' }] },
  {
    step: 4,
    dwell: 15_000,
    actions: [
      { at: 3_000, action: 'encrypt' },
      { at: 6_000, action: 'live-judge', live: true },
    ],
  },
  {
    step: 5,
    dwell: 18_000,
    actions: [
      { at: 2_000, action: 'verify-browser' },
      { at: 5_500, action: 'ask-contract' },
      // flipping re-runs the browser check and re-asks the contract with the flipped body ("bad signature")
      { at: 9_500, action: 'flip-on' },
      { at: 15_000, action: 'flip-off' },
    ],
  },
  {
    step: 6,
    dwell: 17_000,
    actions: [
      { at: 2_500, action: 'decrypt' },
      { at: 8_000, action: 'live-loop', live: true },
    ],
  },
  {
    step: 7,
    dwell: 18_000,
    actions: [
      { at: 2_000, action: 'gauntlet-1' },
      { at: 4_500, action: 'gauntlet-2' },
      { at: 7_000, action: 'gauntlet-3' },
      { at: 9_500, action: 'gauntlet-4' },
      { at: 12_000, action: 'live-frontrun', live: true },
    ],
  },
  { step: 8, dwell: 12_000, actions: [] },
];

/** Hold after an awaited live action completes, so its result is on screen before advancing. */
export const LIVE_HOLD_MS = 3_000;
/** A failed live action: show the error, continue after this. */
export const LIVE_ERROR_HOLD_MS = 5_000;

export const planFor = (live: boolean, timeline: TimelineStep[] = TIMELINE): TimelineStep[] =>
  timeline.map((s) => ({ ...s, actions: s.actions.filter((a) => live || !a.live) }));

export const totalMs = (plan: TimelineStep[]) => plan.reduce((t, s) => t + s.dwell, 0);

/** Actions whose time falls in (prev, now]; prev < 0 means the step just opened. */
export const dueActions = (step: TimelineStep, prevMs: number, nowMs: number): TimelineAction[] =>
  step.actions.filter((a) => a.at > prevMs && a.at <= nowMs);

/** Whether the runner may leave the step: dwell elapsed and no awaited live action still running or holding. */
export const canAdvance = (step: TimelineStep, elapsedMs: number, pendingLive: number, holdUntilMs: number) =>
  elapsedMs >= step.dwell && pendingLive === 0 && elapsedMs >= holdUntilMs;
