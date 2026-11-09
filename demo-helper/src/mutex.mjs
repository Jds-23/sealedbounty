// One request at a time: the helper signs as fixed accounts, so two flows in parallel would race
// on nonces and on program 2's pool. A busy helper answers 409 instead of queueing.
export function createMutex() {
  let holder = null;
  let token = 0;
  return {
    holder: () => holder,
    /** @returns {(() => void) | null} release, or null when busy */
    tryAcquire(name) {
      if (holder !== null) return null;
      holder = name;
      const mine = ++token;
      return () => {
        if (token === mine) holder = null;
      };
    },
  };
}
