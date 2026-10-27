/**
 * The FETCH adapter over `handleChallenge`. One of four, and the thinnest.
 *
 * **NO LOGIC IN AN ADAPTER.** Everything here is translation: a `Response`
 * becomes a `ChallengeContext` on the way in, and a `CoreOutcome` becomes a
 * `Response` (or a throw) on the way out, through `settleFetchOutcome`. It
 * parses no challenge, compares no bar, decides no scope, counts no retry and
 * chooses no error class. If something in this file ever looks like a decision,
 * it belongs in `core.ts` instead — a row that passes here and fails on the
 * axios surface is a leak out of the core, not a difference between transports.
 *
 * The one genuinely transport-shaped obligation it carries is the body: a
 * replay needs the request body while it is still unread, so `planReplay` runs
 * BEFORE the first call and the core is told whether a replay is even possible
 * before any prompt opens. The caller's own response is never consumed — every
 * body read is taken from `clone()`, so `bodyUsed === false` holds on the object
 * the caller receives.
 *
 * SSR-safe: no global is read at module scope. `withAuth()`'s default `next` is
 * resolved inside the call, not here.
 */

import {
  type AbortView,
  type ChallengeContext,
  type UpgradeInterceptorOptionsSource,
  handleChallenge,
  resolveInterceptorOptions,
  settleFetchOutcome,
} from './core';
import { type FetchLike, type ReplayHints, type ReplayPlan, planReplay } from './replay';

/**
 * How many upgrade-aware fetch layers are DISPATCHING through this one, right
 * now, on this synchronous call path.
 *
 * ## The defect
 *
 * `markers` on the fetch surface is a per-wrapper object and is deliberately
 * never on the wire. That is right for one wrapper and wrong for two: with
 * `interceptFetch: true` AND an app-held `withAuth(fetch)` on the same path,
 * the inner layer elevates and replays, and if the server re-challenges the
 * replay the OUTER layer sees a 401 whose markers are empty and elevates again.
 * Two prompts and two challenges for one user action, against a server budget
 * that caps at a few attempts — the single-flight NFR, violated by stacking.
 *
 * ## Why a counter, and why this one
 *
 * Three fixes were on the table. (1) Tag the in-flight request: the only
 * identity both layers share is the caller's `input`/`init` objects, and
 * `fetch('/x')` has neither, so a `WeakSet` keyed on them silently misses the
 * commonest call shape — and a header would make the marker transmissible,
 * which is prohibited. (2) Have `registerFetchMiddleware` refuse to install
 * when a wrapper is already active on that path: it cannot know, because an
 * app-held `withAuth` wrapper is not registered anywhere and the global patch
 * cannot see it. (3) This: make "a layer above me already owns this call"
 * observable, and pass through when it is.
 *
 * The counter is safe against concurrency because it is only ever held across
 * SYNCHRONOUS code. `dispatch` increments, calls `next`, and decrements in
 * `finally` — all before the first `await` — so the window is exactly the inner
 * layer's own synchronous prologue, where it reads the counter. No other
 * request can interleave into a synchronous span, so this is a dynamic extent,
 * not ambient state, and it is SSR-safe for the same reason: it is never
 * non-zero across a suspension point.
 *
 * The limit, stated rather than hidden: an intervening wrapper that `await`s
 * before calling `fetch` breaks the extent, and both layers then elevate as
 * they do today. The fix narrows the defect to that case instead of closing it
 * absolutely — a marker that closed it absolutely would have to travel with the
 * request, which is the thing we must not do. The axios seam carries its own
 * config marker and is a separate channel; a stacked fetch-plus-axios path is
 * not covered here.
 */
let dispatchingLayers = 0;

/**
 * A live view of the caller's signal.
 *
 * Read through getters because the core checks it AFTER awaiting the elevation:
 * a boolean copied at call time would always say "not aborted". The listener
 * pair is forwarded as well — that is what lets the core RACE the abort against
 * a pending proof (REQ-C12) instead of discovering it once the proof settles.
 * Both are bound to the caller's own signal; this adapter never aborts it and
 * never creates a signal of its own.
 */
const abortViewOf = (input: RequestInfo | URL, init?: RequestInit): AbortView | undefined => {
  const signal =
    init?.signal ?? (typeof input === 'object' && input !== null ? (input as Request).signal : undefined) ?? undefined;
  if (!signal) {
    return undefined;
  }
  return {
    get aborted(): boolean {
      return signal.aborted;
    },
    get reason(): unknown {
      return (signal as AbortSignal & { reason?: unknown }).reason;
    },
    ...(typeof signal.addEventListener === 'function'
      ? {
          addEventListener: (type: 'abort', listener: () => void) => signal.addEventListener(type, listener),
          removeEventListener: (type: 'abort', listener: () => void) => signal.removeEventListener(type, listener),
        }
      : {}),
  };
};

/** Reads a header off a `Response`, in the callback shape the one parser takes. */
const headerReader =
  (response: Response) =>
  (name: string): string | null | undefined =>
    response.headers?.get(name);

/**
 * Wraps one `Response` as a `ChallengeContext`.
 *
 * `markers` is shared with the original context, which is the fetch surface's
 * answer to marker storage: the wrapper owns the call, so a per-request object
 * is the whole mechanism. The replayed response re-uses it, so the core's
 * re-entry guard reads the same state it wrote.
 */
const contextFor = (
  response: Response,
  plan: ReplayPlan,
  next: FetchLike,
  markers: ChallengeContext['markers'],
  abort: AbortView | undefined,
): ChallengeContext => ({
  status: response.status,
  getHeader: headerReader(response),
  // A CLONE, always. The response the caller receives must still have an unread
  // body, and the core calls this only when the scope and the channel policy
  // both permit a body read.
  readBody: () => response.clone().json(),
  // The PLAN's snapshot, never a live `urlOf(input)` read at challenge time.
  // Reading the caller's input here was the asymmetry §13.4 revision 6 closes:
  // the request that was authorized and the request that is replayed must be
  // the same request, and the only way to guarantee that is for both to read
  // the one frozen object.
  request: plan.snapshot,
  replay: async (hints?: ReplayHints) => {
    const replayed = await plan.replay(next, hints);
    return contextFor(replayed, plan, next, markers, abort);
  },
  markers,
  raw: response,
  replayable: plan.replayable,
  replayUnsupportedReason: plan.reason,
  signal: abort,
  responseType: response.type,
});

/**
 * Wraps a `fetch`, returning a new function. Installs nothing and touches no
 * global — this is the SSR- and React-Native-safe entry point, and the one the
 * global patch itself is built from.
 */
export const upgradeFetch = (next: FetchLike, source: UpgradeInterceptorOptionsSource): FetchLike => {
  /**
   * Sends through `next` while announcing that THIS layer owns the call.
   *
   * Used for the first send and for every replay, so a nested layer passes the
   * replay through too — otherwise the inner layer would claim the replay that
   * this layer's elevation produced, which is the stacking defect itself.
   */
  const dispatch: FetchLike = (nestedInput, nestedInit) => {
    dispatchingLayers += 1;
    try {
      return next(nestedInput, nestedInit);
    } finally {
      dispatchingLayers -= 1;
    }
  };

  return async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    if (dispatchingLayers > 0) {
      // A layer above us is handling this call: it plans the replay, it owns the
      // elevation, and one challenge is spent. Pure pass-through — no plan, no
      // body clone, no prompt. `dispatch` keeps the claim for layers below us.
      return dispatch(input, init);
    }

    // Resolved PER REQUEST, not at wrap time: a `withAuth()` wrapper built
    // before `enable()` must still see the scope `enable()` installed, and a
    // later `enable()` with a narrower `backend` must narrow this wrapper too.
    const options = resolveInterceptorOptions(source);

    // Before the first send: a `Request` body can only be cloned while unread.
    const plan = planReplay(input, init, options.replay);
    const response = await dispatch(plan.forwardInput, plan.forwardInit);

    const ctx = contextFor(response, plan, dispatch, {}, abortViewOf(input, init));
    const outcome = await handleChallenge(ctx, options);

    const settlement = settleFetchOutcome(outcome, response, options);
    if (settlement.settle === 'reject') {
      throw settlement.error;
    }
    return settlement.value;
  };
};
