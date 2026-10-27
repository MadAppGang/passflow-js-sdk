/**
 * Upgrade orchestration — ONE state machine, and it is the single authority for
 * lifecycle.
 *
 * Turns a parsed RFC 9470 challenge into an elevated session: pick a factor,
 * ask the user, run the prepare round if the factor needs one, assert, then
 * commit through `POST /auth/refresh` with the `upgrade` field.
 *
 * The controller owns no UI. It calls out to a prompt handler, which the React
 * layer (or any consumer) implements — that is what keeps the same logic usable
 * from a headless client.
 *
 * ## Why a state machine rather than rules
 *
 * Three review rounds each found two independently-correct lifecycle fixes
 * colliding: fold-versus-single-flight, replay-binding-versus-aggregation, and
 * a prompt outliving the flight whose state had already been cleared. The cause
 * was not any individual rule — it was that lifecycle was specified as rules
 * scattered across four sections, so two of them could each be locally right
 * and jointly impossible. Everything about when state is set, read and cleared
 * lives here, and nothing else writes these fields.
 *
 * ## The states
 *
 * | state        | meaning                                                        |
 * |--------------|----------------------------------------------------------------|
 * | `idle`       | no flight; every field clear; `inFlight === null`               |
 * | `collecting` | prompt open, no factor selected yet                             |
 * | `proving`    | a factor is selected; `prepare`/commit on the wire              |
 * | `replaying`  | proof accepted; waiters replaying their own bound requests      |
 * | `settling`   | every waiter has reported; the summary is complete              |
 * | `done`       | prompt settled and every waiter settled; one step from `idle`   |
 *
 * ## The decision that shapes all of it
 *
 * **An elevation ends when every waiting request has been retried and settled.**
 * Proof acceptance does NOT end the flight. The previous implementation cleared
 * `inFlight` in a `.finally` on proof completion, and that `.finally` was a real
 * window: a prompt on screen with `inFlight === null`, in which an unrelated
 * challenged request opened a SECOND modal and a waiter could report into a
 * controller that had already forgotten its flight. Clearing happens in one
 * synchronous step, after the prompt has settled, and nowhere else.
 *
 * Two costs the design accepts for that: the prompt stays open for one extra
 * round trip while the replays settle, and a genuinely new challenge arriving in
 * that window queues behind the flight rather than opening a second prompt.
 */

import type { AssuranceBar, UpgradeChallenge } from './challenge';
import { UpgradeInsufficientError, UpgradeSessionChangedError, UpgradeTransportError, UpgradeUnavailableError } from './errors';
import {
  DEFAULT_UPGRADE_FACTORS,
  type UpgradeAssertion,
  type UpgradeFactor,
  UpgradeFactorError,
  type UpgradeFactorType,
  type UpgradePrepared,
  factorRegistry,
} from './factors';
import { selectFactors } from './select';

import type { PlatformAdapter } from '../platform';

/** What the UI is shown when an upgrade is required. */
export type UpgradePromptRequest = {
  /** What the server demanded — the MERGED requirement, when several challenges joined. */
  challenge: UpgradeChallenge;
  /** Usable factors, already ordered — the suggested one first. */
  factors: readonly UpgradeFactor[];
  /** Failure from the previous attempt, when the user is retrying. */
  previousError?: Error;
  /**
   * Called the moment the user picks a factor and BEFORE any answer is
   * submitted. REQUIRED of every prompt implementation — the SDK's own modal,
   * the `useUpgrade` hook and a render-prop override alike.
   *
   * `selected` is defined off this call and off nothing else. Deriving it from
   * `prompt` resolving would implement the SUBMISSION boundary instead: the
   * shipped `UpgradePromptResult` resolves with the code already collected, so
   * `selected` would stay false for the whole interval in which the user has
   * picked TOTP and is typing six digits — and a stronger challenge arriving
   * then would re-rank the list under their fingers, the exact UI jump the
   * selection boundary exists to prevent.
   *
   * An override that never calls it leaves the controller in `collecting` for
   * the whole ceremony, so a late join re-ranks mid-entry: degraded, not silent,
   * because `onRequirementRaised` still fires and the re-rank is observable.
   */
  onFactorSelected: (factor: UpgradeFactorType) => void;
  /**
   * The channel by which the controller pushes a raised bar and a re-ranked list
   * into an OPEN prompt, which updates without resolving. Only ever used before
   * a factor is selected (branch 2). The one-answer resolution contract is
   * unchanged.
   *
   * A prompt SUBSCRIBES by assigning its own handler to this field on the
   * request object it was handed, synchronously, before it awaits anything:
   *
   * ```ts
   * const prompt: UpgradePromptHandler = (request) => {
   *   request.onRequirementRaised = (next) => setView(next);
   *   return collectAnswer(request);
   * };
   * ```
   *
   * It is a slot rather than a controller-supplied function because the
   * direction is controller → prompt: only the prompt knows how to re-render
   * itself. An override that leaves it unset shows the old bar, and the raised
   * bar then surfaces as a re-challenged replay reporting `insufficient` —
   * degraded, never silent.
   */
  onRequirementRaised?: (next: { challenge: UpgradeChallenge; factors: readonly UpgradeFactor[] }) => void;
};

/** The user's answer to an upgrade prompt. */
export type UpgradePromptResult = { type: 'submit'; factor: UpgradeFactorType; code?: string } | { type: 'cancel' };

/** Renders the upgrade UI and resolves once the user submits or backs out. */
export type UpgradePromptHandler = (request: UpgradePromptRequest) => Promise<UpgradePromptResult>;

/** Transport seam — the controller never touches axios directly, so it stays testable. */
export type UpgradeTransport = {
  /**
   * `POST /auth/upgrade/start`. Only called for factors whose `requiresPrepare`
   * is true.
   *
   * Resolves `undefined` when no prepare round was needed after all — a one-shot
   * factor, or a server that answers `prepare_not_required` because its view of
   * the factor differs from ours. Both are recoveries: the factor then asserts
   * with no `prepared`, which is already the TOTP path.
   */
  prepare(method: UpgradeFactorType): Promise<UpgradePrepared | undefined>;
  /** `POST /auth/refresh` carrying `upgrade`. Resolves once elevated tokens are stored. */
  commit(factor: UpgradeFactorType, assertion: UpgradeAssertion): Promise<void>;
};

/** The six states. The controller is always in exactly one. */
export type UpgradeFlightState = 'idle' | 'collecting' | 'proving' | 'replaying' | 'settling' | 'done';

/**
 * Who is waiting on this elevation.
 *
 * A `request` waiter owns a replay bound to its own URL and method. An
 * `imperative` waiter has nothing to replay, but when its caller STATED a bar
 * it still has a locally checkable requirement — which is why `requested`
 * exists, and why an AAL3 imperative call joining an AAL2 flight can no longer
 * be reported as `elevated`.
 */
export type Waiter = { kind: 'request'; url: string; method: string } | { kind: 'imperative'; requested?: AssuranceBar };

/** A waiter's terminal classification. `pending` until it reports. */
export type WaiterOutcome = 'pending' | 'replayed' | 'insufficient' | 'failed';

/** What a waiter reports once its own replay has settled. */
export type WaiterReport = {
  outcome: 'replayed' | 'insufficient' | 'failed';
  obtained?: AssuranceBar;
  required?: AssuranceBar;
};

/**
 * A registered waiter.
 *
 * `report()` is the declared inbound edge: classification happens in the
 * adapter, after `elevate()` resolved, and this is the channel by which it
 * reaches the controller. Because `waiters` is cleared in the final transition
 * rather than on proof completion, the entries are still alive when the summary
 * reads them.
 */
export type WaiterEntry = Waiter & {
  outcome: WaiterOutcome;
  obtained?: AssuranceBar;
  required?: AssuranceBar;
  /** Called exactly once. Idempotent: later calls are ignored. */
  report(result: WaiterReport): void;
};

/** The proof's own outcome, which is NOT any operation's outcome. */
export type UpgradeProof = { status: 'proven'; obtained: AssuranceBar } | { status: 'failed'; reason: Error };

/** What a successful `elevate()` hands back to its caller. */
export type UpgradeElevation = {
  /** This caller's own registered waiter. `report()` is its edge back. */
  waiter: WaiterEntry;
  /** The bar the proof reached, as far as the client can know it. */
  obtained: AssuranceBar;
};

/** One row of the per-flight outcome summary. */
export type UpgradeWaiterSummary = {
  url?: string;
  method?: string;
  outcome: WaiterOutcome;
  obtained?: AssuranceBar;
  required?: AssuranceBar;
};

/**
 * The per-flight outcome summary: a pure function of `waiters` plus `proof`.
 *
 * `terminal` is what the prompt may report. The modal must NOT say "success"
 * while any waiter is re-challenged — for AAL3 endpoints with TOTP-only users
 * that is the NORMAL path, not an edge case, and a design cannot both claim the
 * server is the authority and delete the path by which its second refusal
 * reaches the user.
 */
export type UpgradeFlightSummary = {
  proof: UpgradeProof;
  waiters: UpgradeWaiterSummary[];
  terminal: 'success' | 'insufficient' | 'failed';
  /** The bars of the STRONGEST unmet waiter, so the message is honest. */
  insufficient?: { obtained: AssuranceBar; required: AssuranceBar };
  /** The proof failure, when the flight never produced a proof. */
  error?: Error;
};

export type UpgradeControllerOptions = {
  transport: UpgradeTransport;
  prompt: UpgradePromptHandler;
  platform: PlatformAdapter;
  /** Defaults to the factors this SDK can complete. */
  factors?: readonly UpgradeFactor[];
  /** How many times the user may answer wrongly before the elevation gives up. */
  maxAttempts?: number;
  /**
   * The bar the elevation actually reached, when the host can read it — from the
   * `acr` claim of the freshly stored access token, for instance.
   *
   * Without it the controller reports the bar the ceremony was RANKED for, which
   * is the honest client-side approximation: the server scores `acr` from the
   * base session plus the verified factor and is the only authority, and a
   * replay that is re-challenged corrects the approximation immediately.
   */
  readObtainedBar?: () => AssuranceBar | undefined;
  /**
   * Called once per flight, in the settling transition, after every waiter has
   * reported. This is how the open prompt is given its terminal state, and how
   * the React layer gets exactly one terminal state per flight.
   */
  onFlightSettled?: (summary: UpgradeFlightSummary) => void;
  /**
   * Liveness guard: how long to wait for waiters to report before settling the
   * flight anyway. A waiter that never calls `report()` is an adapter bug, and
   * without a bound it would hold `inFlight` open forever — so every later
   * elevation would join a dead flight, which is a worse failure than settling
   * early. Defaults to 30s.
   */
  replaySettleTimeoutMs?: number;
};

/**
 * Raised when the user dismissed the upgrade rather than failing it.
 *
 * `cause` is carried for one case only: a prompt implementation that threw or
 * rejected is treated as a failed COLLECTION and settles on the cancellation
 * contract, because there is no answer and no proof — but the thrown error is
 * the only evidence of an integration bug, so it travels rather than being
 * swallowed.
 */
export class UpgradeCancelledError extends Error {
  readonly code = 'upgrade_cancelled' as const;
  /** Declared here rather than inherited: `Error.cause` is ES2022, this build targets ES2021 libs. */
  readonly cause?: unknown;

  constructor(cause?: unknown) {
    super('Upgrade authentication was cancelled');
    this.name = 'UpgradeCancelledError';
    if (cause !== undefined) {
      this.cause = cause;
    }
  }
}

/** Raised when no registered factor can satisfy the challenge. */
export class UpgradeUnsatisfiableError extends Error {
  readonly code = 'upgrade_unsatisfiable' as const;

  constructor(message = 'No available authentication factor can satisfy this challenge') {
    super(message);
    this.name = 'UpgradeUnsatisfiableError';
  }
}

/**
 * The server writes `Attempts: 0, MaxAttempts: 5` on every NEWLY CREATED
 * challenge (`upgrade.go:177-180`), so the budget is per challenge, not per
 * session: a later sequential elevation gets its own and consumes nothing from
 * this one. Four local attempts therefore stop one short of the server's five,
 * which keeps the SDK from being the thing that burns the budget while leaving a
 * user who mistypes room to recover.
 */
const DEFAULT_MAX_ATTEMPTS = 4;

/** Default liveness bound on waiter reports. See `replaySettleTimeoutMs`. */
const DEFAULT_SETTLE_TIMEOUT_MS = 30_000;

/** A promise with its resolvers, which is all `elevate`'s per-waiter settlement needs. */
type Deferred<T> = { promise: Promise<T>; resolve: (value: T) => void; reject: (reason: unknown) => void };

const deferred = <T>(): Deferred<T> => {
  let resolve: (value: T) => void = () => undefined;
  let reject: (reason: unknown) => void = () => undefined;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
};

/** A registered waiter plus the controller's own bookkeeping for it. */
type Registration = {
  entry: WaiterEntry;
  /** The bar THIS waiter arrived demanding. Checked against the proof. */
  demanded: AssuranceBar;
  /**
   * True only when the CALLER stated a bar on an imperative call.
   *
   * §13.3's `n/a` cell is the options-LESS imperative call: it states no bar and
   * has no protected operation, so it can never report `insufficient` (C24b).
   * Deriving "stated" from `demanded` is impossible once `demanded` falls back
   * to the challenge's own bar, and with `barMeets` no longer fail-open on an
   * unknown level that fallback would have started rejecting exactly the call
   * the spec says never rejects.
   */
  statedBar: boolean;
  settlement: Deferred<UpgradeElevation>;
  reported: boolean;
};

/** The bar a challenge demands, in the shape the errors and the hook share. */
export const barOf = (challenge: UpgradeChallenge): AssuranceBar => ({
  acrValues: challenge.acrValues,
  level: challenge.requiredLevel,
  maxAge: challenge.maxAge,
});

/**
 * Does `obtained` reach `required`?
 *
 * Only the `acr` axis is decidable client-side. A completed proof always
 * satisfies a freshness demand, since it just happened, and a requirement with
 * no level constrains nothing on this axis — so both of those are `true`.
 *
 * **An UNKNOWN obtained level does not meet a bar.** This is the one place in
 * the feature where fail-open is wrong, and §13.4 revision 6 draws the line
 * explicitly: fail-open governs *recovery* — availability, not logging the user
 * out, not blocking the app — never the *granting of access*. Answering "meets"
 * for a level we could not read is granting access on no evidence.
 *
 * It is NOT pre-judging satisfiability, and the difference is what §13.2 line
 * 1599 and §13.4 line 2213 protect: nothing is refused outright, no elevation
 * is declined, no factor is filtered. The SDK merely declines to ASSERT that a
 * bar was reached; the server's replay re-challenge decides, and that surfaces
 * as §13.3's `insufficient` with both bars attached. The only waiters this can
 * settle locally are imperative ones that STATED a bar, which have no replay to
 * ask the server about.
 */
export const barMeets = (obtained: AssuranceBar, required: AssuranceBar): boolean => {
  if (required.level === undefined) {
    return true;
  }
  if (obtained.level === undefined) {
    return false;
  }
  return obtained.level >= required.level;
};

/** Field-wise merge of two requirements: `acr` tightens up, freshness tightens down. */
export const mergeChallenges = (current: UpgradeChallenge, incoming: UpgradeChallenge): UpgradeChallenge => {
  const level =
    current.requiredLevel === undefined
      ? incoming.requiredLevel
      : incoming.requiredLevel === undefined
        ? current.requiredLevel
        : Math.max(current.requiredLevel, incoming.requiredLevel);

  // The raw list follows the bar that won, so a diagnostic never shows a string
  // that did not set the requirement.
  const acrValues =
    level === undefined
      ? (current.acrValues ?? incoming.acrValues)
      : level === current.requiredLevel
        ? current.acrValues
        : incoming.acrValues;

  const maxAge =
    current.maxAge === undefined
      ? incoming.maxAge
      : incoming.maxAge === undefined
        ? current.maxAge
        : Math.min(current.maxAge, incoming.maxAge);

  const channels = Array.from(new Set([...(current.channels ?? []), ...(incoming.channels ?? [])]));

  return {
    acrValues,
    requiredLevel: level,
    maxAge,
    status: current.status,
    ...(channels.length > 0 ? { channels } : {}),
  };
};

/** Is `incoming` STRICTLY stronger than `current` on either axis? */
const isStrictlyStronger = (current: UpgradeChallenge, incoming: UpgradeChallenge): boolean => {
  const acrRose =
    incoming.requiredLevel !== undefined &&
    (current.requiredLevel === undefined || incoming.requiredLevel > current.requiredLevel);
  const freshnessTightened =
    incoming.maxAge !== undefined && (current.maxAge === undefined || incoming.maxAge < current.maxAge);
  return acrRose || freshnessTightened;
};

export class UpgradeController {
  private readonly transport: UpgradeTransport;
  private readonly prompt: UpgradePromptHandler;
  private readonly platform: PlatformAdapter;
  private readonly registry: Map<UpgradeFactorType, UpgradeFactor>;
  private readonly available: readonly UpgradeFactor[];
  private readonly maxAttempts: number;
  private readonly readObtainedBar?: () => AssuranceBar | undefined;
  private readonly onFlightSettled?: (summary: UpgradeFlightSummary) => void;
  private readonly settleTimeoutMs: number;

  /** The current state. Public for diagnostics and tests; nothing outside writes it. */
  private state: UpgradeFlightState = 'idle';

  /**
   * The elevation currently running.
   *
   * Single-flight is the STATE SET, not a flag: `elevate` returns the existing
   * flight in every state but `idle`, and starts one only from `idle`. A screen
   * that fires several protected requests at once gets several challenges, and
   * every one of them must land on ONE prompt — otherwise the user sees a stack
   * of modals and every extra elevation burns a challenge for nothing.
   */
  private inFlight: Promise<void> | null = null;

  /** The merged requirement. Written at registration and at every join. */
  private requirement: UpgradeChallenge | null = null;

  /** Non-null from the moment the prompt reports a selection, and from nowhere else. */
  private selected: UpgradeFactorType | null = null;

  /** The requirement in force when the factor was selected — what the ceremony was ranked for. */
  private rankedRequirement: UpgradeChallenge | null = null;

  private registrations: Registration[] = [];

  private proof: UpgradeProof | null = null;

  /** Factors the SERVER refused for this user, dropped for the duration of this flight only. */
  private pruned = new Set<UpgradeFactorType>();

  /** The request handed to the open prompt. Its `onRequirementRaised` slot is branch 2's channel. */
  private openPrompt: UpgradePromptRequest | null = null;

  /** Set while `awaitReports` is waiting; called by the reporting path. See H7. */
  private reportsSettled?: () => void;

  constructor(options: UpgradeControllerOptions) {
    this.transport = options.transport;
    this.prompt = options.prompt;
    this.platform = options.platform;
    this.available = options.factors ?? DEFAULT_UPGRADE_FACTORS;
    this.registry = factorRegistry(this.available);
    this.maxAttempts = options.maxAttempts ?? DEFAULT_MAX_ATTEMPTS;
    this.readObtainedBar = options.readObtainedBar;
    this.onFlightSettled = options.onFlightSettled;
    this.settleTimeoutMs = options.replaySettleTimeoutMs ?? DEFAULT_SETTLE_TIMEOUT_MS;
  }

  /** The current lifecycle state. Read-only. */
  get currentState(): UpgradeFlightState {
    return this.state;
  }

  /** True while a flight is open — from the first challenge until the last waiter settled. */
  get active(): boolean {
    return this.inFlight !== null;
  }

  /**
   * Elevates the session so the challenged request can be retried.
   *
   * Every call registers a waiter, including the imperative one. Concurrent
   * callers share one elevation and one prompt; the returned promise settles for
   * THIS caller when the proof settles, and carries that caller's own waiter
   * entry so it can report its replay's outcome back.
   *
   * It resolves when the server accepted a factor and recorded the elevation. It
   * rejects for cancelled, exhausted, unsatisfiable, unavailable, session-changed
   * and non-retryable transport failure — and, for a waiter whose own demanded
   * bar the proof did not reach, with `UpgradeInsufficientError`.
   */
  elevate(challenge: UpgradeChallenge, waiter: Waiter = { kind: 'imperative' }): Promise<UpgradeElevation> {
    const registration = this.register(challenge, waiter);

    if (this.state === 'idle') {
      // T1 — `inFlight` is created BEFORE the prompt opens, so there is no
      // instant in which a modal is on screen and a second challenge finds the
      // controller idle.
      this.state = 'collecting';
      this.requirement = challenge;
      this.inFlight = this.runFlight();
    } else {
      this.join(challenge);
      // T8 and later: the proof has already settled, so this waiter cannot be
      // released by the flight's own loop — it is settled against the existing
      // proof right here. If the proof meets its bar it replays with the others;
      // if not, it is `insufficient` and its caller's retry drives a fresh,
      // SEQUENTIAL elevation. Either way no second prompt opens and no second
      // server challenge is created.
      const settled = this.proof;
      if (settled?.status === 'proven') {
        this.release(registration, settled.obtained);
      } else if (settled?.status === 'failed') {
        this.receiveReport(registration, { outcome: 'failed' });
        registration.settlement.reject(settled.reason);
      }
    }

    return registration.settlement.promise;
  }

  /** Registers a waiter and the bar it arrived demanding. */
  private register(challenge: UpgradeChallenge, waiter: Waiter): Registration {
    const statedBar = waiter.kind === 'imperative' && waiter.requested !== undefined;
    const demanded = waiter.kind === 'imperative' && waiter.requested ? waiter.requested : barOf(challenge);
    const registration: Registration = {
      demanded,
      statedBar,
      settlement: deferred<UpgradeElevation>(),
      reported: false,
      entry: {
        ...waiter,
        outcome: 'pending',
        report: (result: WaiterReport) => this.receiveReport(registration, result),
      },
    };
    this.registrations.push(registration);
    return registration;
  }

  /**
   * Folds a joining challenge into the running flight.
   *
   * The boundary is factor SELECTION. Before it, nothing is on the wire and
   * there is no race, so a strictly stronger challenge folds in place: the
   * requirement rises, the list is re-ranked for the higher bar, and the open
   * prompt is told. After it, a ceremony is running — a `prepare` round trip, a
   * TOTP commit, a WebAuthn ceremony holding the platform authenticator — and
   * neither interrupting it nor starting a second concurrent flight is
   * acceptable, so it completes at the bar it was ranked for and each waiter's
   * own replay decides its own fate.
   */
  private join(incoming: UpgradeChallenge): void {
    const current = this.requirement;
    if (!current) {
      this.requirement = incoming;
      return;
    }

    const stronger = isStrictlyStronger(current, incoming);
    this.requirement = mergeChallenges(current, incoming);

    if (!stronger) {
      // Branch 1 — the common case: two guards on one screen demanding the same
      // bar. Nothing observable changes.
      return;
    }

    if (this.state === 'collecting' && this.selected === null) {
      // Branch 2 — fold in place. One prompt, one ceremony, one challenge.
      this.openPrompt?.onRequirementRaised?.({ challenge: this.requirement, factors: this.offeredFactors() });
    }
    // Branch 3 (`proving`, `replaying`, `settling`, `done`) — the merged
    // requirement is recorded for diagnostics and for the NEXT elevation, but it
    // does not reshape the ceremony in progress. A TOTP commit cannot become an
    // AAL3 proof by rewriting a requirement, so the honest options were
    // "interrupt the ceremony" or "let it finish and tell the late joiner the
    // truth", and the second is chosen.
  }

  /** The factors to offer right now: ranked for the merged bar, minus what the server refused. */
  private offeredFactors(): readonly UpgradeFactor[] {
    const usable = this.available.filter((factor) => !this.pruned.has(factor.type));
    const challenge = this.requirement;
    return challenge ? selectFactors(usable, challenge) : usable;
  }

  /** The waiter's inbound edge. Idempotent — a second call is ignored. */
  private receiveReport(registration: Registration, result: WaiterReport): void {
    if (registration.reported) {
      return;
    }
    registration.reported = true;
    registration.entry.outcome = result.outcome;
    if (result.obtained) {
      registration.entry.obtained = result.obtained;
    }
    if (result.required) {
      registration.entry.required = result.required;
    }
    // The reporting path RESOLVES the wait, rather than a timer discovering it.
    // This is the only edge on which a waiter becomes non-pending, so it is the
    // only place the check belongs.
    this.notifyReportsSettled();
  }

  /** Resolves `awaitReports`' promise when the last outstanding report lands. */
  private notifyReportsSettled(): void {
    if (!this.reportsSettled || this.registrations.some((registration) => !registration.reported)) {
      return;
    }
    const settle = this.reportsSettled;
    this.reportsSettled = undefined;
    settle();
  }

  /**
   * The flight, start to finish.
   *
   * Nothing here clears state: clearing is one synchronous step at the very end,
   * after the prompt has settled, so nothing can observe a half-cleared
   * controller and no waiter can report into a flight the controller has
   * forgotten.
   */
  private async runFlight(): Promise<void> {
    // `prove()` is written not to throw, and this catch is the backstop that
    // makes "every path settles" structural rather than a property of one
    // function. An escaping throw would leave `inFlight` a rejected promise
    // with the state stuck mid-flight: every waiter already registered would
    // hang forever, and every later challenge would join a flight that can
    // never settle. H5's prompt-that-throws was one way in; this closes the
    // class, not the instance.
    let proof: UpgradeProof;
    try {
      proof = await this.prove();
    } catch (e) {
      proof = { status: 'failed', reason: e instanceof Error ? e : new Error(String(e)) };
    }
    this.proof = proof;

    if (proof.status === 'failed') {
      // T7 — no replay is EVER performed without a completed proof. A cancelled
      // elevation produced nothing to replay with, and re-issuing the user's
      // mutation after they declined would be the worst possible reading of
      // "retry".
      for (const registration of this.registrations) {
        this.receiveReport(registration, { outcome: 'failed' });
        registration.settlement.reject(proof.reason);
      }
    } else {
      // T6 → `replaying`. Each waiter is released to replay its OWN bound
      // request, and whether the proof satisfied that waiter's demand is the
      // SERVER's answer to that replay, never a client-side comparison made
      // here (§13.4). Only an imperative waiter, which has no request to
      // replay, is classified in `release()`.
      this.state = 'replaying';
      for (const registration of this.registrations) {
        this.release(registration, proof.obtained);
      }
      await this.awaitReports();
    }

    // T9 → T10 — the summary is complete, the prompt is settled exactly once.
    this.state = 'settling';
    const summary = this.summarise(proof);
    try {
      this.onFlightSettled?.(summary);
    } catch {
      // A consumer's settlement handler must not be able to wedge the flight
      // open: the clearing below is what makes the next call start from `idle`.
    }

    // T11 — one synchronous step, no `await` inside it.
    this.state = 'done';
    this.inFlight = null;
    this.requirement = null;
    this.selected = null;
    this.rankedRequirement = null;
    this.registrations = [];
    this.proof = null;
    this.pruned = new Set();
    this.openPrompt = null;
    this.reportsSettled = undefined;
    this.state = 'idle';
  }

  /**
   * Settles one waiter against the proof.
   *
   * An imperative waiter has no operation to replay, so it is classified here
   * and nowhere else: with no stated bar it simply succeeded, and with a stated
   * bar the proof is checked against it — which is what stops an AAL3 imperative
   * call that joined an AAL2 flight from resolving as though it had been
   * elevated to AAL3.
   *
   * A REQUEST waiter is never pre-judged here, and §13 is explicit about it
   * twice: "a demand above 3 is never refused client-side — the SDK does not
   * pre-judge satisfiability (§13.4) — it ranks factors for the highest bar it
   * knows and lets the server's replay re-challenge decide, surfacing as
   * §13.3's `insufficient`", and "never refuse outright on the default path".
   * The reason is not conformance alone: the client-side comparison is the
   * fragile half — ACR ordinals, the minimum-of-list rule — so refusing here
   * can skip a replay the server would have accepted, and it loses the
   * `elevated-insufficient` diagnostic the replay path raises. So the waiter is
   * released whatever the bar comparison says; `handleChallenge` replays, reads
   * the server's answer, and reports `insufficient` if that is what it is.
   */
  private release(registration: Registration, obtained: AssuranceBar): void {
    if (registration.entry.kind === 'imperative') {
      // Only a STATED bar is checked. An options-less imperative call resolves
      // `{status:'elevated'}` and never `insufficient` — §13.3's `n/a` cell.
      if (registration.statedBar && !barMeets(obtained, registration.demanded)) {
        this.receiveReport(registration, { outcome: 'insufficient', obtained, required: registration.demanded });
        registration.settlement.reject(new UpgradeInsufficientError(obtained, registration.demanded));
        return;
      }
      this.receiveReport(registration, { outcome: 'replayed', obtained });
      registration.settlement.resolve({ waiter: registration.entry, obtained });
      return;
    }

    registration.settlement.resolve({ waiter: registration.entry, obtained });
  }

  /**
   * Waits for every released waiter to report, under the liveness bound.
   *
   * Report-driven, not polled. The previous implementation re-armed a
   * `setTimeout(…, 0)` until the last waiter reported, which burned a timer per
   * event-loop turn for the whole replay window and made the state machine
   * untestable under fake timers — `runAllTimers()` never terminates against a
   * self-re-arming zero-delay timer. `receiveReport` is the one edge on which a
   * waiter stops being pending, so it resolves this promise directly.
   *
   * The deadline stays: a waiter that never reports is an adapter bug, and
   * settling it as `failed` is better than holding `inFlight` open forever,
   * which would make every later elevation join a dead flight.
   */
  private awaitReports(): Promise<void> {
    if (!this.registrations.some((registration) => !registration.reported)) {
      return Promise.resolve();
    }

    return new Promise<void>((resolve) => {
      const deadline = setTimeout(() => {
        this.reportsSettled = undefined;
        for (const registration of this.registrations) {
          if (!registration.reported) {
            registration.reported = true;
            registration.entry.outcome = 'failed';
          }
        }
        resolve();
      }, this.settleTimeoutMs);

      this.reportsSettled = () => {
        clearTimeout(deadline);
        resolve();
      };
    });
  }

  /** The summary: a pure function of the waiters and the proof. */
  private summarise(proof: UpgradeProof): UpgradeFlightSummary {
    const waiters: UpgradeWaiterSummary[] = this.registrations.map((registration) => ({
      ...(registration.entry.kind === 'request' ? { url: registration.entry.url, method: registration.entry.method } : {}),
      outcome: registration.entry.outcome,
      ...(registration.entry.obtained ? { obtained: registration.entry.obtained } : {}),
      ...(registration.entry.required ? { required: registration.entry.required } : {}),
    }));

    if (proof.status === 'failed') {
      return { proof, waiters, terminal: 'failed', error: proof.reason };
    }

    // The strongest unmet waiter supplies the message, so it reads "elevated to
    // AAL2; this action requires AAL3" rather than an arbitrary one of several.
    let strongest: UpgradeWaiterSummary | undefined;
    for (const waiter of waiters) {
      if (waiter.outcome !== 'insufficient') {
        continue;
      }
      const level = waiter.required?.level ?? 0;
      if (!strongest || level > (strongest.required?.level ?? 0)) {
        strongest = waiter;
      }
    }

    if (strongest) {
      return {
        proof,
        waiters,
        terminal: 'insufficient',
        insufficient: {
          obtained: strongest.obtained ?? proof.obtained,
          required: strongest.required ?? {},
        },
      };
    }

    // A waiter that failed, or that never reported at all, is not a success.
    //
    // `success` is a claim about the OPERATIONS, not about the proof: the proof
    // succeeding is already `proof.status === 'proven'` above. Falling through
    // to `success` here let a proven proof plus a `failed` waiter tell the modal
    // "Verification complete" for a request that never completed — and a
    // `pending` waiter means the liveness bound expired with an adapter still
    // owing a report, which is even less of a success.
    if (waiters.some((waiter) => waiter.outcome === 'failed' || waiter.outcome === 'pending')) {
      return { proof, waiters, terminal: 'failed' };
    }

    // Every waiter replayed successfully and none stated an unmet bar. A waiter
    // that stated a bar IS a waiter, so "no waiters → success" can no longer
    // launder an unmet requested bar into a success message.
    return { proof, waiters, terminal: 'success' };
  }

  /**
   * Collects an answer and proves it, re-prompting on every recoverable failure.
   *
   * The prepare round is re-run on every attempt rather than cached: a challenge
   * is single-use and the server consumes it atomically, so a failed attempt has
   * already spent it. Reusing the id would fail with
   * `ErrorUpgradeChallengeInvalid` and look like a bad code to the user.
   */
  private async prove(): Promise<UpgradeProof> {
    let previousError: Error | undefined;

    for (let attempt = 0; attempt < this.maxAttempts; attempt++) {
      const factors = this.offeredFactors();
      if (factors.length === 0) {
        // Reachable without any enrolment knowledge: a caller-supplied `factors`
        // option whose intersection with what the SDK can complete is empty, or
        // flight-local pruning that removed the last factor.
        return { status: 'failed', reason: new UpgradeUnsatisfiableError() };
      }

      const challenge = this.requirement as UpgradeChallenge;

      // A prompt that throws synchronously, or rejects, is a FAILED COLLECTION.
      //
      // There is no answer, so there is nothing to prove and no proof to
      // replay — exactly the shape of a cancellation, which is why it settles
      // on the per-surface cancellation contract (fetch resolves the untouched
      // 401/403, axios and the imperative surface reject
      // `UpgradeCancelledError`, the hook may resolve `null`). Re-prompting
      // would call the same broken implementation again; letting the throw
      // escape left the controller in `collecting` forever, so every later
      // challenge joined a flight that could never settle. The thrown error
      // travels on `cause` so an integration bug is still visible.
      let answer: UpgradePromptResult;
      try {
        answer = await this.collect(challenge, factors, previousError);
      } catch (e) {
        return { status: 'failed', reason: new UpgradeCancelledError(e) };
      }

      if (answer.type === 'cancel') {
        return { status: 'failed', reason: new UpgradeCancelledError() };
      }

      const factor = this.registry.get(answer.factor);
      if (!factor) {
        previousError = new UpgradeUnsatisfiableError(`Unknown authentication factor: ${answer.factor}`);
        this.state = 'collecting';
        this.selected = null;
        continue;
      }

      try {
        await this.proveAndCommit(factor, answer.code);
        const obtained = this.readObtainedBar?.() ?? barOf(this.rankedRequirement ?? challenge);
        return { status: 'proven', obtained };
      } catch (e) {
        // A cancelled ceremony ends the elevation — the user made a choice, and
        // re-prompting them would be nagging, not recovery.
        if (e instanceof UpgradeFactorError && e.cancelled) {
          return { status: 'failed', reason: new UpgradeCancelledError() };
        }

        const terminal = this.classifyProofFailure(e);
        if (terminal) {
          return { status: 'failed', reason: terminal };
        }

        if (e instanceof UpgradeTransportError && e.kind === 'not_registered') {
          // The server stating a fact about this user, not the SDK guessing one:
          // drop that factor for THIS flight only and re-prompt with the rest.
          // Never persisted, and it does not affect a later flight.
          this.pruned.add(factor.type);
        }

        previousError = e as Error;
        // T5 — a recoverable failure returns to `collecting` with the prompt
        // re-shown; `requirement` and the waiters are untouched.
        this.state = 'collecting';
        this.selected = null;
      }
    }

    // The local attempt budget is spent, and that fact is TERMINAL.
    //
    // Returning `previousError` returned the last answer's own error, which is
    // usually a `wrong_code` with `retryable === true` — so every surface above
    // read "ask them again" for a flight that will never ask again, and the UI
    // re-prompted forever against a budget the server had already closed. The
    // budget being spent is what must travel; the last failure travels on
    // `cause`.
    return {
      status: 'failed',
      reason: new UpgradeTransportError({
        kind: 'attempts_exhausted',
        ...(previousError ? { cause: previousError } : {}),
      }),
    };
  }

  /** Opens (or re-opens) the prompt and wires the two prompt → controller edges. */
  private collect(
    challenge: UpgradeChallenge,
    factors: readonly UpgradeFactor[],
    previousError: Error | undefined,
  ): Promise<UpgradePromptResult> {
    const request: UpgradePromptRequest = {
      challenge,
      factors,
      ...(previousError ? { previousError } : {}),
      onFactorSelected: (factor: UpgradeFactorType) => {
        // T3 — the ONLY place `selected` becomes non-null.
        if (this.state === 'collecting') {
          this.state = 'proving';
        }
        this.selected = factor;
        this.rankedRequirement = this.requirement;
      },
    };

    // The prompt subscribes by assigning `request.onRequirementRaised`
    // synchronously, so the object is kept rather than the function: branch 2
    // reads the slot at the moment it needs it.
    this.openPrompt = request;
    return this.prompt(request);
  }

  /** Maps a proof failure to a terminal reason, or `undefined` when the user may retry. */
  private classifyProofFailure(e: unknown): Error | undefined {
    if (e instanceof UpgradeInsufficientError || e instanceof UpgradeUnavailableError) {
      return e;
    }
    if (e instanceof UpgradeSessionChangedError) {
      return e;
    }
    if (e instanceof UpgradeTransportError) {
      switch (e.kind) {
        case 'unavailable':
          // Wrapped, like `session_changed` below, because §13.3's table names
          // `UpgradeUnavailableError` as the rejection on the two throwing
          // surfaces. The fetch and axios adapters re-mapped this kind in
          // `coreOutcomeToError`, so only the imperative surface — which goes
          // straight to the controller — saw the unwrapped
          // `UpgradeTransportError`, and the two surfaces disagreed.
          return new UpgradeUnavailableError(e.message);
        case 'exhausted':
        case 'attempts_exhausted':
        case 'fatal':
        case 'protocol':
        case 'network':
          return e;
        case 'session_changed':
          return new UpgradeSessionChangedError(e.message);
        default:
          // `wrong_code`, `challenge_spent`, `not_registered`,
          // `prepare_not_required` — the user answers again.
          return undefined;
      }
    }
    return undefined;
  }

  /** Runs one full proof for a single factor. */
  private async proveAndCommit(factor: UpgradeFactor, code: string | undefined): Promise<void> {
    const prepared = factor.requiresPrepare ? await this.transport.prepare(factor.type) : undefined;
    const assertion = await factor.assert({ code, prepared, platform: this.platform });
    await this.transport.commit(factor.type, assertion);
  }
}
