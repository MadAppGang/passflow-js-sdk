/**
 * The upgrade core: ONE implementation, transport-agnostic by construction.
 *
 * Every behaviour lives here — recognise a challenge on both channels, decide
 * whether the URL is in scope, run or join the elevation, replay once behind the
 * re-entry guard, and decide the outcome. The four surfaces the SDK offers
 * (`withAuth`, `attachAuth`, `createClient` and the internal axios seam) are
 * ADAPTERS over this function, and the prohibition on them is absolute:
 *
 *   **NO LOGIC IN AN ADAPTER.**
 *
 * An adapter translates transport shapes in and out and does nothing else. It
 * may not parse a challenge, compare a bar, decide scope, count a retry, choose
 * an error class or read a body. If an adapter would need a decision, the
 * decision belongs here instead. The reason is not elegance: an axios response
 * interceptor receives an `AxiosError`, not a callable `next`, and re-issues
 * through `instance.request(config)` — so four independent wirings with two
 * outcome vocabularies is what happens by default, and it is the largest
 * quantity of parallel behaviour in this feature. A row that passes on one
 * adapter and fails on another is a leak of logic out of this file, and the fix
 * is to move it back in, never to fork the expectation per surface.
 *
 * `CoreOutcome` is the settlement table as a discriminated union, which is what
 * makes that table the adapters' specification rather than a prose parallel.
 */

import {
  type AssuranceBar,
  type ChallengeChannel,
  type UpgradeChallenge,
  type UpgradeDiagnostic,
  type UpgradeDiagnosticReason,
  type UpgradeDiagnosticSink,
  readUpgradeChallenge,
} from './challenge';
import { UpgradeCancelledError, type UpgradeElevation, UpgradeUnsatisfiableError, type Waiter, barOf } from './controller';
import { UpgradeInsufficientError, UpgradeSessionChangedError, UpgradeTransportError, UpgradeUnavailableError } from './errors';
import type { ReplayHints, ReplayPolicy } from './replay';
import type { RequestSnapshot } from './snapshot';

/**
 * Where the SDK is allowed to act on a challenge.
 *
 * Two domains, each with its own rule, and NO derived default. Deriving the set
 * was the category error the previous model made: same-origin by default, the
 * document origin, "the origin the first 401 came from" — every one of those is
 * the SDK inferring a trust boundary it has no information about, and a
 * fabricated 403 body from an observed endpoint can provoke a genuine elevation
 * whose replay then carries the freshly elevated credential to that endpoint.
 *
 * The resolved scope is passed IN. No adapter and no wrapper derives it.
 */
export type InterceptionScope = {
  /**
   * Domain 1 — Passflow's own API, derived from `PassflowConfig.url`. Always in
   * scope on any surface the SDK is attached to, which is what makes the
   * zero-config half of the design work. `null` when no `url` is configured:
   * domain 1 is then EMPTY and nothing throws, but the first parseable challenge
   * raises a diagnostic naming `url`, because an app with no `url` would
   * otherwise silently drop `/auth/session/exchange`'s own 403.
   */
  passflow: { origin: string; pathPrefix?: string } | null;
  /**
   * Domain 2 — the customer's own backend, exactly as declared. An absolute
   * origin (optionally with a path prefix) or a same-origin path prefix
   * (`'/api'`). `[]` means nothing beyond domain 1 is in scope — and the
   * predicate must NOT early-return on it.
   */
  backend: string[];
};

export type UpgradeInterceptorOptions = {
  /**
   * Starts or joins the single flight, registering this waiter.
   *
   * Typed to accept a `void`-returning host as well, so a caller that does not
   * use the controller's waiter bookkeeping still works — it just forfeits the
   * per-waiter outcome summary, and the core then trusts the server's verdict on
   * the replay for the `insufficient` decision, which it does anyway.
   */
  elevate: (challenge: UpgradeChallenge, waiter: Waiter) => Promise<UpgradeElevation | void>;
  /** REQUIRED. Resolved once, where the client is built. */
  scope: InterceptionScope;
  /** `'header'` requires the standards channel and never reads the body. */
  requireChallengeChannel?: 'header';
  /**
   * NARROWING ONLY. Returning `false` excludes a URL the two domains admitted;
   * returning `true` can never widen, so an always-true predicate cannot
   * restore the allow-all default this design abolished.
   *
   * It is given the snapshot's **normalised absolute `href`**, never the raw
   * string the caller passed: a narrowing decision is an authorization decision,
   * and those are made on the URL the platform will actually send to (§13.4
   * revision 6). A predicate written against relative paths must therefore
   * match on the path of an absolute URL — `new URL(url).pathname` — rather than
   * on `startsWith('/…')`.
   */
  shouldIntercept?: (url: string) => boolean;
  replay?: ReplayPolicy;
  /** Default `'resolve-original'`. The fetch adapter's only option. */
  onCancel?: 'resolve-original' | 'reject';
  /** §5.5. Snapshotted before the elevation and read again after it. */
  authorizationSwap?: () => { from: string; to: string } | undefined;
  /** Default sink is `console.warn`; pass a function to route elsewhere. */
  onUpgradeDiagnostic?: UpgradeDiagnosticSink;
  /** The bar the elevation reached, when the host can read it from the new token. */
  readObtainedBar?: () => AssuranceBar | undefined;
};

/**
 * How an adapter is given its options: a value, or a getter read per challenge.
 *
 * The getter form is the one the facade uses, and the reason is a defect this
 * seam actually had. `enable()` resolves the interception policy — the scope in
 * particular — and an adapter handed the RESULT of that resolution freezes it at
 * attach time: a client built at module scope, or in a child's `useMemo`, is
 * attached before the provider's enable effect runs, so it would hold
 * `backend: []` forever and never intercept the customer's own backend. A
 * getter also makes re-enabling with a NARROWER `backend` take effect on
 * clients that were already attached, instead of leaving them on the wider
 * scope.
 *
 * A plain value is still accepted: a caller wiring the adapters directly, with
 * a scope it resolved itself, has nothing to re-read.
 */
export type UpgradeInterceptorOptionsSource = UpgradeInterceptorOptions | (() => UpgradeInterceptorOptions);

/** Resolves an options source. Call it ONCE per challenge, never per module. */
export const resolveInterceptorOptions = (source: UpgradeInterceptorOptionsSource): UpgradeInterceptorOptions =>
  typeof source === 'function' ? source() : source;

/**
 * What the core is given about one challenged request, and what it can do with
 * it. The adapter builds this and nothing more.
 */
/**
 * A live view of one caller's abort state, with optional subscription.
 *
 * `AbortSignal` satisfies this structurally, and so does the minimal
 * `{ get aborted() }` getter object the adapters build. The listener pair is
 * what makes the abort an EVENT rather than a flag polled after the fact.
 */
export type AbortView = {
  aborted: boolean;
  reason?: unknown;
  addEventListener?(type: 'abort', listener: () => void): void;
  removeEventListener?(type: 'abort', listener: () => void): void;
};

export type ChallengeContext = {
  status: number;
  /** The shipped callback shape, which is why one parser serves both surfaces. */
  getHeader(name: string): string | null | undefined;
  /**
   * Reads the body. MUST be safe to call only in scope, and MUST NOT disturb the
   * original payload — on the fetch surface that means `res.clone().json()`, so
   * the response the caller receives still has `bodyUsed === false`. The core
   * calls it only when the scope and the channel policy both permit.
   */
  readBody(): Promise<unknown>;
  /**
   * The normalised, immutable snapshot of the request that was challenged —
   * §13.4 revision 6's invariant, and the ONLY description of the request this
   * function will look at.
   *
   * The adapter takes it once, before dispatch, and hands the same object to
   * the scope check, this context, the diagnostics and `planReplay`. Nothing
   * here re-reads the caller's `Request`, `RequestInit` or axios config, so a
   * mutation while the prompt is open cannot change what was authorized, what
   * was reported or what is replayed.
   */
  request: RequestSnapshot;
  /**
   * Replays the ORIGINAL request, once, with the elevated credential. The
   * adapter supplies it; the core decides whether and when it is called, and
   * marks it replayed.
   */
  replay(hints?: ReplayHints): Promise<ChallengeContext>;
  /** Where the adapter stores the core's per-request markers. */
  markers: { upgradeTransaction?: true; replayed?: true };
  /**
   * The adapter's native payload — a `Response`, an `AxiosResponse`, an
   * `AxiosError`. The core never inspects it; it only hands it back so the
   * adapter can return the real thing.
   */
  raw?: unknown;
  /** `false` when `planReplay` refused. The prompt is then never opened. */
  replayable?: boolean;
  /** Why the replay is unsupported, for the diagnostic. */
  replayUnsupportedReason?: string;
  /**
   * The caller's abort state. The SDK never aborts it.
   *
   * Read as a LIVE view, never a snapshot, because the core reads it after
   * awaiting the elevation. The two listener methods are optional and carry
   * REQ-C12: with them the core races the abort against the pending proof, so
   * the caller's own promise settles at abort time instead of waiting for a
   * prompt it has walked away from; without them (a bare `{ aborted }` view)
   * the core falls back to reading the flag once the elevation settles. The
   * elevation itself is never cancelled either way — it is shared.
   */
  signal?: AbortView;
  /** `'cors'` distinguishes the one actionable `'no-channel'` variant. */
  responseType?: string;
  /**
   * `true` when the adapter received this exchange as a REJECTION rather than
   * as a response — axios' `validateStatus` contract, where every non-2xx
   * rejects. `fetch` resolves a 401, so its adapter never sets it.
   *
   * The core classifies the exchange identically either way: this flag decides
   * only how a `replayed` outcome is handed back, so a replay that failed on
   * its own terms keeps failing on the surface's own convention instead of
   * being resolved as a value.
   */
  rejected?: boolean;
};

/**
 * Every terminal outcome, as the settlement table defines them.
 *
 * The invariant: **every path settles.** There is no input that produces a
 * pending promise.
 */
export type CoreOutcome =
  /** Not a challenge. Pass the response through untouched. */
  | { kind: 'not-a-challenge' }
  /** A challenge the SDK is not allowed to act on. Diagnostic only; no body was read. */
  | { kind: 'out-of-scope' }
  | { kind: 'replayed'; response: ChallengeContext }
  /**
   * The proof completed and the operation's replay was challenged again.
   *
   * `response` is the SECOND challenge response, which the fetch surface
   * resolves and tags (§13.3) — so the decision "which response does the caller
   * receive" stays here rather than becoming a per-adapter `??` chain. It is
   * absent only on the re-entry path, where the adapter already holds the object
   * it was handed.
   */
  | { kind: 'insufficient'; obtained: AssuranceBar; required: AssuranceBar; response?: ChallengeContext }
  | { kind: 'cancelled' }
  | { kind: 'exhausted'; error: Error }
  | { kind: 'unsatisfiable' }
  | { kind: 'unavailable' }
  | { kind: 'session-changed' }
  | { kind: 'transport-failure'; status?: number; retryable: boolean; error: Error }
  | { kind: 'replay-unsupported' }
  | { kind: 'aborted'; reason: unknown };

/* ────────────────────────────────────────────────────────────────────────────
 * Scope
 * ──────────────────────────────────────────────────────────────────────────── */

/**
 * Parses a PATTERN — never a request URL.
 *
 * Request URLs are normalised once, before dispatch, by
 * `createRequestSnapshot`; by the time they reach this file they are already a
 * resolved `origin` plus a resolved `pathname`. The only strings left to parse
 * here are the `backend` patterns the developer wrote, which are configuration
 * and carry no attacker-controlled bytes.
 */
const parsePattern = (pattern: string): URL | undefined => {
  try {
    return new URL(pattern);
  } catch {
    return undefined;
  }
};

const pathMatches = (path: string, prefix: string | undefined): boolean => {
  if (!prefix || prefix === '/') {
    return true;
  }
  const normalised = prefix.replace(/\/+$/, '');
  return path === normalised || path.startsWith(`${normalised}/`);
};

/** Is this request inside domain 1? Origin-compare on the RESOLVED url. */
const inPassflowDomain = (request: RequestSnapshot, domain: InterceptionScope['passflow']): boolean => {
  if (!domain || request.origin === undefined) {
    return false;
  }
  return request.origin === domain.origin && pathMatches(request.pathname, domain.pathPrefix);
};

/**
 * Is this request inside a declared backend?
 *
 * A pattern starting with `/` is a **same-origin path prefix**, which is how a
 * SPA declares `backend: '/api'`. "Same-origin" is load-bearing, and it is now
 * decided the only way it can be decided correctly: the snapshot resolved the
 * caller's URL with the platform's own parser, against the document base, and
 * `relativeToBase` says whether the result landed on the base's own origin.
 *
 * That single bit is what separates `/api/x` (in scope) from `/\evil.example/x`,
 * `/<TAB>/evil.example/x` and `//evil.example/x` (all out of scope, because the
 * parser resolves all three to `https://evil.example`) — while leaving
 * `/%5Cevil.example/x` and `/%2F%2Fevil.example/x` IN scope, because an encoded
 * byte is a path character and the parser never decodes it into an authority.
 * Revision 2's `//`-prefix special case is REMOVED rather than stacked on top:
 * two mechanisms for one decision is how the next vector gets in.
 *
 * An absolute pattern matches by origin, plus its own path prefix when it
 * carries one. Same-origin is never implicitly included: that was the derived
 * default this design removed; it is in scope only because `'/…'` says so.
 */
const inDeclaredBackend = (request: RequestSnapshot, patterns: string[]): boolean => {
  for (const pattern of patterns) {
    if (pattern === '') {
      continue;
    }

    if (pattern.startsWith('/')) {
      if (request.relativeToBase && pathMatches(request.pathname, pattern)) {
        return true;
      }
      continue;
    }

    const patternUrl = parsePattern(pattern) ?? parsePattern(`https://${pattern}`);
    if (!patternUrl || request.origin === undefined) {
      continue;
    }
    if (request.origin === patternUrl.origin && pathMatches(request.pathname, patternUrl.pathname)) {
      return true;
    }
  }

  return false;
};

/**
 * The scope decision, identical for every surface, and made on the SNAPSHOT.
 *
 * Precedence, in one ordered rule: domain 1, then domain 2, then
 * `shouldIntercept` as a narrowing-only hook. There is no allow-all opt-in — a
 * developer who genuinely wants every origin lists every origin, which is a
 * sentence they can read in a diff.
 *
 * It takes a `RequestSnapshot` and not a string by design (§13.4 revision 6): a
 * string parameter is an invitation to decide authorization on an un-normalised
 * value, which is exactly the defect this signature removes.
 */
export const isInterceptionScope = (
  request: RequestSnapshot,
  scope: InterceptionScope,
  shouldIntercept?: (url: string) => boolean,
): boolean => {
  const admitted = inPassflowDomain(request, scope.passflow) || inDeclaredBackend(request, scope.backend);
  if (!admitted) {
    return false;
  }
  return shouldIntercept ? shouldIntercept(request.href) !== false : true;
};

/* ────────────────────────────────────────────────────────────────────────────
 * Diagnostics
 * ──────────────────────────────────────────────────────────────────────────── */

/** The default sink: `console.warn`, because `debug` is invisible in production. */
const warn = (diagnostic: UpgradeDiagnostic): void => {
  const detail = diagnostic.detail;
  const message = detail?.message ?? `[passflow] upgrade challenge not actioned: ${diagnostic.reason}`;
  // biome-ignore lint/suspicious/noConsole: this IS the fail-open diagnostic. §13.1/§13.4 make it mandatory that a deployment where step-up silently never fires is distinguishable from one where it was never required, and the default sink must be visible in production — `debug` is not, and an exception would turn a fail-open into a fail-closed. A consumer who wants it elsewhere passes `onUpgradeDiagnostic`.
  console.warn(message, { status: diagnostic.status, url: diagnostic.url, reason: diagnostic.reason, detail });
};

type Reporter = (reason: UpgradeDiagnosticReason, detail?: UpgradeDiagnostic['detail']) => void;

/** Builds the per-request reporter, which fills in the url and method the parser lacks. */
const reporterFor = (ctx: ChallengeContext, options: UpgradeInterceptorOptions): Reporter => {
  const sink = options.onUpgradeDiagnostic ?? warn;
  return (reason, detail) => {
    sink({
      status: ctx.status,
      url: ctx.request.href,
      reason,
      detail: { method: ctx.request.method, ...(detail ?? {}) },
    });
  };
};

/** Forwards a parse's own findings, which are knowable only inside the parse. */
const forwardParseDiagnostics = (
  diagnostics: UpgradeDiagnostic[],
  ctx: ChallengeContext,
  options: UpgradeInterceptorOptions,
): void => {
  const sink = options.onUpgradeDiagnostic ?? warn;
  for (const diagnostic of diagnostics) {
    sink({ ...diagnostic, url: ctx.request.href, detail: { method: ctx.request.method, ...(diagnostic.detail ?? {}) } });
  }
};

/* ────────────────────────────────────────────────────────────────────────────
 * Reading the challenge
 * ──────────────────────────────────────────────────────────────────────────── */

const JSON_CONTENT_TYPE = /\bjson\b/i;

/**
 * Reads a challenge from an IN-SCOPE response.
 *
 * The body-handling rule is strict, and the original response always comes back
 * with `bodyUsed === false`:
 *
 * ```
 * status not in {401,403}                 → never read, never cloned
 * status in {401,403}, content-type JSON  → ALSO parse a CLONE of the body, in
 *                                           try/catch, and merge both channels
 * status in {401,403}, not JSON           → header only; body never read
 * requireChallengeChannel: 'header'       → header only; body never read
 * ```
 *
 * A header hit no longer suppresses the clone read. The short-circuit it
 * replaces ("header parse succeeds → body NEVER read") was an optimisation
 * mistaken for a safety property: reading a CLONE was always the mechanism that
 * kept the caller's body intact, and the merge rule cannot run behind a
 * first-match chain.
 */
const readChallenge = async (
  ctx: ChallengeContext,
  options: UpgradeInterceptorOptions,
): Promise<{ challenge?: UpgradeChallenge; diagnostics: UpgradeDiagnostic[] }> => {
  const headerOnly = options.requireChallengeChannel === 'header';
  const contentType = ctx.getHeader('content-type') ?? '';
  const mayReadBody = !headerOnly && JSON_CONTENT_TYPE.test(contentType);

  let body: unknown;
  if (mayReadBody) {
    try {
      body = await ctx.readBody();
    } catch {
      // A malformed or already-consumed body is not an error path: the header
      // may still carry the challenge, and the caller's response is untouched.
      body = undefined;
    }
  }

  const input = mayReadBody
    ? { status: ctx.status, getHeader: (name: string) => ctx.getHeader(name) ?? undefined, body }
    : { status: ctx.status, getHeader: (name: string) => ctx.getHeader(name) ?? undefined };

  return readUpgradeChallenge(input, { requireChallengeChannel: options.requireChallengeChannel });
};

/** Header-only inspection, for a URL outside the declared scope. */
const readOutOfScopeChallenge = (ctx: ChallengeContext): UpgradeChallenge | undefined =>
  readUpgradeChallenge(
    { status: ctx.status, getHeader: (name: string) => ctx.getHeader(name) ?? undefined },
    { requireChallengeChannel: 'header' },
  ).challenge;

/** The message that names the fix, which is the whole value of this diagnostic. */
const outOfScopeMessage = (url: string, scope: InterceptionScope): string =>
  scope.passflow === null
    ? `[passflow] a 401/403 from ${url} carried an upgrade challenge, but no Passflow endpoint is configured — set \`url\` on the Passflow config.`
    : `[passflow] a 401/403 from ${url} carried an upgrade challenge, but that URL is not covered by the provider's \`backend\` prop — add it there to enable step-up for this API.`;

/* ────────────────────────────────────────────────────────────────────────────
 * Classification
 * ──────────────────────────────────────────────────────────────────────────── */

/** Maps an elevation failure to its settlement-table row. */
const classifyFailure = (e: unknown, obtained: AssuranceBar | undefined): CoreOutcome => {
  if (e instanceof UpgradeCancelledError) {
    return { kind: 'cancelled' };
  }
  if (e instanceof UpgradeUnsatisfiableError) {
    return { kind: 'unsatisfiable' };
  }
  if (e instanceof UpgradeUnavailableError) {
    return { kind: 'unavailable' };
  }
  if (e instanceof UpgradeSessionChangedError) {
    return { kind: 'session-changed' };
  }
  if (e instanceof UpgradeInsufficientError) {
    return { kind: 'insufficient', obtained: e.obtained, required: e.required };
  }
  if (e instanceof UpgradeTransportError) {
    // Both exhaustion kinds settle on the same row of §13.3's table: the
    // server's own budget (`exhausted`) and the controller's local attempt
    // budget (`attempts_exhausted`) are the same statement to a caller — stop,
    // another answer will not help — and both are terminal.
    if (e.kind === 'exhausted' || e.kind === 'attempts_exhausted') {
      return { kind: 'exhausted', error: e };
    }
    if (e.kind === 'unavailable') {
      return { kind: 'unavailable' };
    }
    if (e.kind === 'session_changed') {
      return { kind: 'session-changed' };
    }
    // FR1's non-retryable 400 class — unsupported factor, no session — plus the
    // network and protocol classes. Surfaced, never laundered into a logout:
    // re-authentication is the application's decision, taken on a state it can
    // see.
    return { kind: 'transport-failure', status: e.status, retryable: e.retryable, error: e };
  }
  return {
    kind: 'transport-failure',
    retryable: false,
    error: e instanceof Error ? e : new Error(String(e)),
    ...(obtained ? {} : {}),
  };
};

/**
 * Classifies the replayed response: did this operation actually succeed?
 *
 * Proof completion and a protected operation's outcome are different events. The
 * user can complete TOTP, the server can accept it and record the elevation, and
 * the replay can STILL be challenged — on a higher `acr` bar or on a freshness
 * demand the new proof does not satisfy. For AAL3 endpoints with TOTP-only users
 * that is the normal path, so it gets a first-class outcome carrying both bars
 * rather than a second 401 returned verbatim with nothing to point at.
 */
const classifyReplay = async (
  replayed: ChallengeContext,
  options: UpgradeInterceptorOptions,
  obtained: AssuranceBar,
  report: Reporter,
): Promise<CoreOutcome> => {
  if (replayed.status !== 401 && replayed.status !== 403) {
    return { kind: 'replayed', response: replayed };
  }

  const { challenge, diagnostics } = await readChallenge(replayed, options);
  forwardParseDiagnostics(diagnostics, replayed, options);

  if (!challenge) {
    return { kind: 'replayed', response: replayed };
  }

  const required = barOf(challenge);
  report('elevated-insufficient', { obtained, required });
  return { kind: 'insufficient', obtained, required, response: replayed };
};

/* ────────────────────────────────────────────────────────────────────────────
 * The abort race (REQ-C12)
 * ──────────────────────────────────────────────────────────────────────────── */

/** Either the work finished, or this caller's signal fired first. */
type AbortRace<T> = { aborted: true; reason: unknown } | { aborted: false; value: T };

/**
 * Awaits `work`, but settles early if `signal` aborts first.
 *
 * REQ-C12: an abort must settle the CALLER's promise promptly, without waiting
 * for a proof it has walked away from. The asymmetry that makes this safe is
 * that the elevation is shared and is NEVER cancelled here: `work` keeps
 * running for the other waiters, and only this caller stops awaiting it. The
 * caller of this helper owns what happens to a late-resolving `work` — see the
 * aborted branch in `handleChallenge`.
 *
 * Three ordering details, each one a defect if dropped:
 *
 *   - **Already aborted** is checked before subscribing, because an
 *     `AbortSignal` fires `abort` once and a listener attached afterwards never
 *     hears it.
 *   - **Work wins** still returns `aborted: false`, so the post-settle flag
 *     check in `handleChallenge` keeps its existing meaning. A view with no
 *     listeners takes that path for every abort, which is why the legacy
 *     `{ aborted }` shape still behaves exactly as it did.
 *   - **A rejection of `work` after the abort won** is absorbed by the caller,
 *     not here: nothing is awaiting this promise any more, and an unhandled
 *     rejection in a customer's app over a step-up they cancelled is not an
 *     acceptable trade for a tidier helper.
 */
const raceAbort = async <T>(work: Promise<T>, signal: AbortView | undefined): Promise<AbortRace<T>> => {
  if (!signal) {
    return { aborted: false, value: await work };
  }
  if (signal.aborted) {
    return { aborted: true, reason: signal.reason };
  }
  if (typeof signal.addEventListener !== 'function') {
    return { aborted: false, value: await work };
  }

  let onAbort: (() => void) | undefined;
  const aborted = new Promise<AbortRace<T>>((resolve) => {
    onAbort = () => resolve({ aborted: true, reason: signal.reason });
    signal.addEventListener?.('abort', onAbort);
  });

  try {
    return await Promise.race([work.then((value): AbortRace<T> => ({ aborted: false, value })), aborted]);
  } finally {
    if (onAbort) {
      signal.removeEventListener?.('abort', onAbort);
    }
  }
};

/* ────────────────────────────────────────────────────────────────────────────
 * The core
 * ──────────────────────────────────────────────────────────────────────────── */

/**
 * Detect → scope → elevate → replay once → classify. The one implementation.
 *
 * "Retry exactly once" is structural rather than counted: there is no path from
 * the replay back to the elevation. On a surface that re-enters this function
 * with the replayed request — axios does, because the replay goes back through
 * `instance.request(config)` and hits the same response interceptor — the replay
 * marker is read first and the response is classified without elevating. That
 * guard is written here, once; the adapter only supplies the marker's storage.
 */
export const handleChallenge = async (ctx: ChallengeContext, options: UpgradeInterceptorOptions): Promise<CoreOutcome> => {
  if (ctx.status !== 401 && ctx.status !== 403) {
    return { kind: 'not-a-challenge' };
  }

  // ── the elevation's OWN two rounds are never challenges to act on ──
  //
  // `/auth/upgrade/start` and the committing `/auth/refresh` are themselves
  // access-token-gated, so a 401 on either can parse as a challenge. Acting on
  // one would open a second prompt from inside the first elevation. The marker
  // is positive evidence that we issued the request, and reading it here — not
  // in an adapter — is what keeps the rule identical on every surface.
  if (ctx.markers.upgradeTransaction) {
    return { kind: 'not-a-challenge' };
  }

  const report = reporterFor(ctx, options);

  // ── the re-entry guard: classify and settle, never elevate ──
  if (ctx.markers.replayed) {
    const inScope = isInterceptionScope(ctx.request, options.scope, options.shouldIntercept);
    if (!inScope) {
      return { kind: 'not-a-challenge' };
    }
    const { challenge, diagnostics } = await readChallenge(ctx, options);
    forwardParseDiagnostics(diagnostics, ctx, options);
    if (!challenge) {
      return { kind: 'not-a-challenge' };
    }
    const obtained = options.readObtainedBar?.() ?? {};
    const required = barOf(challenge);
    report('elevated-insufficient', { obtained, required });
    return { kind: 'insufficient', obtained, required, response: ctx };
  }

  // ── scope, before anything reads a body ──
  if (!isInterceptionScope(ctx.request, options.scope, options.shouldIntercept)) {
    // Out of scope the SDK inspects the `WWW-Authenticate` header ONLY and never
    // reads or clones the body, so declaring a scope cannot be widened by a
    // diagnostic. The cross-origin, body-only, out-of-scope case therefore stays
    // silent: a stated limitation, not an oversight. Parsing for diagnostics
    // never elevates and never replays, so the security decision is untouched.
    const challenge = readOutOfScopeChallenge(ctx);
    if (!challenge) {
      return { kind: 'not-a-challenge' };
    }
    report('challenge-out-of-scope', {
      header: ctx.getHeader('www-authenticate') ?? undefined,
      message: outOfScopeMessage(ctx.request.href, options.scope),
    });
    return { kind: 'out-of-scope' };
  }

  const { challenge, diagnostics } = await readChallenge(ctx, options);
  forwardParseDiagnostics(diagnostics, ctx, options);

  if (!challenge) {
    // Fail toward "I don't know" rather than "log them out": no prompt opens, no
    // elevation starts, no blocking state is entered, and the response goes back
    // to the caller untouched. A client-side miss costs a broken flow, never an
    // unauthorized one, because the server is the enforcement point and this is
    // not. But it is never SILENT — a deployment where step-up never fires must
    // be distinguishable from one where it was never required.
    const rawHeader = ctx.getHeader('www-authenticate');
    if (options.requireChallengeChannel !== 'header') {
      report('no-channel', {
        ...(rawHeader ? { header: rawHeader } : {}),
        message:
          ctx.responseType === 'cors' && !rawHeader
            ? `[passflow] a cross-origin ${ctx.status} from ${ctx.request.href} carried no readable challenge: \`WWW-Authenticate\` is not CORS-safelisted, so add \`Access-Control-Expose-Headers: WWW-Authenticate\` on that server, or have it emit the \`upgrade_required\` JSON body.`
            : `[passflow] a ${ctx.status} from ${ctx.request.href} carried no upgrade challenge on either channel; treated as an ordinary ${ctx.status}.`,
      });
    }
    return { kind: 'not-a-challenge' };
  }

  // ── can this request even be honoured? ──
  if (ctx.replayable === false) {
    // Prompting a user, elevating their session and only then discovering we
    // cannot honour it is the worst possible ordering: it spends a server
    // challenge and a user interaction for nothing.
    report('replay-unsupported', {
      message: `[passflow] a ${ctx.status} from ${ctx.request.href} carried an upgrade challenge, but the request cannot be replayed (${
        ctx.replayUnsupportedReason ?? 'unsupported body'
      }), so no prompt was opened.`,
    });
    return { kind: 'replay-unsupported' };
  }

  // §5.5's ordering: `from` is snapshotted BEFORE the elevation, because the
  // commit overwrites storage, and `to` is read after.
  const before = options.authorizationSwap?.();

  const waiter: Waiter = { kind: 'request', url: ctx.request.href, method: ctx.request.method };

  // Aborting the original request does NOT cancel the elevation — it is shared,
  // and one caller walking away must not cancel a prompt three other in-flight
  // requests are waiting on. What the abort DOES do (REQ-C12) is stop THIS
  // caller waiting: its promise settles with the abort its own `catch` already
  // expects from `fetch`, while the flight runs on untouched for the others.
  // `Promise.resolve` wraps the call so that an `elevate` which throws
  // SYNCHRONOUSLY still lands in `classifyFailure` below rather than escaping
  // this function — starting the elevation before the `try` is what made that
  // reachable, and a host whose `elevate` throws on, say, a missing endpoint
  // must still settle on the table and never log anyone out.
  let elevating: Promise<UpgradeElevation | void> | undefined;
  let race: AbortRace<UpgradeElevation | void>;
  try {
    elevating = Promise.resolve(options.elevate(challenge, waiter));
    race = await raceAbort(elevating, ctx.signal);
  } catch (e) {
    return classifyFailure(e, undefined);
  }

  if (race.aborted) {
    // The proof is still pending, so there is no waiter handle to report with
    // yet — the handle arrives only when the elevation resolves. Reporting is
    // therefore deferred to that moment, and NOTHING else is: no bar is read,
    // no `authorizationSwap` is applied, the replay marker is not set and the
    // request is not replayed. A proof that completes after its waiter walked
    // away must not act on that waiter's behalf.
    //
    // `failed` is this waiter's terminal either way — it is what the liveness
    // bound would have assigned — and it must still arrive, or `awaitReports`
    // holds the prompt and every other waiter to the 30s bound over an ordinary
    // input. `receiveReport` is idempotent and safe on a cleared controller, so
    // a late report can neither double-count nor wedge a later challenge.
    //
    // The rejection arm is the unhandled-rejection guard: the elevation's own
    // failure is already the controller's to classify for the waiters that are
    // still listening, and it is never laundered into a logout here.
    elevating?.then(
      (elevation) => elevation?.waiter.report({ outcome: 'failed' }),
      () => {
        // Absorbed deliberately: see above.
      },
    );
    return { kind: 'aborted', reason: race.reason };
  }

  const elevation = race.value;

  // The abort that landed while the elevation was already settling, or against
  // a signal view with no listeners to race.
  if (ctx.signal?.aborted) {
    // The waiter still has to REPORT. Released for its adapter to classify, it
    // otherwise stays `pending` and `awaitReports` polls to the 30s liveness
    // bound — holding every other waiter in the flight, and the prompt, on what
    // is an ordinary input rather than an adapter bug. `failed` is the terminal
    // that bound would have assigned anyway; this only makes it arrive now. The
    // two abort checks inside the replay `catch` below already report before
    // they read the signal, so this is the one branch that needed it.
    elevation?.waiter.report({ outcome: 'failed' });
    return { kind: 'aborted', reason: ctx.signal.reason };
  }

  const obtained = elevation?.obtained ?? options.readObtainedBar?.() ?? barOf(challenge);
  const after = options.authorizationSwap?.();
  const swap = after ? { from: before?.from ?? after.from, to: after.to } : undefined;

  // The marker is set BEFORE the replay, so a surface that re-enters this
  // function with the replayed request takes the guard above instead of
  // elevating again — the loop FR3 prohibits by name.
  ctx.markers.replayed = true;

  let replayed: ChallengeContext;
  try {
    replayed = await ctx.replay(swap ? { authorizationSwap: swap } : undefined);
  } catch (e) {
    // A re-challenged replay is a REFUSAL, not a failure.
    //
    // On the axios surfaces the replay goes back through `request(config)` and
    // re-enters this function, where the re-entry guard above classifies it and
    // `settleAxiosOutcome` REJECTS with `UpgradeInsufficientError` — so the
    // refusal arrives here as a throw. Reporting `failed` for it told the
    // controller's `summarise` nothing about the bar, and a flight whose only
    // waiter was refused was then summarised as `success`: the modal said
    // "Verification complete" for an operation the server declined. The fetch
    // surface already gets this right through `classifyReplay`; this is the
    // same decision for the other three, made here so it cannot drift again.
    if (e instanceof UpgradeInsufficientError) {
      elevation?.waiter.report({ outcome: 'insufficient', obtained: e.obtained, required: e.required });
      if (ctx.signal?.aborted) {
        return { kind: 'aborted', reason: ctx.signal.reason };
      }
      return { kind: 'insufficient', obtained: e.obtained, required: e.required };
    }

    elevation?.waiter.report({ outcome: 'failed' });
    if (ctx.signal?.aborted) {
      return { kind: 'aborted', reason: ctx.signal.reason };
    }
    // A real failure still throws: the replay's own network error is the
    // caller's error, not a step-up outcome.
    throw e;
  }

  const outcome = await classifyReplay(replayed, options, obtained, report);

  if (outcome.kind === 'insufficient') {
    elevation?.waiter.report({ outcome: 'insufficient', obtained: outcome.obtained, required: outcome.required });
  } else {
    elevation?.waiter.report({ outcome: 'replayed', obtained });
  }

  return outcome;
};

/* ────────────────────────────────────────────────────────────────────────────
 * Outcome → error, for the two throwing surfaces
 * ──────────────────────────────────────────────────────────────────────────── */

/**
 * The error class a non-fetch surface rejects with, or `undefined` when the
 * outcome is not a rejection.
 *
 * axios' own contract, expressed in `validateStatus`, is that a non-2xx response
 * REJECTS. Resolving a declined step-up there would invert the library's
 * contract: every caller's post-`await` success path would run after the user
 * clicked "Not now", and `await api.post('/transfer')` would resolve with only a
 * status check the customer was never instructed to write standing between that
 * and treating an unperformed elevated action as performed.
 *
 * Every class carries a literal `code` discriminant as well as being
 * `instanceof`-checkable, and the `code` is the testable tag: it survives
 * bundling, duplicate package copies and cross-realm boundaries.
 */
export const coreOutcomeToError = (outcome: CoreOutcome): Error | undefined => {
  switch (outcome.kind) {
    case 'cancelled':
      return new UpgradeCancelledError();
    case 'unsatisfiable':
      return new UpgradeUnsatisfiableError();
    case 'unavailable':
      return new UpgradeUnavailableError();
    case 'session-changed':
      return new UpgradeSessionChangedError();
    case 'insufficient':
      return new UpgradeInsufficientError(outcome.obtained, outcome.required);
    case 'exhausted':
      return outcome.error;
    case 'transport-failure':
      return outcome.error;
    default:
      // `not-a-challenge`, `out-of-scope`, `replayed`, `replay-unsupported` and
      // `aborted` are not rejections of ours: the first four hand the caller the
      // transport's own result, and an abort throws the signal's reason.
      return undefined;
  }
};

/* ────────────────────────────────────────────────────────────────────────────
 * Outcome → settlement, per surface. The adapters translate, they do not decide.
 * ──────────────────────────────────────────────────────────────────────────── */

/**
 * What an adapter must do with an outcome: hand back an object, or throw.
 *
 * Both surfaces settle from this, so §13.3's table has exactly one encoding in
 * the codebase. An adapter that reached its own conclusion about which response
 * a caller receives, or which error class, would be the per-surface drift the
 * single core exists to prevent.
 */
export type Settlement<T> = { settle: 'resolve'; value: T } | { settle: 'reject'; error: unknown };

/**
 * The fetch surface's settlement.
 *
 * `fetch` resolves on 401 and every caller is written as `if (!res.ok)`, so a
 * declined step-up comes back as the original response — tagged, so it is
 * discriminable — rather than as a rejection their code has never handled. The
 * two exceptions are an abort (which throws the signal's reason, as `fetch`
 * itself does) and the explicit `onCancel: 'reject'` opt-out.
 */
export const settleFetchOutcome = <T extends object>(
  outcome: CoreOutcome,
  original: T,
  options: UpgradeInterceptorOptions,
): Settlement<T> => {
  switch (outcome.kind) {
    case 'replayed':
      return { settle: 'resolve', value: outcome.response.raw as T };
    case 'not-a-challenge':
    case 'out-of-scope':
    case 'replay-unsupported':
      // Untouched and untagged: the SDK either saw nothing to act on, or never
      // opened a prompt, so there is no step-up outcome to report.
      return { settle: 'resolve', value: original };
    case 'aborted':
      return { settle: 'reject', error: outcome.reason };
    case 'cancelled':
      return options.onCancel === 'reject'
        ? { settle: 'reject', error: new UpgradeCancelledError() }
        : { settle: 'resolve', value: tagUpgradeOutcome(original, outcome) };
    case 'insufficient':
      // The SECOND challenge is what the caller receives: it is the response
      // that actually refused the operation, and the bars travel in the tag.
      return { settle: 'resolve', value: tagUpgradeOutcome((outcome.response?.raw as T) ?? original, outcome) };
    default:
      return { settle: 'resolve', value: tagUpgradeOutcome(original, outcome) };
  }
};

/**
 * The axios surface's settlement.
 *
 * axios' own contract, expressed in `validateStatus`, is that a non-2xx
 * response rejects, so every non-success outcome rejects here — with the tagged
 * error class for a step-up outcome, and with the transport's own error when
 * the SDK did not act.
 */
export const settleAxiosOutcome = <T>(outcome: CoreOutcome, originalError: unknown): Settlement<T> => {
  switch (outcome.kind) {
    case 'replayed':
      // A replay that axios itself rejected — a 500, say, carrying no
      // challenge — is still a rejection: resolving it would hand the caller an
      // `AxiosError` as a success value and invert `validateStatus` for the one
      // request step-up touched.
      return outcome.response.rejected
        ? { settle: 'reject', error: outcome.response.raw ?? originalError }
        : { settle: 'resolve', value: outcome.response.raw as T };
    case 'aborted':
      return { settle: 'reject', error: outcome.reason };
    default: {
      const error = coreOutcomeToError(outcome);
      // `not-a-challenge`, `out-of-scope` and `replay-unsupported` produce no
      // error of ours, and the caller gets the rejection axios already had.
      return { settle: 'reject', error: error ?? originalError };
    }
  }
};

/* ────────────────────────────────────────────────────────────────────────────
 * Fetch-surface discriminators
 * ──────────────────────────────────────────────────────────────────────────── */

/**
 * The fetch surface resolves the ORIGINAL 401/403 response, untouched, because
 * `fetch` does not reject on 401 — it resolves with `res.ok === false`, and
 * every caller is written as `if (!res.ok)`. Rejecting would introduce a failure
 * mode their code has never handled. The resolved value is never `null` or
 * `undefined`: that breaks `FetchLike` and throws `TypeError` in customer code
 * on the first `res.ok`.
 *
 * So every non-success outcome needs a discriminator, and they are backed by
 * `WeakSet`s keyed on the object the SDK returned. Two consequences a caller
 * must know, because both produce a confident `false` on a genuine outcome:
 *
 *   - **Check before cloning.** `isUpgradeCancelled(res.clone())` is `false`: a
 *     clone is a different object.
 *   - **One copy of the SDK.** A predicate imported from a second copy of
 *     `@passflow/core` in the same tree reads a different `WeakSet`.
 */
const cancelled = new WeakSet<object>();
const exhausted = new WeakSet<object>();
const insufficient = new WeakSet<object>();
const unsatisfiable = new WeakSet<object>();
const unavailable = new WeakSet<object>();
const sessionChanged = new WeakSet<object>();
const transportFailure = new WeakSet<object>();

/**
 * Tags the response an adapter is about to resolve with the outcome that
 * produced it. The mapping is here, not in the adapter: choosing which set a
 * `CoreOutcome` belongs to is a decision.
 */
export const tagUpgradeOutcome = <T extends object>(response: T, outcome: CoreOutcome): T => {
  switch (outcome.kind) {
    case 'cancelled':
      cancelled.add(response);
      break;
    case 'exhausted':
      exhausted.add(response);
      break;
    case 'insufficient':
      insufficient.add(response);
      break;
    case 'unsatisfiable':
      unsatisfiable.add(response);
      break;
    case 'unavailable':
      unavailable.add(response);
      break;
    case 'session-changed':
      sessionChanged.add(response);
      break;
    case 'transport-failure':
      transportFailure.add(response);
      break;
    default:
      break;
  }
  return response;
};

/** "You were challenged and you declined" — as opposed to "you were not authorised". */
export const isUpgradeCancelled = (response: object): boolean => cancelled.has(response);
export const isUpgradeExhausted = (response: object): boolean => exhausted.has(response);
export const isUpgradeInsufficient = (response: object): boolean => insufficient.has(response);
export const isUpgradeUnsatisfiable = (response: object): boolean => unsatisfiable.has(response);
export const isUpgradeUnavailable = (response: object): boolean => unavailable.has(response);
export const isUpgradeSessionChanged = (response: object): boolean => sessionChanged.has(response);
/** FR1's non-retryable 400 class. */
export const isUpgradeTransportFailure = (response: object): boolean => transportFailure.has(response);

export type { ChallengeChannel };
