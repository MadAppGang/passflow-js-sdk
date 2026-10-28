/**
 * The Facade: one object that assembles the controller, the transport and the
 * adapters, and the only construction surface a consumer touches.
 *
 * `UpgradeController`, the transport, `upgradeFetch` and the fetch registry stay
 * internal. Tests reach their types by importing this directory's modules
 * directly, not through the package entry, because a type on `lib/index.ts` is
 * a supported name whether or not anything public produces a value of it.
 * `UpgradeFacadeDeps` is declared here and exported for that in-tree use only.
 * `UpgradeSessionPin`, declared in `./session`, is the exception: it IS on the
 * entry, because `AuthService.readSessionPin()` is public and returns one.
 *
 * **Five members, and the rule is written down because `structural.md` names
 * Facade-as-God-Object as this family's characteristic failure: adding a sixth
 * requires deleting one.** `createClient` is deliberately NOT a member — it is
 * `axios.create(config)` followed by `attachAuth`, so it lives on the `Passflow`
 * instance where the constructor belongs, and it is not a fourth code path.
 *
 * ## The two gates
 *
 * Passflow's own API (domain 1) is derived from `PassflowConfig.url` and handled
 * with zero configuration. The customer's backend (domain 2) is touched only
 * when `backend` is declared AND an adapter is attached: declaring without
 * attaching observes nothing, attaching without declaring matches nothing
 * beyond domain 1. That double gate is why the elevated-credential replay
 * surface is unreachable in the default configuration — there is no default
 * interception surface at all.
 *
 * ## The session-change reset
 *
 * A challenge is server-bound to the session's `sid`, and an abandoned flight
 * must never elevate a NEW session. `UpgradeController.inFlight` is private with
 * no reset, so on `SignIn` / `SignOut` the controller is DISCARDED and a fresh
 * one constructed. A waiter whose elevation was running across that boundary is
 * settled with `UpgradeSessionChangedError` — never replayed — which §13.3's
 * table maps to the original response on fetch and a tagged rejection on axios.
 *
 * SSR-safe: no global is read at module scope, and nothing is installed until
 * `enable()` is called with `interceptFetch`.
 */

import { FETCH_PRIORITY_UPGRADE, registerFetchMiddleware } from '../interceptors/fetch-registry';
import type { PlatformAdapter } from '../platform';

import { readAcrValues } from './acr';
import { type AxiosReissue, type ResponseInterceptorHost, attachUpgradeAuth, createAxiosUpgradeHandler } from './axios-adapter';
import type { AssuranceBar, UpgradeChallenge, UpgradeDiagnosticSink } from './challenge';
import {
  UpgradeController,
  type UpgradeElevation,
  type UpgradeFlightSummary,
  type UpgradePromptHandler,
  type UpgradeTransport,
  type Waiter,
} from './controller';
import type { InterceptionScope, UpgradeInterceptorOptions } from './core';
import { UpgradeSessionChangedError, UpgradeTransportError, UpgradeUnavailableError } from './errors';
import type { UpgradeFactor } from './factors';
import { upgradeFetch } from './fetch-adapter';
import type { FetchLike, ReplayPolicy } from './replay';
import type { UpgradeSessionPin } from './session';
import { type UpgradeTransportDeps, createUpgradeTransport } from './transport';

/** Domain 1, as resolved once from `PassflowConfig.url`. `null` = unresolved. */
export type PassflowUpgradeDomain = { origin: string; pathPrefix?: string } | null;

/**
 * What the facade needs from its host, as narrow function-shaped dependencies.
 *
 * Everything HTTP arrives pre-wired, which is what keeps this module free of
 * endpoints and of any opinion about delivery mode.
 */
export type UpgradeFacadeDeps = UpgradeTransportDeps & {
  /** The platform adapter, for the WebAuthn ceremony. */
  platform: PlatformAdapter;
  /** Domain 1. Resolved by the host from `url`; the facade never derives it. */
  passflowDomain: PassflowUpgradeDomain;
  /** Construction-time factor override, from `PassflowConfig.upgrade`. */
  factors?: readonly UpgradeFactor[];
  /** The bar the elevation reached, read from the freshly stored access token. */
  readObtainedBar?: () => AssuranceBar | undefined;
  /** §5.5's credential swap. Snapshotted before the elevation, read again after. */
  authorizationSwap?: () => { from: string; to: string } | undefined;
  /**
   * Installs (or clears, on `undefined`) the handler the SDK's OWN axios clients
   * consult inside their existing error interceptor — §4.4's internal seam,
   * which an ordinary customer-registered interceptor is structurally too late
   * to be.
   *
   * It receives a FACTORY rather than a handler because each of the SDK's
   * clients must replay through its own instance: a handler built around one
   * client's `request` would re-issue another client's request on the wrong
   * instance.
   */
  attachInternalSeam?: (factory: ((reissue: AxiosReissue) => (error: unknown) => Promise<unknown>) | undefined) => void;
  /** Subscribes to session changes (`SignIn` / `SignOut`). Returns unsubscribe. */
  onSessionChange?: (listener: () => void) => () => void;
  /**
   * The session and user identity the host can currently read, or `undefined`
   * when this delivery mode exposes none.
   *
   * Read ONCE per flight, when the flight starts, and handed to `commitRefresh`
   * so the token-applying path can refuse to write user A's tokens into user
   * B's session (§13.4 revision 6 / H2).
   */
  readSessionPin?: () => UpgradeSessionPin | undefined;
};

/**
 * Everything `enable()` accepts: the prompt, the interception scope and the
 * interception policy.
 *
 * `requireChallengeChannel`, `backend` and `shouldIntercept` are interception
 * policy and deliberately NOT on `PassflowConfig` — they are per-installation,
 * not client-wide.
 */
export type UpgradeEnableOptions = {
  /** REQUIRED. The js-sdk ships no UI. */
  prompt: UpgradePromptHandler;
  /**
   * Where the customer's own API is: an origin, an origin with a path prefix, or
   * a same-origin path prefix (`'/api'`). Nothing outside this and domain 1 is
   * ever observed, and there is no allow-all opt-in — a developer who wants
   * every origin lists every origin, which is a sentence they can read in a diff.
   */
  backend?: string | string[];
  /**
   * Patches `globalThis.fetch` through the registry, at the upgrade priority.
   * **Off by default**, and a different decision from enabling the UI: one prop
   * for both would bundle "show me the 2FA prompt" with "patch the global", and
   * only the second has the blast radius. It widens which call sites are
   * observed, never the scope.
   */
  interceptFetch?: boolean;
  /** Requires the standards channel. The body is then never read. */
  requireChallengeChannel?: 'header';
  /** NARROWING ONLY: `false` excludes an admitted URL; `true` cannot widen. */
  shouldIntercept?: (url: string) => boolean;
  replay?: ReplayPolicy;
  /** The fetch surface's only option. Default `'resolve-original'`. */
  onCancel?: 'resolve-original' | 'reject';
  onUpgradeDiagnostic?: UpgradeDiagnosticSink;
  factors?: readonly UpgradeFactor[];
  maxAttempts?: number;
  /** One terminal state per flight, after every waiter has reported. */
  onFlightSettled?: (summary: UpgradeFlightSummary) => void;
  /** Forwarded verbatim to the prepare round for passkey upgrades. */
  relyingPartyId?: string;
};

/** What the imperative seam resolves with (§13.4). */
export type UpgradeResult = { status: 'elevated'; acr?: string };

/**
 * What the imperative seam accepts: a bar the CALLER states.
 *
 * Stating one is what makes `UpgradeInsufficientError` reachable on this
 * surface; an options-less call states no bar, has no protected operation to
 * replay, and resolves `{ status: 'elevated' }` (§13.3's `n/a` cell).
 */
export type UpgradeOptions = { acrValues?: string; maxAge?: number };

export type UpgradeFacade = {
  /**
   * Drives an elevation directly — §13.4's imperative seam.
   *
   * The facade is CALLABLE, which is why this signature is here rather than on
   * a method: the documented surface is `passflow.upgrade(options?)`, and the
   * same object also carries `enable`, `withAuth` and the rest. Resolves on
   * proof completion; rejects `UpgradeCancelledError`,
   * `UpgradeUnsatisfiableError`, `UpgradeUnavailableError`,
   * `UpgradeSessionChangedError`, `UpgradeTransportError` — and, when the
   * caller stated a bar the proof did not reach, `UpgradeInsufficientError`.
   */
  (options?: UpgradeOptions): Promise<UpgradeResult>;
  /**
   * Installs the prompt handler and the selected interceptors. Returns an
   * idempotent teardown. Calling `enable()` twice replaces the previous
   * installation and tears the first one down.
   */
  enable(options: UpgradeEnableOptions): () => void;
  /** True when a prompt handler is installed AND the delivery mode can commit. */
  readonly enabled: boolean;
  /**
   * Drives an elevation directly — headless clients, a "verify now" button,
   * tests. Single-flight with the interceptors: concurrent callers share one
   * prompt, because they share one controller.
   */
  elevate(challenge: UpgradeChallenge, waiter?: Waiter): Promise<UpgradeElevation>;
  /** Wraps a fetch and returns the wrapper. Touches no global. */
  withAuth(next?: FetchLike): FetchLike;
  /** Attaches to an axios instance the developer owns, MUTATING it. Returns `detach()`. */
  attachAuth(instance: ResponseInterceptorHost): () => void;
};

/** `backend` as declared → the list the scope predicate reads. */
const declaredBackends = (backend: string | string[] | undefined): string[] => {
  if (backend === undefined) {
    return [];
  }
  return (Array.isArray(backend) ? backend : [backend]).filter((pattern) => pattern !== '');
};

type Installation = {
  controller: UpgradeController;
  options: UpgradeEnableOptions;
  scope: InterceptionScope;
  /** Bumped on every session change; a waiter from an older generation is stale. */
  generation: number;
  /**
   * The identity the CURRENT flight was pinned to, captured when that flight
   * started. Per flight rather than per installation, because an installation
   * outlives a flight.
   */
  pin?: UpgradeSessionPin;
};

export const createUpgradeFacade = (deps: UpgradeFacadeDeps): UpgradeFacade => {
  let installation: Installation | undefined;

  /** Is this installation still the live one, or has the session moved on? */
  const isCurrent = (owner: Installation | undefined): boolean => owner !== undefined && installation === owner;

  /**
   * The transport an installation's controller is given: the host's rounds,
   * each one gated on its owner still being the live installation.
   *
   * The epoch cannot be checked only around `controller.elevate()`, because
   * prepare, commit and token storage all happen INSIDE that one await. A
   * flight whose session changed mid-answer would still commit against the
   * server and store the elevated tokens over the replacement session's, and
   * only then throw. So the check sits immediately before each round that has a
   * side effect, which is the only place it can be both before the commit and
   * after the user's answer.
   *
   * `markSessionInvalid` is gated the same way for the opposite reason: a
   * DISCARDED controller must not be able to reach into the session that
   * replaced it. Its callbacks become no-ops rather than acting on a session
   * they know nothing about.
   *
   * It stays stateless, so one per installation costs nothing; the
   * relying-party id still prefers the one `enable()` was given.
   */
  const transportFor = (owner: () => Installation | undefined): UpgradeTransport => {
    const assertCurrent = (): void => {
      if (!isCurrent(owner())) {
        // Classified, not bare: `classifyUpgradeError` passes an
        // `UpgradeTransportError` through untouched, and `session_changed` is
        // the kind the controller already maps to a terminal
        // `UpgradeSessionChangedError`. A bare throw would be re-bucketed as a
        // network failure by the transport's own catch.
        throw new UpgradeTransportError({ kind: 'session_changed' });
      }
    };

    return createUpgradeTransport({
      ...deps,
      relyingPartyId: () => installation?.options.relyingPartyId ?? deps.relyingPartyId?.(),
      startUpgrade: (payload) => {
        assertCurrent();
        return deps.startUpgrade(payload);
      },
      commitRefresh: (upgrade) => {
        assertCurrent();
        // The pin travels with the commit so the host can verify it at the
        // moment it APPLIES the rotated tokens. `assertCurrent` above is the
        // epoch half and runs first; the two are complementary — the epoch says
        // something changed, the pin says whether it is still the same
        // principal, and only the second can be checked inside the storing path.
        return deps.commitRefresh(upgrade, owner()?.pin);
      },
      ...(deps.markSessionInvalid
        ? {
            markSessionInvalid: (): void => {
              if (isCurrent(owner())) {
                deps.markSessionInvalid?.();
              }
            },
          }
        : {}),
    });
  };

  /**
   * Builds an installation and the controller that belongs to it.
   *
   * The box exists because the controller's transport must be able to name its
   * owner, and the owner is not constructed until the controller is in hand.
   */
  const buildInstallation = (options: UpgradeEnableOptions, generation: number): Installation => {
    const box: { current?: Installation } = {};
    const controller = new UpgradeController({
      transport: transportFor(() => box.current),
      prompt: options.prompt,
      platform: deps.platform,
      factors: options.factors ?? deps.factors,
      ...(options.maxAttempts === undefined ? {} : { maxAttempts: options.maxAttempts }),
      ...(deps.readObtainedBar ? { readObtainedBar: deps.readObtainedBar } : {}),
      ...(options.onFlightSettled ? { onFlightSettled: options.onFlightSettled } : {}),
    });

    const built: Installation = {
      controller,
      options,
      scope: { passflow: deps.passflowDomain, backend: declaredBackends(options.backend) },
      generation,
    };
    box.current = built;
    return built;
  };

  /**
   * The `elevate` the core is given.
   *
   * Two obligations live here and nowhere else: route every surface through the
   * ONE controller instance (that is what makes single-flight hold across the
   * fetch wrapper, an attached axios instance and the internal seam), and refuse
   * to hand back an elevation that belongs to a different session than the
   * challenge did.
   */
  const elevateFor = async (challenge: UpgradeChallenge, waiter: Waiter): Promise<UpgradeElevation> => {
    const current = installation;
    if (!current) {
      // Nothing installed means no prompt and no way to ask the user, which is
      // exactly the `unavailable` row of the settlement table.
      throw new UpgradeUnavailableError('Step-up verification is not enabled on this Passflow instance');
    }

    // Pin the flight to the principal it STARTS under. `active` is false only
    // between flights — it is set before the prompt opens and cleared in the
    // final synchronous step — so this is exactly "the first waiter of a new
    // flight", and every joiner reuses the pin the flight began with.
    if (!current.controller.active) {
      current.pin = deps.readSessionPin?.();
    }

    const elevation = await current.controller.elevate(challenge, waiter);

    if (!isCurrent(current)) {
      // The session changed under the flight. Replaying now would carry a NEW
      // session's elevated credential to a request challenged under the old
      // one. The prepare and commit rounds are guarded separately, inside this
      // installation's own transport, because they run inside the await above —
      // this check protects the replay, and only the replay.
      throw new UpgradeSessionChangedError();
    }

    return elevation;
  };

  /** The resolved interception options, read fresh per call so `enable()` is live. */
  const interceptorOptions = (): UpgradeInterceptorOptions => {
    const current = installation;
    const scope: InterceptionScope = current?.scope ?? { passflow: deps.passflowDomain, backend: [] };
    const options = current?.options;

    return {
      elevate: elevateFor,
      scope,
      ...(options?.requireChallengeChannel ? { requireChallengeChannel: options.requireChallengeChannel } : {}),
      ...(options?.shouldIntercept ? { shouldIntercept: options.shouldIntercept } : {}),
      ...(options?.replay === undefined ? {} : { replay: options.replay }),
      ...(options?.onCancel ? { onCancel: options.onCancel } : {}),
      ...(deps.authorizationSwap ? { authorizationSwap: deps.authorizationSwap } : {}),
      ...(options?.onUpgradeDiagnostic ? { onUpgradeDiagnostic: options.onUpgradeDiagnostic } : {}),
      ...(deps.readObtainedBar ? { readObtainedBar: deps.readObtainedBar } : {}),
    };
  };

  let teardown: (() => void) | undefined;

  const enable = (options: UpgradeEnableOptions): (() => void) => {
    // Calling enable() twice replaces the previous installation rather than
    // stacking a second prompt handler and a second global patch.
    teardown?.();

    installation = buildInstallation(options, 0);

    const disposers: Array<() => void> = [];

    if (deps.attachInternalSeam) {
      const attach = deps.attachInternalSeam;
      // `interceptorOptions` is handed over as a GETTER, not invoked here: the
      // handler resolves it per challenge, so a client attached before this
      // `enable()` — or before a later, narrower one — sees the live scope.
      attach((reissue) => createAxiosUpgradeHandler(interceptorOptions, reissue));
      disposers.push(() => attach(undefined));
    }

    if (options.interceptFetch) {
      // The registry, never a bare assignment: two features that each capture
      // and restore `globalThis.fetch` lose one interceptor non-deterministically.
      disposers.push(
        registerFetchMiddleware((next, input, init) => upgradeFetch(next, interceptorOptions)(input, init), {
          priority: FETCH_PRIORITY_UPGRADE,
          name: 'passflow-upgrade',
        }),
      );
    }

    if (deps.onSessionChange) {
      disposers.push(
        deps.onSessionChange(() => {
          const current = installation;
          if (!current) {
            return;
          }
          // Discard, do not reset: `inFlight` is private and has no reset, and
          // replacing the instance is both the cleanest and the only
          // non-invasive answer. The abandoned flight can no longer release a
          // waiter into the new session — `elevateFor` checks the generation.
          installation = buildInstallation(current.options, current.generation + 1);
        }),
      );
    }

    let torn = false;
    teardown = () => {
      if (torn) {
        return;
      }
      torn = true;
      for (const dispose of disposers) {
        dispose();
      }
      installation = undefined;
      teardown = undefined;
    };

    return teardown;
  };

  /**
   * The imperative seam: `passflow.upgrade(options?)`.
   *
   * There is no request to replay, so there is no challenge on the wire to
   * parse — the "challenge" is the bar the CALLER stated, synthesised here into
   * the one shape the controller ranks factors against. An options-less call
   * synthesises no bar at all, which is what makes it unable to produce
   * `insufficient`.
   */
  const upgradeImperatively = async (options?: UpgradeOptions): Promise<UpgradeResult> => {
    const level = options?.acrValues === undefined ? undefined : readAcrValues(options.acrValues).level;
    const challenge: UpgradeChallenge = {
      status: 401,
      ...(options?.acrValues === undefined ? {} : { acrValues: options.acrValues }),
      ...(level === undefined ? {} : { requiredLevel: level }),
      ...(options?.maxAge === undefined ? {} : { maxAge: options.maxAge }),
    };

    const stated = options?.acrValues !== undefined || options?.maxAge !== undefined;
    const requested: AssuranceBar = {
      ...(options?.acrValues === undefined ? {} : { acrValues: options.acrValues }),
      ...(level === undefined ? {} : { level }),
      ...(options?.maxAge === undefined ? {} : { maxAge: options.maxAge }),
    };

    const elevation = await elevateFor(challenge, { kind: 'imperative', ...(stated ? { requested } : {}) });
    const acr = elevation.obtained.acrValues;
    return { status: 'elevated', ...(acr === undefined ? {} : { acr }) };
  };

  // A callable object, not a plain record: §13.4's documented surface is
  // `passflow.upgrade(options?)` AND `passflow.upgrade.enable({...})`, and both
  // have to be the same thing a consumer holds. `enabled` is a getter, so the
  // members are defined rather than assigned.
  const facade = upgradeImperatively as UpgradeFacade;

  return Object.defineProperties(facade, {
    enable: { value: enable, enumerable: true },
    enabled: {
      enumerable: true,
      get(): boolean {
        return installation !== undefined && deps.canCommit().ok;
      },
    },
    elevate: {
      enumerable: true,
      value: (challenge: UpgradeChallenge, waiter?: Waiter) => elevateFor(challenge, waiter ?? { kind: 'imperative' }),
    },
    withAuth: {
      enumerable: true,
      value: (next?: FetchLike): FetchLike => {
        if (next) {
          // The developer's own function, wrapped as given: binding it would
          // change its `this` and break a method-shaped fetch.
          return upgradeFetch(next, interceptorOptions);
        }
        // Resolved inside the call, never at module or construction scope:
        // reading a global while a module is being imported is the SSR failure.
        const global = typeof globalThis === 'undefined' ? undefined : globalThis;
        if (!global || typeof global.fetch !== 'function') {
          throw new Error('Passflow: withAuth() needs a fetch to wrap — this runtime has none.');
        }
        return upgradeFetch(global.fetch.bind(global) as FetchLike, interceptorOptions);
      },
    },
    attachAuth: {
      enumerable: true,
      value: (instance: ResponseInterceptorHost): (() => void) => attachUpgradeAuth(instance, interceptorOptions),
    },
  });
};
