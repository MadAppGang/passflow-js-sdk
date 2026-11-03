/**
 * The refresh controller: the one place an instance sends `/auth/refresh` (architecture §1, §5).
 * Port of the portal's `token-refresh.ts` policy and the policy half of `cross-tab-refresh.ts`,
 * reworked for the SDK: retries run under the lock with no give-up for transient failures, the
 * schedule is shared by every tab, and events are emitted here, once.
 *
 * State (one discriminated union, §5.1; D3):
 *   idle → waiting (lock queued) → refreshing (request in flight) → idle | backoff | blocked-wait
 *   backoff: the holder keeps the lock, a retry timer is armed, every caller joins the next
 *     attempt; a tab granted the lock with a shared `nextAt` in the future enters it too (handover);
 *   blocked-wait: `error.token.blocked`, the lock released, waiting ≤ 20 s for the successor;
 *   ended: the session ended in this tab (strikes, end message, emptied storage, identity change,
 *     successor timeout, sign-out). An ended tab revives on a new-lineage pair (§2.9.12).
 *
 * Every state carries the session `generation`; an answer or timer of an earlier generation does
 * nothing (the portal's generation rule). An upgrade commit is the exception: it settles through
 * the pin check and the save checks, whatever happened meanwhile.
 *
 * Events go through `emit` with the PassflowEvent string values, so the wiring (P6) can pass the
 * store's notify. Their order follows §2.4: `refresh:start` only next to a send, one outcome per
 * send, `refresh` always followed by `token-cache-expired`, the cache already set when either
 * `refresh` or an end is emitted, one `refresh:failing` / `refresh:recovered` per episode.
 *
 * @module refresh/controller
 */

import type { PassflowAuthorizationResponse, UpgradeRefreshField } from '../api/model';
import type { PlatformAdapter } from '../platform';
import { getDefaultLogger, type Logger } from '../services/logger';
import type { StorageManager } from '../storage';
import type { Tokens } from '../types';
import type { UpgradeSessionPin } from '../upgrade/session';
import { classifyRefreshFailure, type RefreshFailureClass, retryDelay } from './classify';
import {
  BLOCKED_SUCCESSOR_POLL_MS,
  BLOCKED_SUCCESSOR_WAIT_MS,
  COOKIE_BLOCKED_RETRY_MS,
  DEFAULT_REFRESH_STRIKES,
  HELD_BOUND_MS,
  LOGOUT_LOCK_WAIT_MS,
  TAKEOVER_SILENCE_MS,
  THAWED_TIMER_LATENESS_MS,
  UPGRADE_COMMIT_LOCK_WAIT_MS,
} from './constants';
import { type CoordinatorPort, createCrossTabCoordinator, createLocalCoordinator } from './coordinator';
import { PassflowRefreshError, RefreshErrorId, UpgradeCommitInterruptedError } from './errors';
import {
  type CredentialFence,
  createCredentialFence,
  IdentityChanged,
  type SentCredentials,
  SessionEnded,
  type SessionLostCause,
  tokensSubject,
} from './fence';
import { fingerprint, orderOf, type RefreshTokenOrder } from './lineage';
import type { RefreshMessage, RetryInfo, WireLineage, WireTokens } from './protocol';
import { FALLBACK_WARNING, type ResolvedCoordination } from './resolve';
import type { EventOrigin, RefreshErrorInfo, RefreshFailureKind, RefreshTrigger, SessionExpiredReason } from './types';

/** `Refresh.source` (§2.4). */
export type RefreshSource = 'refresh' | 'upgrade' | 'adopted';

/** The `Error` payload of a refresh failure (§2.5). */
export interface RefreshErrorPayload {
  message: string;
  code?: string | number;
  originalError: unknown;
  operation: 'refresh' | 'upgrade.commit';
  source: RefreshTrigger;
  refresh?: RefreshErrorInfo;
}

/** The events the controller emits, keyed by their PassflowEvent string values. */
export interface RefreshEventMap {
  'refresh:start': Record<string, never>;
  refresh: { tokens?: Tokens; source: RefreshSource };
  'token-cache-expired': { isExpired: false };
  'refresh:failing': { since: number; nextRetryAt?: number; origin: EventOrigin };
  'refresh:recovered': { since: number; origin: EventOrigin };
  error: RefreshErrorPayload;
  'session:expired': { reason: SessionExpiredReason; origin: EventOrigin };
  signout: { origin: EventOrigin; userId?: string };
  signin: { tokens: Tokens; origin: 'other-tab' };
}

export type RefreshEmit = <E extends keyof RefreshEventMap>(event: E, payload: RefreshEventMap[E]) => void;

/**
 * Sends one refresh request for the current delivery mode, with no events and no saving
 * (implemented by AuthService, P6). JSON mode: `tokens` are the stored tokens read just before the
 * send; the request sends their refresh token. Cookie/BFF: `tokens` are ignored.
 */
export interface RefreshTransport {
  mode(): 'json' | 'cookie' | 'bff';
  send(job: { tokens?: Tokens; upgrade?: UpgradeRefreshField }): Promise<PassflowAuthorizationResponse>;
  /** Cookie/BFF success side effects: session valid, id token, CSRF. */
  applyOpaque(response: PassflowAuthorizationResponse): Promise<void>;
  /** Cookie/BFF session end (§2.11): the session is marked invalid, and the local id token and CSRF token are cleared. */
  invalidate(): void;
  /** Upgrade commit: throws UpgradeSessionChangedError when the session's identity changed meanwhile. */
  assertPin(pin: UpgradeSessionPin | undefined): void;
  /**
   * Cookie/BFF: the stored id token and CSRF token, read at the send. In fallback (no channel) a
   * change of either after a blocked answer is the successor (§2.11). Absent: the stored id token.
   */
  opaqueMarker?(): string | undefined;
}

/** The token cache the controller writes (TokenCacheService). The optional members are absent in test fakes. */
export interface RefreshTokenCache {
  getTokens(): Tokens | undefined;
  setTokensCache(tokens: Tokens | undefined): void;
  startTokenCheck?(): void;
  stopTokenCheck?(): void;
  tokenExpiredFlag?: boolean;
}

export interface RefreshControllerDeps {
  emit: RefreshEmit;
  storage: Pick<StorageManager, 'getTokens' | 'saveTokens' | 'deleteTokens'>;
  cache: RefreshTokenCache;
  transport: RefreshTransport;
  coordination: ResolvedCoordination;
  /** Wake (the tab back in the foreground): `platform.onForeground`. */
  platform?: Pick<PlatformAdapter, 'onForeground'>;
  /** `refreshStrikes`. A non-integer is floored; below 1 or not finite: the default 3. */
  strikes?: number;
  logger?: Logger;
}

export interface RefreshRequest {
  trigger: RefreshTrigger;
  /** `refreshToken()`: satisfied only by a pair from a request sent at or after the call (§2.8). */
  fresh?: boolean;
}

export interface RefreshController {
  refresh(request: RefreshRequest): Promise<PassflowAuthorizationResponse>;
  /** The pre-request refresh (§2.8): the tokens to send the API call with. */
  ensureFresh(request: { trigger: 'pre-request'; allowStale: boolean }): Promise<Tokens | undefined>;
  commitUpgrade(upgrade: UpgradeRefreshField, pin?: UpgradeSessionPin): Promise<PassflowAuthorizationResponse>;
  /**
   * logOut (§2.8): rejects plain callers, stops the timers, waits for this tab's request in
   * flight, takes the lock (≤ 5 s), posts signed-out naming the newest stored token, runs
   * `cleanup(newestRefreshToken)`, ends the session here and releases. Emits nothing: the caller
   * emits its one SignOut.
   */
  signOut(cleanup: (newest?: string) => Promise<void>): Promise<void>;
  /** reset() (A2): the same without the lock or an API call, synchronously. */
  signOutNow(cleanup: (newest?: string) => void): void;
  /** A new session in this tab (sign-in, register, setTokens): new generation, counters reset. */
  sessionStarted(): void;
  /** The `sub` this tab's session belongs to. */
  identity(): string | undefined;
  readonly coordinated: boolean;
  /** This instance has a cycle: waiting for the lock, a request in flight, a retry or a successor pending. */
  readonly busy: boolean;
  /** The session ended here (or the instance was disposed): `refresh()` rejects with a PassflowRefreshError. */
  readonly ended: boolean;
  dispose(): void;
}

interface Deferred<T> {
  promise: Promise<T>;
  resolve(value: T): void;
  reject(error: unknown): void;
}

function deferred<T>(): Deferred<T> {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  // Joiners that nobody awaits must not surface as unhandled rejections.
  promise.catch(() => undefined);
  return { promise, resolve, reject };
}

/** The callers waiting on one attempt's outcome. */
interface Pending {
  trigger: RefreshTrigger;
  startedAt: number;
  plain: Deferred<PassflowAuthorizationResponse>;
  fresh: { callTime: number; deferred: Deferred<PassflowAuthorizationResponse> }[];
  /** Cookie fallback: the one retry after a blocked answer was spent. */
  cookieRetried?: boolean;
}

interface InFlight {
  generation: number;
  sentAt: number;
  /** Cookie/BFF: the stored id token and CSRF token at the send. */
  marker?: string | undefined;
  trigger: RefreshTrigger;
  /** JSON mode: what the request was sent with. */
  sent?: SentCredentials;
  stored?: Tokens;
  settled: Deferred<void>;
  /** A `Refresh` already followed this request's `RefreshStart` (an adoption heard mid-request): its outcome (§2.4 guarantee 1). */
  outcome?: boolean;
}

type State =
  | { kind: 'idle' }
  | { kind: 'waiting'; pending: Pending }
  | { kind: 'refreshing'; pending: Pending; request: InFlight }
  | { kind: 'backoff'; pending: Pending; dueAt: number; cancel: () => void }
  | {
      kind: 'blocked-wait';
      pending: Pending;
      deadline: number;
      sentAt: number;
      cancel: () => void;
      /** Cookie/BFF: the stored id token and CSRF token at the send; a change is the successor. */
      marker?: string | undefined;
    }
  | { kind: 'ended'; cause: EndCause };

type EndCause =
  | 'strikes'
  | 'session-ended'
  | 'signed-out'
  | 'emptied'
  | 'stored-ended'
  | 'successor-timeout'
  | 'identity-changed'
  | 'signed-out-here'
  | 'disposed';

const END_ERROR: Record<EndCause, RefreshErrorId> = {
  strikes: RefreshErrorId.sessionEnded,
  'session-ended': RefreshErrorId.sessionEnded,
  'stored-ended': RefreshErrorId.sessionEnded,
  'signed-out': RefreshErrorId.signedOut,
  emptied: RefreshErrorId.signedOut,
  'signed-out-here': RefreshErrorId.signedOut,
  'successor-timeout': RefreshErrorId.successorTimeout,
  'identity-changed': RefreshErrorId.identityChanged,
  disposed: RefreshErrorId.disposed,
};

function assertNever(value: never): never {
  throw new Error(`Unexpected refresh state: ${JSON.stringify(value)}`);
}

function resolveStrikes(value: number | undefined): number {
  if (value === undefined || !Number.isFinite(value)) return DEFAULT_REFRESH_STRIKES;
  const floored = Math.floor(value);
  return floored >= 1 ? floored : DEFAULT_REFRESH_STRIKES;
}

function errorMessage(error: unknown, fallback: string): string {
  return error instanceof Error && error.message ? error.message : fallback;
}

function errorCode(error: unknown): string | number | undefined {
  if (typeof error !== 'object' || error === null) return undefined;
  const id = (error as { id?: unknown }).id;
  return typeof id === 'string' || typeof id === 'number' ? id : undefined;
}

function wireTokens(tokens: Tokens | undefined): WireTokens {
  const wire: WireTokens = {};
  if (tokens?.access_token) wire.access_token = tokens.access_token;
  if (tokens?.refresh_token) wire.refresh_token = tokens.refresh_token;
  if (tokens?.id_token) wire.id_token = tokens.id_token;
  if (tokens?.scopes) wire.scopes = [...tokens.scopes];
  return wire;
}

/** The token fields of an answer, with the scopes the request was sent with (as AuthService kept them). */
function tokensOf(response: PassflowAuthorizationResponse, stored: Tokens | undefined): Tokens {
  const tokens: Tokens = {};
  if (response.access_token) tokens.access_token = response.access_token;
  if (response.refresh_token) tokens.refresh_token = response.refresh_token;
  if (response.id_token) tokens.id_token = response.id_token;
  const scopes = stored?.scopes ?? response.scopes;
  if (scopes) tokens.scopes = scopes;
  return tokens;
}

export function createRefreshController(deps: RefreshControllerDeps): RefreshController {
  const { emit, storage, cache, transport, coordination } = deps;
  const clock = coordination.clock;
  const logger = deps.logger ?? getDefaultLogger();
  const maxStrikes = resolveStrikes(deps.strikes);
  const port: CoordinatorPort = coordination.transports
    ? createCrossTabCoordinator({
        locks: coordination.transports.locks,
        channel: coordination.transports.channel,
        tabId: coordination.transports.tabId,
        names: coordination.names,
        clock,
      })
    : createLocalCoordinator();

  let state: State = { kind: 'idle' };
  let generation = 0;
  let disposed = false;
  let warned = !coordination.warnOnFirstCycle;
  // Consecutive failed attempts (transient and auth, §2.7) and auth strikes since the last success.
  let attempts = 0;
  let strikes = 0;
  // The retry schedule of this lineage: this tab's own, or the last one heard from the holder.
  let schedule: RetryInfo | undefined;
  // The open failing episode (§5.3).
  let failing: { since: number } | undefined;
  // Held verdicts on the same cached token since (§2.9.8).
  let heldSince: { fp: string | undefined; at: number } | undefined;
  // The newest `session-refreshed` heard (cookie/BFF).
  let sessionRefreshedAt: number | undefined;
  // The session that ended here: its lineage and cause, for revival (§2.9.12).
  let endedSession: (WireLineage & { cause: EndCause }) | undefined;
  // The token this tab named in its own session-ended: its own later sign-out of it posts no signed-out.
  let endedFp: string | undefined;
  // The identity this tab's session belongs to: read from the cache (else storage) on first use,
  // as after sessionStarted(). Not at construction: Passflow fills the cache from storage after
  // the controller exists, and sign-in-only test doubles of the cache have no getTokens.
  let identitySub: string | undefined;
  // An out-of-turn lock request (upgrade commit, logout).
  let wanting: { purpose: 'commit' | 'logout'; granted: () => void } | undefined;
  // The upgrade commit running under the lock.
  let committing = false;

  const now = (): number => clock.now();
  const mode = (): 'json' | 'cookie' | 'bff' => transport.mode();
  const cachedFp = (): string | undefined => fingerprint(cache.getTokens()?.refresh_token);
  const response = (): PassflowAuthorizationResponse => ({ ...(cache.getTokens() ?? {}) });
  const opaqueMarker = (): string | undefined =>
    transport.opaqueMarker ? transport.opaqueMarker() : storage.getTokens()?.id_token;
  const identity = (): string | undefined => {
    if (identitySub === undefined) identitySub = tokensSubject(cache.getTokens() ?? storage.getTokens());
    return identitySub;
  };

  // ---------------------------------------------------------------------------------------------
  // Storage and wake: one source, the fence's watch first, then this controller's own listener.

  const storageListeners = new Set<() => void>();
  const wakeListeners = new Set<() => void>();
  const fanOut = (listeners: Set<() => void>) => () => {
    for (const listener of Array.from(listeners)) listener();
  };
  const unsubscribeStorage = coordination.onStorageChange?.(fanOut(storageListeners));
  const unsubscribeWake = deps.platform?.onForeground(fanOut(wakeListeners));

  const fence: CredentialFence = createCredentialFence({
    storage,
    cache,
    identity,
    schedule: (fn, ms) => clock.setTimeout(fn, ms),
    onStorageChange: (listener) => {
      storageListeners.add(listener);
      return () => storageListeners.delete(listener);
    },
    onWake: (listener) => {
      wakeListeners.add(listener);
      return () => wakeListeners.delete(listener);
    },
    onSessionLost: (cause) => onSessionLost(cause),
    onStoredSessionSeen: () => {
      if (state.kind === 'blocked-wait') checkSuccessor();
    },
    warn: (message) => logger.warn(message),
  });

  // ---------------------------------------------------------------------------------------------
  // Joiners

  const newPending = (trigger: RefreshTrigger): Pending => ({
    trigger,
    startedAt: now(),
    plain: deferred(),
    fresh: [],
  });

  const pendingOf = (current: State): Pending | undefined =>
    current.kind === 'idle' || current.kind === 'ended' ? undefined : current.pending;

  const join = (pending: Pending, callTime: number | undefined): Promise<PassflowAuthorizationResponse> => {
    if (callTime === undefined) return pending.plain.promise;
    const each = { callTime, deferred: deferred<PassflowAuthorizationResponse>() };
    pending.fresh.push(each);
    return each.deferred.promise;
  };

  /**
   * The attempt delivered tokens (own, adopted or held). A fresh caller is satisfied only by a
   * request sent at or after its call (`sentAt`); any other starts its own (§2.8, D10).
   * `everyone`: no new request can satisfy them (held, a new session), so all resolve.
   */
  const settleSuccess = (pending: Pending, sentAt: number | undefined, everyone = false): void => {
    pending.plain.resolve(response());
    for (const each of pending.fresh) {
      if (everyone || (sentAt !== undefined && sentAt >= each.callTime)) each.deferred.resolve(response());
      else dispatch('refresh-token', each.callTime).then(each.deferred.resolve, each.deferred.reject);
    }
    pending.fresh = [];
  };

  /**
   * The attempt failed. A fresh caller whose call came after that attempt was sent joins the
   * next one instead (it waits only for a request sent before its call).
   */
  const settleFailure = (pending: Pending, error: unknown, attemptAt: number | undefined): void => {
    pending.plain.reject(error);
    for (const each of pending.fresh) {
      if (attemptAt !== undefined && attemptAt < each.callTime) {
        dispatch('refresh-token', each.callTime).then(each.deferred.resolve, each.deferred.reject);
      } else {
        each.deferred.reject(error);
      }
    }
    pending.fresh = [];
  };

  const rejectAll = (pending: Pending | undefined, error: unknown): void => {
    if (!pending) return;
    pending.plain.reject(error);
    for (const each of pending.fresh) each.deferred.reject(error);
    pending.fresh = [];
  };

  // ---------------------------------------------------------------------------------------------
  // Events

  const emitError = (
    operation: 'refresh' | 'upgrade.commit',
    source: RefreshTrigger,
    error: unknown,
    refresh?: RefreshErrorInfo,
  ): void => {
    const payload: RefreshErrorPayload = {
      message: errorMessage(error, 'Token refresh failed'),
      originalError: error,
      operation,
      source,
    };
    const code = errorCode(error);
    if (code !== undefined) payload.code = code;
    if (refresh) payload.refresh = refresh;
    emit('error', payload);
  };

  const errorInfo = (classification: RefreshFailureKind, nextRetryAt?: number): RefreshErrorInfo => {
    const info: RefreshErrorInfo = { classification, willRetry: nextRetryAt !== undefined, strikes, maxStrikes };
    if (nextRetryAt !== undefined) info.nextRetryAt = nextRetryAt;
    return info;
  };

  /** This tab now holds tokens it may use: counters reset, the episode closes, Refresh is emitted. */
  const succeed = (source: RefreshSource, origin: EventOrigin): void => {
    if (state.kind === 'refreshing') state.request.outcome = true;
    attempts = 0;
    strikes = 0;
    schedule = undefined;
    heldSince = undefined;
    port.setRetryInfo(undefined);
    if (cache.tokenExpiredFlag !== undefined) cache.tokenExpiredFlag = false;
    cache.startTokenCheck?.();
    emit('refresh', { tokens: cache.getTokens(), source });
    emit('token-cache-expired', { isExpired: false });
    if (failing) {
      const { since } = failing;
      failing = undefined;
      emit('refresh:recovered', { since, origin });
    }
  };

  const openEpisode = (since: number, nextRetryAt: number | undefined, origin: EventOrigin): void => {
    if (failing) return;
    failing = { since };
    const payload: RefreshEventMap['refresh:failing'] = { since, origin };
    if (nextRetryAt !== undefined) payload.nextRetryAt = nextRetryAt;
    emit('refresh:failing', payload);
  };

  /** tokens-refreshed from the token this tab sent or held to the one it caches now. */
  const postTokens = (from: Pick<WireLineage, 'fp' | 'iat' | 'sid'>, sentAt?: number): void => {
    const tokens = cache.getTokens();
    const to = fingerprint(tokens?.refresh_token);
    if (!from.fp || !to) return;
    port.post({
      type: 'tokens-refreshed',
      tokens: wireTokens(tokens),
      from: from.fp,
      ...(from.iat !== undefined ? { fromIat: from.iat } : {}),
      fromSid: from.sid ?? '',
      to,
      ...(sentAt !== undefined ? { sentAt } : {}),
    });
  };

  const maybeWarn = (): void => {
    if (warned) return;
    warned = true;
    logger.warn(FALLBACK_WARNING);
  };

  // ---------------------------------------------------------------------------------------------
  // Session end and revival

  const cancelTimers = (current: State): void => {
    if (current.kind === 'backoff' || current.kind === 'blocked-wait') current.cancel();
  };

  /**
   * Ends the session in this tab, once per generation (§5.3). The cache is cleared before the
   * event; joiners reject with `error` (default: the PassflowRefreshError of the cause).
   */
  const endSession = (cause: EndCause, error?: unknown): void => {
    if (state.kind === 'ended') return;
    const pending = pendingOf(state);
    cancelTimers(state);
    const lineage = fence.session();
    const userId = identity();
    generation += 1;
    attempts = 0;
    strikes = 0;
    schedule = undefined;
    failing = undefined;
    heldSince = undefined;
    port.setRetryInfo(undefined);
    if (!committing) port.release();
    endedSession = { ...lineage, cause };
    if (cause !== 'disposed') fence.dropSession();
    if ((cause === 'strikes' || cause === 'successor-timeout') && mode() !== 'json') transport.invalidate();
    state = { kind: 'ended', cause };
    rejectAll(pending, error ?? new PassflowRefreshError(END_ERROR[cause]));
    switch (cause) {
      case 'strikes':
        emit('session:expired', { reason: 'refresh_failed', origin: 'this-tab' });
        break;
      case 'session-ended':
      case 'stored-ended':
        emit('session:expired', { reason: 'refresh_failed', origin: 'other-tab' });
        break;
      case 'signed-out':
      case 'emptied':
        emit('signout', userId === undefined ? { origin: 'other-tab' } : { origin: 'other-tab', userId });
        break;
      case 'successor-timeout':
        emit('session:expired', { reason: 'successor_timeout', origin: 'this-tab' });
        break;
      case 'identity-changed':
        emit('session:expired', { reason: 'identity_changed', origin: 'this-tab' });
        break;
      case 'signed-out-here':
      case 'disposed':
        break;
      default:
        assertNever(cause);
    }
  };

  /** §2.9.12: an ended tab takes a stored pair of a new lineage, never the token that ended it. */
  const checkRevival = (): void => {
    if (state.kind !== 'ended' || state.cause === 'disposed' || disposed || mode() !== 'json') return;
    const stored = storage.getTokens();
    const order = orderOf(stored?.refresh_token);
    if (!stored?.refresh_token || !stored.access_token || !order) return;
    if (fence.lineage.isEnded(order) || fence.lineage.isRetired(order)) return;
    const ended = endedSession;
    const sub = tokensSubject(stored);
    if (ended && ended.cause !== 'successor-timeout') {
      const sameUser = !ended.sub || !sub || ended.sub === sub;
      if (sameUser && order.sid === ended.sid) return;
    }
    generation += 1;
    attempts = 0;
    strikes = 0;
    schedule = undefined;
    failing = undefined;
    heldSince = undefined;
    endedSession = undefined;
    identitySub = sub;
    const tokens: Tokens = { ...stored };
    cache.setTokensCache(tokens);
    if (cache.tokenExpiredFlag !== undefined) cache.tokenExpiredFlag = false;
    cache.startTokenCheck?.();
    state = { kind: 'idle' };
    emit('signin', { tokens, origin: 'other-tab' });
  };

  const onSessionLost = (cause: SessionLostCause): void => {
    if (state.kind === 'ended' || disposed) return;
    // The fence's storage watch reads the stored refresh token. Cookie and BFF modes never store
    // one, so "no refresh token stored" says nothing there (§2.11: no token fence in those modes);
    // their ends come from the strikes, the successor wait and the signed-out/session-ended messages.
    if (mode() !== 'json') return;
    endSession(cause === 'emptied' ? 'emptied' : 'identity-changed');
    if (cause === 'identity-changed') checkRevival();
  };

  /** What checkStoredBeforeSend threw (or anything else a storage read under the lock threw). */
  const onStoredLost = (error: unknown): void => {
    if (error instanceof IdentityChanged) {
      endSession('identity-changed');
      checkRevival();
      return;
    }
    if (error instanceof SessionEnded) {
      endSession(error.cause === 'emptied' ? 'emptied' : 'stored-ended');
      return;
    }
    endSession('stored-ended', error);
  };

  // ---------------------------------------------------------------------------------------------
  // Lock and attempts

  const toIdle = (): void => {
    state = { kind: 'idle' };
    if (!committing) port.release();
  };

  const scheduleApplies = (info: RetryInfo): boolean => {
    if (!info.from || mode() !== 'json') return true;
    return info.from === cachedFp() || info.from === fingerprint(storage.getTokens()?.refresh_token);
  };

  const enterBackoff = (pending: Pending): void => {
    const info = schedule;
    if (!info) return;
    if (!port.holding) {
      state = { kind: 'waiting', pending };
      port.request(info.nextAt + TAKEOVER_SILENCE_MS);
      return;
    }
    port.setRetryInfo(info);
    const gen = generation;
    const dueAt = info.nextAt;
    const cancel = clock.setTimeout(
      () => {
        if (gen === generation) onBackoffTimer();
      },
      Math.max(0, dueAt - now()),
    );
    state = { kind: 'backoff', pending, dueAt, cancel };
  };

  /** §5.2 backoff timer, guarded against a thawed tab whose lock was taken meanwhile (§6.11). */
  const onBackoffTimer = (): void => {
    if (state.kind !== 'backoff' || committing) return;
    const { pending, dueAt } = state;
    if (!port.holding || port.foreignHolderHeard() || now() - dueAt > THAWED_TIMER_LATENESS_MS) {
      port.release();
      state = { kind: 'waiting', pending };
      port.request((schedule?.nextAt ?? now()) + TAKEOVER_SILENCE_MS);
      return;
    }
    state = { kind: 'waiting', pending };
    if (!proceedWithLock()) toIdleIfWaiting();
  };

  const toIdleIfWaiting = (): void => {
    if (state.kind === 'idle') port.release();
  };

  /**
   * Under the lock, before sending (§2.9.2): read storage, adopt what is newer, wait out a
   * shared schedule, or send. Returns true while this tab keeps the lock.
   */
  const proceedWithLock = (): boolean => {
    if (state.kind !== 'waiting') return false;
    const pending = state.pending;
    if (mode() !== 'json') return proceedOpaque(pending);
    const before = fence.session();
    let verdict: 'send' | 'adopted' | 'held';
    try {
      verdict = fence.checkStoredBeforeSend();
    } catch (error) {
      onStoredLost(error);
      return false;
    }
    if (verdict === 'held') {
      const fp = cachedFp();
      if (!heldSince || heldSince.fp !== fp || now() - heldSince.at < HELD_BOUND_MS) {
        if (!heldSince || heldSince.fp !== fp) heldSince = { fp, at: now() };
        state = { kind: 'idle' };
        settleSuccess(pending, undefined, true);
        return false;
      }
      // Held for the bound: one held send with the stored token, unless it is known rotated.
      heldSince = { fp, at: now() };
      if (!fence.beginHeldSend()) {
        state = { kind: 'idle' };
        settleSuccess(pending, undefined, true);
        return false;
      }
      return sendJson(pending, 'held');
    }
    heldSince = undefined;
    if (verdict === 'adopted') {
      // Newer tokens of this user were stored: tell the others, they may not have seen them.
      succeed('adopted', 'other-tab');
      postTokens(before);
      if (pending.fresh.length === 0) {
        state = { kind: 'idle' };
        settleSuccess(pending, undefined);
        return false;
      }
      // A fresh caller needs a pair from a request sent after its call: send now, under the lock.
      pending.plain.resolve(response());
    }
    if (schedule && !scheduleApplies(schedule)) schedule = undefined;
    if (schedule && schedule.nextAt > now()) {
      // Handover (§2.9.4): continue the shared schedule; never send before nextAt.
      attempts = schedule.attempt;
      strikes = schedule.strikes;
      if (schedule.failingSince !== undefined) openEpisode(schedule.failingSince, schedule.nextAt, 'other-tab');
      enterBackoff(pending);
      return true;
    }
    if (schedule) {
      attempts = schedule.attempt;
      strikes = schedule.strikes;
    }
    return sendJson(pending, pending.trigger === 'held' ? 'refresh-token' : pending.trigger);
  };

  /** Cookie/BFF under the lock: a session-refreshed heard since the wait began is adopted (§6.4). */
  const proceedOpaque = (pending: Pending): boolean => {
    if (sessionRefreshedAt !== undefined && sessionRefreshedAt >= pending.startedAt) {
      cache.setTokensCache(storage.getTokens());
      succeed('adopted', 'other-tab');
      state = { kind: 'idle' };
      settleSuccess(pending, sessionRefreshedAt);
      return false;
    }
    if (schedule && schedule.nextAt > now()) {
      attempts = schedule.attempt;
      strikes = schedule.strikes;
      enterBackoff(pending);
      return true;
    }
    return sendRequest(pending, pending.trigger, undefined, undefined);
  };

  /** JSON send: the stored token, judged at the send (§5.4 beginSend). */
  const sendJson = (pending: Pending, trigger: RefreshTrigger): boolean => {
    const stored = storage.getTokens();
    const token = stored?.refresh_token;
    if (!token) {
      // Emptied between the check and the send: keep the cache, send nothing.
      state = { kind: 'idle' };
      settleSuccess(pending, undefined, true);
      return false;
    }
    const verdict = fence.beginSend(token);
    switch (verdict.kind) {
      case 'superseded':
        fence.endHeldSend();
        succeed('adopted', 'other-tab');
        state = { kind: 'idle' };
        settleSuccess(pending, undefined);
        return false;
      case 'ended':
        fence.endHeldSend();
        endSession('stored-ended');
        return false;
      case 'identity-changed':
        fence.endHeldSend();
        endSession('identity-changed');
        checkRevival();
        return false;
      case 'send':
        return sendRequest(pending, trigger, verdict.sent, stored);
      default:
        return assertNever(verdict);
    }
  };

  const sendRequest = (
    pending: Pending,
    trigger: RefreshTrigger,
    sent: SentCredentials | undefined,
    stored: Tokens | undefined,
  ): boolean => {
    const request: InFlight = { generation, sentAt: now(), trigger, settled: deferred() };
    if (sent) request.sent = sent;
    else request.marker = opaqueMarker();
    if (stored) request.stored = stored;
    state = { kind: 'refreshing', pending, request };
    port.setRetryInfo(schedule);
    emit('refresh:start', {});
    let answer: Promise<PassflowAuthorizationResponse>;
    try {
      answer = transport.send(stored ? { tokens: stored } : {});
    } catch (error) {
      answer = Promise.reject(error);
    }
    answer.then(
      (result) => {
        onAnswer(request, result)
          .catch((error: unknown) => logger.error('[passflow] Applying a refresh result failed', error))
          .finally(() => request.settled.resolve());
      },
      (error: unknown) => {
        onFailure(request, error);
        request.settled.resolve();
      },
    );
    return true;
  };

  const isCurrent = (request: InFlight): boolean =>
    !disposed && request.generation === generation && state.kind === 'refreshing' && state.request === request;

  const onAnswer = async (request: InFlight, result: PassflowAuthorizationResponse): Promise<void> => {
    if (request.sent?.held) fence.endHeldSend();
    if (!isCurrent(request) || state.kind !== 'refreshing') return;
    const { pending } = state;
    if (!request.sent) {
      // Cookie/BFF: no token to fence; the sign-out fence is the generation check. The identity
      // check is on the answer's id token `sub` (§2.11): another user's answer is never applied.
      const answerSub = tokensSubject({ ...(result.id_token ? { id_token: result.id_token } : {}) });
      const mine = identity();
      if (answerSub !== undefined && mine !== undefined && answerSub !== mine) {
        const error = new PassflowRefreshError(RefreshErrorId.identityChanged);
        emitError('refresh', request.trigger, error, errorInfo('auth'));
        endSession('identity-changed', error);
        return;
      }
      try {
        await transport.applyOpaque(result);
      } catch (error) {
        onFailure(request, error);
        return;
      }
      if (!isCurrent(request)) return;
      cache.setTokensCache({ ...(storage.getTokens() ?? {}), ...tokensOf(result, undefined) });
      succeed('refresh', 'this-tab');
      const sub = identity();
      port.post(sub === undefined ? { type: 'session-refreshed', at: now() } : { type: 'session-refreshed', at: now(), sub });
      toIdle();
      settleSuccess(pending, request.sentAt);
      return;
    }
    const cachedBefore = cachedFp();
    const verdict = fence.commitSave(request.sent, tokensOf(result, request.stored));
    switch (verdict.kind) {
      case 'saved':
        succeed('refresh', 'this-tab');
        postTokens(request.sent.order, request.sentAt);
        toIdle();
        settleSuccess(pending, request.sentAt);
        return;
      case 'superseded':
        // The pair was already moved on (another tab's rotation, a setTokens): a success here. It
        // answers this tab's own request, so a fresh caller from before the send is satisfied
        // (§2.6 "the caller resolves with the stored successor"); no second request. A tab that
        // already adopted that pair mid-request emitted its outcome then: no second Refresh.
        if (!request.outcome || cachedFp() !== cachedBefore) succeed('adopted', 'other-tab');
        if (verdict.adopted) postTokens(request.sent.order);
        toIdle();
        settleSuccess(pending, request.sentAt);
        return;
      case 'ended': {
        const error = new PassflowRefreshError(
          verdict.cause === 'emptied' ? RefreshErrorId.signedOut : RefreshErrorId.sessionEnded,
        );
        emitError('refresh', request.trigger, error, errorInfo('auth'));
        endSession(verdict.cause === 'emptied' ? 'emptied' : 'stored-ended', error);
        return;
      }
      case 'identity-changed': {
        const error = new PassflowRefreshError(RefreshErrorId.identityChanged);
        emitError('refresh', request.trigger, error, errorInfo('auth'));
        endSession('identity-changed', error);
        checkRevival();
        return;
      }
      default:
        assertNever(verdict);
    }
  };

  const onFailure = (request: InFlight, error: unknown): void => {
    if (request.sent?.held) fence.endHeldSend();
    if (!isCurrent(request) || state.kind !== 'refreshing') return;
    const { pending } = state;
    let failure: RefreshFailureClass;
    let heldRefused = false;
    if (request.sent) {
      const cachedBefore = cachedFp();
      const verdict = fence.judgeFailure(request.sent, error);
      switch (verdict.kind) {
        case 'superseded':
          // As for a superseded 200: the stored successor answers this tab's own request.
          if (!request.outcome || cachedFp() !== cachedBefore) succeed('adopted', 'other-tab');
          toIdle();
          settleSuccess(pending, request.sentAt);
          return;
        case 'ended':
          emitError('refresh', request.trigger, error, errorInfo('auth'));
          endSession(verdict.cause === 'emptied' ? 'emptied' : 'stored-ended', error);
          return;
        case 'identity-changed':
          emitError('refresh', request.trigger, error, errorInfo('auth'));
          endSession('identity-changed', error);
          checkRevival();
          return;
        case 'own':
          failure = verdict.failure;
          heldRefused = verdict.heldRefused;
          break;
        default:
          assertNever(verdict);
      }
    } else {
      failure = classifyRefreshFailure(error, now());
    }

    if (heldRefused) {
      // A held send only tested the stored token: it is dead, and the cached token after it is the successor.
      emitError('refresh', request.trigger, error, errorInfo(failure.kind));
      succeed('adopted', 'other-tab');
      toIdle();
      settleSuccess(pending, undefined, true);
      return;
    }

    switch (failure.kind) {
      case 'blocked':
        emitError('refresh', request.trigger, error, errorInfo('blocked'));
        enterBlockedWait(pending, request.sentAt, error, request.marker);
        return;
      case 'auth': {
        strikes += 1;
        attempts += 1;
        if (strikes >= maxStrikes) {
          emitError('refresh', request.trigger, error, errorInfo('auth'));
          endByStrikes(request, error);
          return;
        }
        scheduleRetry(request, pending, error, failure);
        return;
      }
      case 'transient':
        attempts += 1;
        scheduleRetry(request, pending, error, failure);
        return;
      default:
        assertNever(failure.kind);
    }
  };

  /** A failed attempt that will retry: Error, RefreshFailing once, retry-scheduled, backoff (§5.2). */
  const scheduleRetry = (request: InFlight, pending: Pending, error: unknown, failure: RefreshFailureClass): void => {
    const nextAt = now() + retryDelay(attempts, clock.random(), failure.retryAfterMs);
    const kind = failure.kind === 'auth' ? 'auth' : 'transient';
    emitError('refresh', request.trigger, error, errorInfo(kind, nextAt));
    if (kind === 'transient') openEpisode(now(), nextAt, 'this-tab');
    const info: RetryInfo = { kind, attempt: attempts, nextAt, strikes };
    const from = request.sent?.order.fp;
    if (from) info.from = from;
    if (failing) info.failingSince = failing.since;
    schedule = info;
    if (port.holding) {
      port.post({ type: 'retry-scheduled', message: errorMessage(error, 'Token refresh failed'), retry: info });
    }
    enterBackoff(newPending('retry'));
    settleFailure(pending, error, request.sentAt);
  };

  /** The last strike (§2.6 auth): every tab of the lineage ends; storage only if it still holds the dead token. */
  const endByStrikes = (request: InFlight, error: unknown): void => {
    const sub = request.sent?.sub ?? identity();
    const order = request.sent?.order;
    const named: WireLineage = {};
    if (order?.fp) named.fp = order.fp;
    if (sub) named.sub = sub;
    if (order?.sid) named.sid = order.sid;
    if (order?.iat !== undefined) named.iat = order.iat;
    // Post before deleting, so other tabs read the end before the emptied storage (§2.9.10).
    if (named.fp || named.sub) port.post({ type: 'session-ended', ...named });
    if (named.fp) {
      endedFp = named.fp;
      fence.endLineage({ ...named, fp: named.fp });
    }
    if (order) fence.deleteIfStillDead(order);
    endSession('strikes', error);
  };

  // ---------------------------------------------------------------------------------------------
  // Blocked: wait for the successor (§2.6 row 1)

  const enterBlockedWait = (pending: Pending, sentAt: number, error: unknown, marker?: string): void => {
    port.release();
    logger.warn(
      `[passflow] The refresh token was already used, most likely by another tab; waiting for its successor: ${errorMessage(error, 'blocked')}`,
    );
    const gen = generation;
    const deadline = now() + BLOCKED_SUCCESSOR_WAIT_MS;
    const blocked: Extract<State, { kind: 'blocked-wait' }> = {
      kind: 'blocked-wait',
      pending,
      deadline,
      sentAt,
      cancel: () => undefined,
      marker,
    };
    state = blocked;
    if (checkSuccessor()) return;
    const cookieFallback = mode() !== 'json' && !port.coordinated && !pending.cookieRetried;
    const tick = (): void => {
      if (gen !== generation || state !== blocked) return;
      if (checkSuccessor()) return;
      if (cookieFallback) {
        // Cookie fallback (§2.11): no channel tells of the successor; the shared cookie jar
        // already holds the rotated cookie, so retry once.
        pending.cookieRetried = true;
        state = { kind: 'waiting', pending };
        port.request();
        return;
      }
      if (now() >= deadline) {
        logger.warn('[passflow] No successor of the used refresh token appeared; ending the session in this tab only.');
        endSession('successor-timeout');
        return;
      }
      blocked.cancel = clock.setTimeout(tick, BLOCKED_SUCCESSOR_POLL_MS);
    };
    blocked.cancel = clock.setTimeout(tick, cookieFallback ? COOKIE_BLOCKED_RETRY_MS : BLOCKED_SUCCESSOR_POLL_MS);
  };

  /** True when the wait ended on a successor (adopted from cache or storage). */
  const checkSuccessor = (): boolean => {
    if (state.kind !== 'blocked-wait') return false;
    const current = state;
    if (mode() === 'json') {
      if (!fence.adoptSuccessor()) return false;
    } else {
      const heard = sessionRefreshedAt !== undefined && sessionRefreshedAt >= current.sentAt;
      // Fallback (no channel): a change of the stored id token or CSRF token after the send (§2.11).
      const marker = opaqueMarker();
      const changed = !port.coordinated && marker !== undefined && marker !== current.marker;
      if (!heard && !changed) return false;
      cache.setTokensCache(storage.getTokens());
    }
    if (state !== current) return false;
    current.cancel();
    succeed('adopted', 'other-tab');
    state = { kind: 'idle' };
    settleSuccess(current.pending, undefined, true);
    return true;
  };

  // ---------------------------------------------------------------------------------------------
  // Messages

  const isThisSession = (message: WireLineage): boolean => {
    const mine = identity();
    const sameUser = !message.sub || !mine || message.sub === mine;
    if (mode() !== 'json') return !message.fp && sameUser;
    return !!message.fp && message.fp === cachedFp() && sameUser;
  };

  /**
   * A sign-out ends every tab of that user (§2.9.7), whatever session (`sid`) or token it holds; a
   * session-ended stays scoped to its lineage. Another user's tab is never ended.
   */
  const isSignedOutUser = (type: 'session-ended' | 'signed-out', message: WireLineage): boolean => {
    if (type !== 'signed-out' || !message.sub) return false;
    const mine = identity();
    return mine !== undefined && message.sub === mine;
  };

  /** The holder's schedule for this lineage (heartbeat or retry-scheduled). */
  const noteRetry = (info: RetryInfo, attemptEnded: boolean, message: string): void => {
    if (state.kind === 'ended' || !scheduleApplies(info)) return;
    const previousAt = schedule?.nextAt;
    schedule = info;
    if (info.failingSince !== undefined) openEpisode(info.failingSince, info.nextAt, 'other-tab');
    if (!attemptEnded || state.kind !== 'waiting') return;
    // The holder's attempt failed: this attempt's joiners settle; the tab stays queued.
    const id = info.kind === 'transient' ? RefreshErrorId.unavailable : RefreshErrorId.authRetry;
    const error = new PassflowRefreshError(id, { nextRetryAt: info.nextAt, cause: message || undefined });
    const pending = state.pending;
    state.pending = newPending(pending.trigger);
    settleFailure(pending, error, previousAt);
  };

  /** Another tab's result reached this tab. `changed`: the cache took new tokens (else it already held them). */
  const adoptedFromMessage = (sentAt: number | undefined, changed: boolean): void => {
    if (changed) succeed('adopted', 'other-tab');
    switch (state.kind) {
      case 'waiting':
      case 'backoff': {
        const pending = state.pending;
        cancelTimers(state);
        toIdle();
        settleSuccess(pending, sentAt);
        return;
      }
      case 'blocked-wait': {
        const pending = state.pending;
        state.cancel();
        state = { kind: 'idle' };
        settleSuccess(pending, undefined, true);
        return;
      }
      case 'idle':
      case 'refreshing':
      case 'ended':
        return;
      default:
        assertNever(state);
    }
  };

  const onEndMessage = (message: Extract<RefreshMessage, { type: 'session-ended' | 'signed-out' }>): void => {
    const lineage: WireLineage = {};
    if (message.fp) lineage.fp = message.fp;
    if (message.sub) lineage.sub = message.sub;
    if (message.sid) lineage.sid = message.sid;
    if (message.iat !== undefined) lineage.iat = message.iat;
    const mine = state.kind !== 'ended' && (isThisSession(lineage) || isSignedOutUser(message.type, lineage));
    if (lineage.fp) fence.endLineage({ ...lineage, fp: lineage.fp });
    if (mine) endSession(message.type === 'signed-out' ? 'signed-out' : 'session-ended');
    // A dead-session end that empties the storage under a tab ahead of it does not end that tab;
    // a user's sign-out does (fence endedElsewhere).
    fence.endedElsewhere(message.type, lineage);
  };

  const onMessage = (message: RefreshMessage): void => {
    if (disposed) return;
    switch (message.type) {
      case 'tokens-refreshed': {
        if (state.kind === 'ended') {
          checkRevival();
          return;
        }
        if (mode() !== 'json') return;
        const before = cachedFp();
        if (!fence.adoptTokens(message)) return;
        const changed = cachedFp() !== before;
        if (!changed && state.kind === 'idle') return;
        schedule = undefined;
        adoptedFromMessage(message.sentAt, changed);
        return;
      }
      case 'session-refreshed': {
        if (mode() === 'json' || state.kind === 'ended') return;
        const mine = identity();
        if (message.sub && mine && message.sub !== mine) return;
        sessionRefreshedAt = Math.max(sessionRefreshedAt ?? 0, message.at);
        if (state.kind === 'refreshing') return;
        cache.setTokensCache(storage.getTokens());
        schedule = undefined;
        if (state.kind === 'blocked-wait') {
          checkSuccessor();
          return;
        }
        adoptedFromMessage(message.at, true);
        return;
      }
      case 'still-refreshing':
        if (message.retry) noteRetry(message.retry, false, '');
        repostWanted();
        return;
      case 'retry-scheduled':
        noteRetry(message.retry, true, message.message);
        repostWanted();
        return;
      case 'refresh-failed': {
        // Legacy portal holder: a failed attempt with no schedule.
        if (state.kind === 'ended' || mode() !== 'json') return;
        if (message.from !== cachedFp() && message.from !== fingerprint(storage.getTokens()?.refresh_token)) return;
        openEpisode(now(), undefined, 'other-tab');
        if (state.kind === 'waiting') {
          const pending = state.pending;
          state.pending = newPending(pending.trigger);
          settleFailure(pending, new PassflowRefreshError(RefreshErrorId.unavailable, { cause: message.message }), undefined);
        }
        return;
      }
      case 'lock-wanted':
        // A holder in backoff with no request in flight yields; it keeps the schedule as a waiter (§6.9).
        if (state.kind === 'backoff' && port.holding && !committing) {
          const pending = state.pending;
          state.cancel();
          port.release();
          state = { kind: 'waiting', pending };
          port.request((schedule?.nextAt ?? now()) + TAKEOVER_SILENCE_MS);
        }
        return;
      case 'session-ended':
      case 'signed-out':
        onEndMessage(message);
        return;
      case 'takeover':
      case 'rate-limited':
        return;
      default:
        assertNever(message);
    }
  };

  /** A3: a tab still waiting to be granted for a commit or logout re-posts lock-wanted on each holder message. */
  const repostWanted = (): void => {
    if (wanting && !port.holding) port.post({ type: 'lock-wanted', purpose: wanting.purpose });
  };

  // ---------------------------------------------------------------------------------------------
  // Coordinator handlers

  port.attach({
    onGranted: () => {
      if (disposed) return false;
      if (wanting) {
        const granted = wanting;
        wanting = undefined;
        granted.granted();
        return true;
      }
      if (state.kind !== 'waiting') return false;
      return proceedWithLock();
    },
    onLockLost: () => {
      if (state.kind === 'backoff') {
        const pending = state.pending;
        state.cancel();
        state = { kind: 'waiting', pending };
        port.request((schedule?.nextAt ?? now()) + TAKEOVER_SILENCE_MS);
      }
    },
    onMessage,
  });

  // Storage writes and wake, after the fence's watch: revive, or adopt forward while idle.
  const onStorageOrWake = (): void => {
    if (disposed) return;
    if (state.kind === 'ended') {
      checkRevival();
      return;
    }
    if (state.kind === 'blocked-wait' && mode() !== 'json') {
      checkSuccessor();
      return;
    }
    if (state.kind !== 'idle' || mode() !== 'json' || committing) return;
    const before = fence.session();
    try {
      if (fence.checkStoredBeforeSend() !== 'adopted') return;
    } catch {
      // The fence's own watch reported a lost session; nothing to adopt.
      return;
    }
    succeed('adopted', 'other-tab');
    if (port.coordinated) postTokens(before);
  };
  storageListeners.add(onStorageOrWake);
  wakeListeners.add(onStorageOrWake);

  // ---------------------------------------------------------------------------------------------
  // Entry points

  /** Starts a cycle or joins the current one. */
  const dispatch = (trigger: RefreshTrigger, callTime: number | undefined): Promise<PassflowAuthorizationResponse> => {
    if (disposed) return Promise.reject(new PassflowRefreshError(RefreshErrorId.disposed));
    switch (state.kind) {
      case 'ended':
        return Promise.reject(new PassflowRefreshError(RefreshErrorId.sessionEnded));
      case 'idle': {
        const pending = newPending(trigger);
        state = { kind: 'waiting', pending };
        const promise = join(pending, callTime);
        if (port.holding && !committing) {
          // Holding already (a logout's lock): proceed now.
          if (!proceedWithLock()) toIdleIfWaiting();
        } else {
          port.request(schedule ? schedule.nextAt + TAKEOVER_SILENCE_MS : undefined);
        }
        return promise;
      }
      case 'waiting':
      case 'refreshing':
      case 'backoff':
      case 'blocked-wait':
        return join(state.pending, callTime);
      default:
        return assertNever(state);
    }
  };

  const refresh = (request: RefreshRequest): Promise<PassflowAuthorizationResponse> => {
    if (disposed) return Promise.reject(new PassflowRefreshError(RefreshErrorId.disposed));
    maybeWarn();
    if (state.kind === 'ended') return Promise.reject(new PassflowRefreshError(RefreshErrorId.sessionEnded));
    if (mode() === 'json' && !cache.getTokens()?.refresh_token) {
      const stored = storage.getTokens();
      if (!stored?.refresh_token) {
        const error = new Error(stored ? 'No refresh token found' : 'No tokens found');
        emitError('refresh', request.trigger, error);
        return Promise.reject(error);
      }
    }
    return dispatch(request.trigger, request.fresh ? now() : undefined);
  };

  const ensureFresh = (request: { trigger: 'pre-request'; allowStale: boolean }): Promise<Tokens | undefined> => {
    if (disposed) return Promise.reject(new PassflowRefreshError(RefreshErrorId.disposed));
    if (state.kind === 'ended') return Promise.resolve(cache.getTokens());
    const retryPending =
      state.kind === 'backoff' || state.kind === 'blocked-wait' || (schedule !== undefined && schedule.nextAt > now());
    if (request.allowStale && retryPending) return Promise.resolve(cache.getTokens());
    return refresh({ trigger: request.trigger }).then(() => cache.getTokens());
  };

  /** Asks for the lock out of turn (§2.9.13): lock-wanted, then queue (A4: joins a queued request). */
  const want = (purpose: 'commit' | 'logout', maxWaitMs: number): Promise<'granted' | 'timeout'> => {
    if (port.holding) return Promise.resolve('granted');
    return new Promise((resolve) => {
      let cancelTimeout: () => void = () => undefined;
      const slot = {
        purpose,
        granted: () => {
          cancelTimeout();
          resolve('granted');
        },
      };
      wanting = slot;
      port.post({ type: 'lock-wanted', purpose });
      port.request();
      cancelTimeout = clock.setTimeout(
        () => {
          if (wanting !== slot) return;
          wanting = undefined;
          // Leave the queue unless this tab's own refresh still waits in it.
          if (state.kind !== 'waiting') port.release();
          resolve('timeout');
        },
        Math.max(0, maxWaitMs),
      );
    });
  };

  /** Waits for this tab's own request in flight, at most `maxWaitMs`. */
  const settledInFlight = async (maxWaitMs: number): Promise<void> => {
    if (state.kind !== 'refreshing') return;
    const settled = state.request.settled.promise;
    await new Promise<void>((resolve) => {
      const cancel = clock.setTimeout(resolve, Math.max(0, maxWaitMs));
      settled.then(() => {
        cancel();
        resolve();
      });
    });
  };

  /** After a commit under the lock: continue this tab's own wait, the shared schedule, or release. */
  const afterCommit = (): void => {
    committing = false;
    if (disposed) return;
    if (!port.holding) return;
    if (state.kind === 'waiting') {
      if (!proceedWithLock()) toIdleIfWaiting();
      return;
    }
    if (state.kind === 'backoff') {
      // The commit failed (a success left backoff): the same nextAt (§5.2).
      const pending = state.pending;
      state.cancel();
      enterBackoff(pending);
      return;
    }
    if (state.kind === 'idle' && schedule && schedule.nextAt > now() && scheduleApplies(schedule)) {
      // §2.9.13: the commit tab continues the schedule from nextAt.
      attempts = schedule.attempt;
      strikes = schedule.strikes;
      enterBackoff(newPending('retry'));
      return;
    }
    if (state.kind === 'idle') port.release();
  };

  const commitUpgrade = async (
    upgrade: UpgradeRefreshField,
    pin?: UpgradeSessionPin,
  ): Promise<PassflowAuthorizationResponse> => {
    if (disposed) throw new PassflowRefreshError(RefreshErrorId.disposed);
    maybeWarn();
    const deadline = now() + UPGRADE_COMMIT_LOCK_WAIT_MS;
    await settledInFlight(deadline - now());
    if (!port.holding || state.kind === 'refreshing') {
      const granted = state.kind === 'refreshing' ? 'timeout' : await want('commit', deadline - now());
      if (granted === 'timeout') {
        const error = new UpgradeCommitInterruptedError('lock-timeout');
        emitError('upgrade.commit', 'upgrade', error);
        throw error;
      }
    }
    committing = true;
    try {
      return await sendUpgrade(upgrade, pin);
    } finally {
      afterCommit();
    }
  };

  const sendUpgrade = async (upgrade: UpgradeRefreshField, pin?: UpgradeSessionPin): Promise<PassflowAuthorizationResponse> => {
    let sent: SentCredentials | undefined;
    let stored: Tokens | undefined;
    if (mode() === 'json') {
      const before = fence.session();
      try {
        // Storage ahead of the cache: adopt first, then send the stored token (§2.8).
        if (fence.checkStoredBeforeSend() === 'adopted') {
          succeed('adopted', 'other-tab');
          postTokens(before);
        }
      } catch {
        // An ended or changed session: the pin check decides.
      }
      stored = storage.getTokens();
      const token = stored?.refresh_token;
      if (!token) {
        const error = new Error(stored ? 'No refresh token found' : 'No tokens found');
        emitError('upgrade.commit', 'upgrade', error);
        throw error;
      }
      const verdict = fence.beginSend(token);
      sent = verdict.kind === 'send' ? verdict.sent : { refreshToken: token, order: orderOf(token) ?? { fp: token } };
    }
    const sentAt = now();
    emit('refresh:start', {});
    let result: PassflowAuthorizationResponse;
    try {
      result = await transport.send(stored ? { tokens: stored, upgrade } : { upgrade });
    } catch (error) {
      // Never classified (§2.6 override): no strike, no retry, tokens kept. A blocked commit retires the sent token.
      if (sent) fence.judgeFailure(sent, error);
      emitError('upgrade.commit', 'upgrade', error);
      throw error;
    }
    try {
      transport.assertPin(pin);
    } catch (error) {
      emitError('upgrade.commit', 'upgrade', error);
      throw error;
    }
    if (!sent) {
      await transport.applyOpaque(result);
      cache.setTokensCache({ ...(storage.getTokens() ?? {}), ...tokensOf(result, undefined) });
      upgradeSucceeded(sentAt);
      const sub = identity();
      port.post(sub === undefined ? { type: 'session-refreshed', at: now() } : { type: 'session-refreshed', at: now(), sub });
      return response();
    }
    const verdict = fence.commitSave(sent, tokensOf(result, stored));
    if (verdict.kind === 'saved') {
      upgradeSucceeded(sentAt);
      postTokens(sent.order, sentAt);
      return response();
    }
    // Never resolves as superseded or adopted (§2.6, D11).
    const error = new UpgradeCommitInterruptedError('superseded');
    emitError('upgrade.commit', 'upgrade', error);
    if (verdict.kind === 'superseded' && verdict.adopted) succeed('adopted', 'other-tab');
    throw error;
  };

  /** A successful commit ends the episode and settles this tab's own waiting callers. */
  const upgradeSucceeded = (sentAt: number): void => {
    succeed('upgrade', 'this-tab');
    if (state.kind === 'waiting' || state.kind === 'backoff' || state.kind === 'blocked-wait') {
      const pending = state.pending;
      cancelTimers(state);
      state = { kind: 'idle' };
      settleSuccess(pending, sentAt);
    }
  };

  /** Names the newest stored token (else the cache) in a signed-out, unless this tab already ended it. */
  const postSignedOut = (): void => {
    const stored = fence.storedSession();
    const named = stored.fp ? stored : fence.session();
    // JSON mode names a token: a sub-only signed-out would end every tab of the user, those on a
    // live session this tab never held included. Cookie/BFF messages are scoped by sub (§2.10).
    if (mode() === 'json' ? !named.fp : !named.sub) return;
    if (named.fp && named.fp === endedFp) return;
    port.post({ type: 'signed-out', ...named });
    if (named.fp) fence.endLineage({ ...named, fp: named.fp });
  };

  const stopForSignOut = (): void => {
    const pending = pendingOf(state);
    rejectAll(pending, new PassflowRefreshError(RefreshErrorId.signedOut));
    if (state.kind === 'backoff' || state.kind === 'blocked-wait' || state.kind === 'waiting') {
      cancelTimers(state);
      state = { kind: 'idle' };
    }
  };

  const signOut = async (cleanup: (newest?: string) => Promise<void>): Promise<void> => {
    // A disposed instance has no lock, channel or cycle left; local cleanup still runs.
    if (disposed) return cleanup(storage.getTokens()?.refresh_token);
    const deadline = now() + LOGOUT_LOCK_WAIT_MS;
    stopForSignOut();
    // A request already in flight is not abandoned: its answer lands before the logout.
    await settledInFlight(deadline - now());
    stopForSignOut();
    if (port.coordinated && !port.holding) await want('logout', deadline - now());
    try {
      postSignedOut();
      await cleanup(storage.getTokens()?.refresh_token);
    } finally {
      if (state.kind !== 'ended') endSession('signed-out-here');
      endedFp = undefined;
      port.release();
    }
  };

  const signOutNow = (cleanup: (newest?: string) => void): void => {
    if (disposed) return cleanup(storage.getTokens()?.refresh_token);
    stopForSignOut();
    try {
      postSignedOut();
      cleanup(storage.getTokens()?.refresh_token);
    } finally {
      if (state.kind !== 'ended') endSession('signed-out-here');
      endedFp = undefined;
    }
  };

  const sessionStarted = (): void => {
    if (disposed) return;
    const pending = pendingOf(state);
    cancelTimers(state);
    generation += 1;
    attempts = 0;
    strikes = 0;
    schedule = undefined;
    failing = undefined;
    heldSince = undefined;
    endedSession = undefined;
    endedFp = undefined;
    identitySub = undefined;
    port.setRetryInfo(undefined);
    state = { kind: 'idle' };
    if (!committing) port.release();
    if (pending) settleSuccess(pending, undefined, true);
  };

  const dispose = (): void => {
    if (disposed) return;
    const pending = pendingOf(state);
    cancelTimers(state);
    disposed = true;
    generation += 1;
    state = { kind: 'ended', cause: 'disposed' };
    rejectAll(pending, new PassflowRefreshError(RefreshErrorId.disposed));
    wanting = undefined;
    fence.stop();
    port.dispose();
    unsubscribeStorage?.();
    unsubscribeWake?.();
  };

  return {
    refresh,
    ensureFresh,
    commitUpgrade,
    signOut,
    signOutNow,
    sessionStarted,
    identity,
    get coordinated() {
      return port.coordinated;
    },
    get busy() {
      return state.kind !== 'idle' && state.kind !== 'ended';
    },
    get ended() {
      return state.kind === 'ended';
    },
    dispose,
  };
}

/** The order of a refresh token, for callers that name tokens in messages. */
export type { RefreshTokenOrder };
