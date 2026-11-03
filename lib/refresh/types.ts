/**
 * Public types of multi-tab-safe token refresh (PFL-792, architecture §2.2-2.5).
 *
 * @module refresh/types
 */

/** Options of one lock request: exclusive mode only, as the SDK uses `navigator.locks`. */
export interface RefreshLockOptions {
  ifAvailable?: boolean;
  steal?: boolean;
  signal?: AbortSignal;
}

/** The part of `navigator.locks` (LockManager) the SDK uses: exclusive mode only. */
export interface RefreshLockManager {
  request(name: string, options: RefreshLockOptions, callback: (lock: unknown) => unknown): Promise<unknown>;
}

/** The part of BroadcastChannel the SDK uses. Must not deliver an instance's own posts to itself. */
export interface RefreshChannel {
  postMessage(message: unknown): void;
  addEventListener(type: 'message', listener: (event: { data: unknown }) => void): void;
  removeEventListener(type: 'message', listener: (event: { data: unknown }) => void): void;
  close(): void;
}

/** Time source for every refresh timer of one instance (heartbeat, silence, retry, waits). */
export interface RefreshClock {
  /** Epoch ms. */
  now(): number;
  /** Runs `fn` after `ms`; returns the cancel. */
  setTimeout(fn: () => void, ms: number): () => void;
  /** `[0, 1)` for backoff jitter. Default `Math.random`. */
  random?(): number;
}

/** Transports for the cross-tab protocol, supplied by tests, Electron or custom hosts. */
export interface RefreshCoordinator {
  locks: RefreshLockManager;
  /** One per Passflow instance; closed by `dispose()`. */
  channel: RefreshChannel;
  /** Default: `crypto.randomUUID()` or a random string. */
  tabId?: string;
  /** Another tab wrote the shared token storage. Called once at construction; returns unsubscribe. */
  onStorageChange?: (listener: () => void) => () => void;
  /** Default: `Date.now` / `setTimeout` / `Math.random`. */
  clock?: RefreshClock;
}

/** How tabs of this origin coordinate token refresh (`PassflowConfig.refreshCoordination`). */
export type RefreshCoordination = 'web-locks' | 'none' | RefreshCoordinator;

/** What asked for a refresh (`ErrorPayload.source`). */
export type RefreshTrigger =
  /** `Passflow.refreshToken()` / `AuthService.refreshToken()` */
  | 'refresh-token'
  /** `TokenCacheService.getTokensWithRefresh()` */
  | 'token-check'
  /** `getTokens(true)` / `session({ doRefresh: true })` */
  | 'session'
  /** An SDK API call whose access token expires within 30 s */
  | 'pre-request'
  /** Step-up commit */
  | 'upgrade'
  /** The scheduled retry, with no new caller */
  | 'retry'
  /** The held-tab send */
  | 'held';

/** How a failed `/auth/refresh` is read (architecture §2.6). */
export type RefreshFailureKind = 'transient' | 'blocked' | 'auth';

/** Refresh details on `ErrorPayload` for operations `refresh` and `upgrade.commit`. */
export interface RefreshErrorInfo {
  classification: RefreshFailureKind;
  /** A retry is scheduled (transient, or auth with strikes left). */
  willRetry: boolean;
  /** Epoch ms of the retry, when `willRetry`. */
  nextRetryAt?: number;
  /** Auth failures since the last success, after this one. */
  strikes: number;
  /** Resolved `refreshStrikes`. */
  maxStrikes: number;
}

/** Whether an event was caused by this tab's own action or learnt from another tab. */
export type EventOrigin = 'this-tab' | 'other-tab';

/** Why a session ended (`SessionExpired.reason`). */
export type SessionExpiredReason =
  /** `refreshStrikes` auth failures (this tab, or another tab of the lineage). */
  | 'refresh_failed'
  /** `error.token.blocked` and no successor within 20 s; this tab only. */
  | 'successor_timeout'
  /** Storage now holds another user's tokens. */
  | 'identity_changed'
  /** Legacy members, never emitted. */
  | 'token_invalid'
  | 'logged_out';
