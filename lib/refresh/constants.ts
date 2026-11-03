/**
 * Refresh coordination constants (PFL-792).
 *
 * Names and timings are normative: architecture §2.7 (timing) and §2.10 (wire names). The base
 * lock and channel names match the portal's `cross-tab-refresh.ts`, so tabs running the portal
 * wrapper and tabs running this SDK can share one browser during a rollout.
 *
 * @module refresh/constants
 */

/** Web Lock held by the one tab that refreshes. */
export const REFRESH_LOCK = 'passflow-refresh';
/** Web Lock a waiter takes (`ifAvailable`) before it steals {@link REFRESH_LOCK} from a silent holder. */
export const REFRESH_TAKEOVER_LOCK = 'passflow-refresh-takeover';
/** BroadcastChannel every tab of the origin listens on. */
export const AUTH_CHANNEL = 'passflow-auth';
/** Wire protocol version the SDK sends. Messages without `v` (portal wrapper tabs) are accepted. */
export const PROTOCOL_VERSION = 1;

/**
 * Delay after the n-th consecutive failed attempt (1-based): 1 s, 3 s, 10 s, 30 s, then 60 s for
 * every later attempt. Transient and auth failures both index it.
 */
export const RETRY_SCHEDULE_MS: readonly number[] = Object.freeze([1_000, 3_000, 10_000, 30_000, 60_000]);
/** Jitter added to a step: `floor(step × JITTER_RATIO × random())`, `random ∈ [0, 1)`. */
export const JITTER_RATIO = 0.2;
/** Upper bound for a server's Retry-After (seconds or HTTP date). */
export const MAX_RETRY_AFTER_MS = 600_000;

/** Holder heartbeat (`still-refreshing`) while it holds the lock. */
export const HEARTBEAT_MS = 5_000;
/** Silence after which one waiter takes over the lock. */
export const TAKEOVER_SILENCE_MS = 20_000;
/** After `error.token.blocked`: how long a tab waits for the successor before it ends itself. */
export const BLOCKED_SUCCESSOR_WAIT_MS = 20_000;
/** Storage poll interval during the blocked successor wait. */
export const BLOCKED_SUCCESSOR_POLL_MS = 1_000;
/** "Held" verdicts on the same cached token for this long allow one held send. */
export const HELD_BOUND_MS = 20_000;
/** Shared storage emptied before any explaining message: wait this long for `session-ended`/`signed-out`. */
export const EMPTIED_STORAGE_MESSAGE_WAIT_MS = 2_000;
/** A backoff timer that fires later than this after its due time (a thawed tab) re-queues instead of sending. */
export const THAWED_TIMER_LATENESS_MS = 20_000;
/** Cookie-mode fallback: one retry this long after a blocked answer when no successor sign appears. */
export const COOKIE_BLOCKED_RETRY_MS = 1_000;

/** Auth failures since the last success after which the session ends (`refreshStrikes` default). */
export const DEFAULT_REFRESH_STRIKES = 3;
/** Upgrade commit: total wait for the refresh lock. */
export const UPGRADE_COMMIT_LOCK_WAIT_MS = 10_000;
/** `logOut()`: wait for the refresh lock before proceeding without it. */
export const LOGOUT_LOCK_WAIT_MS = 5_000;
/** Pre-request refresh: an access token expiring within this many seconds is refreshed first. */
export const PRE_REQUEST_REFRESH_WINDOW_S = 30;

/**
 * Lineage memory bounds (portal `refresh-lineage.ts`). None grows with the number of rotations.
 * - TIE_MEMORY: fingerprints retired within the newest retired second of one session.
 * - SESSION_MEMORY: sessions whose retired floor is remembered.
 * - ENDED_MEMORY: ended sessions remembered (also bounds the fence's end-message memory).
 */
export const TIE_MEMORY = 32;
export const SESSION_MEMORY = 8;
export const ENDED_MEMORY = 4;
