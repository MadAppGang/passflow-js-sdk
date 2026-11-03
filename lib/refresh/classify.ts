/**
 * Classification of a failed `/auth/refresh` (architecture §2.6, normative) and the retry
 * schedule (§2.7).
 *
 * The error id decides first; the HTTP status is only the fallback for ids not in the table. The
 * engine answers several dead-session cases with 500 and one with 403, and `PassflowError`'s
 * constructor defaults a missing status to 500, so a status-only rule would read a dead session
 * as an outage.
 *
 * | # | Match (first wins)                          | Kind      |
 * |---|---------------------------------------------|-----------|
 * | 1 | id `error.token.blocked`                    | blocked   |
 * | 2 | id in {@link REFRESH_AUTH_FAILURE_IDS}       | auth      |
 * | 3 | status 429                                  | transient |
 * | 4 | no HTTP status                              | transient |
 * | 5 | status >= 500                               | transient |
 * | 6 | status 400-499                              | auth      |
 *
 * A superseded outcome is not a classification: the credential fence decides it before an error
 * reaches this table. Upgrade commits are never classified.
 *
 * @module refresh/classify
 */

import { JITTER_RATIO, MAX_RETRY_AFTER_MS, RETRY_SCHEDULE_MS } from './constants';
import type { RefreshFailureKind } from './types';

/** §2.6 row 1: the token was already used (nearly always by another tab), or the session was revoked. */
export const BLOCKED_REFRESH_TOKEN_ID = 'error.token.blocked';

/** §2.6 row 2: the session cannot be refreshed, whatever the status. */
export const REFRESH_AUTH_FAILURE_IDS: readonly string[] = Object.freeze([
  'error.token.invalid.error',
  'error.api.token.parse.error',
  'error.api.user.blocked',
  'error.2fa.required_by_app',
  'error.validation.token.invalid.subject',
  'error.not.found',
]);

export interface RefreshFailureClass {
  kind: RefreshFailureKind;
  /** The HTTP status read, when there was one. */
  status?: number;
  /** The engine error id read, when there was one. */
  id?: string;
  /** Transient answers only: Retry-After in ms, clamped to [0, 600 000]. */
  retryAfterMs?: number;
}

type HeaderBag = Record<string, unknown> & { get?: (name: string) => unknown };

interface ErrorShape {
  id?: unknown;
  status?: unknown;
  retryAfter?: unknown;
  response?: { status?: unknown; headers?: unknown; data?: unknown };
}

/** Retry-After from response headers: AxiosHeaders (whose `get()` ignores case) or a plain object. */
export function readRetryAfterHeader(headers: unknown): unknown {
  if (typeof headers !== 'object' || headers === null) return undefined;
  const bag = headers as HeaderBag;
  if (typeof bag.get === 'function') return bag.get('retry-after');
  return bag['retry-after'] ?? bag['Retry-After'];
}

/**
 * Retry-After as a delay in ms from `now`: delta-seconds (a non-negative integer, as a number or
 * a string) or an HTTP date. Clamped to [0, {@link MAX_RETRY_AFTER_MS}]. Undefined for anything
 * else.
 */
export function parseRetryAfter(value: unknown, now: number): number | undefined {
  if (typeof value === 'number') {
    if (!Number.isFinite(value) || value < 0) return undefined;
    return Math.min(MAX_RETRY_AFTER_MS, Math.floor(value) * 1000);
  }
  if (typeof value !== 'string') return undefined;
  const text = value.trim();
  if (text === '') return undefined;
  if (/^\d+$/.test(text)) {
    return Math.min(MAX_RETRY_AFTER_MS, Number.parseInt(text, 10) * 1000);
  }
  // Not delta-seconds: only an HTTP date (it has letters) counts, so "-5" or "1.5" do not parse
  // as dates.
  if (!/[a-z]/i.test(text)) return undefined;
  const at = Date.parse(text);
  if (Number.isNaN(at)) return undefined;
  return Math.min(MAX_RETRY_AFTER_MS, Math.max(0, at - now));
}

function httpStatus(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isInteger(value) && value >= 100 && value <= 599 ? value : undefined;
}

function errorId(e: ErrorShape): string | undefined {
  if (typeof e.id === 'string' && e.id !== '') return e.id;
  const data = e.response?.data;
  if (typeof data !== 'object' || data === null) return undefined;
  const error = (data as { error?: unknown }).error;
  if (typeof error !== 'object' || error === null) return undefined;
  const id = (error as { id?: unknown }).id;
  return typeof id === 'string' && id !== '' ? id : undefined;
}

/**
 * Reads what a refresh request rejected with: a `PassflowError` (`id`, `status`), an axios-like
 * error (`response.status`, `response.data.error.id`, `response.headers['retry-after']`), or
 * anything else (no status: transient).
 */
export function classifyRefreshFailure(error: unknown, now: number = Date.now()): RefreshFailureClass {
  if (typeof error !== 'object' || error === null) return { kind: 'transient' };
  const e = error as ErrorShape;
  const id = errorId(e);
  const status = httpStatus(e.response?.status) ?? httpStatus(e.status);
  const read: Omit<RefreshFailureClass, 'kind'> = {};
  if (status !== undefined) read.status = status;
  if (id !== undefined) read.id = id;

  if (id === BLOCKED_REFRESH_TOKEN_ID) return { kind: 'blocked', ...read };
  if (id !== undefined && REFRESH_AUTH_FAILURE_IDS.includes(id)) return { kind: 'auth', ...read };
  if (status !== undefined && status >= 400 && status <= 499 && status !== 429) return { kind: 'auth', ...read };
  // 429, no status, >= 500, and the 1xx-3xx statuses no refusal uses: transient.
  if (status === undefined) return { kind: 'transient', ...read };
  const retryAfterMs = parseRetryAfter(e.retryAfter ?? readRetryAfterHeader(e.response?.headers), now);
  return retryAfterMs === undefined ? { kind: 'transient', ...read } : { kind: 'transient', ...read, retryAfterMs };
}

/**
 * Delay before the next attempt after the n-th consecutive failed attempt (1-based):
 * `max(S[min(n,5)-1] + floor(S[min(n,5)-1] × 0.2 × r), retryAfterMs ?? 0)` with
 * `S = [1000, 3000, 10000, 30000, 60000]`, `r` clamped to [0, 0.999] (non-finite: 0), and
 * `retryAfterMs` clamped to [0, 600 000].
 */
export function retryDelay(attempt: number, random: number, retryAfterMs?: number): number {
  const last = RETRY_SCHEDULE_MS.length;
  const n = Number.isFinite(attempt) ? Math.min(Math.max(Math.floor(attempt), 1), last) : 1;
  const step = RETRY_SCHEDULE_MS[n - 1] ?? RETRY_SCHEDULE_MS[last - 1] ?? 60_000;
  const r = Number.isFinite(random) ? Math.min(Math.max(random, 0), 0.999) : 0;
  const jittered = step + Math.floor(step * JITTER_RATIO * r);
  const floor =
    retryAfterMs !== undefined && Number.isFinite(retryAfterMs) ? Math.min(Math.max(retryAfterMs, 0), MAX_RETRY_AFTER_MS) : 0;
  return Math.max(jittered, floor);
}
