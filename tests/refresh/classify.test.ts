// Architecture §2.6 (normative): the error id decides first; the HTTP status is only the fallback
// for ids not in the table. Retry-After cases ported from the portal's refresh-rate-limit.test.ts
// and token-refresh.ts (rateLimitOf / readRetryAfterHeader).
import { describe, expect, it } from 'vitest';
import { PassflowError } from '../../lib/api/model';
import {
  BLOCKED_REFRESH_TOKEN_ID,
  classifyRefreshFailure,
  parseRetryAfter,
  REFRESH_AUTH_FAILURE_IDS,
  readRetryAfterHeader,
  retryDelay,
} from '../../lib/refresh/classify';
import { MAX_RETRY_AFTER_MS, RETRY_SCHEDULE_MS } from '../../lib/refresh/constants';
import { PassflowRefreshError, RefreshErrorId, UpgradeCommitInterruptedError } from '../../lib/refresh/errors';

function passflowError(id: string, status?: number): PassflowError {
  // `status` omitted: the constructor defaults it to 500 (lib/api/model.ts), as for an engine
  // envelope with no status.
  return new PassflowError({
    id,
    message: id,
    status: status as number,
    location: '/auth/refresh',
    time: '2026-11-03T00:00:00Z',
  });
}

function axiosError(status: number | undefined, id?: string, headers: unknown = {}) {
  return {
    isAxiosError: true,
    message: 'Request failed',
    config: { url: '/auth/refresh', method: 'post' },
    response: status === undefined ? undefined : { status, headers, data: id ? { error: { id } } : {} },
  };
}

describe('REFRESH_AUTH_FAILURE_IDS', () => {
  it('should list exactly the §2.6 row 2 ids', () => {
    expect([...REFRESH_AUTH_FAILURE_IDS].sort()).toEqual(
      [
        'error.token.invalid.error',
        'error.api.token.parse.error',
        'error.api.user.blocked',
        'error.2fa.required_by_app',
        'error.validation.token.invalid.subject',
        'error.not.found',
      ].sort(),
    );
    expect(Object.isFrozen(REFRESH_AUTH_FAILURE_IDS)).toBe(true);
  });
});

describe('classifyRefreshFailure (§2.6 table, first match wins)', () => {
  it.each([
    // Row 1: blocked, whatever the status.
    ['row 1: error.token.blocked / 400', passflowError(BLOCKED_REFRESH_TOKEN_ID, 400), 'blocked'],
    ['row 1: error.token.blocked / 500', passflowError(BLOCKED_REFRESH_TOKEN_ID, 500), 'blocked'],
    ['row 1: error.token.blocked / 429', passflowError(BLOCKED_REFRESH_TOKEN_ID, 429), 'blocked'],
    ['row 1: error.token.blocked, raw axios body', axiosError(400, BLOCKED_REFRESH_TOKEN_ID), 'blocked'],
    // Row 2: auth by id, any status.
    ['row 2: error.token.invalid.error / 400', passflowError('error.token.invalid.error', 400), 'auth'],
    ['row 2: error.api.token.parse.error / 400', passflowError('error.api.token.parse.error', 400), 'auth'],
    ['row 2: error.api.user.blocked / 403', passflowError('error.api.user.blocked', 403), 'auth'],
    ['row 2: error.2fa.required_by_app / 400', passflowError('error.2fa.required_by_app', 400), 'auth'],
    [
      'row 2: error.validation.token.invalid.subject / 500',
      passflowError('error.validation.token.invalid.subject', 500),
      'auth',
    ],
    ['row 2: error.not.found / 500', passflowError('error.not.found', 500), 'auth'],
    ['row 2: auth id with a defaulted status (500)', passflowError('error.not.found'), 'auth'],
    ['row 2: auth id with status 503', passflowError('error.token.invalid.error', 503), 'auth'],
    ['row 2: auth id with status 429', passflowError('error.api.user.blocked', 429), 'auth'],
    ['row 2: auth id, raw axios body', axiosError(500, 'error.not.found'), 'auth'],
    // Row 3: 429.
    ['row 3: unknown id / 429', passflowError('error.api.refresh.rate_limited', 429), 'transient'],
    ['row 3: raw axios 429', axiosError(429), 'transient'],
    // Row 4: no HTTP status.
    ['row 4: network error (axios, no response)', axiosError(undefined), 'transient'],
    ['row 4: plain Error', new Error('Network Error'), 'transient'],
    ['row 4: a string throw', 'boom', 'transient'],
    ['row 4: undefined', undefined, 'transient'],
    ['row 4: null', null, 'transient'],
    ['row 4: abort', Object.assign(new Error('aborted'), { name: 'AbortError' }), 'transient'],
    // Row 5: >= 500.
    ['row 5: error.http.503 / 503', passflowError('error.http.503', 503), 'transient'],
    ['row 5: unknown id / 500', passflowError('error.internal', 500), 'transient'],
    ['row 5: unknown id with a defaulted status', passflowError('error.storage'), 'transient'],
    ['row 5: raw axios 502', axiosError(502), 'transient'],
    // Row 6: 400-499.
    ['row 6: unknown id / 404', passflowError('error.http.404', 404), 'auth'],
    ['row 6: unknown id / 401', passflowError('error.unauthorized', 401), 'auth'],
    ['row 6: raw axios 403 with no body id', axiosError(403), 'auth'],
  ])('%s → %s', (_name, error, kind) => {
    expect(classifyRefreshFailure(error).kind).toBe(kind);
  });

  it('should read the id before the status for every auth id', () => {
    for (const id of REFRESH_AUTH_FAILURE_IDS) {
      for (const status of [400, 403, 429, 500, 503]) {
        expect(classifyRefreshFailure(passflowError(id, status)).kind).toBe('auth');
      }
    }
  });

  it('should report the status and id it read', () => {
    expect(classifyRefreshFailure(passflowError('error.not.found', 500))).toMatchObject({
      kind: 'auth',
      status: 500,
      id: 'error.not.found',
    });
    expect(classifyRefreshFailure(axiosError(undefined))).toEqual({ kind: 'transient' });
  });

  it('should prefer the response status over a top-level one', () => {
    const error = { status: 500, response: { status: 404, data: {} } };
    expect(classifyRefreshFailure(error)).toMatchObject({ kind: 'auth', status: 404 });
  });

  it('should treat a status outside 100-599 as no status', () => {
    expect(classifyRefreshFailure({ status: 0 }).kind).toBe('transient');
    expect(classifyRefreshFailure({ status: Number.NaN }).kind).toBe('transient');
    expect(classifyRefreshFailure({ status: '400' }).kind).toBe('transient');
  });

  it('should read a 1xx-3xx status as transient (no refusal)', () => {
    expect(classifyRefreshFailure({ status: 302 }).kind).toBe('transient');
  });

  it('should read Retry-After from a raw axios 429 (plain header object, seconds)', () => {
    const result = classifyRefreshFailure(axiosError(429, undefined, { 'retry-after': '30' }), 0);
    expect(result).toEqual({ kind: 'transient', status: 429, retryAfterMs: 30_000 });
  });

  it('should read Retry-After through AxiosHeaders.get', () => {
    const headers = { get: (name: string) => (name === 'retry-after' ? 12 : undefined) };
    expect(classifyRefreshFailure(axiosError(429, undefined, headers), 0).retryAfterMs).toBe(12_000);
  });

  it("should read a PassflowError's own numeric retryAfter (seconds, test-double affordance)", () => {
    const error = Object.assign(passflowError('error.api.refresh.rate_limited', 429), { retryAfter: 7 });
    expect(classifyRefreshFailure(error, 0).retryAfterMs).toBe(7_000);
  });

  it('should honour Retry-After on a 503 too', () => {
    expect(classifyRefreshFailure(axiosError(503, undefined, { 'Retry-After': '5' }), 0).retryAfterMs).toBe(5_000);
  });

  it('should carry no retryAfterMs for blocked or auth answers', () => {
    const blocked = axiosError(400, BLOCKED_REFRESH_TOKEN_ID, { 'retry-after': '30' });
    expect(classifyRefreshFailure(blocked, 0).retryAfterMs).toBeUndefined();
  });

  it("should classify the SDK's own refresh errors by their status (they never reach /auth/refresh)", () => {
    expect(classifyRefreshFailure(new PassflowRefreshError(RefreshErrorId.unavailable)).kind).toBe('transient');
    expect(classifyRefreshFailure(new UpgradeCommitInterruptedError('lock-timeout')).kind).toBe('transient');
  });
});

describe('readRetryAfterHeader', () => {
  it('should read AxiosHeaders.get, a lower-case key, or a canonical key', () => {
    expect(readRetryAfterHeader({ get: () => '3' })).toBe('3');
    expect(readRetryAfterHeader({ 'retry-after': '4' })).toBe('4');
    expect(readRetryAfterHeader({ 'Retry-After': '5' })).toBe('5');
    expect(readRetryAfterHeader(undefined)).toBeUndefined();
    expect(readRetryAfterHeader('x')).toBeUndefined();
  });
});

describe('parseRetryAfter', () => {
  const now = Date.parse('2026-11-03T10:00:00Z');

  it('should read delta-seconds', () => {
    expect(parseRetryAfter('30', now)).toBe(30_000);
    expect(parseRetryAfter(' 2 ', now)).toBe(2_000);
    expect(parseRetryAfter(7, now)).toBe(7_000);
    expect(parseRetryAfter('0', now)).toBe(0);
  });

  it('should read an HTTP date relative to now, never below 0', () => {
    expect(parseRetryAfter('Tue, 03 Nov 2026 10:00:45 GMT', now)).toBe(45_000);
    expect(parseRetryAfter('Tue, 03 Nov 2026 09:59:00 GMT', now)).toBe(0);
  });

  it(`should clamp to ${MAX_RETRY_AFTER_MS} ms`, () => {
    expect(parseRetryAfter('3600', now)).toBe(MAX_RETRY_AFTER_MS);
    expect(parseRetryAfter('Wed, 04 Nov 2026 10:00:00 GMT', now)).toBe(MAX_RETRY_AFTER_MS);
  });

  it('should ignore anything else', () => {
    expect(parseRetryAfter(undefined, now)).toBeUndefined();
    expect(parseRetryAfter('', now)).toBeUndefined();
    expect(parseRetryAfter('soon', now)).toBeUndefined();
    expect(parseRetryAfter('-5', now)).toBeUndefined();
    expect(parseRetryAfter('1.5', now)).toBeUndefined();
    expect(parseRetryAfter(-1, now)).toBeUndefined();
    expect(parseRetryAfter(Number.POSITIVE_INFINITY, now)).toBeUndefined();
    expect(parseRetryAfter({}, now)).toBeUndefined();
  });
});

describe('retryDelay (§2.7)', () => {
  it('should follow 1, 3, 10, 30 s then 60 s for every later attempt, with random = 0', () => {
    expect([1, 2, 3, 4, 5, 6, 7, 50].map((n) => retryDelay(n, 0))).toEqual([
      1_000, 3_000, 10_000, 30_000, 60_000, 60_000, 60_000, 60_000,
    ]);
    expect(RETRY_SCHEDULE_MS).toEqual([1_000, 3_000, 10_000, 30_000, 60_000]);
  });

  it('should add jitter of floor(step × 0.2 × random), below 20 % of the step', () => {
    expect(retryDelay(1, 0.5)).toBe(1_100);
    expect(retryDelay(5, 0.5)).toBe(66_000);
    expect(retryDelay(1, 0.9999)).toBe(1_000 + Math.floor(1_000 * 0.2 * 0.999));
    expect(retryDelay(2, 0.999)).toBeLessThan(3_000 * 1.2);
  });

  it('should clamp random into [0, 0.999] and treat a non-finite one as 0', () => {
    expect(retryDelay(1, -3)).toBe(1_000);
    expect(retryDelay(1, 7)).toBe(1_000 + Math.floor(1_000 * 0.2 * 0.999));
    expect(retryDelay(1, Number.NaN)).toBe(1_000);
  });

  it('should treat an attempt below 1 as the first', () => {
    expect(retryDelay(0, 0)).toBe(1_000);
    expect(retryDelay(-2, 0)).toBe(1_000);
  });

  it('should wait at least Retry-After, clamped to [0, 600 s]', () => {
    expect(retryDelay(1, 0, 30_000)).toBe(30_000);
    expect(retryDelay(5, 0, 30_000)).toBe(60_000);
    expect(retryDelay(1, 0, 3_600_000)).toBe(600_000);
    expect(retryDelay(1, 0, -10)).toBe(1_000);
    expect(retryDelay(1, 0, undefined)).toBe(1_000);
  });
});
