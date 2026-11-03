import { describe, expect, test } from 'vitest';
import { PassflowError, PassflowEvent, REFRESH_AUTH_FAILURE_IDS } from '../../lib/index';
import { axiosError, BASE, errors, expectClearAtEnd, expectNoEnd, http, network, observe, pair, world } from './public-fixture';

// This expectation is transcribed independently from the normative table, not derived from the SDK constant.
const AUTH_IDS = [
  'error.token.invalid.error',
  'error.api.token.parse.error',
  'error.api.user.blocked',
  'error.2fa.required_by_app',
  'error.validation.token.invalid.subject',
  'error.not.found',
];
const idCases = [
  ...AUTH_IDS.flatMap((id) => [400, 403, 429, 500].map((status) => ({ id, status, kind: 'auth' }))),
  ...[400, 429, 500].map((status) => ({ id: 'error.token.blocked', status, kind: 'blocked' })),
];

describe('id-first classification observable on public refresh errors', () => {
  test('REQ-7 TEST-16 the exported auth-failure table contains exactly the six documented ids', () => {
    expect([...REFRESH_AUTH_FAILURE_IDS].sort()).toEqual([...AUTH_IDS].sort());
  });

  test.each(idCases)(
    'REQ-7 REQ-13 TEST-16 $id status=$status is $kind before status fallback',
    async ({ id, status, kind }) => {
      const failure = http(id, status);
      // Each HTTP answer is a distinct failure object; reporting deduplicates by object identity.
      const w = world((_request, index) => ({ error: index === 0 ? failure : http(id, status) }));
      const initial = pair();
      w.seed(initial);
      const a = w.open('A', { refreshStrikes: 2 });
      await w.ready();
      const result = observe(a.sdk.refreshToken());
      await w.run();

      // A blocked answer opens a successor wait; it is an Error event now, not caller settlement.
      if (kind === 'blocked') expect(result.status).toBe('pending');
      else {
        expect(result.status).toBe('rejected');
        expect(result.error).toBe(failure);
      }
      expect(errors(a)).toHaveLength(1);
      expect(errors(a)[0]).toMatchObject({
        operation: 'refresh',
        source: 'refresh-token',
        refresh: {
          classification: kind,
          willRetry: kind === 'auth',
          strikes: kind === 'auth' ? 1 : 0,
          maxStrikes: 2,
        },
      });
      expect(a.sdk.getCachedTokens()).toEqual(initial);
      expectNoEnd(a);
      if (kind === 'auth') {
        expect(errors(a)[0]?.refresh?.nextRetryAt).toBe(BASE + 1_000);
        await w.run(1_000);
        expect(a.of(PassflowEvent.SessionExpired)).toEqual([{ reason: 'refresh_failed', origin: 'this-tab' }]);
        expect(errors(a)).toHaveLength(2);
        expect(errors(a)[1]?.refresh).toMatchObject({ classification: 'auth', strikes: 2, willRetry: false });
        expect(await w.stored()).toBeUndefined();
        expectClearAtEnd(a);
      } else {
        expect(errors(a)[0]?.refresh?.nextRetryAt).toBeUndefined();
        await w.run(20_000);
        expect(result).toMatchObject({
          status: 'rejected',
          error: { id: 'error.refresh.successor_timeout', status: 401 },
        });
        expect(w.requests).toHaveLength(1);
        expect(a.of(PassflowEvent.SessionExpired)).toEqual([{ reason: 'successor_timeout', origin: 'this-tab' }]);
        expect(await w.stored()).toEqual(initial);
      }
    },
  );

  test('REQ-7 TEST-16 a known auth id without supplied status stays auth with PassflowError default status', async () => {
    const envelope = {
      id: 'error.not.found',
      message: 'deleted user',
      location: '/auth/refresh',
      time: new Date(BASE).toISOString(),
    };
    const failure = new PassflowError(envelope as ConstructorParameters<typeof PassflowError>[0]);
    const w = world(() => ({ error: failure }));
    w.seed(pair());
    const a = w.open('A');
    await w.ready();
    observe(a.sdk.refreshToken());
    await w.run();
    expect(errors(a)).toHaveLength(1);
    expect(errors(a)[0]?.refresh).toMatchObject({ classification: 'auth', strikes: 1, willRetry: true });
  });

  const statusCases = [
    ...[100, 199, 200, 299, 300, 399, 429, 500, 503, 599, 0, -1, 99, 600, Infinity, NaN].map((status) => ({
      status,
      kind: 'transient',
    })),
    ...[400, 401, 403, 404, 409, 422, 499].map((status) => ({ status, kind: 'auth' })),
  ];
  test.each(statusCases)('REQ-7 TEST-17 unknown id with status=$status falls back to $kind', async ({ status, kind }) => {
    const w = world(() => ({ error: axiosError(status, 'error.qa.unknown') }));
    const initial = pair();
    w.seed(initial);
    const a = w.open('A', { refreshStrikes: 2 });
    await w.ready();
    observe(a.sdk.refreshToken());
    await w.run();
    expect(errors(a)).toHaveLength(1);
    expect(errors(a)[0]?.refresh).toMatchObject({
      classification: kind,
      strikes: kind === 'auth' ? 1 : 0,
      willRetry: true,
      maxStrikes: 2,
      nextRetryAt: BASE + 1_000,
    });
    await w.run(1_000);
    if (kind === 'auth') {
      expect(a.of(PassflowEvent.SessionExpired)).toEqual([{ reason: 'refresh_failed', origin: 'this-tab' }]);
      expect(await w.stored()).toBeUndefined();
    } else {
      expectNoEnd(a);
      expect(a.sdk.getCachedTokens()).toEqual(initial);
      expect(await w.stored()).toEqual(initial);
      expect(errors(a)[1]?.refresh?.strikes).toBe(0);
    }
  });

  test.each([
    ['network', () => network()],
    ['timeout', () => Object.assign(new Error('timeout'), { isAxiosError: true, code: 'ECONNABORTED' })],
    ['CORS', () => new TypeError('Failed to fetch')],
    ['abort', () => Object.assign(new Error('aborted'), { name: 'AbortError' })],
    ['plain Error', () => new Error('untyped failure')],
    ['plain object', () => ({ message: 'failure' })],
    ['string', () => 'failure'],
    ['null', () => null],
    ['undefined', () => undefined],
  ] as const)('REQ-7 TEST-17 non-HTTP %s is transient with no strike', async (_label, makeError) => {
    const failure = makeError();
    const w = world(() => ({ error: failure }));
    const initial = pair();
    w.seed(initial);
    const a = w.open('A');
    await w.ready();
    const result = observe(a.sdk.refreshToken());
    await w.run();
    expect(result.status).toBe('rejected');
    expect(result.error).toBe(failure);
    expect(errors(a)).toHaveLength(1);
    expect(errors(a)[0]?.refresh).toMatchObject({
      classification: 'transient',
      strikes: 0,
      willRetry: true,
      nextRetryAt: BASE + 1_000,
    });
    expect(await w.stored()).toEqual(initial);
    expectNoEnd(a);
  });

  test.each([
    { id: 'error.not.found', status: 429, kind: 'auth', strikes: 1, retry: true },
    { id: 'error.token.blocked', status: 500, kind: 'blocked', strikes: 0, retry: false },
    { id: 'error.qa.unknown', status: 503, kind: 'transient', strikes: 0, retry: true },
  ])('REQ-7 REQ-13 TEST-18 axios body $id overrides status=$status', async ({ id, status, kind, strikes, retry }) => {
    const w = world(() => ({ error: axiosError(status, id) }));
    w.seed(pair());
    const a = w.open('A');
    await w.ready();
    observe(a.sdk.refreshToken());
    await w.run();
    expect(errors(a)).toHaveLength(1);
    expect(errors(a)[0]?.refresh).toMatchObject({ classification: kind, strikes, willRetry: retry });
  });

  test('REQ-9 REQ-16 TEST-23 default third auth strike ends all tabs once and clears cache before event', async () => {
    const w = world(() => ({ error: http('error.not.found', 500) }));
    w.seed(pair());
    const a = w.open('A');
    const b = w.open('B');
    await w.ready();
    observe(a.sdk.refreshToken());
    observe(b.sdk.refreshToken());
    await w.run();
    expectNoEnd(a, b);
    await w.run(1_000);
    expectNoEnd(a, b);
    await w.run(3_000);
    expect(w.requests.map((r) => r.at)).toEqual([0, 1_000, 4_000]);
    expect(errors(a).map((e) => e.refresh?.strikes)).toEqual([1, 2, 3]);
    expect(errors(a).map((e) => e.refresh?.willRetry)).toEqual([true, true, false]);
    expect(errors(b)).toEqual([]);
    expect(a.of(PassflowEvent.SessionExpired)).toEqual([{ reason: 'refresh_failed', origin: 'this-tab' }]);
    expect(b.of(PassflowEvent.SessionExpired)).toEqual([{ reason: 'refresh_failed', origin: 'other-tab' }]);
    for (const tab of [a, b]) {
      expectClearAtEnd(tab);
      expect(tab.of(PassflowEvent.SignOut)).toEqual([]);
      expect(await tab.sdk.getTokens(true)).toBeUndefined();
      expect(await tab.sdk.getTokensWithRefresh()).toBeUndefined();
      const result = observe(tab.sdk.refreshToken());
      await w.run();
      expect(result).toMatchObject({ status: 'rejected', error: { id: 'error.refresh.session_ended', status: 401 } });
    }
    await w.run(60_000);
    expect(w.requests).toHaveLength(3);
    expect(await w.stored()).toBeUndefined();
    expect(w.hub.posted.filter((m) => (m.data as { type?: string }).type === 'session-ended')).toHaveLength(1);
  });

  test.each([
    { option: 1, threshold: 1 },
    { option: 1.9, threshold: 1 },
    { option: 2.9, threshold: 2 },
    { option: undefined, threshold: 3 },
    { option: 0, threshold: 3 },
    { option: -1, threshold: 3 },
    { option: 0.9, threshold: 3 },
    { option: NaN, threshold: 3 },
    { option: Infinity, threshold: 3 },
    { option: -Infinity, threshold: 3 },
  ])('REQ-9 TEST-24 refreshStrikes=$option resolves to $threshold', async ({ option, threshold }) => {
    const w = world(() => ({ error: http('error.token.invalid.error', 400) }));
    w.seed(pair());
    const a = w.open('A', { refreshStrikes: option });
    await w.ready();
    observe(a.sdk.refreshToken());
    await w.run();
    for (let count = 1; count < threshold; count += 1) {
      expectNoEnd(a);
      await w.run(count === 1 ? 1_000 : 3_000);
    }
    expect(w.requests).toHaveLength(threshold);
    expect(errors(a).map((e) => e.refresh?.maxStrikes)).toEqual(Array(threshold).fill(threshold));
    expect(a.of(PassflowEvent.SessionExpired)).toEqual([{ reason: 'refresh_failed', origin: 'this-tab' }]);
  });

  test('REQ-9 REQ-10 TEST-25 auth,503,auth,auth ends at fourth answer and does not reset strikes', async () => {
    const sequence = [
      http('error.token.invalid.error', 400),
      http(),
      http('error.token.invalid.error', 400),
      http('error.token.invalid.error', 400),
    ];
    const w = world((_r, index) => ({ error: sequence[index] ?? http() }));
    w.seed(pair());
    const a = w.open('A');
    await w.ready();
    observe(a.sdk.refreshToken());
    await w.run(4_000);
    expectNoEnd(a);
    expect(errors(a).map((e) => e.refresh?.strikes)).toEqual([1, 1, 2]);
    await w.run(10_000);
    expect(w.requests.map((r) => r.at)).toEqual([0, 1_000, 4_000, 14_000]);
    expect(errors(a).map((e) => e.refresh?.strikes)).toEqual([1, 1, 2, 3]);
    expect(a.of(PassflowEvent.SessionExpired)).toEqual([{ reason: 'refresh_failed', origin: 'this-tab' }]);
    expect(a.of(PassflowEvent.RefreshRecovered)).toEqual([]);
  });

  test.each(['success', 'adoption', 'setTokens'] as const)(
    'REQ-9 REQ-10 TEST-26 %s resets both attempts and auth strikes',
    async (reset) => {
      let succeed = false;
      const w = world(() => (succeed ? 'success' : { error: http('error.not.found', 500) }));
      const initial = pair();
      w.seed(initial);
      const a = w.open('A');
      await w.ready();
      observe(a.sdk.refreshToken());
      await w.run();
      expect(errors(a)[0]?.refresh?.strikes).toBe(1);

      if (reset === 'success') {
        succeed = true;
        await w.run(1_000);
        succeed = false;
      } else {
        await w.run(500);
        const next = pair(undefined, {
          tag: 'new-session',
          sid: reset === 'setTokens' ? 'new-sid' : 'qa-session',
          expired: false,
        });
        if (reset === 'setTokens') a.sdk.setTokens(next);
        else w.seed({ ...next, ...pair(Number(a.sdk.getParsedTokens()?.refresh_token?.iat) + 1, { expired: false }) });
        await w.run();
      }
      const requestsBefore = w.requests.length;
      const result = observe(a.sdk.refreshToken());
      // Adoption resets the counters; it does not promise cancellation of the already pending timer.
      // Allow either an idle send now or joining that timer at the original 1,000 ms deadline.
      await w.run(reset === 'adoption' ? 500 : 0);
      expect(w.requests).toHaveLength(requestsBefore + 1);
      expect(result.status).toBe('rejected');
      const attempt = w.requests[requestsBefore]!;
      const last = errors(a)[errors(a).length - 1]!;
      expect(last.refresh).toMatchObject({
        classification: 'auth',
        strikes: 1,
        willRetry: true,
        nextRetryAt: BASE + attempt.at + 1_000,
      });
      expectNoEnd(a);
    },
  );
});
