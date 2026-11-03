import { describe, expect, test } from 'vitest';
import { PassflowEvent, PassflowRefreshError, RefreshErrorId } from '../../lib/index';
import {
  axiosError,
  BASE,
  errors,
  expectNoEnd,
  expectRefreshOrder,
  http,
  observe,
  pair,
  SCHEDULE,
  world,
} from './public-fixture';

describe('one browser-wide retry schedule, caller settlement and episode events', () => {
  test('REQ-10 REQ-13 REQ-14 TEST-27 three-minute 503 outage has seven scheduled requests and keeps every token', async () => {
    const w = world(() => ({ error: http() }));
    const initial = pair();
    w.seed(initial);
    const a = w.open('A');
    const b = w.open('B');
    await w.ready();
    observe(a.sdk.refreshToken());
    observe(b.sdk.refreshToken());
    await w.run(50_000);
    expect(w.requests.map((r) => r.at)).toEqual(SCHEDULE.slice(0, 5));
    const joinedA = observe(a.sdk.refreshToken());
    const joinedB = observe(b.sdk.refreshToken());
    await w.run(53_999);
    expect(joinedA.status).toBe('pending');
    expect(joinedB.status).toBe('pending');
    expect(w.requests).toHaveLength(5);
    await w.run(1);
    expect(joinedA.status).toBe('rejected');
    expect(joinedB).toMatchObject({
      status: 'rejected',
      error: {
        id: RefreshErrorId.unavailable,
        status: 503,
        nextRetryAt: BASE + 164_000,
      },
    });
    await w.run(76_000);
    expect(w.requests.map((r) => r.at)).toEqual(SCHEDULE);
    expect(a.of(PassflowEvent.RefreshStart)).toHaveLength(7);
    expect(b.of(PassflowEvent.RefreshStart)).toEqual([]);
    expect(errors(a)).toHaveLength(7);
    expect(errors(a).map((e) => e.operation)).toEqual(Array(7).fill('refresh'));
    expect(errors(a).map((e) => e.refresh?.strikes)).toEqual(Array(7).fill(0));
    expect(errors(b)).toEqual([]);
    for (const [tab, origin] of [
      [a, 'this-tab'],
      [b, 'other-tab'],
    ] as const) {
      expect(tab.of(PassflowEvent.RefreshFailing)).toEqual([{ since: BASE, nextRetryAt: BASE + 1_000, origin }]);
      expect(tab.of(PassflowEvent.RefreshRecovered)).toEqual([]);
      expect(tab.sdk.getCachedTokens()).toEqual(initial);
    }
    expect(await w.stored()).toEqual(initial);
    expectNoEnd(a, b);
    await w.run(44_000);
    expect(w.requests.map((r) => r.at)).toEqual([...SCHEDULE, 224_000]);
  });

  test('REQ-10 REQ-14 TEST-28 healthy server from 120 seconds recovers every tab only at the 164-second retry', async () => {
    const w = world((request) => (request.at < 120_000 ? { error: http() } : 'success'));
    w.seed(pair());
    const a = w.open('A');
    const b = w.open('B');
    await w.ready();
    observe(a.sdk.refreshToken());
    observe(b.sdk.refreshToken());
    await w.run(120_000);
    const callers = [a, b].map((tab) => observe(tab.sdk.refreshToken()));
    const checks = [a, b].map((tab) => observe(tab.sdk.getTokensWithRefresh()));
    await w.run(43_999);
    expect(w.requests.map((r) => r.at)).toEqual(SCHEDULE.slice(0, 6));
    expect([...callers, ...checks].map((r) => r.status)).toEqual(Array(4).fill('pending'));
    await w.run(1);
    expect(w.requests.map((r) => r.at)).toEqual(SCHEDULE);
    for (const result of [...callers, ...checks]) {
      expect(result).toMatchObject({ status: 'resolved', value: a.sdk.getCachedTokens() });
    }
    for (const [tab, origin] of [
      [a, 'this-tab'],
      [b, 'other-tab'],
    ] as const) {
      expect(tab.of(PassflowEvent.RefreshFailing)).toHaveLength(1);
      expect(tab.of(PassflowEvent.RefreshRecovered)).toEqual([{ since: BASE, origin }]);
      expectRefreshOrder(tab);
    }
    await w.run(180_000);
    expect(w.requests).toHaveLength(7);
    expectNoEnd(a, b);
  });

  test.each([
    { r: -10, delays: [1_000, 3_000, 10_000, 30_000, 60_000, 60_000] },
    { r: 0, delays: [1_000, 3_000, 10_000, 30_000, 60_000, 60_000] },
    { r: 0.5, delays: [1_100, 3_300, 11_000, 33_000, 66_000, 66_000] },
    { r: 0.999, delays: [1_199, 3_599, 11_998, 35_994, 71_988, 71_988] },
    { r: 1, delays: [1_199, 3_599, 11_998, 35_994, 71_988, 71_988] },
    { r: 100, delays: [1_199, 3_599, 11_998, 35_994, 71_988, 71_988] },
  ])('REQ-10 TEST-29 jitter r=$r uses exact floor/clamp at every step', async ({ r, delays }) => {
    const w = world(() => ({ error: http() }), { random: () => r });
    w.seed(pair());
    const a = w.open('A');
    await w.ready();
    observe(a.sdk.refreshToken());
    await w.run();
    let deadline = 0;
    for (let index = 0; index < delays.length; index += 1) {
      deadline += delays[index]!;
      expect(errors(a)[index]?.refresh?.nextRetryAt).toBe(BASE + deadline);
      await w.run(delays[index]! - 1);
      expect(w.requests).toHaveLength(index + 1);
      await w.run(1);
      expect(w.requests[index + 1]?.at).toBe(deadline);
    }
    expectNoEnd(a);
  });

  test('REQ-10 TEST-30 retry is due one second after failed answer arrival rather than send', async () => {
    const w = world(() => 'hold');
    w.seed(pair());
    const a = w.open('A');
    await w.ready();
    observe(a.sdk.refreshToken());
    await w.run(700);
    w.requests[0]!.reject(http());
    await w.run();
    expect(errors(a)[0]?.refresh?.nextRetryAt).toBe(BASE + 1_700);
    await w.run(999);
    expect(w.requests).toHaveLength(1);
    await w.run(1);
    expect(w.requests.map((r) => r.at)).toEqual([0, 1_700]);
  });

  test.each([
    { status: 429, header: '30', delay: 30_000 },
    { status: 503, header: '30', delay: 30_000 },
    { status: 500, header: new Date(BASE + 45_000).toUTCString(), delay: 45_000 },
    { status: 429, header: new Date(BASE - 45_000).toUTCString(), delay: 1_000 },
    { status: 429, header: '900', delay: 600_000 },
    { status: 503, header: '0', delay: 1_000 },
    { status: 503, header: '-30', delay: 1_000 },
    { status: 429, header: 'not-a-date', delay: 1_000 },
  ])(
    'REQ-6 REQ-11 TEST-31 status=$status Retry-After=$header shares a $delay ms minimum',
    async ({ status, header, delay }) => {
      const w = world((_r, index) => (index === 0 ? { error: axiosError(status, 'error.qa.transient', header) } : 'success'));
      w.seed(pair());
      const a = w.open('A');
      const b = w.open('B');
      await w.ready();
      observe(a.sdk.refreshToken());
      observe(b.sdk.refreshToken());
      await w.run();
      expect(errors(a)[0]?.refresh?.nextRetryAt).toBe(BASE + delay);
      const waiting = observe(b.sdk.refreshToken());
      await w.run(delay - 1);
      expect(waiting.status).toBe('pending');
      expect(w.requests).toHaveLength(1);
      expect(w.hub.posted.filter((m) => (m.data as { type?: string }).type === 'takeover')).toEqual([]);
      await w.run(1);
      expect(w.requests.map((r) => r.at)).toEqual([0, delay]);
      expect(waiting.status).toBe('resolved');
      expect(errors(b)).toEqual([]);
      expectNoEnd(a, b);
    },
  );

  test.each(
    (['refreshToken', 'getTokens', 'token-check', 'session', 'pre-request'] as const).flatMap((caller) =>
      (['holder', 'waiting'] as const).map((side) => ({ caller, side })),
    ),
  )(
    'REQ-12 REQ-13 TEST-32 TEST-33 pending retry joins $caller in $side tab and settles on the next attempt',
    async ({ caller, side }) => {
      const failures = [http(), http()];
      const w = world((_request, index) => ({ error: failures[index] ?? http() }));
      const initial = pair();
      w.seed(initial);
      const a = w.open('A');
      const b = w.open('B');
      const target = side === 'holder' ? a : b;
      await w.ready();
      observe(a.sdk.refreshToken());
      await w.run(500);
      const invoke = (): Promise<unknown> => {
        switch (caller) {
          case 'refreshToken':
            return target.sdk.refreshToken();
          case 'getTokens':
            return target.sdk.getTokens(true);
          case 'token-check':
            return target.sdk.getTokensWithRefresh();
          case 'session':
            return target.sdk.session({ doRefresh: true });
          case 'pre-request':
            return target.sdk.getUserPasskeys();
        }
      };
      const pending = observe(invoke());
      await w.run(499);
      expect(pending.status).toBe('pending');
      expect(w.requests).toHaveLength(1);
      await w.run(1);
      expect(w.requests.map((r) => r.at)).toEqual([0, 1_000]);
      if (caller === 'refreshToken' || caller === 'pre-request') {
        if (side === 'holder') {
          expect(pending.status).toBe('rejected');
          expect(pending.error).toBe(failures[1]);
        } else
          expect(pending).toMatchObject({
            status: 'rejected',
            error: { id: RefreshErrorId.unavailable, status: 503, nextRetryAt: BASE + 4_000 },
          });
      } else if (caller === 'session') expect(pending.status).toBe('resolved');
      else expect(pending).toMatchObject({ status: 'resolved', value: initial });
      expect(errors(a)).toHaveLength(2);
      if (caller === 'pre-request' && side === 'waiting') {
        // The authoritative contract reports only the waiting tab's own API operation here.
        expect(errors(b)).toEqual([expect.objectContaining({ operation: 'passkey.list' })]);
      } else expect(errors(b)).toEqual([]);
      expect(b.of(PassflowEvent.RefreshStart)).toEqual([]);
      expect(a.sdk.getCachedTokens()).toEqual(initial);
      expect(b.sdk.getCachedTokens()).toEqual(initial);
      expectNoEnd(a, b);
    },
  );

  test('REQ-2 REQ-12 TEST-34 explicit refresh called later than the current send waits then sends anew', async () => {
    const w = world(() => 'hold');
    const initial = pair();
    w.seed(initial);
    const a = w.open('A');
    const b = w.open('B');
    await w.ready();
    const first = observe(a.sdk.refreshToken());
    await w.run(10);
    const fresh = observe(b.sdk.refreshToken());
    await w.run();
    expect(w.requests).toHaveLength(1);
    const next = pair(undefined, { expired: false, tag: 'first-success' });
    const issued = { ...next, ...pair(Number(a.sdk.getParsedTokens()?.refresh_token?.iat) + 1, { expired: false }) };
    w.requests[0]!.resolve(issued);
    await w.run();
    expect(first.status).toBe('resolved');
    expect(fresh.status).toBe('pending');
    expect(w.requests).toHaveLength(2);
    expect(w.requests[1]).toMatchObject({ at: 10, token: issued.refresh_token });
    const final = pair(Number(b.sdk.getParsedTokens()?.refresh_token?.iat) + 1, { expired: false });
    w.requests[1]!.resolve(final);
    await w.run();
    expect(fresh).toMatchObject({ status: 'resolved', value: final });
  });

  test.each([
    { id: 'error.http.503', status: 503, expected: RefreshErrorId.unavailable },
    { id: 'error.not.found', status: 500, expected: RefreshErrorId.authRetry },
  ])('REQ-12 REQ-13 TEST-35 waiting explicit caller exposes $expected with nextRetryAt', async ({ id, status, expected }) => {
    const failure = http(id, status);
    const w = world(() => ({ error: failure }));
    w.seed(pair());
    const a = w.open('A');
    const b = w.open('B');
    await w.ready();
    const own = observe(a.sdk.refreshToken());
    const joined = observe(b.sdk.refreshToken());
    await w.run();
    expect(own.error).toBe(failure);
    expect(joined.error).toBeInstanceOf(PassflowRefreshError);
    expect(joined).toMatchObject({
      status: 'rejected',
      error: { id: expected, status: expected === RefreshErrorId.unavailable ? 503 : 401, nextRetryAt: BASE + 1_000 },
    });
    expect(errors(a)).toHaveLength(1);
    expect(errors(b)).toEqual([]);
  });

  test.each(
    [
      { trigger: 'refresh-token', invoke: (sdk: ReturnType<typeof world>['tabs'][number]['sdk']) => sdk.refreshToken() },
      { trigger: 'session', invoke: (sdk: ReturnType<typeof world>['tabs'][number]['sdk']) => sdk.getTokens(true) },
      { trigger: 'token-check', invoke: (sdk: ReturnType<typeof world>['tabs'][number]['sdk']) => sdk.getTokensWithRefresh() },
      { trigger: 'pre-request', invoke: (sdk: ReturnType<typeof world>['tabs'][number]['sdk']) => sdk.getUserPasskeys() },
    ].flatMap((entry) => [
      { ...entry, failure: http() },
      { ...entry, failure: http('error.not.found', 500) },
      { ...entry, failure: http('error.token.blocked', 400) },
    ]),
  )(
    'REQ-12 REQ-13 TEST-36 $trigger reports $failure.id once and keeps tokens until a real end',
    async ({ trigger, invoke, failure }) => {
      const w = world(() => ({ error: failure }));
      // Use an expired access token so the pre-request caller must await refresh and reject on failure.
      // The contract does not specify inclusion of the exact 30-second boundary.
      const initial = pair();
      w.seed(initial);
      const a = w.open('A');
      await w.ready();
      const result = observe<unknown>(invoke(a.sdk));
      await w.run();
      expect(w.requests).toHaveLength(1);
      expect(errors(a)).toEqual([expect.objectContaining({ operation: 'refresh', source: trigger })]);
      expect(a.sdk.getCachedTokens()).toEqual(initial);
      expectNoEnd(a);
      if (failure.id === 'error.token.blocked') {
        // Every initiating caller, not just later joiners, awaits a successor or the local end.
        expect(result.status).toBe('pending');
        await w.run(19_999);
        expect(result.status).toBe('pending');
        expectNoEnd(a);
        await w.run(1);
        if (trigger === 'session' || trigger === 'token-check') {
          expect(result).toMatchObject({ status: 'resolved', value: undefined });
        } else
          expect(result).toMatchObject({
            status: 'rejected',
            error: { id: 'error.refresh.successor_timeout', status: 401 },
          });
        expect(a.of(PassflowEvent.SessionExpired)).toEqual([{ reason: 'successor_timeout', origin: 'this-tab' }]);
        expect(errors(a).filter((error) => error.operation === 'refresh')).toHaveLength(1);
        expect(w.requests).toHaveLength(1);
        expect(await w.stored()).toEqual(initial);
      } else if (trigger === 'session' || trigger === 'token-check') {
        expect(result).toMatchObject({ status: 'resolved', value: initial });
      } else expect(result.error).toBe(failure);
    },
  );

  test('REQ-13 TEST-36 an unattended scheduled attempt reports retry as its source', async () => {
    const w = world(() => ({ error: http() }));
    w.seed(pair());
    const a = w.open('A');
    await w.ready();
    observe(a.sdk.refreshToken());
    await w.run(1_000);
    expect(errors(a).map((e) => e.source)).toEqual(['refresh-token', 'retry']);
    expect(errors(a).map((e) => e.operation)).toEqual(['refresh', 'refresh']);
  });

  test('REQ-14 REQ-15 TEST-37 TEST-38 idle peers see one ordered failing/recovered episode', async () => {
    const w = world((_r, index) => (index < 2 ? { error: http() } : 'success'));
    w.seed(pair());
    const a = w.open('A');
    const idle = w.open('idle');
    await w.ready();
    observe(a.sdk.refreshToken());
    await w.run(4_000);
    expect(a.names()).toEqual([
      PassflowEvent.RefreshStart,
      PassflowEvent.Error,
      PassflowEvent.RefreshFailing,
      PassflowEvent.RefreshStart,
      PassflowEvent.Error,
      PassflowEvent.RefreshStart,
      PassflowEvent.Refresh,
      PassflowEvent.TokenCacheExpired,
      PassflowEvent.RefreshRecovered,
    ]);
    expect(idle.names()).toEqual([
      PassflowEvent.RefreshFailing,
      PassflowEvent.Refresh,
      PassflowEvent.TokenCacheExpired,
      PassflowEvent.RefreshRecovered,
    ]);
    expect(a.of(PassflowEvent.RefreshRecovered)).toEqual([{ since: BASE, origin: 'this-tab' }]);
    expect(idle.of(PassflowEvent.RefreshRecovered)).toEqual([{ since: BASE, origin: 'other-tab' }]);
    expect(errors(idle)).toEqual([]);
    expectRefreshOrder(a);
    expectRefreshOrder(idle);
  });

  test.each(['reset', 'last-strike'] as const)(
    'REQ-14 REQ-16 TEST-39 episode ending in %s never emits recovery',
    async (ending) => {
      const w = world((_r, index) => ({ error: index === 0 ? http() : http('error.not.found', 500) }));
      w.seed(pair());
      const a = w.open('A', { refreshStrikes: 1 });
      const b = w.open('B', { refreshStrikes: 1 });
      await w.ready();
      observe(a.sdk.refreshToken());
      await w.run();
      if (ending === 'reset') a.sdk.reset();
      await w.run(10_000);
      for (const tab of [a, b]) {
        expect(tab.of(PassflowEvent.RefreshFailing)).toHaveLength(1);
        expect(tab.of(PassflowEvent.RefreshRecovered)).toEqual([]);
        expect(tab.of(ending === 'reset' ? PassflowEvent.SignOut : PassflowEvent.SessionExpired)).toHaveLength(1);
      }
    },
  );

  test('REQ-14 TEST-40 a later outage creates a new episode rather than reusing the recovered one', async () => {
    let fail = true;
    const w = world(() => (fail ? { error: http() } : 'success'));
    w.seed(pair());
    const a = w.open('A');
    const b = w.open('B');
    await w.ready();
    observe(a.sdk.refreshToken());
    await w.run();
    fail = false;
    await w.run(1_000);
    await w.run(500);
    fail = true;
    observe(a.sdk.refreshToken());
    await w.run();
    fail = false;
    await w.run(1_000);
    for (const tab of [a, b]) {
      expect(tab.of(PassflowEvent.RefreshFailing).map((e) => e.since)).toEqual([BASE, BASE + 1_500]);
      expect(tab.of(PassflowEvent.RefreshRecovered).map((e) => e.since)).toEqual([BASE, BASE + 1_500]);
    }
    expectNoEnd(a, b);
  });
});
