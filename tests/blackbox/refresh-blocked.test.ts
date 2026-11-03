import { describe, expect, test } from 'vitest';
import { PassflowEvent } from '../../lib/index';
import { errors, expectClearAtEnd, expectNoEnd, http, observe, pair, successor, tokenMessage, world } from './public-fixture';

describe('blocked refresh is a local successor wait, never browser-wide session deletion', () => {
  test('REQ-8 REQ-16 TEST-19 blocked waits exactly 20 seconds then ends only the requesting tab', async () => {
    const failure = http('error.token.blocked', 400);
    const w = world(() => ({ error: failure }));
    const initial = pair();
    w.seed(initial);
    const a = w.open('A', { refreshStrikes: 1 });
    const b = w.open('B', { refreshStrikes: 1 });
    await w.ready();
    const snapshot = w.snapshot();
    const first = observe(a.sdk.refreshToken());
    await w.run();
    expect(first.status).toBe('pending');
    expect(errors(a)).toHaveLength(1);
    expect(errors(a)[0]?.refresh).toMatchObject({
      classification: 'blocked',
      strikes: 0,
      maxStrikes: 1,
      willRetry: false,
    });
    const waiter = observe(a.sdk.refreshToken());
    await w.run(19_999);
    expect(first.status).toBe('pending');
    expect(waiter.status).toBe('pending');
    expectNoEnd(a, b);
    expect(w.snapshot()).toEqual(snapshot);
    await w.run(1);

    for (const result of [first, waiter])
      expect(result).toMatchObject({
        status: 'rejected',
        error: { id: 'error.refresh.successor_timeout', status: 401 },
      });
    expect(a.of(PassflowEvent.SessionExpired)).toEqual([{ reason: 'successor_timeout', origin: 'this-tab' }]);
    expectClearAtEnd(a);
    expectNoEnd(b);
    expect(b.sdk.getCachedTokens()).toEqual(initial);
    expect(w.snapshot()).toEqual(snapshot);
    expect(await w.stored()).toEqual(initial);
    expect(w.requests).toHaveLength(1);
    expect(a.of(PassflowEvent.SignOut)).toEqual([]);
    expect(a.of(PassflowEvent.RefreshFailing)).toEqual([]);
    expect(
      w.hub.posted.filter((m) => ['signed-out', 'session-ended'].includes(String((m.data as { type?: string }).type))),
    ).toEqual([]);
  });

  test.each(['broadcast', 'storage', 'poll', 'foreground'] as const)(
    'REQ-8 TEST-20 successor discovered by %s recovers blocked wait without another request',
    async (path) => {
      const w = world(() => ({ error: http('error.token.blocked', 400) }), {
        watchStorage: path === 'storage',
      });
      const initial = pair();
      w.seed(initial);
      const a = w.open('A');
      await w.ready();
      observe(a.sdk.refreshToken());
      await w.run();
      const waiter = observe(a.sdk.refreshToken());
      const next = successor(initial.refresh_token);
      w.seed(next);
      if (path === 'broadcast') w.post(tokenMessage(initial, next));
      if (path === 'foreground') a.wake();
      if (path === 'poll') {
        await w.run(999);
        expect(waiter.status).toBe('pending');
        expect(a.sdk.getCachedTokens()).toEqual(initial);
        await w.run(1);
      } else await w.run();
      expect(waiter).toMatchObject({ status: 'resolved', value: next });
      expect(a.of(PassflowEvent.Refresh)).toEqual([expect.objectContaining({ source: 'adopted', tokens: next })]);
      await w.run(20_000);
      expectNoEnd(a);
      expect(w.requests).toHaveLength(1);
      expect(await w.stored()).toEqual(next);
    },
  );

  test('REQ-8 REQ-12 TEST-21 all later token/session callers join blocked successor wait', async () => {
    const w = world(() => ({ error: http('error.token.blocked', 400) }));
    const initial = pair();
    w.seed(initial);
    const a = w.open('A');
    await w.ready();
    observe(a.sdk.refreshToken());
    await w.run();
    const explicit = observe(a.sdk.refreshToken());
    const session = observe(a.sdk.getTokens(true));
    const check = observe(a.sdk.getTokensWithRefresh());
    const callbackTokens: unknown[] = [];
    const configured = observe(
      a.sdk.session({
        doRefresh: true,
        createSession: async ({ tokens }) => {
          callbackTokens.push(tokens);
        },
      }),
    );
    await w.run(500);
    expect([explicit.status, session.status, check.status, configured.status]).toEqual([
      'pending',
      'pending',
      'pending',
      'pending',
    ]);
    expect(w.requests).toHaveLength(1);
    const next = successor(initial.refresh_token);
    w.seed(next);
    await w.run();
    for (const result of [explicit, session, check]) expect(result).toMatchObject({ status: 'resolved', value: next });
    expect(configured.status).toBe('resolved');
    expect(callbackTokens).toEqual([next]);
    expect(w.requests).toHaveLength(1);
  });

  test('REQ-8 TEST-22 revoked sessions send once and time out independently, including a fresh page', async () => {
    const w = world(() => ({ error: http('error.token.blocked', 400) }));
    const initial = pair();
    w.seed(initial);
    const a = w.open('A');
    const b = w.open('B');
    await w.ready();
    observe(a.sdk.refreshToken());
    await w.run(5_000);
    observe(b.sdk.refreshToken());
    await w.run(15_000);
    expect(a.of(PassflowEvent.SessionExpired)).toEqual([{ reason: 'successor_timeout', origin: 'this-tab' }]);
    expectNoEnd(b);
    await w.run(5_000);
    expect(b.of(PassflowEvent.SessionExpired)).toEqual([{ reason: 'successor_timeout', origin: 'this-tab' }]);

    const c = w.open('fresh-page');
    await w.run();
    expect(c.sdk.getCachedTokens()).toEqual(initial);
    observe(c.sdk.refreshToken());
    await w.run(19_999);
    expectNoEnd(c);
    await w.run(1);
    expect(c.of(PassflowEvent.SessionExpired)).toEqual([{ reason: 'successor_timeout', origin: 'this-tab' }]);
    expect(w.requests.map((r) => r.at)).toEqual([0, 5_000, 25_000]);
    expect(await w.stored()).toEqual(initial);
    for (const tab of [a, b, c]) {
      expect(tab.of(PassflowEvent.SignOut)).toEqual([]);
      expect(errors(tab)).toHaveLength(1);
    }
  });
});
