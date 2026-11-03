import { describe, expect, test } from 'vitest';
import { PassflowEvent } from '../../lib/index';
import {
  endMessage,
  ends,
  errors,
  expectClearAtEnd,
  expectNoEnd,
  http,
  observe,
  pair,
  successor,
  world,
} from './public-fixture';

describe('session end, cross-user safety, revival and held-tab behaviour', () => {
  test('REQ-16 REQ-17 TEST-41 reset emits one post-clear local SignOut synchronously and one peer SignOut', async () => {
    const w = world();
    w.seed(pair());
    const a = w.open('A');
    const b = w.open('B');
    await w.ready();
    const returned = a.sdk.reset();
    expect(returned).toBeUndefined();
    expect(a.of(PassflowEvent.SignOut)).toEqual([{ origin: 'this-tab', userId: 'qa-user' }]);
    expect(a.sdk.getCachedTokens()).toBeUndefined();
    expectClearAtEnd(a);
    await w.run(5_000);
    expect(b.of(PassflowEvent.SignOut)).toEqual([{ origin: 'other-tab', userId: 'qa-user' }]);
    expectClearAtEnd(b);
    expect(a.of(PassflowEvent.SessionExpired)).toEqual([]);
    expect(b.of(PassflowEvent.SessionExpired)).toEqual([]);
    expect(w.requests).toEqual([]);
    expect(await w.stored()).toBeUndefined();
    expect(w.hub.posted.filter((m) => (m.data as { type?: string }).type === 'signed-out')).toHaveLength(1);
  });

  test('REQ-13 REQ-17 REQ-27 TEST-42 reset(message) clears and signs out before reporting and throwing', async () => {
    const w = world();
    w.seed(pair());
    const a = w.open('A');
    await w.ready();
    expect(() => a.sdk.reset('qa reset requested')).toThrow('qa reset requested');
    expect(a.names()).toEqual([PassflowEvent.SignOut, PassflowEvent.Error]);
    expect(a.of(PassflowEvent.SignOut)).toEqual([{ origin: 'this-tab', userId: 'qa-user' }]);
    expect(errors(a)).toEqual([
      expect.objectContaining({
        operation: 'reset',
        code: 'RESET_ERROR',
        message: 'qa reset requested',
      }),
    ]);
    expectClearAtEnd(a);
    expect(await w.stored()).toBeUndefined();
  });

  test('REQ-17 REQ-29 TEST-43 signed-out ends every matching sub across different sid but not another user', async () => {
    const w = world(() => 'hold', { watchStorage: false });
    const first = pair();
    w.seed(first);
    const a = w.open('old-session');
    await w.run();
    // Preserve the cached session's storage view while other sessions are arranged. Otherwise
    // a message-triggered storage read may legitimately switch this tab to the foreign user.
    w.shared.lag('old-session');
    const sameUser = pair(undefined, { sid: 'second-session', expired: false });
    w.seed(sameUser);
    const b = w.open('second-session');
    await w.run();
    w.shared.lag('second-session');
    const foreign = pair(undefined, { sub: 'foreign-user', sid: 'foreign-session', expired: false });
    w.seed(foreign);
    const c = w.open('foreign-session');
    await w.ready();

    expect(a.sdk.getCachedTokens()).toEqual(first);
    expect(b.sdk.getCachedTokens()).toEqual(sameUser);
    expect(c.sdk.getCachedTokens()).toEqual(foreign);
    w.post(endMessage(first, 'signed-out'));
    await w.run(5_000);
    for (const tab of [a, b]) {
      expect(tab.of(PassflowEvent.SignOut)).toEqual([{ origin: 'other-tab', userId: 'qa-user' }]);
      expectClearAtEnd(tab);
    }
    expectNoEnd(c);
    expect(c.sdk.getCachedTokens()).toEqual(foreign);
    expect(await w.stored()).toEqual(foreign);
    expect(w.requests).toEqual([]);
  });

  test.each(['ahead-in-same-session', 'different-live-session'] as const)(
    'REQ-5 REQ-18 REQ-29 TEST-44 older session-ended preserves %s',
    async (relation) => {
      const old = pair();
      const current =
        relation === 'ahead-in-same-session'
          ? successor(old.refresh_token)
          : pair(undefined, { sid: 'different-sid', expired: false });
      const w = world();
      w.seed(current);
      const a = w.open('A');
      await w.ready();
      w.post(endMessage(old));
      await w.run(5_000);
      expectNoEnd(a);
      expect(a.sdk.getCachedTokens()).toEqual(current);
      expect(await w.stored()).toEqual(current);
    },
  );

  test('REQ-16 REQ-18 TEST-45 unexplained emptied storage ends only after the full two-second wait', async () => {
    const w = world();
    w.seed(pair());
    const a = w.open('A');
    await w.ready();
    w.empty();
    await w.run(1_999);
    expectNoEnd(a);
    expect(w.requests).toEqual([]);
    await w.run(1);
    expect(a.of(PassflowEvent.SignOut)).toEqual([expect.objectContaining({ origin: 'other-tab' })]);
    expect(a.of(PassflowEvent.SessionExpired)).toEqual([]);
    expectClearAtEnd(a);
    await w.run(10_000);
    expect(ends(a)).toHaveLength(1);
    expect(await w.stored()).toBeUndefined();
  });

  test('REQ-18 TEST-46 older explanation preserves an ahead cache and empty storage suppresses refresh sends', async () => {
    const w = world();
    const old = pair();
    const ahead = pair(Number(1900000000 - 100) + 1);
    w.seed(ahead);
    const a = w.open('A');
    await w.ready();
    w.empty();
    await w.run(1_000);
    w.post(endMessage(old));
    await w.run(1_001);
    expectNoEnd(a);
    expect(a.sdk.getCachedTokens()).toEqual(ahead);
    observe(a.sdk.getTokensWithRefresh());
    await w.run(10_000);
    expect(w.requests).toEqual([]);
    expectNoEnd(a);
    const newest = successor(ahead.refresh_token);
    w.seed(newest);
    await w.run();
    expect(a.sdk.getCachedTokens()).toEqual(newest);
  });

  test.each(['session-ended', 'signed-out'] as const)(
    'REQ-16 REQ-18 TEST-47 timely %s explanation produces one correct end rather than a fallback end',
    async (type) => {
      const w = world();
      const initial = pair();
      w.seed(initial);
      const a = w.open('A');
      await w.ready();
      w.empty();
      await w.run(1_500);
      expectNoEnd(a);
      w.post(endMessage(initial, type));
      await w.run(5_000);
      expect(ends(a)).toHaveLength(1);
      if (type === 'session-ended') {
        expect(a.of(PassflowEvent.SessionExpired)).toEqual([{ reason: 'refresh_failed', origin: 'other-tab' }]);
        expect(a.of(PassflowEvent.SignOut)).toEqual([]);
      } else {
        expect(a.of(PassflowEvent.SignOut)).toEqual([{ origin: 'other-tab', userId: 'qa-user' }]);
        expect(a.of(PassflowEvent.SessionExpired)).toEqual([]);
      }
      expectClearAtEnd(a);
    },
  );

  test('REQ-16 REQ-19 TEST-48 identity change clears old cache for SessionExpired then revives with foreign SignIn', async () => {
    const w = world();
    w.seed(pair());
    const a = w.open('A');
    await w.ready();
    const foreign = pair(undefined, { sub: 'new-user', sid: 'new-session', expired: false });
    w.seed(foreign);
    await w.run();

    expect(a.of(PassflowEvent.SessionExpired)).toEqual([{ reason: 'identity_changed', origin: 'this-tab' }]);
    expectClearAtEnd(a);
    const endIndex = a.events.findIndex((e) => e.event === PassflowEvent.SessionExpired);
    const signInIndex = a.events.findIndex((e) => e.event === PassflowEvent.SignIn);
    expect(signInIndex).toBeGreaterThan(endIndex);
    expect(a.events[signInIndex]?.cached).toEqual(foreign);
    expect(a.of(PassflowEvent.SignIn)).toEqual([expect.objectContaining({ origin: 'other-tab', tokens: foreign })]);
    expect(a.of(PassflowEvent.SignOut)).toEqual([]);
    expect(a.sdk.getParsedTokens()?.refresh_token?.sub).toBe('new-user');
    expect(await w.stored()).toEqual(foreign);
    expect(w.requests).toEqual([]);
  });

  test.each(['same-user-new-sid', 'another-user'] as const)(
    'REQ-19 TEST-49 an ended tab ignores the ended token and revives on %s',
    async (kind) => {
      const w = world();
      const initial = pair();
      w.seed(initial);
      const a = w.open('A');
      await w.ready();
      w.post(endMessage(initial, 'signed-out'));
      await w.run();
      expect(a.sdk.getCachedTokens()).toBeUndefined();
      w.seed(initial);
      await w.run();
      expect(a.sdk.getCachedTokens()).toBeUndefined();
      expect(a.of(PassflowEvent.SignIn)).toEqual([]);

      const next = pair(undefined, {
        sub: kind === 'another-user' ? 'new-user' : 'qa-user',
        sid: 'new-sid',
      });
      w.seed(next);
      await w.run();
      expect(a.of(PassflowEvent.SignIn)).toEqual([expect.objectContaining({ origin: 'other-tab', tokens: next })]);
      const refreshed = observe(a.sdk.getTokensWithRefresh());
      await w.run();
      expect(refreshed).toMatchObject({ status: 'resolved', value: successor(next.refresh_token) });
      expect(w.requests).toHaveLength(1);
    },
  );

  test.each([
    { id: 'error.token.blocked', status: 400 },
    { id: 'error.not.found', status: 500 },
  ])('REQ-20 TEST-50 held send of stored older token refused with $id never strikes or ends', async ({ id, status }) => {
    const w = world(() => ({ error: http(id, status) }), { watchStorage: false });
    const older = pair();
    w.seed(older);
    const oldStorage = w.snapshot();
    const a = w.open('A', { refreshStrikes: 1 });
    await w.ready();
    const cached = pair(1900000000 - 90);
    a.sdk.setTokens(cached);
    w.restore(oldStorage);

    const first = observe(a.sdk.getTokensWithRefresh());
    await w.run();
    expect(first).toMatchObject({ status: 'resolved', value: cached });
    expect(w.requests).toEqual([]);
    await w.run(19_999);
    observe(a.sdk.getTokensWithRefresh());
    await w.run();
    expect(w.requests).toEqual([]);
    await w.run(1);
    const held = observe(a.sdk.getTokensWithRefresh());
    await w.run();
    expect(w.requests.map((r) => r.token)).toEqual([older.refresh_token]);
    expect(held).toMatchObject({ status: 'resolved', value: cached });
    expect(errors(a)).toHaveLength(1);
    expect(errors(a)[0]).toMatchObject({
      operation: 'refresh',
      source: 'held',
      refresh: { strikes: 0, willRetry: false },
    });
    await w.run(60_000);
    observe(a.sdk.getTokensWithRefresh());
    await w.run();
    expect(w.requests).toHaveLength(1);
    expect(a.sdk.getCachedTokens()).toEqual(cached);
    expectNoEnd(a);
  });
});
