import { describe, expect, test } from 'vitest';
import { PassflowEvent } from '../../lib/index';
import { errors, expectNoEnd, expectRefreshOrder, http, observe, pair, successor, tokenMessage, world } from './public-fixture';

describe('compare-and-set saves and forward-only refresh lineage', () => {
  test.each(['success', 'transient', 'auth', 'blocked'] as const)(
    'REQ-4 REQ-15 TEST-9 superseded %s resolves to stored successor without reporting failure',
    async (outcome) => {
      const w = world(() => 'hold');
      const initial = pair();
      w.seed(initial);
      const a = w.open('A');
      const b = w.open('B');
      await w.ready();
      const result = observe(a.sdk.refreshToken());
      await w.run();
      const saved = successor(initial.refresh_token);
      b.sdk.setTokens(saved);
      await w.run();

      const request = w.requests[0]!;
      if (outcome === 'success') request.resolve(successor(initial.refresh_token, 20));
      else
        request.reject(
          http(outcome === 'auth' ? 'error.not.found' : outcome === 'blocked' ? 'error.token.blocked' : 'error.http.503', 500),
        );
      await w.run();
      expect(result).toMatchObject({ status: 'resolved', value: saved });
      expect(await w.stored()).toEqual(saved);
      expect(a.sdk.getCachedTokens()).toEqual(saved);
      expect(errors(a)).toEqual([]);
      expect(a.of(PassflowEvent.Refresh).map((e) => e.source)).toContain('adopted');
      expectRefreshOrder(a);
      expectNoEnd(a, b);
    },
  );

  test('REQ-4 REQ-17 TEST-10 late success cannot recreate storage after synchronous reset', async () => {
    const w = world(() => 'hold');
    const initial = pair();
    w.seed(initial);
    const a = w.open('A');
    await w.ready();
    const result = observe(a.sdk.refreshToken());
    await w.run();
    a.sdk.reset();
    const cleared = w.snapshot();
    w.requests[0]!.resolve(successor(initial.refresh_token));
    await w.run();
    expect(result).toMatchObject({ status: 'rejected', error: { id: 'error.refresh.signed_out' } });
    expect(a.sdk.getCachedTokens()).toBeUndefined();
    expect(await w.stored()).toBeUndefined();
    expect(w.snapshot()).toEqual(cleared);
    expect(a.of(PassflowEvent.SignOut)).toEqual([{ origin: 'this-tab', userId: 'qa-user' }]);
    expect(a.of(PassflowEvent.Refresh)).toEqual([]);
  });

  test('REQ-4 REQ-19 TEST-11 late old-user answer preserves a foreign live session', async () => {
    const w = world(() => 'hold');
    const initial = pair();
    w.seed(initial);
    const a = w.open('A');
    await w.ready();
    observe(a.sdk.refreshToken());
    await w.run();
    const foreign = pair(undefined, { sub: 'other-user', sid: 'other-session', expired: false });
    w.seed(foreign);
    await w.run();
    w.requests[0]!.resolve(successor(initial.refresh_token, 100));
    await w.run();
    expect(await w.stored()).toEqual(foreign);
    expect(a.sdk.getCachedTokens()).toEqual(foreign);
    expect(a.of(PassflowEvent.SessionExpired)).toEqual([{ reason: 'identity_changed', origin: 'this-tab' }]);
    expect(a.of(PassflowEvent.SignIn)).toEqual([expect.objectContaining({ origin: 'other-tab', tokens: foreign })]);
  });

  test('REQ-5 TEST-12 server response with older refresh iat never rolls cache or storage back', async () => {
    const w = world(() => 'hold');
    const initial = pair();
    w.seed(initial);
    const a = w.open('A');
    await w.ready();
    observe(a.sdk.refreshToken());
    await w.run();
    const older = pair(Number(a.sdk.getParsedTokens()?.refresh_token?.iat) - 1, { expired: false });
    w.requests[0]!.resolve(older);
    await w.run();
    // Forward-only ordering constrains the refresh token, not the other fields of the answer.
    expect(a.sdk.getCachedTokens()?.refresh_token).toBe(initial.refresh_token);
    expect((await w.stored())?.refresh_token).toBe(initial.refresh_token);
    expect(a.of(PassflowEvent.Refresh).some((e) => e.tokens?.refresh_token === older.refresh_token)).toBe(false);
    expectNoEnd(a);
  });

  test.each(['older', 'same-second-unproven'] as const)(
    'REQ-5 REQ-29 TEST-13 ignores %s broadcast without forward proof',
    async (kind) => {
      const w = world();
      const held = pair();
      w.seed(held);
      const a = w.open('A');
      await w.ready();
      const iat = Number(a.sdk.getParsedTokens()?.refresh_token?.iat);
      const previous = pair(iat - 1);
      const candidate = pair(kind === 'older' ? iat - 1 : iat, { tag: 'unproven', expired: false });
      w.post(tokenMessage(previous, candidate));
      await w.run();
      expect(a.sdk.getCachedTokens()).toEqual(held);
      expect(await w.stored()).toEqual(held);
      expect(a.of(PassflowEvent.Refresh)).toEqual([]);
      expect(w.requests).toEqual([]);
    },
  );

  test('REQ-5 REQ-15 REQ-29 TEST-14 blocked retirement proof permits a same-second successor', async () => {
    const w = world(() => ({ error: http('error.token.blocked', 400) }), { watchStorage: false });
    const initial = pair();
    w.seed(initial);
    const a = w.open('A');
    await w.ready();
    observe(a.sdk.refreshToken());
    await w.run();
    const waiting = observe(a.sdk.getTokensWithRefresh());
    const sameSecond = pair(Number(a.sdk.getParsedTokens()?.refresh_token?.iat), {
      tag: 'issued-in-same-second',
      expired: false,
    });
    w.seed(sameSecond);
    w.post(tokenMessage(initial, sameSecond));
    await w.run();
    expect(waiting).toMatchObject({ status: 'resolved', value: sameSecond });
    expect(a.sdk.getCachedTokens()).toEqual(sameSecond);
    expect(a.of(PassflowEvent.Refresh)).toEqual([expect.objectContaining({ source: 'adopted', tokens: sameSecond })]);
    expectRefreshOrder(a);
    await w.run(20_000);
    expectNoEnd(a);
    expect(w.requests).toHaveLength(1);
  });

  test('REQ-5 REQ-30 TEST-15 distant stale replays cannot undo a long rotation chain', async () => {
    const w = world();
    const initial = pair();
    w.seed(initial);
    const a = w.open('A');
    await w.ready();
    const history = [initial];
    for (let i = 0; i < 80; i += 1) {
      const result = observe(a.sdk.refreshToken());
      await w.run();
      expect(result.status).toBe('resolved');
      history.push(a.sdk.getCachedTokens() as typeof initial);
    }
    const latest = history[history.length - 1]!;
    for (let i = 1; i < history.length - 1; i += 1) w.post(tokenMessage(history[i - 1]!, history[i]!));
    await w.run();
    expect(a.sdk.getCachedTokens()).toEqual(latest);
    expect(await w.stored()).toEqual(latest);
    expect(w.requests).toHaveLength(80);
    expectNoEnd(a);
  });
});
