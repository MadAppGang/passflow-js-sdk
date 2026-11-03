import { describe, expect, test } from 'vitest';
import { PassflowEvent } from '../../lib/index';
import { BASE, errors, expectNoEnd, expectRefreshOrder, http, observe, pair, successor, world } from './public-fixture';

describe('browser-wide refresh coordination through public Passflow instances', () => {
  test('REQ-1 REQ-2 REQ-15 TEST-1 four simultaneous calls send once and expose own/adopted outcomes', async () => {
    const w = world(() => 'hold');
    const initial = pair();
    w.seed(initial);
    const tabs = ['A', 'B', 'C', 'D'].map((id) => w.open(id));
    await w.ready();

    const pending = tabs.map((tab) => observe(tab.sdk.refreshToken()));
    await w.run();
    expect(w.requests.map((r) => ({ token: r.token, at: r.at }))).toEqual([{ token: initial.refresh_token, at: 0 }]);
    const issued = successor(initial.refresh_token);
    w.requests[0]!.resolve(issued);
    await w.run();

    for (const result of pending) expect(result).toMatchObject({ status: 'resolved', value: issued });
    for (const [index, tab] of tabs.entries()) {
      expect(tab.sdk.getCachedTokens()).toEqual(issued);
      expect(await tab.sdk.getTokens()).toEqual(issued);
      expect(tab.sdk.getParsedTokens()?.refresh_token?.iat).toBe(BASE / 1_000 - 99);
      expect(tab.names()).toEqual(
        index === 0
          ? [PassflowEvent.RefreshStart, PassflowEvent.Refresh, PassflowEvent.TokenCacheExpired]
          : [PassflowEvent.Refresh, PassflowEvent.TokenCacheExpired],
      );
      expect(tab.of(PassflowEvent.Refresh)).toEqual([
        expect.objectContaining({ tokens: issued, source: index === 0 ? 'refresh' : 'adopted' }),
      ]);
      expectRefreshOrder(tab);
      expect(errors(tab)).toEqual([]);
    }
    expectNoEnd(...tabs);
    expect(await w.stored()).toEqual(issued);
  });

  test('REQ-2 REQ-12 TEST-2 expiry-driven callers join an already-sent request', async () => {
    const w = world(() => 'hold');
    const initial = pair();
    w.seed(initial);
    const a = w.open('A');
    const b = w.open('B');
    await w.ready();
    const explicit = observe(a.sdk.refreshToken());
    await w.run();
    await w.run(10);
    const session = observe(b.sdk.getTokens(true));
    const check = observe(a.sdk.getTokensWithRefresh());
    await w.run();
    expect(w.requests).toHaveLength(1);
    expect(session.status).toBe('pending');
    expect(check.status).toBe('pending');

    const issued = successor(initial.refresh_token);
    w.requests[0]!.resolve(issued);
    await w.run();
    for (const result of [explicit, session, check]) {
      expect(result).toMatchObject({ status: 'resolved', value: issued });
    }
    expect(w.requests).toHaveLength(1);
    expect(b.of(PassflowEvent.RefreshStart)).toEqual([]);
    expectNoEnd(a, b);
  });

  test('REQ-3 TEST-3 a queued non-fresh caller reads and adopts newer storage before sending', async () => {
    const w = world(() => 'hold', { watchStorage: false });
    const initial = pair();
    w.seed(initial);
    const b = w.open('B');
    await w.ready();
    let release!: () => void;
    const external = w.locks.forTab('external').request(
      'passflow-refresh',
      {},
      () =>
        new Promise<void>((resolve) => {
          release = resolve;
        }),
    );
    await w.run();
    const pending = observe(b.sdk.getTokensWithRefresh());
    await w.run();
    const newer = successor(initial.refresh_token);
    w.seed(newer);
    release();
    await external;
    await w.run();

    expect(w.requests).toEqual([]);
    expect(pending).toMatchObject({ status: 'resolved', value: newer });
    expect(b.of(PassflowEvent.RefreshStart)).toEqual([]);
    expect(b.of(PassflowEvent.Refresh)).toEqual([expect.objectContaining({ source: 'adopted', tokens: newer })]);
    expectRefreshOrder(b);
  });

  test('REQ-2 REQ-3 TEST-4 explicit freshness still sends after adopting the storage successor', async () => {
    const w = world(() => 'hold', { watchStorage: false });
    const initial = pair();
    w.seed(initial);
    const a = w.open('A');
    await w.ready();
    const newer = successor(initial.refresh_token);
    w.seed(newer);

    const pending = observe(a.sdk.refreshToken());
    await w.run();
    expect(w.requests.map((r) => r.token)).toEqual([newer.refresh_token]);
    expect(a.sdk.getCachedTokens()).toEqual(newer);
    const newest = successor(newer.refresh_token);
    w.requests[0]!.resolve(newest);
    await w.run();
    expect(pending).toMatchObject({ status: 'resolved', value: newest });
    expect(a.of(PassflowEvent.Refresh).map((p) => p.source)).toContain('adopted');
    const refreshes = a.of(PassflowEvent.Refresh);
    expect(refreshes[refreshes.length - 1]?.source).toBe('refresh');
  });

  test('REQ-6 TEST-6 five-second holder heartbeats prevent takeover during a long live request', async () => {
    const w = world(() => 'hold');
    w.seed(pair());
    const a = w.open('A');
    const b = w.open('B');
    await w.ready();
    observe(a.sdk.refreshToken());
    observe(b.sdk.getTokensWithRefresh());
    await w.run();
    const heartbeatCount = () => w.hub.posted.filter((m) => (m.data as { type?: string }).type === 'still-refreshing').length;
    const initialCount = heartbeatCount();
    await w.run(4_999);
    expect(heartbeatCount()).toBe(initialCount);
    await w.run(1);
    expect(heartbeatCount()).toBe(initialCount + 1);
    for (let i = 0; i < 5; i += 1) await w.run(5_000);
    expect(heartbeatCount()).toBe(initialCount + 6);
    expect(w.requests).toHaveLength(1);
    expect(b.of(PassflowEvent.RefreshStart)).toEqual([]);
    expectNoEnd(a, b);
  });

  test('REQ-4 REQ-6 TEST-7 only one waiter takes over at 20 seconds and the old answer cannot overwrite', async () => {
    const w = world(() => 'hold');
    const initial = pair();
    w.seed(initial);
    const a = w.open('A');
    const b = w.open('B');
    const c = w.open('C');
    await w.ready();
    observe(a.sdk.refreshToken());
    observe(b.sdk.getTokensWithRefresh());
    observe(c.sdk.getTokensWithRefresh());
    await w.run();
    w.clock.freeze(a.id);

    await w.run(19_999);
    expect(w.requests).toHaveLength(1);
    await w.run(1);
    expect(w.requests).toHaveLength(2);
    const winner = successor(initial.refresh_token);
    w.requests[1]!.resolve(winner);
    await w.run();
    expect(b.sdk.getCachedTokens()).toEqual(winner);
    expect(c.sdk.getCachedTokens()).toEqual(winner);

    w.clock.thaw(a.id);
    w.requests[0]!.resolve(successor(initial.refresh_token, 50));
    await w.run();
    expect(await w.stored()).toEqual(winner);
    expect(a.sdk.getCachedTokens()).toEqual(winner);
    expect(w.requests).toHaveLength(2);
    expect(w.hub.posted.filter((m) => (m.data as { type?: string }).type === 'takeover')).toHaveLength(1);
    expectNoEnd(a, b, c);
  });

  test('REQ-6 TEST-8 killing an outage holder preserves nextAt and attempt count on handover', async () => {
    const w = world(() => ({ error: http() }));
    w.seed(pair());
    const a = w.open('A');
    const b = w.open('B');
    await w.ready();
    observe(a.sdk.refreshToken());
    observe(b.sdk.refreshToken());
    await w.run(20_000);
    expect(w.requests.map((r) => r.at)).toEqual([0, 1_000, 4_000, 14_000]);
    w.kill(a);
    await w.run(23_999);
    expect(w.requests).toHaveLength(4);
    await w.run(1);
    expect(w.requests.map((r) => r.at)).toEqual([0, 1_000, 4_000, 14_000, 44_000]);
    await w.run(60_000);
    expect(w.requests.map((r) => r.at)).toEqual([0, 1_000, 4_000, 14_000, 44_000, 104_000]);
    expect(b.of(PassflowEvent.RefreshStart)).toHaveLength(2);
    expectNoEnd(b);
  });
});
