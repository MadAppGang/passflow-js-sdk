import { describe, expect, test, vi } from 'vitest';
import { PassflowEvent, type RefreshChannel, RefreshErrorId } from '../../lib/index';
import { createFakeChannelHub } from '../refresh/fakes';
import { errors, expectNoEnd, http, observe, pair, SECOND, successor, tokenMessage, type World, world } from './public-fixture';

function installBrowser(w: World) {
  const names: string[] = [];
  const hubs = new Map<string, ReturnType<typeof createFakeChannelHub>>();
  let channelId = 0;
  const browserLocks = w.locks.forTab('browser-task-source');
  vi.stubGlobal('navigator', {
    userAgent: 'QA browser',
    language: 'en',
    onLine: true,
    locks: browserLocks,
  });
  vi.stubGlobal(
    'BroadcastChannel',
    class {
      constructor(name: string) {
        names.push(name);
        let hub = hubs.get(name);
        if (!hub) {
          hub = createFakeChannelHub(w.clock);
          hubs.set(name, hub);
        }
        return hub.channel(`browser-channel-${channelId++}`) as unknown as RefreshChannel;
      }
    },
  );
  return { names, hubs, browserLocks };
}

describe('default transport eligibility, local fallback and public teardown', () => {
  test('REQ-1 REQ-29 TEST-5 storage prefixes use separate browser wire namespaces', async () => {
    const w = world(() => 'hold', { mode: 'browser' });
    const browser = installBrowser(w);
    const one = pair(undefined, { sub: 'app-one' });
    const two = pair(undefined, { sub: 'app-two' });
    w.seed(one, { keyStoragePrefix: 'one' });
    w.seed(two, { keyStoragePrefix: 'two' });
    const a = w.open('A', { keyStoragePrefix: 'one' });
    const b = w.open('B', { keyStoragePrefix: 'one' });
    const c = w.open('C', { keyStoragePrefix: 'two' });
    const d = w.open('D', { keyStoragePrefix: 'two' });
    await w.ready();
    const results = [a, b, c, d].map((tab) => observe(tab.sdk.refreshToken()));
    await w.run();
    expect(w.requests).toHaveLength(2);
    expect(w.locks.isHeld('passflow-refresh:one')).toBe(true);
    expect(w.locks.isHeld('passflow-refresh:two')).toBe(true);
    expect(browser.names.sort()).toEqual(['passflow-auth:one', 'passflow-auth:one', 'passflow-auth:two', 'passflow-auth:two']);
    for (const request of w.requests) request.resolve(successor(request.token));
    await w.run();
    expect(results.every((r) => r.status === 'resolved')).toBe(true);
    for (const tab of [a, b]) expect(tab.sdk.getCachedTokens()).toEqual(successor(one.refresh_token));
    for (const tab of [c, d]) expect(tab.sdk.getCachedTokens()).toEqual(successor(two.refresh_token));
    expectNoEnd(a, b, c, d);
  });

  test('REQ-1 REQ-4 REQ-21 TEST-51 explicit none permits two local sends but CAS drops the later answer', async () => {
    const w = world(() => 'hold', { mode: 'none' });
    const initial = pair();
    w.seed(initial);
    const a = w.open('A');
    const b = w.open('B');
    await w.ready();
    const results = [observe(a.sdk.refreshToken()), observe(b.sdk.refreshToken())];
    await w.run();
    expect(w.requests.map((r) => r.token)).toEqual([initial.refresh_token, initial.refresh_token]);
    const saved = successor(initial.refresh_token);
    w.requests[1]!.resolve(saved);
    await w.run();
    w.requests[0]!.resolve(successor(initial.refresh_token, 50));
    await w.run();
    for (const result of results) expect(result).toMatchObject({ status: 'resolved', value: saved });
    expect(a.sdk.getCachedTokens()).toEqual(saved);
    expect(a.of(PassflowEvent.Refresh).map((p) => p.source)).toEqual(['adopted']);
    expect(errors(a)).toEqual([]);
    expect(await w.stored()).toEqual(saved);
    expectNoEnd(a, b);
  });

  test('REQ-21 TEST-52 none instances keep separate retries and never delete outage tokens', async () => {
    vi.spyOn(Math, 'random').mockReturnValue(0);
    const w = world(() => ({ error: http() }), { mode: 'none' });
    const initial = pair();
    w.seed(initial);
    const a = w.open('A');
    const b = w.open('B');
    await w.ready();
    observe(a.sdk.refreshToken());
    observe(b.sdk.refreshToken());
    await w.run();
    expect(w.requests.map((r) => r.at)).toEqual([0, 0]);
    await w.run(999);
    expect(w.requests).toHaveLength(2);
    await w.run(1);
    expect(w.requests.map((r) => r.at)).toEqual([0, 0, 1_000, 1_000]);
    for (const tab of [a, b]) {
      expect(tab.sdk.getCachedTokens()).toEqual(initial);
      expect(tab.of(PassflowEvent.RefreshFailing)).toEqual([expect.objectContaining({ origin: 'this-tab' })]);
    }
    expectNoEnd(a, b);
  });

  test.each(['locks', 'channel'] as const)(
    'REQ-1 REQ-21 TEST-53 missing browser %s warns once on first refresh, never on construction',
    async (missing) => {
      vi.spyOn(Math, 'random').mockReturnValue(0);
      const warnings: string[] = [];
      vi.spyOn(console, 'warn').mockImplementation((...args: unknown[]) => {
        warnings.push(args.map(String).join(' '));
      });
      const w = world(() => ({ error: http() }), { mode: 'browser' });
      installBrowser(w);
      if (missing === 'locks') vi.stubGlobal('navigator', { userAgent: 'QA browser' });
      else vi.stubGlobal('BroadcastChannel', undefined);
      w.seed(pair());
      const a = w.open('A');
      await w.ready();
      expect(warnings).toEqual([]);
      observe(a.sdk.refreshToken());
      await w.run();
      expect(warnings).toHaveLength(1);
      expect(warnings[0]).toMatch(/^\[passflow\]/);
      await w.run(1_000);
      const joined = observe(a.sdk.refreshToken());
      await w.run(3_000);
      expect(joined.status).toBe('rejected');
      expect(w.requests).toHaveLength(3);
      expect(warnings).toHaveLength(1);
    },
  );

  test.each(['explicit-none', 'per-tab-storage', 'ios', 'android', 'no-window'] as const)(
    'REQ-1 REQ-21 TEST-54 fallback condition %s is silent',
    async (condition) => {
      const warnings: unknown[][] = [];
      vi.spyOn(console, 'warn').mockImplementation((...args) => {
        warnings.push(args);
      });
      vi.stubGlobal('navigator', { userAgent: 'QA platform' });
      vi.stubGlobal('BroadcastChannel', undefined);
      if (condition === 'no-window') {
        vi.stubGlobal('window', undefined);
        vi.stubGlobal('document', undefined);
      }
      const w = world(() => ({ error: http() }), {
        mode: condition === 'explicit-none' ? 'none' : 'browser',
        sharedHint: condition !== 'per-tab-storage',
        device: condition === 'ios' || condition === 'android' ? condition : 'web',
      });
      w.seed(pair());
      const a = w.open('A');
      await w.ready();
      observe(a.sdk.refreshToken());
      await w.run();
      expect(w.requests).toHaveLength(1);
      expect(warnings).toEqual([]);
    },
  );

  test('REQ-1 REQ-21 TEST-55 default browser coordination accepts an adapter wrapping shared storage', async () => {
    const warnings: unknown[][] = [];
    vi.spyOn(console, 'warn').mockImplementation((...args) => {
      warnings.push(args);
    });
    const w = world(() => 'hold', { mode: 'browser' });
    const browser = installBrowser(w);
    const initial = pair();
    w.seed(initial);
    const a = w.open('A');
    const b = w.open('B');
    await w.ready();
    const first = observe(a.sdk.refreshToken());
    const second = observe(b.sdk.refreshToken());
    await w.run();
    expect(w.requests).toHaveLength(1);
    expect(w.locks.isHeld('passflow-refresh')).toBe(true);
    expect(browser.names).toEqual(['passflow-auth', 'passflow-auth']);
    w.requests[0]!.resolve(successor(initial.refresh_token));
    await w.run();
    expect(first.status).toBe('resolved');
    expect(second.status).toBe('resolved');
    expect(b.of(PassflowEvent.RefreshStart)).toEqual([]);
    expect(warnings).toEqual([]);
  });

  test.each(['foreground', 'storage-event'] as const)(
    'REQ-21 TEST-56 none adopts newer shared storage on %s without HTTP',
    async (trigger) => {
      const w = world(() => 'hold', { mode: 'none' });
      const initial = pair();
      w.seed(initial);
      const a = w.open('A');
      await w.ready();
      const issued = successor(initial.refresh_token);
      w.seed(issued);
      if (trigger === 'foreground') a.wake();
      else {
        const key = [...w.shared.items].find(([, value]) => value === issued.refresh_token)?.[0];
        expect(key).toBeDefined();
        window.dispatchEvent(new StorageEvent('storage', { key: key!, newValue: issued.refresh_token }));
      }
      await w.run();
      expect(a.sdk.getCachedTokens()).toEqual(issued);
      expect(a.sdk.getParsedTokens()?.refresh_token?.iat).toBe(SECOND - 99);
      expect(a.of(PassflowEvent.Refresh)).toEqual([expect.objectContaining({ source: 'adopted', tokens: issued })]);
      expect(w.requests).toEqual([]);
    },
  );

  test.each(['retry', 'blocked-wait', 'in-flight'] as const)(
    'REQ-23 TEST-57 dispose rejects pending %s callers and stops future requests/events',
    async (state) => {
      const w = world(() =>
        state === 'in-flight'
          ? 'hold'
          : {
              error: state === 'retry' ? http() : http('error.token.blocked', 400),
            },
      );
      const initial = pair();
      w.seed(initial);
      const a = w.open('A');
      await w.ready();
      const first = observe(a.sdk.refreshToken());
      await w.run();
      const pending = state === 'in-flight' ? first : observe(a.sdk.refreshToken());
      await w.run();
      expect(pending.status).toBe('pending');
      w.close(a);
      await w.run();
      const eventCount = a.events.length;
      expect(pending).toMatchObject({ status: 'rejected', error: { id: RefreshErrorId.disposed } });
      const next = successor(initial.refresh_token);
      w.seed(next);
      w.post(tokenMessage(initial, next));
      a.wake();
      if (state === 'in-flight') w.requests[0]!.resolve(next);
      await w.run(120_000);
      expect(w.requests).toHaveLength(1);
      expect(a.events).toHaveLength(eventCount);
    },
  );

  test('REQ-23 TEST-58 disposing a queued tab leaves the other joiners able to receive the answer', async () => {
    const w = world(() => 'hold');
    const initial = pair();
    w.seed(initial);
    const a = w.open('A');
    const b = w.open('B');
    const c = w.open('C');
    await w.ready();
    observe(a.sdk.refreshToken());
    await w.run();
    const removed = observe(b.sdk.refreshToken());
    const pending = observe(c.sdk.getTokensWithRefresh());
    await w.run();
    w.close(b);
    await w.run();
    expect(removed).toMatchObject({ status: 'rejected', error: { id: RefreshErrorId.disposed } });
    const count = b.events.length;
    const issued = successor(initial.refresh_token);
    w.requests[0]!.resolve(issued);
    await w.run();
    expect(pending).toMatchObject({ status: 'resolved', value: issued });
    expect(b.events).toHaveLength(count);
    expect(w.requests).toHaveLength(1);
  });

  test('REQ-23 TEST-58 beforeunload and pagehide do not dispose the live page refresh path', async () => {
    const w = world();
    w.seed(pair());
    const a = w.open('A');
    await w.ready();
    a.unload();
    window.dispatchEvent(new Event('beforeunload'));
    window.dispatchEvent(new Event('pagehide'));
    const pending = observe(a.sdk.refreshToken());
    await w.run();
    expect(pending.status).toBe('resolved');
    expect(w.requests).toHaveLength(1);
    expectNoEnd(a);
  });

  test('REQ-28 TEST-59 token-check refreshes by expiry before the 60-second output flag check', async () => {
    const w = world(() => 'success', { mode: 'none' });
    w.seed(pair(undefined, { expired: false, exp: SECOND + 31 }));
    const a = w.open('A');
    await w.ready();
    await w.run(32_000);
    expect(w.requests).toEqual([]);
    expect(a.of(PassflowEvent.TokenCacheExpired)).toEqual([]);
    const pending = observe(a.sdk.getTokensWithRefresh());
    await w.run();
    expect(pending.status).toBe('resolved');
    expect(w.requests).toHaveLength(1);
    expect(a.of(PassflowEvent.TokenCacheExpired)).toEqual([{ isExpired: false }]);
  });

  test('REQ-28 TEST-59 interval and foreground expiry observation emit an output flag without refreshing', async () => {
    const w = world(() => 'success', { mode: 'none' });
    // Start well outside the early-expiry window. A one-second token may already flag expiry
    // during initialization, whose events ready() clears; repeated true events are not promised.
    w.seed(pair(undefined, { expired: false, exp: SECOND + 120 }));
    const a = w.open('A');
    await w.ready();
    await w.run(180_000);
    a.wake();
    await w.run();
    expect(w.requests).toEqual([]);
    expect(a.of(PassflowEvent.TokenCacheExpired)).toContainEqual({ isExpired: true });
    observe(a.sdk.getTokensWithRefresh());
    await w.run();
    expect(w.requests).toHaveLength(1);
    expect(a.of(PassflowEvent.TokenCacheExpired)).toContainEqual({ isExpired: false });
  });
  test('REQ-1 TEST-55 custom coordinator never falls back on a non-web per-tab-storage host', async () => {
    const warnings: unknown[][] = [];
    vi.spyOn(console, 'warn').mockImplementation((...args) => {
      warnings.push(args);
    });
    vi.stubGlobal('navigator', {});
    vi.stubGlobal('BroadcastChannel', undefined);
    const w = world(() => 'hold', { device: 'android', sharedHint: false });
    const initial = pair();
    w.seed(initial);
    const a = w.open('A');
    const b = w.open('B');
    await w.ready();
    const callers = [a, b].map((tab) => observe(tab.sdk.refreshToken()));
    await w.run();
    expect(w.requests).toHaveLength(1);
    w.requests[0]!.resolve(successor(initial.refresh_token));
    await w.run();
    expect(callers.map((caller) => caller.status)).toEqual(['resolved', 'resolved']);
    expect(b.of(PassflowEvent.RefreshStart)).toEqual([]);
    expect(warnings).toEqual([]);
  });
});
