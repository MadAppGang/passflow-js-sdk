import { afterEach, describe, expect, test, vi } from 'vitest';
import {
  type PassflowConfig,
  PassflowError,
  PassflowEvent,
  TokenDeliveryMode,
  totpFactor,
  UpgradeUnavailableError,
} from '../../lib/index';
import {
  BASE,
  errors,
  expectClearAtEnd,
  expectNoEnd,
  expectRefreshOrder,
  observe,
  pair,
  type World,
  world,
} from './public-fixture';

const BFF = {
  enabled: true,
  callbackUrl: '/bff/callback',
  refreshUrl: '/bff/refresh',
  logoutUrl: '/bff/logout',
  statusUrl: '/bff/status',
};

function response(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get: (name: string) => headers[name.toLowerCase()] ?? null },
    json: async () => body,
  } as unknown as Response;
}

interface FetchRecord {
  url: string;
  at: number;
  init?: RequestInit;
  resolve(value: Response): void;
  reject(error: unknown): void;
}

function bff(
  answer: (call: FetchRecord, index: number) => Response | 'hold',
  mode: 'custom' | 'none' = 'custom',
  tokenExchange: PassflowConfig['tokenExchange'] = BFF,
) {
  const w = world(() => 'hold', { mode, config: { tokenExchange } });
  const refreshes: FetchRecord[] = [];
  const logouts: FetchRecord[] = [];
  vi.stubGlobal('fetch', (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    return new Promise<Response>((resolve, reject) => {
      const call: FetchRecord = { url, init, at: w.now(), resolve, reject };
      if (url === BFF.refreshUrl) {
        refreshes.push(call);
        const value = answer(call, refreshes.length - 1);
        if (value !== 'hold') resolve(value);
      } else if (url === BFF.logoutUrl) {
        logouts.push(call);
        resolve(response(200, { status: 'ok' }));
      } else if (url === BFF.statusUrl) resolve(response(200, { valid: true }));
      else if (url === BFF.callbackUrl) resolve(response(200, { status: 'ok' }));
      else reject(new Error('Unexpected BFF URL: ' + url));
    });
  });
  return { w, refreshes, logouts };
}

function seedId(w: World) {
  const initial = pair(undefined, { expired: false });
  w.seed({ id_token: initial.id_token, scopes: initial.scopes });
  return initial;
}

const cleanup: (() => void)[] = [];
afterEach(() => {
  for (const disable of cleanup.splice(0)) disable();
});

describe('BFF unreadable-token refresh through fetch only', () => {
  test('REQ-25 TEST-66 refresh is POST with credentials and stores only the new id token', async () => {
    const next = pair(1_900_000_010, { expired: false });
    const { w, refreshes } = bff(() =>
      response(200, {
        id_token: next.id_token,
        csrf_token: 'new-csrf',
        token_delivery: 'cookie',
      }),
    );
    seedId(w);
    const a = w.open('A');
    await w.ready();
    expect(a.sdk.getDeliveryMode()).toBe(TokenDeliveryMode.BFF);
    const pending = observe(a.sdk.refreshToken());
    await w.run();
    expect(pending.status).toBe('resolved');
    expect(refreshes).toHaveLength(1);
    expect(refreshes[0]).toMatchObject({ url: '/bff/refresh', init: { method: 'POST', credentials: 'include' } });
    expect(w.requests).toEqual([]);
    expect(a.sdk.getCachedTokens()).toMatchObject({ id_token: next.id_token });
    expect(a.sdk.getCachedTokens()?.access_token).toBeUndefined();
    expect(a.sdk.getCachedTokens()?.refresh_token).toBeUndefined();
    expect((await w.stored())?.id_token).toBe(next.id_token);
    expect(a.of(PassflowEvent.Refresh).map((p) => p.source)).toEqual(['refresh']);
    expectRefreshOrder(a);
    expectNoEnd(a);
  });

  test.each([
    { status: 500, id: 'error.not.found', kind: 'auth' },
    { status: 429, id: 'error.token.invalid.error', kind: 'auth' },
    { status: 500, id: 'error.token.blocked', kind: 'blocked' },
    { status: 403, id: 'error.qa.unknown', kind: 'auth' },
    { status: 429, id: undefined, kind: 'transient' },
    { status: 503, id: undefined, kind: 'transient' },
  ])('REQ-7 REQ-13 REQ-25 TEST-67 BFF status=$status id=$id classifies $kind', async ({ status, id, kind }) => {
    const { w, refreshes } = bff(() =>
      response(
        status,
        id
          ? {
              error: { id, message: 'server failure' },
            }
          : {},
      ),
    );
    const initial = seedId(w);
    const a = w.open('A', { refreshStrikes: 2 });
    await w.ready();
    const pending = observe(a.sdk.refreshToken());
    await w.run();
    // Blocked reports the HTTP error immediately but settles callers only after the successor wait.
    if (kind === 'blocked') expect(pending.status).toBe('pending');
    else {
      expect(pending.status).toBe('rejected');
      expect(pending.error).toBeInstanceOf(PassflowError);
      expect(pending.error).toMatchObject({ status, id: id ?? 'error.http.' + status });
    }
    expect(refreshes).toHaveLength(1);
    expect(errors(a)).toEqual([
      expect.objectContaining({
        operation: 'refresh',
        source: 'refresh-token',
        refresh: expect.objectContaining({
          classification: kind,
          strikes: kind === 'auth' ? 1 : 0,
          willRetry: kind !== 'blocked',
        }),
      }),
    ]);
    expect(a.sdk.getCachedTokens()?.id_token).toBe(initial.id_token);
    expectNoEnd(a);
  });

  test('REQ-7 REQ-25 TEST-67 BFF network failure remains transient and retries through fetch', async () => {
    const failure = new TypeError('Failed to fetch');
    const { w, refreshes } = bff((call) => {
      call.reject(failure);
      return 'hold';
    });
    const initial = seedId(w);
    const a = w.open('A');
    await w.ready();
    const pending = observe(a.sdk.refreshToken());
    await w.run();
    expect(pending.error).toBe(failure);
    expect(errors(a)[0]?.refresh).toMatchObject({
      classification: 'transient',
      willRetry: true,
      strikes: 0,
      nextRetryAt: BASE + 1_000,
    });
    await w.run(1_000);
    expect(refreshes.map((r) => r.at)).toEqual([0, 1_000]);
    expect(a.sdk.getCachedTokens()?.id_token).toBe(initial.id_token);
    expectNoEnd(a);
  });

  test('REQ-15 REQ-25 TEST-68 BFF tabs share one POST and peer re-reads id token on session-refreshed', async () => {
    const { w, refreshes } = bff(() => 'hold');
    seedId(w);
    const a = w.open('A');
    const b = w.open('B');
    await w.ready();
    const callers = [a, b].map((tab) => observe(tab.sdk.refreshToken()));
    await w.run();
    expect(refreshes).toHaveLength(1);
    const next = pair(1_900_000_010, { expired: false });
    refreshes[0]!.resolve(response(200, { id_token: next.id_token, csrf_token: 'next-csrf' }));
    await w.run();
    expect(callers.map((caller) => caller.status)).toEqual(['resolved', 'resolved']);
    expect(w.requests).toEqual([]);
    for (const [tab, source] of [
      [a, 'refresh'],
      [b, 'adopted'],
    ] as const) {
      expect(tab.sdk.getCachedTokens()?.id_token).toBe(next.id_token);
      expect(tab.of(PassflowEvent.Refresh).map((p) => p.source)).toEqual([source]);
      expectRefreshOrder(tab);
    }
    expect(b.of(PassflowEvent.RefreshStart)).toEqual([]);
    expect(w.hub.posted.filter((m) => (m.data as { type?: string }).type === 'session-refreshed')).toHaveLength(1);
    expectNoEnd(a, b);
  });

  test('REQ-25 TEST-69 BFF transient preserves validity but final auth strike clears id/CSRF before SessionExpired', async () => {
    const initial = pair(undefined, { expired: false });
    const { w } = bff((_call, index) => {
      if (index === 0) return response(200, { id_token: initial.id_token, csrf_token: 'session-csrf' });
      if (index === 1) return response(503, {});
      return response(500, { error: { id: 'error.not.found', message: 'deleted user' } });
    });
    seedId(w);
    const a = w.open('A', { refreshStrikes: 1 });
    await w.ready();
    observe(a.sdk.refreshToken());
    await w.run();
    expect(a.sdk.isAuthenticated()).toBe(true);
    observe(a.sdk.refreshToken());
    await w.run();
    expect(a.sdk.isAuthenticated()).toBe(true);
    expect(a.sdk.getCachedTokens()?.id_token).toBe(initial.id_token);
    expect([...w.shared.items.values()]).toContain('session-csrf');
    expectNoEnd(a);
    await w.run(1_000);
    expect(a.sdk.isAuthenticated()).toBe(false);
    expect(a.sdk.getCachedTokens()).toBeUndefined();
    expect([...w.shared.items.values()]).not.toContain(initial.id_token);
    expect([...w.shared.items.values()]).not.toContain('session-csrf');
    expect(a.of(PassflowEvent.SessionExpired)).toEqual([{ reason: 'refresh_failed', origin: 'this-tab' }]);
    expect(a.of(PassflowEvent.RefreshRecovered)).toEqual([]);
    expectClearAtEnd(a);
  });

  test.each(['stored-id-successor', 'retry-once'] as const)(
    'REQ-8 REQ-25 TEST-70 blocked BFF fallback uses %s instead of signing out',
    async (path) => {
      vi.spyOn(Math, 'random').mockReturnValue(0);
      const next = pair(1_900_000_010, { expired: false });
      const { w, refreshes } = bff(
        (_call, index) =>
          index === 0
            ? response(400, { error: { id: 'error.token.blocked', message: 'already used' } })
            : response(200, { id_token: next.id_token }),
        'none',
      );
      seedId(w);
      const a = w.open('A');
      await w.ready();
      observe(a.sdk.refreshToken());
      await w.run();
      const joined = observe(a.sdk.refreshToken());
      if (path === 'stored-id-successor') {
        await w.run(500);
        w.seed({ id_token: next.id_token });
        a.wake();
        await w.run();
        expect(joined.status).toBe('resolved');
        expect(refreshes).toHaveLength(1);
      } else {
        await w.run(999);
        expect(refreshes).toHaveLength(1);
        expect(joined.status).toBe('pending');
        await w.run(1);
        expect(refreshes.map((r) => r.at)).toEqual([0, 1_000]);
        expect(joined.status).toBe('resolved');
      }
      await w.run(25_000);
      expectNoEnd(a);
      expect(a.sdk.getCachedTokens()?.id_token).toBe(next.id_token);
      expect(refreshes).toHaveLength(path === 'retry-once' ? 2 : 1);
    },
  );

  test('REQ-22 REQ-25 TEST-71 BFF refuses upgrade before a request or RefreshStart', async () => {
    const { w, refreshes } = bff(() => response(200, {}));
    seedId(w);
    const a = w.open('A');
    await w.ready();
    cleanup.push(
      a.sdk.upgrade.enable({
        factors: [totpFactor],
        prompt: async (request) => {
          request.onFactorSelected('totp');
          return { type: 'submit', factor: 'totp', code: '123456' };
        },
      }),
    );
    const result = observe(a.sdk.upgrade());
    await w.run();
    expect(result.status).toBe('rejected');
    expect(result.error).toBeInstanceOf(UpgradeUnavailableError);
    expect(refreshes).toEqual([]);
    expect(w.requests).toEqual([]);
    expect(a.of(PassflowEvent.RefreshStart)).toEqual([]);
    expectNoEnd(a);
  });

  test.each(['answer-first', 'timeout'] as const)(
    'REQ-17 REQ-25 REQ-26 TEST-72 BFF logout waits for in-flight refresh or its five-second bound (%s)',
    async (path) => {
      const { w, refreshes, logouts } = bff(() => 'hold');
      seedId(w);
      const a = w.open('A');
      const b = w.open('B');
      await w.ready();
      observe(a.sdk.refreshToken());
      await w.run();
      const logout = observe(b.sdk.logOut());
      await w.run();
      expect(logouts).toEqual([]);
      const next = pair(1_900_000_010, { expired: false });
      if (path === 'answer-first') {
        await w.run(2_000);
        expect(logouts).toEqual([]);
        refreshes[0]!.resolve(response(200, { id_token: next.id_token }));
        await w.run();
        expect(logouts).toHaveLength(1);
        expect(logouts[0]?.at).toBe(2_000);
      } else {
        await w.run(4_999);
        expect(logouts).toEqual([]);
        await w.run(1);
        expect(logouts).toHaveLength(1);
        expect(logouts[0]?.at).toBe(5_000);
        refreshes[0]!.resolve(response(200, { id_token: next.id_token }));
        await w.run();
      }
      expect(logout.status).toBe('resolved');
      for (const [tab, origin] of [
        [a, 'other-tab'],
        [b, 'this-tab'],
      ] as const) {
        expect(tab.of(PassflowEvent.SignOut)).toEqual([expect.objectContaining({ origin, userId: 'qa-user' })]);
        expectClearAtEnd(tab);
        expect(tab.sdk.getCachedTokens()).toBeUndefined();
        expect(tab.of(PassflowEvent.SessionExpired)).toEqual([]);
      }
      expect([...w.shared.items.values()]).not.toContain(next.id_token);
      expect(logouts[0]?.init?.credentials).toBe('include');
      expect(logouts[0]?.init?.method).toBe('POST');
    },
  );

  test('REQ-17 REQ-25 REQ-26 TEST-72 BFF logout bypasses an idle backoff holder and stops the old schedule', async () => {
    const { w, refreshes, logouts } = bff(() => response(503, {}));
    seedId(w);
    const a = w.open('A');
    const b = w.open('B');
    await w.ready();
    observe(a.sdk.refreshToken());
    await w.run(20_000);
    expect(refreshes.map((r) => r.at)).toEqual([0, 1_000, 4_000, 14_000]);
    const logout = observe(b.sdk.logOut());
    await w.run();
    expect(logout.status).toBe('resolved');
    expect(logouts.map((r) => r.at)).toEqual([20_000]);
    await w.run(90_000);
    expect(refreshes).toHaveLength(4);
    for (const tab of [a, b]) {
      expect(tab.of(PassflowEvent.SignOut)).toHaveLength(1);
      expect(tab.of(PassflowEvent.RefreshRecovered)).toEqual([]);
    }
  });

  test('REQ-25 TEST-73 BFF without refreshUrl preserves JSON request fallback', async () => {
    const { w, refreshes } = bff(() => response(200, {}), 'custom', {
      enabled: true,
      callbackUrl: BFF.callbackUrl,
    });
    const initial = pair();
    w.seed(initial, { tokenExchange: undefined });
    const a = w.open('A');
    await w.ready();
    const pending = observe(a.sdk.refreshToken());
    await w.run();
    expect(w.requests.map((r) => r.token)).toEqual([initial.refresh_token]);
    expect(refreshes).toEqual([]);
    w.requests[0]!.resolve(pair(1_900_000_010, { expired: false }));
    await w.run();
    expect(pending.status).toBe('resolved');
    expectNoEnd(a);
  });
  test('REQ-25 TEST-66 BFF answer identity cannot replace the requesting user with a foreign id token', async () => {
    const foreign = pair(undefined, { sub: 'foreign-user', sid: 'foreign-session', expired: false });
    const { w, refreshes } = bff(() => response(200, { id_token: foreign.id_token }));
    seedId(w);
    const a = w.open('A');
    await w.ready();
    const pending = observe(a.sdk.refreshToken());
    await w.run();
    expect(refreshes).toHaveLength(1);
    expect(pending.status).toBe('rejected');
    expect(a.sdk.getCachedTokens()?.id_token).not.toBe(foreign.id_token);
    expect([...w.shared.items.values()]).not.toContain(foreign.id_token);
    expect(a.of(PassflowEvent.Refresh).some((event) => event.tokens?.id_token === foreign.id_token)).toBe(false);
  });
});
