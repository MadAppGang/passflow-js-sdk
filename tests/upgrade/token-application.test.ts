// @vitest-environment node
// REQ-7, REQ-52–55, REQ-96–97: C38–C41 / T-S5 / T-S6.
// The real AuthService is the token-application subject; only its I/O ports are faked.
// No module mocks, private fields, epoch-field access or mock invocation assertions.
import { afterEach, describe, expect, test, vi } from 'vitest';
import { AuthService } from '../../lib/services/auth-service';
import { StorageManager } from '../../lib/storage';
import { PassflowEvent } from '../../lib/store';
import { isUpgradeSessionChanged } from '../../lib/upgrade/core';
import { createUpgradeFacade } from '../../lib/upgrade/facade';
import { createMockPlatform } from '../helpers/mock-platform';
import { FakeStorage } from '../storage/fake-storage';
import { challengeResponse, deferred } from './fetch-fixtures';
import { challenge, observed, tokensFor } from './pass2-fixtures';

type AuthArgs = ConstructorParameters<typeof AuthService>;
type AuthResponse = Awaited<ReturnType<AuthService['refreshToken']>>;

// The token store is the real StorageManager over an in-memory backing, so an identity read goes
// through the same path it takes in production. State is observable through real service getters
// and public auth events, not spy call counts.
function applicationFixture(initial = tokensFor('A', 'session-A')) {
  const backing = new FakeStorage();
  const storage = new StorageManager({ storage: backing as unknown as Storage });
  storage.saveTokens(initial);
  let cached: typeof initial | undefined = initial;
  let login = initial;
  const reply = deferred<AuthResponse>();
  const entered = deferred<void>();
  const events: { event: unknown; data: unknown }[] = [];
  const warnings: unknown[][] = [];
  vi.spyOn(console, 'warn').mockImplementation((...args) => {
    warnings.push(args);
  });
  const parsed = () => {
    if (!cached) return undefined;
    const decode = (token: string) => JSON.parse(Buffer.from(token.split('.')[1]!, 'base64url').toString());
    return {
      access_token: decode(cached.access_token),
      id_token: decode(cached.id_token),
      refresh_token: decode(cached.refresh_token),
      scopes: cached.scopes,
    };
  };
  const cache = {
    setTokensCache: (tokens?: typeof initial) => {
      cached = tokens && { ...tokens };
    },
    getTokens: () => cached,
    getParsedTokens: parsed,
    isExpired: () => false,
    getTokensWithRefresh: async () => cached,
    initialize: () => {},
    startTokenCheck: () => {},
    isRefreshing: false,
    tokenExpiredFlag: false,
  };
  const service = new AuthService(
    {
      signIn: async () => login,
      logOut: async () => ({ status: 'ok' }),
      refreshToken: async () => {
        entered.resolve();
        return reply.promise;
      },
    } as unknown as AuthArgs[0],
    { getDeviceId: () => 'qa-device' } as unknown as AuthArgs[1],
    storage,
    {
      notify: (event: unknown, data: unknown) => {
        events.push({ event, data });
      },
    } as unknown as AuthArgs[3],
    cache as unknown as AuthArgs[4],
    initial.scopes,
    false,
    'https://auth.example',
    {},
    'qa',
    undefined,
    createMockPlatform(),
  );
  return {
    service,
    reply,
    entered,
    events,
    warnings,
    storage: () => storage.getTokens(),
    async relogin(sub: string, sid: string) {
      login = tokensFor(sub, sid);
      await service.logOut();
      await service.signIn({ email: sub.toLowerCase() + '@example.com', password: 'qa-password' });
      return { ...storage.getTokens()! };
    },
    async signInWithCookieDelivery() {
      login = { ...tokensFor('A', 'session-A'), token_delivery: 'cookie' } as typeof initial;
      await service.logOut();
      await service.signIn({ email: 'a@example.com', password: 'qa-password' });
    },
    // Corrupts the stored access token, the one source `readSessionPin` reads the identity from.
    makeUnreadable() {
      const accessToken = storage.getTokens()!.access_token;
      for (const [key, value] of backing.data) {
        if (value === accessToken) backing.setItem(key, 'not-a-jwt');
      }
    },
    failStorageReads() {
      vi.spyOn(backing, 'getItem').mockImplementation(() => {
        throw new Error('storage is not available');
      });
    },
  };
}
afterEach(() => vi.restoreAllMocks());

describe('token application identity pin', () => {
  test.each([
    { label: 'different user', sub: 'B', sid: 'session-B' },
    { label: 'same user, different session', sub: 'A', sid: 'session-A-new' },
  ])('REQ-52 REQ-96 C38 T-S5 discards delayed tokens for $label without ending the live session', async ({ sub, sid }) => {
    const f = applicationFixture();
    const pin = f.service.readSessionPin();
    expect(pin).toEqual({ sub: 'A', sid: 'session-A' });
    const result = observed(f.service.refreshToken({ type: 'totp', assertion: { code: '123456' } }, pin));
    await f.entered.promise;

    const live = await f.relogin(sub, sid);
    const checkpoint = f.events.length;
    f.reply.resolve(tokensFor('A', 'session-A', '2'));

    expect(await result).toMatchObject({ ok: false, error: { code: 'upgrade_session_changed' } });
    expect(await f.service.getTokens(false)).toEqual(live);
    expect(f.storage()).toEqual(live);
    expect(f.service.readSessionPin()).toEqual({ sub, sid });
    expect(
      f.events.slice(checkpoint).filter((e) => e.event === PassflowEvent.SignOut || e.event === PassflowEvent.Refresh),
    ).toEqual([]);
  });

  test('REQ-53 REQ-96 C39 identity still rejects when the facade receives no epoch-change notifications', async () => {
    const f = applicationFixture();
    // Public epoch input is held constant: no listener is ever notified. No private epoch is read.
    const facade = createUpgradeFacade({
      platform: createMockPlatform(),
      passflowDomain: { origin: 'https://auth.example' },
      canCommit: () => ({ ok: true }),
      startUpgrade: async () => {
        throw new Error('TOTP must not prepare');
      },
      commitRefresh: async (upgrade, pin) => {
        await f.service.refreshToken(upgrade, pin);
      },
      readSessionPin: () => f.service.readSessionPin(),
      onSessionChange: () => () => {},
    });
    const disable = facade.enable({
      backend: 'https://app.example',
      interceptFetch: false,
      prompt: async (request) => {
        request.onFactorSelected('totp');
        return { type: 'submit', factor: 'totp', code: '123456' };
      },
    });
    const original = challengeResponse();
    let dispatches = 0;
    try {
      const result = facade.withAuth(async () => {
        dispatches++;
        return original;
      })('https://app.example/private');
      await f.entered.promise;
      const live = await f.relogin('B', 'session-B');
      const checkpoint = f.events.length;
      f.reply.resolve(tokensFor('A', 'session-A', '2'));

      const response = await result;
      expect(response).toBe(original);
      expect(isUpgradeSessionChanged(response)).toBe(true);
      expect(response.bodyUsed).toBe(false);
      expect(dispatches).toBe(1);
      expect(await f.service.getTokens(false)).toEqual(live);
      expect(f.storage()).toEqual(live);
      expect(
        f.events.slice(checkpoint).filter((e) => e.event === PassflowEvent.SignOut || e.event === PassflowEvent.Refresh),
      ).toEqual([]);
    } finally {
      disable();
    }
  });

  test('REQ-54 REQ-97 C40 T-S6 applies matching tokens once and replays normally', async () => {
    const f = applicationFixture();
    const facade = createUpgradeFacade({
      platform: createMockPlatform(),
      passflowDomain: { origin: 'https://auth.example' },
      canCommit: () => ({ ok: true }),
      startUpgrade: async () => {
        throw new Error('unexpected prepare');
      },
      readSessionPin: () => f.service.readSessionPin(),
      commitRefresh: async (upgrade, pin) => {
        await f.service.refreshToken(upgrade, pin);
      },
      readObtainedBar: () => ({ level: 2, acrValues: '2' }),
    });
    const disable = facade.enable({
      backend: 'https://app.example',
      interceptFetch: false,
      prompt: async (request) => {
        request.onFactorSelected('totp');
        return { type: 'submit', factor: 'totp', code: '123456' };
      },
    });
    let dispatches = 0;
    const success = new Response('protected result');
    try {
      const result = facade.withAuth(async () => (++dispatches === 1 ? challengeResponse() : success))(
        'https://app.example/private',
      );
      await f.entered.promise;
      const elevated = tokensFor('A', 'session-A', '2');
      f.reply.resolve(elevated);
      expect(await result).toBe(success);
      expect(await f.service.getTokens(false)).toEqual(elevated);
      expect(f.storage()).toEqual(elevated);
      expect(f.events.filter((e) => e.event === PassflowEvent.Refresh)).toHaveLength(1);
      expect(f.events.filter((e) => e.event === PassflowEvent.SignOut)).toEqual([]);
      expect(dispatches).toBe(2);
    } finally {
      disable();
    }
  });

  test('C38 C41 cookie delivery: a captured pin with no identity at application discards the tokens', async () => {
    const f = applicationFixture();
    const pin = f.service.readSessionPin();
    await f.signInWithCookieDelivery();
    const before = f.storage();
    const checkpoint = f.events.length;
    const result = observed(f.service.refreshToken({ type: 'totp', assertion: { code: '123456' } }, pin));
    await f.entered.promise;
    f.reply.resolve(tokensFor('A', 'session-A', '2'));

    expect(await result).toMatchObject({ ok: false, error: { code: 'upgrade_session_changed' } });
    expect(f.storage()).toEqual(before);
    expect(
      f.events.slice(checkpoint).filter((e) => e.event === PassflowEvent.SignOut || e.event === PassflowEvent.Refresh),
    ).toEqual([]);
    expect(f.warnings).toHaveLength(1);
  });

  test('C41 an identity read that throws reads as no identity', () => {
    const f = applicationFixture();
    f.failStorageReads();
    expect(f.service.readSessionPin()).toBeUndefined();
  });

  test('REQ-55 C41 captured pin fails closed if application-time identity becomes unreadable', async () => {
    const f = applicationFixture();
    const pin = f.service.readSessionPin();
    expect(pin).toBeDefined();
    const result = observed(f.service.refreshToken({ type: 'totp', assertion: { code: '123456' } }, pin));
    await f.entered.promise;
    f.makeUnreadable();
    expect(f.service.readSessionPin()).toBeUndefined();
    const before = { ...f.storage()! };
    f.reply.resolve(tokensFor('A', 'session-A', '2'));

    expect(await result).toMatchObject({ ok: false, error: { code: 'upgrade_session_changed' } });
    expect(f.storage()).toEqual(before);
    expect(f.events.filter((e) => e.event === PassflowEvent.SignOut || e.event === PassflowEvent.Refresh)).toEqual([]);
    expect(f.warnings).toHaveLength(1);
  });

  test('REQ-52 REQ-55 REQ-96 C38 C41 all joined operations settle and preserve live tokens on unreadable application identity', async () => {
    const f = applicationFixture();
    const summaries: { terminal: string }[] = [];
    const facade = createUpgradeFacade({
      platform: createMockPlatform(),
      passflowDomain: { origin: 'https://auth.example' },
      canCommit: () => ({ ok: true }),
      startUpgrade: async () => {
        throw new Error('unexpected prepare');
      },
      readSessionPin: () => f.service.readSessionPin(),
      commitRefresh: async (upgrade, pin) => {
        await f.service.refreshToken(upgrade, pin);
      },
    });
    const disable = facade.enable({
      backend: 'https://app.example',
      interceptFetch: false,
      onFlightSettled: (summary) => {
        summaries.push(summary);
      },
      prompt: async (request) => {
        request.onFactorSelected('totp');
        return { type: 'submit', factor: 'totp', code: '123456' };
      },
    });
    let dispatches = 0;
    const originals: Response[] = [];
    const wrapped = facade.withAuth(async () => {
      dispatches++;
      const response = challengeResponse();
      originals.push(response);
      return response;
    });
    try {
      const first = wrapped('https://app.example/first');
      await f.entered.promise;
      const second = observed(
        facade.elevate(challenge(), {
          kind: 'request',
          url: 'https://app.example/second',
          method: 'GET',
        }),
      );
      const imperative = observed(facade());
      f.makeUnreadable();
      const live = { ...f.storage()! };
      f.reply.resolve(tokensFor('A', 'session-A', '2'));
      const response = await first;
      expect(response).toBe(originals[0]);
      expect(isUpgradeSessionChanged(response)).toBe(true);
      expect(response.bodyUsed).toBe(false);
      expect(await second).toMatchObject({ ok: false, error: { code: 'upgrade_session_changed' } });
      expect(await imperative).toMatchObject({ ok: false, error: { code: 'upgrade_session_changed' } });
      expect(f.storage()).toEqual(live);
      expect(f.events.filter((e) => e.event === PassflowEvent.SignOut || e.event === PassflowEvent.Refresh)).toEqual([]);
      expect(f.warnings).toHaveLength(1);
      expect(dispatches).toBe(1);
      await vi.waitFor(() => expect(summaries).toHaveLength(1));
      expect(summaries[0]!.terminal).toBe('failed');
    } finally {
      disable();
    }
  });

  // The no-pin exception is Phase 4 round 3's reading of C41: a delivery mode that keeps the access
  // token out of reach never has an identity, and the epoch guard is its protection.
  test('REQ-55 C41 compatibility: a refresh which never captured a pin still applies tokens', async () => {
    const f = applicationFixture();
    f.makeUnreadable();
    expect(f.service.readSessionPin()).toBeUndefined();
    const result = f.service.refreshToken({ type: 'totp', assertion: { code: '123456' } });
    await f.entered.promise;
    const elevated = tokensFor('A', 'session-A', '2');
    f.reply.resolve(elevated);
    await result;

    expect(f.storage()).toEqual(elevated);
    expect(await f.service.getTokens(false)).toEqual(elevated);
    expect(f.events.filter((e) => e.event === PassflowEvent.Refresh)).toHaveLength(1);
    expect(f.events.filter((e) => e.event === PassflowEvent.SignOut)).toEqual([]);
  });
});
