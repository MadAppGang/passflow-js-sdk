/**
 * The first factor on a PKCE app: every native sign-in path sends a challenge and
 * redeems the code it gets back, and nothing that is not a token reaches storage.
 */
import { beforeEach, describe, expect, Mock, test, vi } from 'vitest';
import { AuthAPI } from '../../lib/api';
import { DeviceService } from '../../lib/device';
import { s256Challenge } from '../../lib/pkce';
import type { PlatformAdapter } from '../../lib/platform';
import { AuthService } from '../../lib/services/auth-service';
import { TokenCacheService } from '../../lib/services/token-cache-service';
import { StorageManager } from '../../lib/storage';
import { PassflowEvent, PassflowStore } from '../../lib/store';
import { VALID_TOKENS } from '../helpers/fixtures';
import { createMockPlatform } from '../helpers/mock-platform';

const CODE = { code: 'authz-code' };

describe('AuthService on a PKCE app', () => {
  let authApi: Record<string, Mock>;
  let storageManager: StorageManager;
  let store: PassflowStore;
  let events: PassflowEvent[];
  let readPkceEnabled: Mock;
  let service: AuthService;

  beforeEach(() => {
    localStorage.clear();
    sessionStorage.clear();
    authApi = {
      signIn: vi.fn().mockResolvedValue(CODE),
      signUp: vi.fn().mockResolvedValue(CODE),
      passkeyRegisterStart: vi.fn().mockResolvedValue({ challenge_id: 'pk-1', publicKey: { user: { id: 'u' } } }),
      passkeyRegisterComplete: vi.fn().mockResolvedValue(CODE),
      passkeyAuthenticateStart: vi.fn().mockResolvedValue({ challenge_id: 'pk-1', publicKey: {} }),
      passkeyAuthenticateComplete: vi.fn().mockResolvedValue(CODE),
      pkceExchange: vi.fn().mockImplementation(async () => ({ ...VALID_TOKENS })),
    };
    storageManager = new StorageManager({ prefix: '' });
    store = new PassflowStore();
    events = [];
    store.subscribe({ onAuthChange: (event) => events.push(event) });
    readPkceEnabled = vi.fn().mockResolvedValue(true);
    service = new AuthService(
      authApi as unknown as AuthAPI,
      { getDeviceId: () => 'device-1' } as unknown as DeviceService,
      storageManager,
      store,
      { setTokensCache: vi.fn(), getParsedTokens: vi.fn() } as unknown as TokenCacheService,
      ['id', 'openid'],
      false,
      'https://auth.example.com',
      {},
      'app-1',
      undefined,
      createMockPlatform() as unknown as PlatformAdapter,
      readPkceEnabled,
    );
  });

  const paths: Array<[string, string, () => Promise<{ access_token?: string; code?: string }>, PassflowEvent]> = [
    ['signIn', 'signIn', () => service.signIn({ email: 'a@example.com', password: 'pw' }), PassflowEvent.SignIn],
    ['signUp', 'signUp', () => service.signUp({ user: { email: 'a@example.com', password: 'pw' } }), PassflowEvent.Register],
    [
      'passkeyRegister',
      'passkeyRegisterStart',
      () => service.passkeyRegister({ scopes: ['id'], relying_party_id: 'example.com', redirect_url: 'https://example.com' }),
      PassflowEvent.Register,
    ],
    [
      'passkeyAuthenticate',
      'passkeyAuthenticateStart',
      () => service.passkeyAuthenticate({ relying_party_id: 'example.com' }),
      PassflowEvent.SignIn,
    ],
  ];

  test.each(paths)('%s sends a challenge and exchanges the code for tokens', async (_name, startCall, run, doneEvent) => {
    const response = await run();

    const verifier = authApi.pkceExchange.mock.calls[0]?.[1] as string;
    expect(authApi.pkceExchange).toHaveBeenCalledExactlyOnceWith(CODE.code, verifier);
    expect(authApi[startCall]?.mock.calls[0]?.[0].code_challenge).toBe(await s256Challenge(verifier));
    expect(response).not.toHaveProperty('code');
    expect(response.access_token).toBe(VALID_TOKENS.access_token);
    expect(storageManager.getTokens()?.access_token).toBe(VALID_TOKENS.access_token);
    expect(events).toContain(doneEvent);
  });

  test.each(paths)('%s sends no challenge on an app without PKCE', async (_name, startCall, run) => {
    readPkceEnabled.mockResolvedValue(false);
    for (const call of ['signIn', 'signUp', 'passkeyRegisterComplete', 'passkeyAuthenticateComplete']) {
      authApi[call]?.mockResolvedValue({ ...VALID_TOKENS });
    }

    await run();

    expect(authApi[startCall]?.mock.calls[0]?.[0]).not.toHaveProperty('code_challenge');
    expect(authApi.pkceExchange).not.toHaveBeenCalled();
  });

  describe('resetPassword', () => {
    const REDIRECT = 'https://app.example.com/after-reset';

    test('sends a challenge, exchanges the code and keeps the redirect the server put on it', async () => {
      authApi.resetPassword = vi.fn().mockResolvedValue({ ...CODE, redirect_url: REDIRECT });

      const response = await service.resetPassword('new-password');

      const verifier = authApi.pkceExchange?.mock.calls[0]?.[1] as string;
      expect(authApi.pkceExchange).toHaveBeenCalledExactlyOnceWith(CODE.code, verifier);
      expect(authApi.resetPassword.mock.calls[0]?.[3]).toBe(await s256Challenge(verifier));
      expect(response).not.toHaveProperty('code');
      expect(response).toMatchObject({ access_token: VALID_TOKENS.access_token, redirect_url: REDIRECT });
      expect(storageManager.getTokens()?.access_token).toBe(VALID_TOKENS.access_token);
      expect(events).toContain(PassflowEvent.SignIn);
    });

    test('a reset that owes its second factor keeps the verifier for the code that comes after it', async () => {
      authApi.resetPassword = vi.fn().mockResolvedValue({ requires_2fa: true, tfa_token: 'tfa.jwt.token' });

      await service.resetPassword('new-password');

      expect(authApi.pkceExchange).not.toHaveBeenCalled();
      expect(service.hasPendingPkceSignIn()).toBe(true);
      expect(storageManager.getTokens()).toBeUndefined();
      expect(events).toContain(PassflowEvent.TwoFactorRequired);
      expect(events).not.toContain(PassflowEvent.SignIn);
    });

    test('sends no challenge on an app without PKCE', async () => {
      readPkceEnabled.mockResolvedValue(false);
      authApi.resetPassword = vi.fn().mockResolvedValue({ ...VALID_TOKENS });

      await service.resetPassword('new-password');

      expect(authApi.resetPassword.mock.calls[0]).toHaveLength(3);
      expect(authApi.pkceExchange).not.toHaveBeenCalled();
    });
  });

  test('a setting that cannot be read leaves the decision to the server', async () => {
    readPkceEnabled.mockRejectedValue(new Error('network'));
    authApi.signIn?.mockResolvedValue({ ...VALID_TOKENS });

    await service.signIn({ email: 'a@example.com', password: 'pw' });

    expect(authApi.signIn?.mock.calls[0]?.[0]).not.toHaveProperty('code_challenge');
  });

  test('the caller keeps its payload: the challenge is not written onto it', async () => {
    const payload = { email: 'a@example.com', password: 'pw' };

    await service.signIn(payload);

    expect(payload).not.toHaveProperty('code_challenge');
  });

  test('the verifier is left out of the event when the app has no PKCE', async () => {
    readPkceEnabled.mockResolvedValue(false);
    authApi.signIn?.mockResolvedValue({ tfa_token: 'tfa' });
    const seen: unknown[] = [];
    store.subscribe({ onAuthChange: (_event, payload) => seen.push(payload) }, [PassflowEvent.TwoFactorRequired]);

    await service.signIn({ email: 'a@example.com', password: 'pw' });

    expect(seen).toEqual([{ email: 'a@example.com', challengeId: '', tfaToken: 'tfa' }]);
  });

  test('an exchange the server gates on a second factor stays pending', async () => {
    authApi.pkceExchange?.mockResolvedValue({ tfa_token: 'tfa' });

    await service.signIn({ email: 'a@example.com', password: 'pw' });

    expect(events).toContain(PassflowEvent.TwoFactorRequired);
    expect(events).not.toContain(PassflowEvent.SignIn);
    expect(storageManager.getTokens()).toBeUndefined();
  });

  test('a code with nothing to redeem it is refused, and stores nothing', async () => {
    readPkceEnabled.mockResolvedValue(false);

    await expect(service.signIn({ email: 'a@example.com', password: 'pw' })).rejects.toThrow(/not exchanged/);

    expect(storageManager.getTokens()).toBeUndefined();
    expect(events).toContain(PassflowEvent.Error);
    expect(events).not.toContain(PassflowEvent.SignIn);
  });

  test('a redirect answer under a parent is not treated as a code', async () => {
    authApi.signIn?.mockResolvedValue({ redirect_url: 'https://rp.example/cb?code=parent' });

    await service.signIn({ email: 'a@example.com', password: 'pw' });

    expect(authApi.pkceExchange).not.toHaveBeenCalled();
  });
});
