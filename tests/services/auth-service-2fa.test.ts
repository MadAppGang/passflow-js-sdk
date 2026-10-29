/**
 * A sign-in that owes its second factor, on every sign-in path.
 *
 * The server answers such a sign-in with `{tfa_token}` in place of tokens
 * (and a federated popup with `#tfa_token=` in its callback fragment). None of
 * that is a session: nothing may be stored and no SignIn/Register event may
 * fire, and the TwoFactorService must end up holding the 2FA token so its
 * verify call can carry it.
 *
 * The store and the TwoFactorService are real here, so the hand-over is
 * exercised end to end rather than asserted on a mocked `notify`.
 */
import { Mock, beforeEach, describe, expect, test, vi } from 'vitest';
import { AuthAPI, PassflowAuthorizationResponse, Providers } from '../../lib/api';
import { TwoFactorApiClient } from '../../lib/api/two-factor';
import { DeviceService } from '../../lib/device';
import type { PlatformAdapter } from '../../lib/platform';
import { AuthService } from '../../lib/services/auth-service';
import { TokenCacheService } from '../../lib/services/token-cache-service';
import { TwoFactorService } from '../../lib/services/two-factor-service';
import { StorageManager } from '../../lib/storage';
import { PassflowEvent, PassflowStore } from '../../lib/store';
import { VALID_TOKENS } from '../helpers/fixtures';
import { createMockPlatform } from '../helpers/mock-platform';

const TFA_TOKEN = 'eyJhbGciOiJIUzI1NiJ9.eyJ0eXBlIjoiMmZhIn0.sig';
const PENDING: PassflowAuthorizationResponse = { tfa_token: TFA_TOKEN, challenge_id: 'ch-1' };
const ORIGIN = 'https://app.example.com';

describe('AuthService — a sign-in pending its second factor', () => {
  let authApi: Record<string, Mock>;
  let twoFactorApi: { verify: Mock };
  let storageManager: StorageManager;
  let tokenCache: { setTokensCache: Mock; getParsedTokens: Mock };
  let store: PassflowStore;
  let events: PassflowEvent[];
  let twoFactor: TwoFactorService;
  let platform: ReturnType<typeof createMockPlatform>;
  let createSession: Mock;
  let authService: AuthService;

  beforeEach(() => {
    localStorage.clear();
    sessionStorage.clear();

    authApi = {
      signIn: vi.fn().mockResolvedValue(PENDING),
      signUp: vi.fn().mockResolvedValue(PENDING),
      passwordlessSignInComplete: vi.fn().mockResolvedValue({ ...PENDING, redirect_url: '' }),
      passkeyRegisterStart: vi.fn().mockResolvedValue({ challenge_id: 'pk-1', publicKey: { user: { id: 'u' } } }),
      passkeyRegisterComplete: vi.fn().mockResolvedValue(PENDING),
      passkeyAuthenticateStart: vi.fn().mockResolvedValue({ challenge_id: 'pk-1', publicKey: {} }),
      passkeyAuthenticateComplete: vi.fn().mockResolvedValue(PENDING),
      resetPassword: vi.fn().mockResolvedValue(PENDING),
      validateSession: vi.fn(),
    };

    storageManager = new StorageManager({ prefix: '' });
    vi.spyOn(storageManager, 'saveTokens');

    tokenCache = { setTokensCache: vi.fn(), getParsedTokens: vi.fn() };

    store = new PassflowStore();
    events = [];
    store.subscribe({ onAuthChange: (event) => events.push(event) });

    twoFactorApi = { verify: vi.fn().mockResolvedValue({ success: true, ...VALID_TOKENS }) };
    twoFactor = new TwoFactorService(twoFactorApi as unknown as TwoFactorApiClient, store);

    platform = createMockPlatform({
      getCurrentUrl: vi.fn().mockReturnValue({
        href: `${ORIGIN}/`,
        origin: ORIGIN,
        pathname: '/',
        search: '',
        hash: '',
        hostname: 'app.example.com',
      }),
    });
    createSession = vi.fn();

    authService = new AuthService(
      authApi as unknown as AuthAPI,
      { getDeviceId: () => 'device-1' } as unknown as DeviceService,
      storageManager,
      store,
      tokenCache as unknown as TokenCacheService,
      ['id', 'openid'],
      false,
      'https://auth.example.com',
      { createSession },
      'app-1',
      undefined,
      platform as unknown as PlatformAdapter,
    );
  });

  const paths: Array<[string, () => Promise<unknown>]> = [
    ['signIn', () => authService.signIn({ email: 'a@example.com', password: 'pw' })],
    ['signUp', () => authService.signUp({ user: { email: 'a@example.com', password: 'pw' } })],
    ['passwordlessSignInComplete', () => authService.passwordlessSignInComplete({ challenge_id: 'pl-1', otp: '123456' })],
    ['passkeyAuthenticate', () => authService.passkeyAuthenticate({ relying_party_id: 'app.example.com' })],
    ['resetPassword', () => authService.resetPassword('new-password')],
    [
      'passkeyRegister',
      () => authService.passkeyRegister({ scopes: ['id'], relying_party_id: 'app.example.com', redirect_url: ORIGIN }),
    ],
    [
      'federatedAuthWithPopup',
      () => {
        platform.openAuthUrl.mockResolvedValueOnce({
          callbackSearch: '?user_state=xyz',
          callbackHash: `#tfa_token=${TFA_TOKEN}`,
        });
        return authService.federatedAuthWithPopup({ provider: Providers.google, redirect_url: ORIGIN });
      },
    ],
  ];

  test.each(paths)('%s stores nothing and emits TwoFactorRequired, not SignIn/Register', async (_name, run) => {
    await run();

    expect(storageManager.saveTokens).not.toHaveBeenCalled();
    expect(tokenCache.setTokensCache).not.toHaveBeenCalled();
    expect(createSession).not.toHaveBeenCalled();
    expect(events).toContain(PassflowEvent.TwoFactorRequired);
    expect(events).not.toContain(PassflowEvent.SignIn);
    expect(events).not.toContain(PassflowEvent.Register);
    expect(events).not.toContain(PassflowEvent.Error);
  });

  test.each(paths)('%s hands the 2FA token to the TwoFactorService', async (_name, run) => {
    await run();

    expect(twoFactor.isVerificationRequired()).toBe(true);
    await twoFactor.verify('123456');
    expect(twoFactorApi.verify).toHaveBeenCalledWith(expect.objectContaining({ code: '123456', tfa_token: TFA_TOKEN }));
  });

  test('signUp passes the registering email along with the token', async () => {
    const seen: unknown[] = [];
    store.subscribe({ onAuthChange: (_e, payload) => seen.push(payload) }, [PassflowEvent.TwoFactorRequired]);

    await authService.signUp({ user: { email: 'new@example.com', password: 'pw' } });

    expect(seen).toEqual([{ email: 'new@example.com', challengeId: 'ch-1', tfaToken: TFA_TOKEN }]);
  });

  test('a federated popup pending 2FA does not navigate the page away', async () => {
    platform.openAuthUrl.mockResolvedValueOnce({ callbackSearch: '', callbackHash: `#tfa_token=${TFA_TOKEN}` });

    await authService.federatedAuthWithPopup({ provider: Providers.google, redirect_url: ORIGIN });

    expect(platform.navigateTo).not.toHaveBeenCalled();
  });

  test('a sign-in that comes back with tokens still signs in', async () => {
    authApi.signUp.mockResolvedValueOnce({ ...VALID_TOKENS });

    await authService.signUp({ user: { email: 'a@example.com', password: 'pw' } });

    expect(storageManager.saveTokens).toHaveBeenCalled();
    expect(events).toContain(PassflowEvent.Register);
    expect(events).not.toContain(PassflowEvent.TwoFactorRequired);
  });

  test('a completed sign-in clears a pending second factor', async () => {
    // Left from an abandoned attempt, or planted with a `#tfa_token=` link.
    await authService.signIn({ email: 'a@example.com', password: 'pw' });
    expect(twoFactor.isVerificationRequired()).toBe(true);

    authApi.signIn.mockResolvedValueOnce({ ...VALID_TOKENS });
    await authService.signIn({ email: 'a@example.com', password: 'pw' });

    expect(twoFactor.isVerificationRequired()).toBe(false);
  });

  test('a federated popup with tokens in its query still signs in', async () => {
    platform.openAuthUrl.mockResolvedValueOnce({
      callbackSearch: `?access_token=${VALID_TOKENS.access_token}`,
      callbackHash: '',
    });

    await authService.federatedAuthWithPopup({ provider: Providers.google, redirect_url: ORIGIN });

    expect(storageManager.saveTokens).toHaveBeenCalled();
    expect(events).toContain(PassflowEvent.SignIn);
    expect(events).not.toContain(PassflowEvent.TwoFactorRequired);
  });
});
