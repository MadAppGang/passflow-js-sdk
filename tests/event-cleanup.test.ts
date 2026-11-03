/**
 * Event cleanup (PFL-792, architecture §8), labels part: every `Error` the SDK emits carries an
 * `operation`, and one failure produces one `Error` (the innermost reporter wins).
 *
 * SignOut part (§2.8, §8.3): `logOut()` and `reset()` emit exactly one `SignOut{origin:'this-tab',
 * userId}`, after the cache and storage are cleared, also when the session had already ended.
 */
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import { PassflowError } from '../lib/api/model';
import { Passflow } from '../lib/passflow';
import { PassflowRefreshError, RefreshErrorId } from '../lib/refresh/errors';
import { type ErrorPayload, PassflowEvent, type PassflowOperation } from '../lib/store';
import type { Tokens } from '../lib/types';
import { TEST_CONFIG } from './helpers/fixtures';
import { jwt } from './refresh/jwt';

vi.mock('@simplewebauthn/browser', () => ({
  startAuthentication: vi.fn().mockResolvedValue({ id: 'auth-id' }),
  startRegistration: vi.fn().mockResolvedValue({ id: 'reg-id' }),
}));

type Internals = Record<string, Record<string, (...args: unknown[]) => unknown>>;

const apiError = (id = 'error.test') =>
  new PassflowError({ id, message: `failed: ${id}`, status: 400, location: '/test', time: new Date().toISOString() });

describe('Error events carry an operation', () => {
  let passflow: Passflow;
  let internals: Internals;
  let errors: () => ErrorPayload[];

  beforeEach(() => {
    vi.restoreAllMocks();
    localStorage.clear();
    Object.defineProperty(window, 'location', {
      value: { origin: 'https://example.com', search: '', hash: '', pathname: '/', href: 'https://example.com/' },
      writable: true,
    });
    window.history.replaceState = vi.fn();

    passflow = new Passflow(TEST_CONFIG);
    internals = passflow as unknown as Internals;
    const onAuthChange = vi.fn();
    passflow.subscribe({ onAuthChange });
    errors = () => onAuthChange.mock.calls.filter(([event]) => event === PassflowEvent.Error).map(([, payload]) => payload);
  });

  // [public call, internal owner field, internal method, expected operation]
  const wrapperCases: Array<[string, (p: Passflow) => Promise<unknown>, string, string, PassflowOperation]> = [
    // TEST-17 / REQ-14: inject at the API boundary so the real completion path reports the failure.
    [
      'verifyEmailCode',
      (p) => p.verifyEmailCode({ challenge_id: 'c', otp: '1' }),
      'authApi',
      'validateEmailCode',
      'email-verification.complete',
    ],
    ['logOut', (p) => p.logOut(), 'authService', 'logOut', 'log-out'],
    ['getAppSettings', (p) => p.getAppSettings(), 'appApi', 'getAppSettings', 'settings.app'],
    ['getSettingsAll', (p) => p.getSettingsAll(), 'settingApi', 'getSettingsAll', 'settings.all'],
    [
      'getPasswordPolicySettings',
      (p) => p.getPasswordPolicySettings(),
      'settingApi',
      'getPasswordPolicySettings',
      'settings.password-policy',
    ],
    ['getPasskeySettings', (p) => p.getPasskeySettings(), 'settingApi', 'getPasskeySettings', 'settings.passkey'],
    ['getUserPasskeys', (p) => p.getUserPasskeys(), 'userService', 'getUserPasskeys', 'passkey.list'],
    ['renameUserPasskey', (p) => p.renameUserPasskey('n', 'id'), 'userService', 'renameUserPasskey', 'passkey.rename'],
    ['deleteUserPasskey', (p) => p.deleteUserPasskey('id'), 'userService', 'deleteUserPasskey', 'passkey.delete'],
    ['addUserPasskey', (p) => p.addUserPasskey(), 'userService', 'addUserPasskey', 'passkey.add'],
    ['joinInvitation', (p) => p.joinInvitation('t'), 'tenantService', 'joinInvitation', 'invitation.join'],
    ['createTenant', (p) => p.createTenant('t'), 'tenantService', 'createTenant', 'tenant.create'],
    [
      'requestInviteLink',
      (p) => p.requestInviteLink({ email: 'a@b.co' } as never),
      'invitationService',
      'requestInviteLink',
      'invitation.request-link',
    ],
    [
      'getInvitations',
      (p) => p.getInvitations({ tenantID: 't' } as never),
      'invitationService',
      'getInvitations',
      'invitation.list',
    ],
    ['deleteInvitation', (p) => p.deleteInvitation('t'), 'invitationService', 'deleteInvitation', 'invitation.delete'],
    ['resendInvitation', (p) => p.resendInvitation('t'), 'invitationService', 'resendInvitation', 'invitation.resend'],
    ['getInvitationLink', (p) => p.getInvitationLink('i'), 'invitationService', 'getInvitationLink', 'invitation.get-link'],
    ['getTwoFactorStatus', (p) => p.getTwoFactorStatus(), 'twoFactorService', 'getStatus', '2fa.status'],
    ['beginTwoFactorSetup', (p) => p.beginTwoFactorSetup(), 'twoFactorService', 'beginSetup', '2fa.setup.begin'],
    ['confirmTwoFactorSetup', (p) => p.confirmTwoFactorSetup('1'), 'twoFactorService', 'confirmSetup', '2fa.setup.confirm'],
    ['verifyTwoFactor', (p) => p.verifyTwoFactor('1'), 'twoFactorService', 'verify', '2fa.verify'],
    [
      'useTwoFactorRecoveryCode',
      (p) => p.useTwoFactorRecoveryCode('1'),
      'twoFactorService',
      'useRecoveryCode',
      '2fa.recovery.use',
    ],
    ['disableTwoFactor', (p) => p.disableTwoFactor('1'), 'twoFactorService', 'disable', '2fa.disable'],
    [
      'regenerateTwoFactorRecoveryCodes',
      (p) => p.regenerateTwoFactorRecoveryCodes('1'),
      'twoFactorService',
      'regenerateRecoveryCodes',
      '2fa.recovery.regenerate',
    ],
    ['getTrustedDevices', (p) => p.getTrustedDevices(), 'twoFactorService', 'getTrustedDevices', '2fa.trusted-devices.list'],
    [
      'revokeTrustedDevice',
      (p) => p.revokeTrustedDevice('d'),
      'twoFactorService',
      'revokeTrustedDevice',
      '2fa.trusted-devices.revoke',
    ],
  ];

  test.each(wrapperCases)('Passflow.%s reports operation %s', async (_name, call, owner, method, operation) => {
    const error = apiError();
    vi.spyOn(internals[owner], method).mockRejectedValue(error);

    await expect(call(passflow)).rejects.toBe(error);

    expect(errors()).toEqual([{ operation, message: error.message, originalError: error, code: 'error.test' }]);
  });

  test('a non-Error rejection uses the context message', async () => {
    vi.spyOn(internals.appApi, 'getAppSettings').mockRejectedValue('nope');

    await expect(passflow.getAppSettings()).rejects.toBe('nope');

    expect(errors()).toEqual([
      { operation: 'settings.app', message: 'Get app settings failed', originalError: 'nope', code: undefined },
    ]);
  });

  // The TwoFactorService reports first with its 2fa.* operation; Passflow.handleError catches the
  // same object and must add nothing.
  const twoFactorCases: Array<[string, (p: Passflow) => Promise<unknown>, string, PassflowOperation]> = [
    ['getTwoFactorStatus', (p) => p.getTwoFactorStatus(), 'getStatus', '2fa.status'],
    ['beginTwoFactorSetup', (p) => p.beginTwoFactorSetup(), 'beginSetup', '2fa.setup.begin'],
    ['disableTwoFactor', (p) => p.disableTwoFactor('123456'), 'disable', '2fa.disable'],
    [
      'regenerateTwoFactorRecoveryCodes',
      (p) => p.regenerateTwoFactorRecoveryCodes('123456'),
      'regenerateRecoveryCodes',
      '2fa.recovery.regenerate',
    ],
    ['getTrustedDevices', (p) => p.getTrustedDevices(), 'getTrustedDevices', '2fa.trusted-devices.list'],
    ['revokeTrustedDevice', (p) => p.revokeTrustedDevice('d'), 'revokeTrustedDevice', '2fa.trusted-devices.revoke'],
  ];

  test.each(twoFactorCases)(
    'a 2FA API failure under Passflow.%s emits exactly one Error',
    async (_name, call, apiMethod, operation) => {
      const error = apiError('error.2fa.test');
      vi.spyOn(internals.twoFactorApi, apiMethod).mockRejectedValue(error);

      await expect(call(passflow)).rejects.toBe(error);

      expect(errors()).toEqual([{ operation, message: error.message, originalError: error, code: 'error.2fa.test' }]);
    },
  );

  test('signIn validation reports sign-in once', async () => {
    await expect(passflow.signIn({ email: 'not-an-email', password: 'x' })).rejects.toThrow('Invalid email format');

    expect(errors()).toEqual([expect.objectContaining({ operation: 'sign-in', code: 'VALIDATION_ERROR' })]);
  });

  test('signIn API failure reports sign-in once', async () => {
    const error = apiError('error.user.not.found');
    vi.spyOn(internals.authApi, 'signIn').mockRejectedValue(error);

    await expect(passflow.signIn({ email: 'a@b.co', password: 'x' })).rejects.toBe(error);

    expect(errors()).toEqual([
      { operation: 'sign-in', message: error.message, originalError: error, code: 'error.user.not.found' },
    ]);
  });

  test('signUp validation reports sign-up', async () => {
    await expect(passflow.signUp({ user: { email: 'bad', password: 'x' } } as never)).rejects.toThrow('Invalid email format');

    expect(errors()).toEqual([expect.objectContaining({ operation: 'sign-up', code: 'VALIDATION_ERROR' })]);
  });

  test('reset(message) reports reset with RESET_ERROR', () => {
    expect(() => passflow.reset('gone')).toThrow('gone');

    expect(errors()).toEqual([{ operation: 'reset', message: 'gone', code: 'RESET_ERROR' }]);
  });

  test('an invalid access token in the URL reports tokens.from-url', () => {
    // Hash form: the test setup's URLSearchParams stand-in does not strip a leading '?'.
    Object.defineProperty(window, 'location', {
      value: {
        origin: 'https://example.com',
        search: '',
        hash: '#access_token=not-a-jwt',
        pathname: '/',
        href: 'https://example.com/#access_token=not-a-jwt',
      },
      writable: true,
    });

    expect(passflow.handleTokensRedirect()).toBeUndefined();

    expect(errors()).toEqual([
      { operation: 'tokens.from-url', message: 'Invalid access token format received', code: 'INVALID_TOKEN_FORMAT' },
    ]);
  });
});

describe('One SignOut per sign-out, after the cache is cleared', () => {
  let passflow: Passflow;
  let internals: Internals;
  /** Each event with what the tab held when it was emitted. */
  let seen: { event: PassflowEvent; payload: unknown; cached: Tokens | undefined; stored: number }[];
  let issued = 0;

  const pairOf = (sub: string, iat: number, exp = 4_102_444_800): Tokens => {
    issued += 1;
    return {
      access_token: jwt({ sub, sid: 's1', exp, iat, jti: `access-${issued}`, type: 'access' }),
      refresh_token: jwt({ sub, sid: 's1', exp: 4_102_444_800, iat, jti: `refresh-${issued}`, type: 'refresh' }),
      scopes: TEST_CONFIG.scopes,
    };
  };

  const outage = () =>
    new PassflowError({
      id: 'error.http.503',
      message: 'unavailable',
      status: 503,
      location: '/auth/refresh',
      time: new Date().toISOString(),
    });

  const signOuts = () => seen.filter((e) => e.event === PassflowEvent.SignOut);
  const logOutApi = () => internals.authApi.logOut as unknown as ReturnType<typeof vi.fn>;

  beforeEach(() => {
    vi.restoreAllMocks();
    localStorage.clear();
    sessionStorage.clear();
    passflow = new Passflow({ ...TEST_CONFIG, refreshCoordination: 'none' });
    internals = passflow as unknown as Internals;
    seen = [];
    passflow.subscribe({
      onAuthChange: (event, payload) =>
        seen.push({ event, payload, cached: passflow.getCachedTokens(), stored: localStorage.length }),
    });
    vi.spyOn(internals.authApi, 'logOut').mockResolvedValue({ status: 'ok' });
  });

  afterEach(() => {
    passflow.dispose();
    vi.useRealTimers();
  });

  test('logOut() emits exactly one SignOut{this-tab, userId}, cache and storage already cleared', async () => {
    passflow.setTokens(pairOf('user-a', 1_700_000_000));
    seen = [];

    await passflow.logOut();

    expect(signOuts()).toEqual([
      { event: PassflowEvent.SignOut, payload: { origin: 'this-tab', userId: 'user-a' }, cached: undefined, stored: 0 },
    ]);
    expect(passflow.getCachedTokens()).toBeUndefined();
  });

  test('logOut() logs out the newest stored refresh token, not the cached one', async () => {
    passflow.setTokens(pairOf('user-a', 1_700_000_000));
    const newer = pairOf('user-a', 1_700_000_060);
    (internals.storageManager as unknown as { saveTokens(t: Tokens): void }).saveTokens(newer);

    await passflow.logOut();

    expect(logOutApi()).toHaveBeenCalledTimes(1);
    expect(logOutApi().mock.calls[0]?.[1]).toBe(newer.refresh_token);
  });

  test('logOut() whose API call fails still cleans up and emits one SignOut', async () => {
    logOutApi().mockRejectedValue(new Error('offline'));
    passflow.setTokens(pairOf('user-a', 1_700_000_000));

    await passflow.logOut();

    expect(signOuts()).toHaveLength(1);
    expect(localStorage.length).toBe(0);
    expect(passflow.getCachedTokens()).toBeUndefined();
  });

  test('logOut() after the session already ended still emits its one SignOut', async () => {
    passflow.setTokens(pairOf('user-a', 1_700_000_000));
    await passflow.logOut();
    seen = [];

    await passflow.logOut();

    expect(signOuts()).toHaveLength(1);
    expect(signOuts()[0]?.payload).toMatchObject({ origin: 'this-tab' });
    expect(signOuts()[0]?.cached).toBeUndefined();
  });

  test('logOut() stops a pending retry: its joiner rejects signed_out and nothing is sent afterwards', async () => {
    vi.useFakeTimers();
    const failure = outage();
    const refreshToken = vi.spyOn(internals.authApi, 'refreshToken').mockRejectedValue(failure);
    passflow.setTokens(pairOf('user-a', 1_700_000_000, 1_600_000_000));
    await expect(passflow.refreshToken()).rejects.toBe(failure);
    const joiner = passflow.refreshToken().catch((error: unknown) => error);

    await passflow.logOut();
    await vi.advanceTimersByTimeAsync(120_000);

    const rejection = await joiner;
    expect(rejection).toBeInstanceOf(PassflowRefreshError);
    expect((rejection as PassflowRefreshError).id).toBe(RefreshErrorId.signedOut);
    expect(refreshToken).toHaveBeenCalledTimes(1);
    expect(signOuts()).toHaveLength(1);
    expect(seen.some((e) => e.event === PassflowEvent.SessionExpired)).toBe(false);
  });

  test('reset() is synchronous and emits one SignOut{this-tab, userId} after clearing', () => {
    passflow.setTokens(pairOf('user-a', 1_700_000_000));
    seen = [];

    passflow.reset();

    expect(signOuts()).toEqual([
      { event: PassflowEvent.SignOut, payload: { origin: 'this-tab', userId: 'user-a' }, cached: undefined, stored: 0 },
    ]);
    expect(logOutApi()).not.toHaveBeenCalled();
  });

  test('reset(message) emits SignOut, then Error{reset}, then throws', () => {
    passflow.setTokens(pairOf('user-a', 1_700_000_000));
    seen = [];

    expect(() => passflow.reset('gone')).toThrow('gone');

    expect(seen.map((e) => e.event)).toEqual([PassflowEvent.SignOut, PassflowEvent.Error]);
  });

  test('reset() twice emits one SignOut each time', () => {
    passflow.setTokens(pairOf('user-a', 1_700_000_000));
    seen = [];

    passflow.reset();
    passflow.reset();

    expect(signOuts()).toHaveLength(2);
  });

  test('dispose() rejects a pending refresh caller with error.refresh.disposed and stops the retry', async () => {
    vi.useFakeTimers();
    const failure = outage();
    const refreshToken = vi.spyOn(internals.authApi, 'refreshToken').mockRejectedValue(failure);
    passflow.setTokens(pairOf('user-a', 1_700_000_000, 1_600_000_000));
    await expect(passflow.refreshToken()).rejects.toBe(failure);
    const joiner = passflow.refreshToken().catch((error: unknown) => error);

    passflow.dispose();
    await vi.advanceTimersByTimeAsync(120_000);

    expect(((await joiner) as PassflowRefreshError).id).toBe(RefreshErrorId.disposed);
    expect(refreshToken).toHaveBeenCalledTimes(1);
  });

  test('logOut() after dispose() still clears everything and emits one SignOut', async () => {
    passflow.setTokens(pairOf('user-a', 1_700_000_000));
    passflow.dispose();

    await passflow.logOut();

    expect(signOuts()).toHaveLength(1);
    expect(localStorage.length).toBe(0);
    expect(passflow.getCachedTokens()).toBeUndefined();
  });
});
