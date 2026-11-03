/**
 * Amendment A1 (PFL-792): every sign-in starts a new session in the refresh controller, not only
 * the paths that emit `SignIn`/`Register` themselves. A tab that signed out, or whose session
 * ended, and then signs in again through its second factor (code, recovery code, a PKCE app's
 * code exchange) or `setTokens()` refreshes normally at the next expiry.
 *
 * Real `Passflow` instances; only the HTTP layer is stubbed.
 */
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import { AppAPI, AuthAPI, PassflowError } from '../../lib/api';
import { TwoFactorApiClient } from '../../lib/api/two-factor';
import { Passflow } from '../../lib/passflow';
import { PassflowEvent } from '../../lib/store';
import type { Tokens } from '../../lib/types';
import { TEST_CONFIG } from '../helpers/fixtures';
import { jwt } from './jwt';

const EXPIRED = 1_600_000_000;
const FUTURE = 4_102_444_800;
const PENDING = { requires_2fa: true, tfa_token: 'tfa.jwt.token', challenge_id: 'c-1' };
const SCOPES = TEST_CONFIG.scopes;

let issued = 0;

/** A token pair of `sub`'s session `sid`; the access token expired unless `fresh`. */
const pairOf = (sub: string, sid: string, iat: number, fresh = false): Tokens => {
  issued += 1;
  return {
    access_token: jwt({ sub, sid, exp: fresh ? FUTURE : EXPIRED, iat, jti: `access-${issued}`, type: 'access' }),
    refresh_token: jwt({ sub, sid, exp: FUTURE, iat, jti: `refresh-${issued}`, type: 'refresh' }),
    scopes: SCOPES,
  };
};

const claimsOf = (token: string | undefined): { sub?: string; sid?: string; iat?: number } =>
  token ? JSON.parse(Buffer.from(token.split('.')[1] ?? '', 'base64url').toString()) : {};

const AUTH_FAILURE = () =>
  new PassflowError({
    id: 'error.token.invalid.error',
    message: 'token is invalid',
    status: 400,
    location: '/auth/refresh',
    time: '2026-11-03T00:00:00Z',
  });

type Completion = 'verifyTwoFactor' | 'useTwoFactorRecoveryCode';

describe('a new sign-in after the session ended refreshes at the next expiry (A1)', () => {
  let refreshToken: ReturnType<typeof vi.spyOn>;
  let events: { event: PassflowEvent; payload: unknown }[];
  /** What the second factor completes with: the pair B, or (PKCE app) a code exchanged for it. */
  let secondFactorPair: Tokens;

  /** The refresh endpoint: rotates any token it is sent within its session (a later iat). */
  const rotating = async (refresh: string) => {
    const { sub = '', sid = '', iat = 0 } = claimsOf(refresh);
    return { ...pairOf(sub, sid, iat + 60, true) } as never;
  };

  const stubSecondFactor = (pkceEnabled: boolean) => {
    vi.spyOn(AppAPI.prototype, 'getAppSettings').mockResolvedValue({ pkce_enabled: pkceEnabled } as never);
    vi.spyOn(AuthAPI.prototype, 'pkceExchange').mockImplementation(async () => ({ ...secondFactorPair }) as never);
    const answer = () => (pkceEnabled ? { code: 'authz-code' } : { ...secondFactorPair });
    vi.spyOn(TwoFactorApiClient.prototype, 'verify').mockImplementation(async () => ({ success: true, ...answer() }) as never);
    vi.spyOn(TwoFactorApiClient.prototype, 'useRecoveryCode').mockImplementation(
      async () => ({ success: true, remaining_recovery_codes: 5, ...answer() }) as never,
    );
  };

  const newPassflow = (config: Partial<ConstructorParameters<typeof Passflow>[0]> = {}) => {
    const passflow = new Passflow({ ...TEST_CONFIG, refreshCoordination: 'none', ...config });
    passflow.subscribe({ onAuthChange: (event, payload) => events.push({ event, payload }) });
    return passflow;
  };

  const signInWithSecondFactor = async (passflow: Passflow, method: Completion) => {
    await passflow.signIn({ email: 'b@example.com', password: 'pw' });
    if (method === 'verifyTwoFactor') await passflow.verifyTwoFactor('123456');
    else await passflow.useTwoFactorRecoveryCode('ABCD-1234');
  };

  const sentTokens = () => refreshToken.mock.calls.map((call: unknown[]) => call[0]);
  const named = (event: PassflowEvent) => events.filter((e) => e.event === event).map((e) => e.payload);

  beforeEach(() => {
    localStorage.clear();
    sessionStorage.clear();
    events = [];
    vi.spyOn(AuthAPI.prototype, 'signIn').mockImplementation(async () => ({ ...PENDING }) as never);
    vi.spyOn(AuthAPI.prototype, 'logOut').mockResolvedValue({ status: 'ok' } as never);
    refreshToken = vi.spyOn(AuthAPI.prototype, 'refreshToken').mockImplementation(rotating);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe.each<[string, boolean]>([
    ['an app without PKCE', false],
    ['a PKCE app', true],
  ])('on %s', (_name, pkceEnabled) => {
    test.each<Completion>(['verifyTwoFactor', 'useTwoFactorRecoveryCode'])(
      'sign out as A, %s as B in the same tab: the next expiry refreshes B',
      async (method) => {
        stubSecondFactor(pkceEnabled);
        const passflow = newPassflow();
        // User A works in this tab and refreshes once: the controller knows A's session.
        passflow.setTokens(pairOf('user-a', 'sid-a', 1_700_000_000));
        await passflow.getTokensWithRefresh();
        expect(claimsOf(passflow.getCachedTokens()?.refresh_token).sub).toBe('user-a');

        await passflow.logOut();
        secondFactorPair = pairOf('user-b', 'sid-b', 1_700_000_100);
        await signInWithSecondFactor(passflow, method);
        expect(passflow.getCachedTokens()?.refresh_token).toBe(secondFactorPair.refresh_token);

        const tokens = await passflow.getTokensWithRefresh();

        expect(sentTokens().at(-1)).toBe(secondFactorPair.refresh_token);
        expect(claimsOf(tokens?.refresh_token)).toMatchObject({ sub: 'user-b', sid: 'sid-b', iat: 1_700_000_160 });
        // Saved: getTokens() reads storage.
        expect((await passflow.getTokens())?.refresh_token).toBe(tokens?.refresh_token);
        expect(named(PassflowEvent.SessionExpired)).toEqual([]);
        expect(named(PassflowEvent.Refresh).at(-1)).toMatchObject({ source: 'refresh' });
      },
    );

    test.each<Completion>(['verifyTwoFactor', 'useTwoFactorRecoveryCode'])(
      'the session ended on its last strike, %s signs in again: the next expiry refreshes',
      async (method) => {
        stubSecondFactor(pkceEnabled);
        const passflow = newPassflow({ refreshStrikes: 1 });
        passflow.setTokens(pairOf('user-a', 'sid-a', 1_700_000_000));
        refreshToken.mockRejectedValueOnce(AUTH_FAILURE());
        await passflow.getTokensWithRefresh();
        expect(named(PassflowEvent.SessionExpired)).toEqual([{ reason: 'refresh_failed', origin: 'this-tab' }]);
        expect(passflow.getCachedTokens()).toBeUndefined();

        secondFactorPair = pairOf('user-a', 'sid-a2', 1_700_000_100);
        await signInWithSecondFactor(passflow, method);
        const before = refreshToken.mock.calls.length;

        const tokens = await passflow.getTokensWithRefresh();

        expect(refreshToken.mock.calls.length).toBe(before + 1);
        expect(sentTokens().at(-1)).toBe(secondFactorPair.refresh_token);
        expect(claimsOf(tokens?.refresh_token)).toMatchObject({ sub: 'user-a', sid: 'sid-a2' });
        expect(named(PassflowEvent.SessionExpired)).toHaveLength(1);
      },
    );
  });

  test('setTokens() after the session ended: the next expiry refreshes', async () => {
    const passflow = newPassflow({ refreshStrikes: 1 });
    passflow.setTokens(pairOf('user-a', 'sid-a', 1_700_000_000));
    refreshToken.mockRejectedValueOnce(AUTH_FAILURE());
    await passflow.getTokensWithRefresh();
    expect(named(PassflowEvent.SessionExpired)).toHaveLength(1);

    const next = pairOf('user-a', 'sid-a2', 1_700_000_100);
    passflow.setTokens(next);
    const tokens = await passflow.getTokensWithRefresh();

    expect(sentTokens().at(-1)).toBe(next.refresh_token);
    expect(claimsOf(tokens?.refresh_token)).toMatchObject({ sub: 'user-a', sid: 'sid-a2' });
  });

  test('refreshToken() after the session ended rejects until a new sign-in, then refreshes', async () => {
    stubSecondFactor(false);
    const passflow = newPassflow({ refreshStrikes: 1 });
    passflow.setTokens(pairOf('user-a', 'sid-a', 1_700_000_000));
    refreshToken.mockRejectedValueOnce(AUTH_FAILURE());
    await passflow.getTokensWithRefresh();
    expect(passflow.getCachedTokens()).toBeUndefined();

    secondFactorPair = pairOf('user-b', 'sid-b', 1_700_000_100);
    await signInWithSecondFactor(passflow, 'verifyTwoFactor');
    const response = await passflow.refreshToken();

    expect(sentTokens().at(-1)).toBe(secondFactorPair.refresh_token);
    expect(claimsOf(response.refresh_token)).toMatchObject({ sub: 'user-b', sid: 'sid-b' });
  });
});
