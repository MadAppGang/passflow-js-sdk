/**
 * A sign-in that ends at its second factor, through the public Passflow methods:
 * the tokens are applied once, in the delivery mode, and BFF tokens stay out of
 * browser storage. Only the HTTP layer is stubbed.
 */
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import { AppAPI, AuthAPI } from '../../lib/api';
import { TwoFactorApiClient } from '../../lib/api/two-factor';
import { Passflow } from '../../lib/passflow';
import { getDefaultLogger } from '../../lib/services/logger';
import { PassflowEvent } from '../../lib/store';
import { TEST_CONFIG, VALID_ACCESS_TOKEN, VALID_ID_TOKEN, VALID_REFRESH_TOKEN, VALID_TOKENS } from '../helpers/fixtures';

const CALLBACK_URL = 'https://app.example.com/bff/callback';
const PENDING = { requires_2fa: true, tfa_token: 'tfa.jwt.token', challenge_id: 'c-1' };
const CREDENTIALS = { email: 'a@example.com', password: 'pw' };

const BFF_CONFIG = {
  ...TEST_CONFIG,
  tokenExchange: { enabled: true, callbackUrl: CALLBACK_URL },
};

type Completion = 'verifyTwoFactor' | 'useTwoFactorRecoveryCode';

const complete = (passflow: Passflow, method: Completion) =>
  method === 'verifyTwoFactor' ? passflow.verifyTwoFactor('123456') : passflow.useTwoFactorRecoveryCode('ABCD-1234');

describe('second factor completion through Passflow', () => {
  let setItem: ReturnType<typeof vi.spyOn>;
  /** Every value ever written to browser storage: a token written and later removed still counts. */
  const stored = () => setItem.mock.calls.map((call: unknown[]) => call[1]);
  let fetchMock: ReturnType<typeof vi.fn>;
  let getAppSettings: ReturnType<typeof vi.spyOn>;
  let pkceExchange: ReturnType<typeof vi.spyOn>;
  let verify: ReturnType<typeof vi.spyOn>;
  let useRecoveryCode: ReturnType<typeof vi.spyOn>;

  /** The second factor answers with a code on a PKCE app, and with the tokens on any other. */
  const stubApis = (pkceEnabled: boolean) => {
    const answer = pkceEnabled ? { code: 'authz-code' } : { ...VALID_TOKENS };
    getAppSettings.mockResolvedValue({ pkce_enabled: pkceEnabled } as never);
    verify.mockImplementation(async () => ({ success: true, ...answer }) as never);
    useRecoveryCode.mockImplementation(async () => ({ success: true, remaining_recovery_codes: 5, ...answer }) as never);
  };

  beforeEach(() => {
    localStorage.clear();
    sessionStorage.clear();
    setItem = vi.spyOn(localStorage, 'setItem');
    fetchMock = vi.fn().mockResolvedValue({ ok: true, status: 200, json: async () => ({ authenticated: false }) });
    vi.stubGlobal('fetch', fetchMock);

    getAppSettings = vi.spyOn(AppAPI.prototype, 'getAppSettings');
    pkceExchange = vi.spyOn(AuthAPI.prototype, 'pkceExchange').mockImplementation(async () => ({ ...VALID_TOKENS }) as never);
    vi.spyOn(AuthAPI.prototype, 'signIn').mockImplementation(async () => ({ ...PENDING }) as never);
    verify = vi.spyOn(TwoFactorApiClient.prototype, 'verify');
    useRecoveryCode = vi.spyOn(TwoFactorApiClient.prototype, 'useRecoveryCode');
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  describe.each<[string, boolean]>([
    ['a PKCE app', true],
    ['an app without PKCE', false],
  ])('BFF delivery on %s', (_name, pkceEnabled) => {
    test.each<Completion>(['verifyTwoFactor', 'useTwoFactorRecoveryCode'])(
      '%s keeps the access and refresh tokens out of browser storage',
      async (method) => {
        stubApis(pkceEnabled);
        const passflow = new Passflow(BFF_CONFIG);
        await passflow.signIn(CREDENTIALS);

        const response = await complete(passflow, method);

        expect(response.access_token).toBe(VALID_ACCESS_TOKEN);
        expect(stored()).not.toContain(VALID_ACCESS_TOKEN);
        expect(stored()).not.toContain(VALID_REFRESH_TOKEN);
        expect(stored()).toContain(VALID_ID_TOKEN);

        const forwards = fetchMock.mock.calls.filter(([url]) => url === CALLBACK_URL);
        expect(forwards).toHaveLength(1);
        expect(JSON.parse(forwards[0]?.[1].body)).toMatchObject({
          access_token: VALID_ACCESS_TOKEN,
          refresh_token: VALID_REFRESH_TOKEN,
        });
        expect(passflow.isTwoFactorVerificationRequired()).toBe(false);
      },
    );
  });

  test.each<Completion>(['verifyTwoFactor', 'useTwoFactorRecoveryCode'])(
    '%s on JSON delivery still stores the tokens',
    async (method) => {
      stubApis(false);
      const passflow = new Passflow(TEST_CONFIG);
      await passflow.signIn(CREDENTIALS);

      await complete(passflow, method);

      expect(stored()).toContain(VALID_ACCESS_TOKEN);
      expect(stored()).toContain(VALID_REFRESH_TOKEN);
      expect(fetchMock.mock.calls.filter(([url]) => url === CALLBACK_URL)).toHaveLength(0);
    },
  );

  test('joinInvitation keeps BFF tokens out of browser storage', async () => {
    const passflow = new Passflow(BFF_CONFIG);
    vi.spyOn(passflow.tenant, 'joinInvitation').mockResolvedValue({ ...VALID_TOKENS } as never);

    await passflow.joinInvitation('invite-token');

    expect(stored()).not.toContain(VALID_ACCESS_TOKEN);
    expect(stored()).not.toContain(VALID_REFRESH_TOKEN);
    expect(fetchMock.mock.calls.filter(([url]) => url === CALLBACK_URL)).toHaveLength(1);
  });

  describe('the PKCE verifier', () => {
    test('is not on the TwoFactorRequired event, and only the pending entry holds it', async () => {
      stubApis(true);
      const passflow = new Passflow(TEST_CONFIG);
      const payloads: unknown[] = [];
      passflow.subscribe({
        onAuthChange: (event, payload) => {
          if (event === PassflowEvent.TwoFactorRequired) payloads.push(payload);
        },
      });

      await passflow.signIn(CREDENTIALS);

      expect(payloads).toEqual([{ email: CREDENTIALS.email, challengeId: 'c-1', tfaToken: PENDING.tfa_token }]);
      expect(sessionStorage.getItem('passflow_2fa_challenge')).not.toContain('Verifier');
    });

    test('survives a redirect: a new client on the page redeems the code', async () => {
      stubApis(true);
      await new Passflow(TEST_CONFIG).signIn(CREDENTIALS);
      const verifier = JSON.parse(sessionStorage.getItem('passflow_2fa_pkce') ?? '{}').verifier;

      await new Passflow(TEST_CONFIG).verifyTwoFactor('123456');

      expect(pkceExchange).toHaveBeenCalledExactlyOnceWith('authz-code', verifier);
      expect(sessionStorage.getItem('passflow_2fa_pkce')).toBeNull();
    });

    test('is read from memory first', async () => {
      stubApis(true);
      const passflow = new Passflow(TEST_CONFIG);
      await passflow.signIn(CREDENTIALS);
      const verifier = JSON.parse(sessionStorage.getItem('passflow_2fa_pkce') ?? '{}').verifier;
      sessionStorage.removeItem('passflow_2fa_pkce');

      await passflow.verifyTwoFactor('123456');

      expect(pkceExchange).toHaveBeenCalledExactlyOnceWith('authz-code', verifier);
    });

    test('a failed exchange keeps the pending second factor; a later success clears it', async () => {
      stubApis(true);
      const passflow = new Passflow(TEST_CONFIG);
      await passflow.signIn(CREDENTIALS);
      pkceExchange.mockRejectedValueOnce(new Error('network'));

      await expect(passflow.verifyTwoFactor('123456')).rejects.toThrow('network');

      expect(passflow.isTwoFactorVerificationRequired()).toBe(true);
      expect(sessionStorage.getItem('passflow_2fa_pkce')).not.toBeNull();
      expect(stored()).not.toContain(VALID_ACCESS_TOKEN);

      await passflow.verifyTwoFactor('123456');

      expect(passflow.isTwoFactorVerificationRequired()).toBe(false);
      expect(sessionStorage.getItem('passflow_2fa_pkce')).toBeNull();
    });
  });

  describe('the PKCE setting', () => {
    const SIGN_IN = () => CREDENTIALS;

    test('is fetched once per appId', async () => {
      stubApis(false);
      const passflow = new Passflow(TEST_CONFIG);

      await passflow.signIn(SIGN_IN());
      await passflow.signIn(SIGN_IN());

      expect(getAppSettings).toHaveBeenCalledTimes(1);
    });

    test('is fetched again after setAppId', async () => {
      stubApis(false);
      const passflow = new Passflow(TEST_CONFIG);
      await passflow.signIn(SIGN_IN());

      passflow.setAppId('another-app');
      await passflow.signIn(SIGN_IN());

      expect(getAppSettings).toHaveBeenCalledTimes(2);
    });

    test('a failed fetch is logged, sends no challenge and is not kept', async () => {
      stubApis(false);
      const warn = vi.spyOn(getDefaultLogger(), 'warn').mockImplementation(() => undefined);
      const consoleWarn = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
      getAppSettings.mockRejectedValueOnce(new Error('network'));
      const passflow = new Passflow(TEST_CONFIG);

      await passflow.signIn(SIGN_IN());

      expect(AuthAPI.prototype.signIn).toHaveBeenLastCalledWith(
        expect.not.objectContaining({ code_challenge: expect.anything() }),
        expect.anything(),
        expect.anything(),
      );
      expect(warn.mock.calls.length + consoleWarn.mock.calls.length).toBe(1);

      await passflow.signIn(SIGN_IN());

      expect(getAppSettings).toHaveBeenCalledTimes(2);
    });
  });
});
