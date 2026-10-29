/**
 * What goes on the wire for the sign-in and 2FA completion calls.
 *
 * Requests run through the real AxiosClient, interceptors included, and stop
 * at a capturing adapter, so these tests see the config axios would send:
 * `withCredentials` (the trusted-device cookie only travels with it), the
 * body's `trust_device`, and the 2FA token as the Bearer credential.
 */
import type { AxiosAdapter, InternalAxiosRequestConfig } from 'axios';
import { beforeEach, describe, expect, test } from 'vitest';
import { AuthAPI, PassflowError } from '../../lib/api';
import { TwoFactorApiClient } from '../../lib/api/two-factor';
import { StorageManager } from '../../lib/storage';
import { TEST_CONFIG, VALID_TOKENS } from '../helpers/fixtures';

type Captured = InternalAxiosRequestConfig;

const TFA_TOKEN = 'tfa.jwt.token';

/** Points a client's axios instance at an adapter that records each request. */
const capture = (
  client: object,
  answer: (config: Captured) => { status: number; data: unknown } = () => ({ status: 200, data: {} }),
) => {
  const requests: Captured[] = [];
  const adapter: AxiosAdapter = async (config) => {
    requests.push(config);
    const { status, data } = answer(config);
    const response = { data, status, statusText: '', headers: {}, config };
    if (status >= 400) {
      const error = Object.assign(new Error(`Request failed with status code ${status}`), {
        isAxiosError: true,
        config,
        response,
      });
      throw error;
    }
    return response;
  };
  // The axios instance is private; reaching it is the point of this harness.
  (
    client as unknown as { axiosClient: { instance: { defaults: { adapter: unknown } } } }
  ).axiosClient.instance.defaults.adapter = adapter;
  return requests;
};

const body = (config: Captured) => JSON.parse(config.data as string) as Record<string, unknown>;

describe('sign-in calls go with credentials', () => {
  let api: AuthAPI;
  let requests: Captured[];

  beforeEach(() => {
    localStorage.clear();
    api = new AuthAPI(TEST_CONFIG, new StorageManager({ prefix: '' }));
    requests = capture(api);
  });

  const credentialed: Array<[string, (api: AuthAPI) => Promise<unknown>]> = [
    ['signIn /auth/login', (a) => a.signIn({ email: 'a@example.com', password: 'pw' }, 'd', 'web' as never)],
    ['signUp /auth/register', (a) => a.signUp({ user: { email: 'a@example.com', password: 'pw' } })],
    ['passwordlessSignInComplete', (a) => a.passwordlessSignInComplete({ challenge_id: 'c', otp: '1' })],
    ['passkeyAuthenticateComplete', (a) => a.passkeyAuthenticateComplete({} as never, 'd', 'c')],
    ['passkeyRegisterComplete', (a) => a.passkeyRegisterComplete({} as never, 'd', 'c')],
  ];

  test.each(credentialed)('%s', async (_name, call) => {
    await call(api);
    expect(requests).toHaveLength(1);
    expect(requests[0].withCredentials).toBe(true);
  });

  test('a call that does not end a sign-in is left as it was', async () => {
    await api.sendPasswordResetEmail({ email: 'a@example.com' } as never);
    expect(requests[0].withCredentials).toBeFalsy();
  });

  test('credentials add no Authorization or CSRF header to a sign-in', async () => {
    await api.signIn({ email: 'a@example.com', password: 'pw' }, 'd', 'web' as never);
    expect(requests[0].headers.Authorization).toBeUndefined();
    expect(requests[0].headers['X-CSRF-Token']).toBeUndefined();
  });
});

describe('2FA completion calls', () => {
  let api: TwoFactorApiClient;
  let requests: Captured[];

  beforeEach(() => {
    localStorage.clear();
    api = new TwoFactorApiClient(TEST_CONFIG, new StorageManager({ prefix: '' }));
    requests = capture(api, () => ({ status: 200, data: { success: true, ...VALID_TOKENS } }));
  });

  describe.each([
    [
      'verify',
      (a: TwoFactorApiClient, trust?: boolean) => a.verify({ code: '123456', tfa_token: TFA_TOKEN, trust_device: trust }),
    ],
    [
      'useRecoveryCode',
      (a: TwoFactorApiClient, trust?: boolean) =>
        a.useRecoveryCode({ recovery_code: 'ABCD-1234', tfa_token: TFA_TOKEN, trust_device: trust }),
    ],
    [
      'verifyV2',
      (a: TwoFactorApiClient, trust?: boolean) =>
        a.verifyV2({ challenge_id: 'c', method: 'totp', response: '123456', trust_device: trust }, TFA_TOKEN),
    ],
  ])('%s', (_name, call) => {
    test('sends trust_device only when asked', async () => {
      await call(api);
      await call(api, false);
      await call(api, true);

      expect(body(requests[0])).not.toHaveProperty('trust_device');
      expect(body(requests[1])).not.toHaveProperty('trust_device');
      expect(body(requests[2]).trust_device).toBe(true);
    });

    test('goes with credentials and the 2FA token as Bearer', async () => {
      await call(api);
      expect(requests[0].withCredentials).toBe(true);
      expect(requests[0].headers.Authorization).toBe(`Bearer ${TFA_TOKEN}`);
    });
  });

  test('verifyV2 posts to the verify-challenge route', async () => {
    await api.verifyV2({ challenge_id: 'c', method: 'totp', response: '1' }, TFA_TOKEN);
    expect(requests[0].url).toBe('/v2/auth/2fa/verify');
  });
});

describe('trusted devices', () => {
  const device = {
    id: 'dev-1',
    user_agent: 'Mozilla/5.0',
    created_at: '2026-10-01T00:00:00Z',
    last_used_at: '2026-10-20T00:00:00Z',
    expires_at: '2026-11-01T00:00:00Z',
    current: true,
  };

  test('lists the devices out of the response envelope, with credentials', async () => {
    const api = new TwoFactorApiClient(TEST_CONFIG, new StorageManager({ prefix: '' }));
    const requests = capture(api, () => ({ status: 200, data: { devices: [device] } }));

    await expect(api.getTrustedDevices()).resolves.toEqual([device]);
    expect(requests[0].method).toBe('get');
    expect(requests[0].url).toBe('/v2/user/2fa/trusted-devices');
    expect(requests[0].withCredentials).toBe(true);
  });

  test('revokes one device by id', async () => {
    const api = new TwoFactorApiClient(TEST_CONFIG, new StorageManager({ prefix: '' }));
    const requests = capture(api, () => ({ status: 200, data: { deleted: true } }));

    await api.revokeTrustedDevice('dev-1');
    expect(requests[0].method).toBe('delete');
    expect(requests[0].url).toBe('/v2/user/2fa/trusted-devices/dev-1');
  });

  test('revoking an unknown device rejects with the 404', async () => {
    const api = new TwoFactorApiClient(TEST_CONFIG, new StorageManager({ prefix: '' }));
    capture(api, () => ({
      status: 404,
      data: { error: { id: 'error.not_found', message: 'trusted device not found', status: 404 } },
    }));

    const failure = api.revokeTrustedDevice('nope');
    await expect(failure).rejects.toBeInstanceOf(PassflowError);
    await expect(failure).rejects.toMatchObject({ status: 404 });
  });
});
