/**
 * First-time 2FA enrolment on a `required` app (PFL-769): what goes on the wire, and whose credential.
 *
 * Requests run through the real AxiosClient and TwoFactorService, interceptors included, and stop at
 * a capturing adapter. A stored session must never replace the `tfa_token` or the setup link's session.
 */
import type { AxiosAdapter, InternalAxiosRequestConfig } from 'axios';
import { beforeEach, describe, expect, test, vi } from 'vitest';
import { TwoFactorApiClient } from '../../lib/api/two-factor';
import { TwoFactorService } from '../../lib/services/two-factor-service';
import { StorageManager } from '../../lib/storage';
import { PassflowEvent, PassflowStore } from '../../lib/store';
import { TokenDeliveryMode } from '../../lib/token/delivery-manager';
import { TEST_CONFIG, VALID_TOKENS } from '../helpers/fixtures';

type Captured = InternalAxiosRequestConfig;
type Answer = { status: number; data: unknown };

const TFA_TOKEN = 'tfa.jwt.token';
const SESSION_TOKEN = 'setup.session.token';
const STORED_BEARER = `Bearer ${VALID_TOKENS.access_token}`;
const QR_ANSWER = { secret: 'S3CRET', qr_code_url: 'otpauth://totp/x', qr_code_image: 'data:image/png;base64,iVBOR' };
const CONFIRM_ANSWER = { enabled: true, recovery_codes: ['a', 'b'] };

const setup = (answer: (config: Captured) => Answer = () => ({ status: 200, data: {} })) => {
  localStorage.clear();
  sessionStorage.clear();
  const storage = new StorageManager({ prefix: '' });
  const api = new TwoFactorApiClient(TEST_CONFIG, storage);
  const requests: Captured[] = [];
  const adapter: AxiosAdapter = async (config) => {
    requests.push(config);
    const { status, data } = answer(config);
    const response = { data, status, statusText: '', headers: {}, config };
    if (status >= 400) {
      throw Object.assign(new Error(`Request failed with status code ${status}`), { isAxiosError: true, config, response });
    }
    return response;
  };
  // The axios instance is private; reaching it is the point of this harness.
  const client = (
    api as unknown as {
      axiosClient: {
        instance: { defaults: { adapter: unknown } };
        tokenDeliveryManager: { setMode(mode: string): void };
      };
    }
  ).axiosClient;
  client.instance.defaults.adapter = adapter;
  const store = new PassflowStore();
  const service = new TwoFactorService(api, store);
  return { api, service, store, storage, requests, client };
};

const lastRequest = (requests: Captured[]) => requests[requests.length - 1];
const bearerOf = (config: Captured) => config.headers.get('Authorization');

describe('enrolment on a pending sign-in', () => {
  const answers = (config: Captured): Answer => {
    if (config.url === '/auth/2fa/enrollment') return { status: 200, data: { enrollment: 'direct' } };
    if (config.url === '/auth/2fa/enrollment/email-link') return { status: 200, data: { email_sent: true } };
    if (config.url === '/auth/2fa/setup/begin') return { status: 200, data: QR_ANSWER };
    if (config.url === '/auth/2fa/setup/confirm') return { status: 200, data: CONFIRM_ANSWER };
    return { status: 200, data: {} };
  };

  const calls: Array<[string, string, string, (s: TwoFactorService) => Promise<unknown>]> = [
    ['read the state', 'get', '/auth/2fa/enrollment', (s) => s.getEnrollment()],
    ['send the link', 'post', '/auth/2fa/enrollment/email-link', (s) => s.sendSetupLink()],
    ['begin', 'post', '/auth/2fa/setup/begin', (s) => s.beginEnrollment()],
    ['confirm', 'post', '/auth/2fa/setup/confirm', (s) => s.confirmEnrollment('123456')],
  ];

  test.each(calls)('%s goes on the tfa_token, not the stored session', async (_name, method, url, call) => {
    const { service, storage, requests } = setup(answers);
    storage.saveTokens(VALID_TOKENS);
    service.setPartialAuthState('', '', TFA_TOKEN);

    await call(service);

    expect(requests).toHaveLength(1);
    expect(requests[0].method).toBe(method);
    expect(requests[0].url).toBe(url);
    expect(bearerOf(requests[0])).toBe(`Bearer ${TFA_TOKEN}`);
  });

  test.each(calls)('%s with no pending sign-in sends nothing and rejects', async (_name, _method, _url, call) => {
    const { service, requests } = setup(answers);

    await expect(call(service)).rejects.toThrow('User must sign in first');
    expect(requests).toHaveLength(0);
  });

  test('the state comes back as the bare value', async () => {
    const { service } = setup(answers);
    service.setPartialAuthState('', '', TFA_TOKEN);

    await expect(service.getEnrollment()).resolves.toBe('direct');
  });

  test('begin and confirm send no stale body and the code, respectively', async () => {
    const { service, requests } = setup(answers);
    service.setPartialAuthState('', '', TFA_TOKEN);

    await service.beginEnrollment();
    expect(requests[0].data).toBeUndefined();

    await service.confirmEnrollment('123456');
    expect(JSON.parse(requests[1].data as string)).toEqual({ code: '123456' });
  });

  test('a confirmed enrolment leaves the sign-in pending, and verify finishes it with the same code', async () => {
    const { service, requests } = setup((config) =>
      config.url === '/auth/2fa/verify' ? { status: 200, data: VALID_TOKENS } : answers(config),
    );
    service.setPartialAuthState('', '', TFA_TOKEN);

    await service.confirmEnrollment('123456');
    expect(service.isVerificationRequired()).toBe(true);

    await service.verify('123456');
    const verify = lastRequest(requests);
    expect(verify.url).toBe('/auth/2fa/verify');
    expect(bearerOf(verify)).toBe(`Bearer ${TFA_TOKEN}`);
    expect(JSON.parse(verify.data as string)).toEqual({ code: '123456' });
    expect(service.isVerificationRequired()).toBe(false);
  });

  test('confirm refuses a malformed code without a request', async () => {
    const { service, requests } = setup(answers);
    service.setPartialAuthState('', '', TFA_TOKEN);

    await expect(service.confirmEnrollment('12')).rejects.toThrow('Invalid TOTP code format');
    expect(requests).toHaveLength(0);
  });

  test('a server refusal reaches the caller with its id and is reported once', async () => {
    const { service, store } = setup(() => ({
      status: 403,
      data: { error: { id: 'error.2fa.enrollment.not_allowed', message: 'no', status: 403 } },
    }));
    const onError = vi.fn();
    store.subscribe({ onAuthChange: onError }, [PassflowEvent.Error]);
    service.setPartialAuthState('', '', TFA_TOKEN);

    await expect(service.beginEnrollment()).rejects.toMatchObject({ id: 'error.2fa.enrollment.not_allowed', status: 403 });
    expect(onError).toHaveBeenCalledTimes(1);
    expect(onError.mock.calls[0][1]).toMatchObject({ operation: '2fa.setup.begin' });
  });

  test('a 429 on a POST is not retried: every request counts against the budget', async () => {
    const { service, requests } = setup(() => ({ status: 429, data: { error: 'too many' } }));
    service.setPartialAuthState('', '', TFA_TOKEN);

    await expect(service.sendSetupLink()).rejects.toMatchObject({ response: { status: 429 } });
    expect(requests).toHaveLength(1);
  });
});

describe('a setup link session', () => {
  const answers = (config: Captured): Answer => {
    if (config.url?.startsWith('/auth/2fa-setup/')) {
      return { status: 200, data: { valid: true, user_id: 'u1', app_id: 'a1', session_token: SESSION_TOKEN, expires_in: 900 } };
    }
    if (config.url === '/user/2fa/setup/begin') return { status: 200, data: QR_ANSWER };
    if (config.url === '/user/2fa/setup/confirm') return { status: 200, data: CONFIRM_ANSWER };
    if (config.url === '/user/2fa/status') return { status: 200, data: { enabled: false } };
    return { status: 200, data: {} };
  };

  const calls: Array<[string, string, (s: TwoFactorService) => Promise<unknown>]> = [
    ['status', '/user/2fa/status', (s) => s.getStatus()],
    ['begin', '/user/2fa/setup/begin', (s) => s.beginSetup()],
    ['confirm', '/user/2fa/setup/confirm', (s) => s.confirmSetup('123456')],
  ];

  test.each(calls)('%s goes on the session token with nothing stored', async (_name, url, call) => {
    const { service, requests } = setup(answers);
    await service.validateTwoFactorSetupMagicLink('t0k');

    await call(service);

    expect(lastRequest(requests).url).toBe(url);
    expect(bearerOf(lastRequest(requests))).toBe(`Bearer ${SESSION_TOKEN}`);
  });

  test.each(calls)('%s goes on the session token with another user signed in', async (_name, url, call) => {
    const { service, storage, requests } = setup(answers);
    storage.saveTokens(VALID_TOKENS);
    await service.validateTwoFactorSetupMagicLink('t0k');

    await call(service);

    expect(lastRequest(requests).url).toBe(url);
    expect(bearerOf(lastRequest(requests))).toBe(`Bearer ${SESSION_TOKEN}`);
  });

  test.each(calls)('%s goes on the session token in cookie mode', async (_name, url, call) => {
    const { service, client, requests } = setup(answers);
    client.tokenDeliveryManager.setMode(TokenDeliveryMode.Cookie);
    await service.validateTwoFactorSetupMagicLink('t0k');

    await call(service);

    expect(lastRequest(requests).url).toBe(url);
    expect(bearerOf(lastRequest(requests))).toBe(`Bearer ${SESSION_TOKEN}`);
  });

  test('the link itself is read with no bearer, asking for JSON', async () => {
    const { service, storage, requests } = setup(answers);
    storage.saveTokens(VALID_TOKENS);

    await service.validateTwoFactorSetupMagicLink('t0k');

    expect(requests[0].url).toBe('/auth/2fa-setup/t0k');
    expect(bearerOf(requests[0])).toBeFalsy();
    expect(requests[0].headers.get('Accept')).toContain('application/json');
  });

  test('the session lasts what the server said', async () => {
    const { service } = setup(answers);
    const before = Date.now();

    await service.validateTwoFactorSetupMagicLink('t0k');

    const expiresAt = service.getMagicLinkSession()?.expiresAt ?? 0;
    expect(expiresAt).toBeGreaterThanOrEqual(before + 900_000);
    expect(expiresAt).toBeLessThan(before + 901_000);
  });

  test('a correct confirm ends the session: later setup calls use the stored session again', async () => {
    const { service, storage, requests } = setup(answers);
    storage.saveTokens(VALID_TOKENS);
    await service.validateTwoFactorSetupMagicLink('t0k');

    await service.confirmSetup('123456');
    expect(service.hasMagicLinkSession()).toBe(false);

    await service.beginSetup();
    expect(bearerOf(lastRequest(requests))).toBe(STORED_BEARER);
  });

  test('a wrong code keeps the session for the next try and does not touch the stored session', async () => {
    const { service, storage, requests, client } = setup((config) =>
      config.url === '/user/2fa/setup/confirm'
        ? { status: 401, data: { error: { id: 'error.api.request.2fa_code.invalid', message: 'no', status: 401 } } }
        : answers(config),
    );
    storage.saveTokens(VALID_TOKENS);
    const invalidate = vi.spyOn(client.tokenDeliveryManager as never, 'setSessionInvalid' as never);
    await service.validateTwoFactorSetupMagicLink('t0k');

    await expect(service.confirmSetup('123456')).rejects.toMatchObject({ id: 'error.api.request.2fa_code.invalid' });

    expect(service.hasMagicLinkSession()).toBe(true);
    expect(invalidate).not.toHaveBeenCalled();
    expect(requests).toHaveLength(2);
  });

  test('a finished sign-in ends the session', async () => {
    const { service, store } = setup(answers);
    await service.validateTwoFactorSetupMagicLink('t0k');

    store.notify(PassflowEvent.SignIn, { tokens: VALID_TOKENS, parsedTokens: undefined } as never);

    expect(service.hasMagicLinkSession()).toBe(false);
  });

  test('without a session the stored bearer goes, as it always did', async () => {
    const { service, storage, requests } = setup(answers);
    storage.saveTokens(VALID_TOKENS);

    await service.beginSetup();

    expect(bearerOf(requests[0])).toBe(STORED_BEARER);
  });
});

describe('reading a setup link', () => {
  const refusal =
    (id: string, status = 400) =>
    () => ({ status, data: { error: { id, message: `server: ${id}`, status } } });

  test.each([
    ['error.2fa.setup.token.already_used', 400, 'ALREADY_USED'],
    ['error.2fa.setup.token.expired', 400, 'EXPIRED_TOKEN'],
    ['error.2fa.setup.token.revoked', 400, 'REVOKED_TOKEN'],
    ['error.2fa.setup.token.invalid', 400, 'INVALID_TOKEN'],
    ['error.2fa.setup.token.not.found', 400, 'INVALID_TOKEN'],
    ['error.internal', 500, 'SERVER_ERROR'],
  ])('%s answers %i as %s, with the server message and no session', async (id, status, code) => {
    const { service } = setup(refusal(id, status));

    const result = await service.validateTwoFactorSetupMagicLink('t0k');

    expect(result).toEqual({ success: false, error: { code, message: `server: ${id}` } });
    expect(service.hasMagicLinkSession()).toBe(false);
  });

  test('valid: false is a refusal, even on a 200', async () => {
    const { service } = setup(() => ({ status: 200, data: { valid: false } }));

    const result = await service.validateTwoFactorSetupMagicLink('t0k');

    expect(result.success).toBe(false);
    expect(result.error?.code).toBe('INVALID_TOKEN');
    expect(service.hasMagicLinkSession()).toBe(false);
  });
});

describe('the setup answer', () => {
  test('the image the server sends becomes qr_code, on both setup routes', async () => {
    const { api } = setup(() => ({ status: 200, data: QR_ANSWER }));

    const expected = { secret: 'S3CRET', qr_code: 'iVBOR', qr_code_url: 'otpauth://totp/x' };
    await expect(api.beginSetup()).resolves.toEqual(expected);
    await expect(api.beginEnrollment(TFA_TOKEN)).resolves.toEqual(expected);
  });

  test('with no image, qr_code is empty and the url is still there', async () => {
    const { api } = setup(() => ({ status: 200, data: { secret: 'S3CRET', qr_code_url: 'otpauth://totp/x' } }));

    await expect(api.beginSetup()).resolves.toEqual({ secret: 'S3CRET', qr_code: '', qr_code_url: 'otpauth://totp/x' });
  });
});
