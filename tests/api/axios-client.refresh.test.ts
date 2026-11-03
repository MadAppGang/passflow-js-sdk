/**
 * The pre-request refresh of AxiosClient (PFL-792, architecture §3.3 / §2.8 row "SDK API call").
 *
 * Real AxiosClient over a real StorageManager; only the HTTP adapter is stubbed. The refresh
 * handler stands in for the refresh controller (`Passflow` installs `ensureFresh`).
 */
import { AxiosError, type AxiosResponse, type InternalAxiosRequestConfig } from 'axios';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import { AuthAPI } from '../../lib/api';
import { AxiosClient, type AxiosRefreshHandler } from '../../lib/api/axios-client';
import { PassflowError } from '../../lib/api/model';
import { Passflow } from '../../lib/passflow';
import { StorageManager } from '../../lib/storage';
import { type ErrorPayload, PassflowEvent } from '../../lib/store';
import { TokenDeliveryMode } from '../../lib/token/delivery-manager';
import type { Tokens } from '../../lib/types';
import { TEST_CONFIG } from '../helpers/fixtures';
import { createMockPlatform } from '../helpers/mock-platform';
import { jwt } from '../refresh/jwt';

const nowS = () => Math.floor(Date.now() / 1000);
let issued = 0;

/** A token pair whose access token expires `expiresIn` seconds from now. */
const pairExpiringIn = (expiresIn: number): Tokens => {
  issued += 1;
  return {
    access_token: jwt({ sub: 'user-1', exp: nowS() + expiresIn, jti: `access-${issued}`, type: 'access' }),
    refresh_token: jwt({ sub: 'user-1', sid: 's1', iat: nowS(), jti: `refresh-${issued}`, type: 'refresh' }),
    scopes: ['id', 'offline'],
  };
};

const memoryStorage = (): Storage => {
  const items = new Map<string, string>();
  return {
    get length() {
      return items.size;
    },
    clear: () => items.clear(),
    key: (index: number) => Array.from(items.keys())[index] ?? null,
    getItem: (key: string) => items.get(key) ?? null,
    setItem: (key: string, value: string) => {
      items.set(key, String(value));
    },
    removeItem: (key: string) => {
      items.delete(key);
    },
  };
};

type Adapter = (config: InternalAxiosRequestConfig) => Promise<AxiosResponse>;

const ok = (config: InternalAxiosRequestConfig): AxiosResponse => ({
  data: { ok: true },
  status: 200,
  statusText: 'OK',
  headers: {},
  config,
});

const failWith =
  (status: number, headers: Record<string, string> = {}): Adapter =>
  (config) =>
    Promise.reject(
      new AxiosError(`Request failed with status code ${status}`, 'ERR_BAD_REQUEST', config, null, {
        data: {},
        status,
        statusText: String(status),
        headers,
        config,
      }),
    );

describe('AxiosClient pre-request refresh', () => {
  let storage: StorageManager;
  let client: AxiosClient;
  let sent: InternalAxiosRequestConfig[];
  let adapter: Adapter;

  const bearerOf = (config: InternalAxiosRequestConfig | undefined) => config?.headers?.Authorization;

  const setAdapter = (next: Adapter) => {
    adapter = next;
  };

  beforeEach(() => {
    storage = new StorageManager({ storage: memoryStorage() });
    client = new AxiosClient({ url: 'https://api.example.com', appId: 'app', platform: createMockPlatform() }, storage);
    sent = [];
    adapter = async (config) => ok(config);
    (client as unknown as { instance: { defaults: { adapter: Adapter } } }).instance.defaults.adapter = (config) => {
      sent.push(config);
      return adapter(config);
    };
  });

  test('a token expiring within 30 s calls the handler once, allowStale, and sends the returned bearer', async () => {
    const stored = pairExpiringIn(10);
    storage.saveTokens(stored);
    const fresh = pairExpiringIn(3600);
    const handler = vi.fn<AxiosRefreshHandler>().mockResolvedValue(fresh);
    client.setRefreshHandler(handler);

    await client.get('/user/me');

    expect(handler).toHaveBeenCalledTimes(1);
    expect(handler).toHaveBeenCalledWith({ trigger: 'pre-request', allowStale: true });
    expect(bearerOf(sent[0])).toBe(`Bearer ${fresh.access_token}`);
  });

  test('an expired token asks with allowStale false', async () => {
    storage.saveTokens(pairExpiringIn(-60));
    const fresh = pairExpiringIn(3600);
    const handler = vi.fn<AxiosRefreshHandler>().mockResolvedValue(fresh);
    client.setRefreshHandler(handler);

    await client.get('/user/me');

    expect(handler).toHaveBeenCalledWith({ trigger: 'pre-request', allowStale: false });
    expect(bearerOf(sent[0])).toBe(`Bearer ${fresh.access_token}`);
  });

  test('a token outside the window sends the stored bearer without asking', async () => {
    const stored = pairExpiringIn(3600);
    storage.saveTokens(stored);
    const handler = vi.fn<AxiosRefreshHandler>();
    client.setRefreshHandler(handler);

    await client.get('/user/me');

    expect(handler).not.toHaveBeenCalled();
    expect(bearerOf(sent[0])).toBe(`Bearer ${stored.access_token}`);
  });

  test('each expiring call asks the handler once (the controller does the single flight)', async () => {
    storage.saveTokens(pairExpiringIn(-1));
    const fresh = pairExpiringIn(3600);
    const handler = vi.fn<AxiosRefreshHandler>().mockResolvedValue(fresh);
    client.setRefreshHandler(handler);

    await Promise.all([client.get('/user/me'), client.get('/tenant'), client.get('/user/passkey')]);

    expect(handler).toHaveBeenCalledTimes(3);
    expect(sent.map(bearerOf)).toEqual(Array(3).fill(`Bearer ${fresh.access_token}`));
  });

  test('expired token and a failed refresh: the call rejects with that same error, sends nothing and deletes nothing', async () => {
    const stored = pairExpiringIn(-60);
    storage.saveTokens(stored);
    const failure = new PassflowError({
      id: 'error.refresh.unavailable',
      message: 'unavailable',
      status: 503,
      location: '/auth/refresh',
      time: new Date().toISOString(),
    });
    client.setRefreshHandler(vi.fn<AxiosRefreshHandler>().mockRejectedValue(failure));

    const outcome = await client.get('/user/me').catch((error: unknown) => error);

    expect(outcome).toBe(failure);
    expect(sent).toHaveLength(0);
    expect(storage.getTokens()).toEqual(stored);
  });

  test('a not-yet-expired token and a failed refresh: the call goes out with the current bearer', async () => {
    const stored = pairExpiringIn(10);
    storage.saveTokens(stored);
    client.setRefreshHandler(vi.fn<AxiosRefreshHandler>().mockRejectedValue(new Error('outage')));

    await client.get('/user/me');

    expect(bearerOf(sent[0])).toBe(`Bearer ${stored.access_token}`);
    expect(storage.getTokens()).toEqual(stored);
  });

  test('a session that ended (handler resolves undefined) sends the current bearer', async () => {
    const stored = pairExpiringIn(-60);
    storage.saveTokens(stored);
    client.setRefreshHandler(vi.fn<AxiosRefreshHandler>().mockResolvedValue(undefined));

    await client.get('/user/me');

    expect(bearerOf(sent[0])).toBe(`Bearer ${stored.access_token}`);
  });

  test('/auth/refresh skips the pre-request refresh and is never aborted, even while one is in flight', async () => {
    storage.saveTokens(pairExpiringIn(-60));
    let finish: (tokens: Tokens) => void = () => undefined;
    const handler = vi.fn<AxiosRefreshHandler>(
      () =>
        new Promise<Tokens>((resolve) => {
          finish = resolve;
        }),
    );
    client.setRefreshHandler(handler);

    const apiCall = client.get('/user/me');
    await vi.waitFor(() => expect(handler).toHaveBeenCalledTimes(1));
    // The controller's own request goes out through the same client while the API call waits.
    await client.post('/auth/refresh', { refresh_token: 'r' });

    expect(handler).toHaveBeenCalledTimes(1);
    expect(sent).toHaveLength(1);
    expect(sent[0]?.url).toBe('/auth/refresh');
    expect(sent[0]?.signal).toBeUndefined();

    const fresh = pairExpiringIn(3600);
    finish(fresh);
    await apiCall;
    expect(bearerOf(sent[1])).toBe(`Bearer ${fresh.access_token}`);
  });

  test('logout skips the pre-request refresh and sends the current bearer', async () => {
    const stored = pairExpiringIn(-60);
    storage.saveTokens(stored);
    const handler = vi.fn<AxiosRefreshHandler>();
    client.setRefreshHandler(handler);

    await client.post('/user/logout', {});

    expect(handler).not.toHaveBeenCalled();
    expect(bearerOf(sent[0])).toBe(`Bearer ${stored.access_token}`);
  });

  test('without a handler (a client built standalone) nothing refreshes: the stored bearer goes out', async () => {
    const stored = pairExpiringIn(-60);
    storage.saveTokens(stored);

    await client.get('/user/me');

    expect(bearerOf(sent[0])).toBe(`Bearer ${stored.access_token}`);
    expect(storage.getTokens()).toEqual(stored);
  });

  test('setRefreshHandler(undefined) detaches the handler', async () => {
    storage.saveTokens(pairExpiringIn(-60));
    const handler = vi.fn<AxiosRefreshHandler>();
    client.setRefreshHandler(handler);
    client.setRefreshHandler(undefined);

    await client.get('/user/me');

    expect(handler).not.toHaveBeenCalled();
  });

  test('cookie mode never asks the handler and sends no bearer', async () => {
    storage.saveTokens(pairExpiringIn(-60));
    (client as unknown as { tokenDeliveryManager: { setMode(mode: TokenDeliveryMode): void } }).tokenDeliveryManager.setMode(
      TokenDeliveryMode.Cookie,
    );
    const handler = vi.fn<AxiosRefreshHandler>();
    client.setRefreshHandler(handler);

    await client.get('/user/me');

    expect(handler).not.toHaveBeenCalled();
    expect(bearerOf(sent[0])).toBeUndefined();
    expect(sent[0]?.withCredentials).toBe(true);
  });

  describe('responses', () => {
    const invalidations = () =>
      vi.spyOn(
        (client as unknown as { tokenDeliveryManager: { setSessionInvalid(): void } }).tokenDeliveryManager,
        'setSessionInvalid',
      );

    test('a 401 from /auth/refresh does not mark the session invalid (the controller decides)', async () => {
      const spy = invalidations();
      setAdapter(failWith(401));

      await expect(client.post('/auth/refresh', {})).rejects.toBeInstanceOf(PassflowError);

      expect(spy).not.toHaveBeenCalled();
    });

    test('a 401 from any other endpoint still marks the session invalid', async () => {
      const spy = invalidations();
      setAdapter(failWith(401));

      await expect(client.get('/user/me')).rejects.toBeInstanceOf(PassflowError);

      expect(spy).toHaveBeenCalledTimes(1);
    });

    test('a 429 from /auth/refresh is not retried and reaches the caller raw', async () => {
      setAdapter(failWith(429, { 'retry-after': '0' }));

      const outcome = await client.get('/auth/refresh').catch((error: unknown) => error);

      expect(sent).toHaveLength(1);
      expect(outcome).toBeInstanceOf(AxiosError);
      expect((outcome as AxiosError).response?.status).toBe(429);
    });

    test('a 429 from another idempotent endpoint is still retried', async () => {
      let calls = 0;
      setAdapter((config) => {
        calls += 1;
        return calls === 1 ? failWith(429, { 'retry-after': '0' })(config) : Promise.resolve(ok(config));
      });

      await client.get('/user/me');

      expect(sent).toHaveLength(2);
    });
  });
});

describe('Passflow wires every API client to its refresh controller', () => {
  let passflow: Passflow | undefined;
  let sent: InternalAxiosRequestConfig[];
  let events: { event: PassflowEvent; payload: unknown }[];

  const outage = () =>
    new PassflowError({
      id: 'error.http.503',
      message: 'unavailable',
      status: 503,
      location: '/auth/refresh',
      time: new Date().toISOString(),
    });

  const start = (tokens: Tokens): Passflow => {
    localStorage.clear();
    const instance = new Passflow({ ...TEST_CONFIG, refreshCoordination: 'none' });
    passflow = instance;
    instance.setTokens(tokens);
    events = [];
    instance.subscribe({ onAuthChange: (event, payload) => events.push({ event, payload }) });
    sent = [];
    const userClient = (instance as unknown as { userApi: { axiosClient: unknown } }).userApi.axiosClient as {
      instance: { defaults: { adapter: Adapter } };
    };
    userClient.instance.defaults.adapter = async (config) => {
      sent.push(config);
      return { ...ok(config), data: [] };
    };
    return instance;
  };

  afterEach(() => {
    passflow?.dispose();
    passflow = undefined;
    vi.restoreAllMocks();
  });

  test('an expired access token: one refresh through the controller, the call sends the new bearer', async () => {
    const fresh = pairExpiringIn(3600);
    const refreshToken = vi.spyOn(AuthAPI.prototype, 'refreshToken').mockResolvedValue({ ...fresh } as never);
    const instance = start(pairExpiringIn(-60));

    await instance.getUserPasskeys();

    expect(refreshToken).toHaveBeenCalledTimes(1);
    expect(sent[0]?.headers?.Authorization).toBe(`Bearer ${fresh.access_token}`);
    expect(instance.getCachedTokens()?.access_token).toBe(fresh.access_token);
    expect(events.filter((e) => e.event === PassflowEvent.Refresh)).toHaveLength(1);
  });

  test('an expired access token and a 503: the call rejects with the refresh error, tokens kept, one Error', async () => {
    const stored = pairExpiringIn(-60);
    const failure = outage();
    vi.spyOn(AuthAPI.prototype, 'refreshToken').mockRejectedValue(failure);
    const instance = start(stored);

    const outcome = await instance.getUserPasskeys().catch((error: unknown) => error);

    expect(outcome).toBe(failure);
    expect(sent).toHaveLength(0);
    expect(instance.getCachedTokens()?.refresh_token).toBe(stored.refresh_token);
    const errors = events.filter((e) => e.event === PassflowEvent.Error).map((e) => e.payload as ErrorPayload);
    expect(errors).toHaveLength(1);
    expect(errors[0]).toMatchObject({ operation: 'refresh', source: 'pre-request', originalError: failure });
    expect(events.some((e) => e.event === PassflowEvent.SessionExpired || e.event === PassflowEvent.SignOut)).toBe(false);
  });

  test('a not-yet-expired token during the pending retry: sent at once with the current bearer, no new request', async () => {
    const stored = pairExpiringIn(10);
    const refreshToken = vi.spyOn(AuthAPI.prototype, 'refreshToken').mockRejectedValue(outage());
    const instance = start(stored);

    await instance.getUserPasskeys();
    await instance.getUserPasskeys();

    expect(refreshToken).toHaveBeenCalledTimes(1);
    expect(sent.map((config) => config.headers?.Authorization)).toEqual([
      `Bearer ${stored.access_token}`,
      `Bearer ${stored.access_token}`,
    ]);
  });
});
