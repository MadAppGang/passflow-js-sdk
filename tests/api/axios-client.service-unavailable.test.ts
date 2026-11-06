/**
 * Service-unavailable mapping in AxiosClient: a network failure with no response, or a gateway
 * 502/503/504 answer, rejects with one PassflowError (`error.service.unavailable`). Everything else
 * keeps its behaviour.
 *
 * Real AxiosClient over a real StorageManager; only the HTTP adapter is stubbed.
 */
import { AxiosError, type AxiosResponse, type InternalAxiosRequestConfig } from 'axios';
import { beforeEach, describe, expect, test } from 'vitest';
import { AxiosClient } from '../../lib/api/axios-client';
import {
  classifyUpgradeError,
  PassflowError,
  SERVICE_UNAVAILABLE_ERROR_ID,
  SERVICE_UNAVAILABLE_MESSAGE,
} from '../../lib/index';
import { classifyRefreshFailure } from '../../lib/refresh/classify';
import { StorageManager } from '../../lib/storage';
import type { Tokens } from '../../lib/types';
import { createMockPlatform } from '../helpers/mock-platform';
import { jwt } from '../refresh/jwt';

const ID = 'error.service.unavailable';
const MESSAGE = 'Passflow is temporarily unavailable. Please try again in a moment.';
const BODY_SENTINEL = 'leak-check-sentinel-value';

type Adapter = (config: InternalAxiosRequestConfig) => Promise<AxiosResponse>;

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

const nowS = () => Math.floor(Date.now() / 1000);
const longLivedPair = (): Tokens => ({
  access_token: jwt({ sub: 'user-1', exp: nowS() + 3600, jti: 'access-secret-jti', type: 'access' }),
  refresh_token: jwt({ sub: 'user-1', sid: 's1', iat: nowS(), jti: 'refresh-secret-jti', type: 'refresh' }),
  scopes: ['id', 'offline'],
});

/** No response: what the XHR and fetch adapters produce when the browser blocks or drops the call. */
const noResponse =
  (code: string | undefined, cause?: unknown): Adapter =>
  (config) => {
    const error = new AxiosError(code === 'ERR_CANCELED' ? 'canceled' : 'Network Error', code, config, { sent: true });
    if (cause !== undefined) (error as AxiosError & { cause?: unknown }).cause = cause;
    return Promise.reject(error);
  };

const respond =
  (status: number, data: unknown): Adapter =>
  (config) =>
    Promise.reject(
      new AxiosError(
        `Request failed with status code ${status}`,
        status >= 500 ? 'ERR_BAD_RESPONSE' : 'ERR_BAD_REQUEST',
        config,
        { sent: true },
        { data, status, statusText: String(status), headers: {}, config },
      ),
    );

const outcomeOf = (promise: Promise<unknown>) =>
  promise.then(
    () => {
      throw new Error('call must reject, not resolve');
    },
    (error: unknown) => error,
  );

/** Every own property (enumerable or not) of the value and of everything it references. */
const walk = (value: unknown) => {
  const keys = new Set<string>();
  const strings: string[] = [];
  const seen = new WeakSet<object>();
  const visit = (v: unknown) => {
    if (typeof v === 'string') {
      strings.push(v);
      return;
    }
    if (!v || (typeof v !== 'object' && typeof v !== 'function')) return;
    if (seen.has(v as object)) return;
    seen.add(v as object);
    for (const key of Object.getOwnPropertyNames(v)) {
      keys.add(key);
      let child: unknown;
      try {
        child = (v as Record<string, unknown>)[key];
      } catch {
        continue;
      }
      visit(child);
    }
  };
  visit(value);
  return { keys, text: strings.join('\n') };
};

describe('AxiosClient service unavailable', () => {
  let storage: StorageManager;
  let client: AxiosClient;
  let sent: InternalAxiosRequestConfig[];
  let adapter: Adapter;

  beforeEach(() => {
    storage = new StorageManager({ storage: memoryStorage() });
    client = new AxiosClient({ url: 'https://api.example.com', appId: 'app', platform: createMockPlatform() }, storage);
    sent = [];
    adapter = (config) => Promise.resolve({ data: {}, status: 200, statusText: 'OK', headers: {}, config });
    (client as unknown as { instance: { defaults: { adapter: Adapter } } }).instance.defaults.adapter = (config) => {
      sent.push(config);
      return adapter(config);
    };
  });

  const expectUnavailable = (error: unknown, status: number, path: string) => {
    expect(error).toBeInstanceOf(PassflowError);
    const e = error as PassflowError & { cause?: unknown };
    expect(e.id).toBe(ID);
    expect(e.message).toBe(MESSAGE);
    expect(e.status).toBe(status);
    expect(e.location).toContain(path);
    expect(e.cause).toBeDefined();
  };

  describe('network failure with no response (REQ-1a, REQ-2, REQ-3, REQ-4)', () => {
    test('XHR-style ERR_NETWORK without a cause rejects with error.service.unavailable, status 0', async () => {
      adapter = noResponse('ERR_NETWORK');
      const error = await outcomeOf(client.get('/user/me'));
      expectUnavailable(error, 0, '/user/me');
      expect((error as { cause?: { code?: string } }).cause?.code).toBe('ERR_NETWORK');
    });

    test('fetch-style ERR_NETWORK with a TypeError cause keeps that TypeError under the cause', async () => {
      const typeError = new TypeError('Failed to fetch');
      adapter = noResponse('ERR_NETWORK', typeError);
      const error = await outcomeOf(client.get('/user/me'));
      expectUnavailable(error, 0, '/user/me');
      const cause = (error as { cause?: { code?: string; cause?: unknown } }).cause;
      expect(cause?.code).toBe('ERR_NETWORK');
      expect(cause?.cause).toBe(typeError);
    });

    test('an AxiosError with no code and a TypeError cause rejects with error.service.unavailable', async () => {
      const typeError = new TypeError('Failed to fetch');
      adapter = noResponse(undefined, typeError);
      const error = await outcomeOf(client.post('/auth/login', { email: 'a@b.c' }));
      expectUnavailable(error, 0, '/auth/login');
      expect((error as { cause?: { cause?: unknown } }).cause?.cause).toBe(typeError);
    });

    test('the request is sent once: no retry (REQ-5)', async () => {
      adapter = noResponse('ERR_NETWORK');
      await outcomeOf(client.get('/user/me'));
      expect(sent).toHaveLength(1);
    });
  });

  describe('gateway responses 502/503/504 (REQ-1b, REQ-2, REQ-3, REQ-4)', () => {
    const bodies: Array<{ kind: string; data: unknown }> = [
      { kind: 'plain object', data: { message: 'Service Unavailable' } },
      { kind: 'string/HTML', data: '<html><body>502 Bad Gateway</body></html>' },
      { kind: 'empty', data: undefined },
    ];
    const cases = [502, 503, 504].flatMap((status) => bodies.map((body) => ({ status, ...body })));

    test.each(cases)('$status with a $kind body rejects with error.service.unavailable', async ({ status, data }) => {
      adapter = respond(status, data);
      const error = await outcomeOf(client.get('/tenant'));
      expectUnavailable(error, status, '/tenant');
    });

    test('a 503 the Passflow server wrote keeps its own error id', async () => {
      adapter = respond(503, {
        error: {
          id: 'error.2fa.setup_link.send_failed',
          message: 'The email could not be sent',
          status: 503,
          location: '/auth/2fa/setup-link',
          time: '2026-11-07T00:00:00Z',
        },
      });
      const error = await outcomeOf(client.post('/auth/2fa/setup-link', {}));
      expect(error).toBeInstanceOf(PassflowError);
      expect((error as PassflowError).id).toBe('error.2fa.setup_link.send_failed');
      expect((error as PassflowError).status).toBe(503);
    });

    test('a GET answered 503 is sent once: no retry (REQ-5)', async () => {
      adapter = respond(503, { message: 'Service Unavailable' });
      await outcomeOf(client.get('/tenant'));
      expect(sent).toHaveLength(1);
    });
  });

  describe('unchanged behaviour (REQ-5)', () => {
    test('ERR_CANCELED rejects with the original error, not a PassflowError', async () => {
      let original: unknown;
      adapter = (config) => {
        const rejection = noResponse('ERR_CANCELED')(config);
        rejection.catch((e: unknown) => {
          original = e;
        });
        return rejection;
      };
      const error = await outcomeOf(client.get('/user/me'));
      expect(error).not.toBeInstanceOf(PassflowError);
      expect(error).toBe(original);
      expect((error as AxiosError).code).toBe('ERR_CANCELED');
    });

    test('ETIMEDOUT with a TypeError cause rejects unchanged', async () => {
      let original: unknown;
      adapter = (config) => {
        const rejection = noResponse('ETIMEDOUT', new TypeError('Failed to fetch'))(config);
        rejection.catch((e: unknown) => {
          original = e;
        });
        return rejection;
      };
      const error = await outcomeOf(client.get('/user/me'));
      expect(error).toBe(original);
      expect((error as { id?: string }).id).not.toBe(ID);
    });

    test('ECONNABORTED rejects with the original error', async () => {
      let original: unknown;
      adapter = (config) => {
        const rejection = noResponse('ECONNABORTED')(config);
        rejection.catch((e: unknown) => {
          original = e;
        });
        return rejection;
      };
      const error = await outcomeOf(client.get('/user/me'));
      expect(error).toBe(original);
      expect((error as AxiosError).code).toBe('ECONNABORTED');
    });

    test('a bare TypeError (not an AxiosError) from the request side rejects unchanged', async () => {
      const original = new TypeError('Cannot read properties of undefined');
      adapter = () => Promise.reject(original);
      const error = await outcomeOf(client.get('/user/me'));
      expect(error).toBe(original);
    });

    test('400 with a Passflow-format body keeps the body error id', async () => {
      adapter = respond(400, {
        error: { id: 'error.bad.request', message: 'Bad', status: 400, location: '/auth/login', time: '2026-11-07T00:00:00Z' },
      });
      const error = await outcomeOf(client.post('/auth/login', { email: 'a@b.c' }));
      expect(error).toBeInstanceOf(PassflowError);
      expect((error as PassflowError).id).toBe('error.bad.request');
      expect((error as PassflowError).status).toBe(400);
    });

    test.each([500, 501, 505])('%i with a plain object body keeps the generic id error.http.<status>', async (status) => {
      adapter = respond(status, { message: 'Internal' });
      const error = await outcomeOf(client.post('/auth/login', { email: 'a@b.c' }));
      expect(error).toBeInstanceOf(PassflowError);
      expect((error as PassflowError).id).toBe(`error.http.${status}`);
      expect((error as PassflowError).status).toBe(status);
    });
  });

  describe('serialisation carries no request secrets (REQ-3)', () => {
    const scenarios: Array<{ name: string; make: () => Adapter; status: number }> = [
      { name: 'network', make: () => noResponse('ERR_NETWORK', new TypeError('Failed to fetch')), status: 0 },
      { name: '503', make: () => respond(503, { message: 'Service Unavailable' }), status: 503 },
    ];

    test.each(scenarios)(
      '$name: JSON and a full property walk find no config, request, response or secret',
      async ({ make, status }) => {
        const tokens = longLivedPair();
        storage.saveTokens(tokens);
        adapter = make();

        // An authenticated POST, so the request carries a bearer as well as a password body.
        const error = await outcomeOf(client.post('/user/logout', { email: 'qa@example.com', password: BODY_SENTINEL }));
        expectUnavailable(error, status, '/user/logout');
        // The stubbed request really carried both secrets.
        expect(String(sent[0]?.data)).toContain(BODY_SENTINEL);
        expect(String(sent[0]?.headers?.Authorization)).toContain(tokens.access_token);

        const json = JSON.stringify(error) ?? '';
        for (const forbidden of ['"config"', '"request"', '"response"', BODY_SENTINEL, tokens.access_token, 'Bearer ']) {
          expect(json).not.toContain(forbidden);
        }

        const { keys, text } = walk(error);
        expect(keys.has('config')).toBe(false);
        expect(keys.has('request')).toBe(false);
        expect(keys.has('response')).toBe(false);
        expect(text).not.toContain(BODY_SENTINEL);
        expect(text).not.toContain(tokens.access_token);
        expect(text).not.toContain(tokens.refresh_token);
        expect(text).not.toContain('Bearer ');
      },
    );
  });

  describe('classifiers (REQ-6)', () => {
    test('classifyRefreshFailure: the network error is transient', async () => {
      adapter = noResponse('ERR_NETWORK');
      const error = await outcomeOf(client.get('/user/me'));
      expect((error as PassflowError).id).toBe(ID);
      expect(classifyRefreshFailure(error).kind).toBe('transient');
    });

    test('classifyRefreshFailure: the 503 error is transient', async () => {
      adapter = respond(503, '<html>Service Unavailable</html>');
      const error = await outcomeOf(client.get('/user/me'));
      expect((error as PassflowError).id).toBe(ID);
      expect(classifyRefreshFailure(error).kind).toBe('transient');
    });

    test("classifyUpgradeError(err, 'start') reads the network error as 'network'", async () => {
      adapter = noResponse('ERR_NETWORK', new TypeError('Failed to fetch'));
      const error = await outcomeOf(client.get('/user/me'));
      expect((error as PassflowError).id).toBe(ID);
      expect(classifyUpgradeError(error, 'start').kind).toBe('network');
    });

    test('one POST to /auth/refresh failing with ERR_NETWORK is classified transient', async () => {
      adapter = noResponse('ERR_NETWORK');
      const error = await outcomeOf(client.post('/auth/refresh', { refresh_token: 'r' }));
      expect(sent).toHaveLength(1);
      expect(sent[0]?.url).toBe('/auth/refresh');
      expectUnavailable(error, 0, '/auth/refresh');
      expect(classifyRefreshFailure(error).kind).toBe('transient');
    });
  });

  test('the id and message are public constants of the package entry (REQ-2)', () => {
    expect(SERVICE_UNAVAILABLE_ERROR_ID).toBe('error.service.unavailable');
    expect(SERVICE_UNAVAILABLE_MESSAGE).toBe('Passflow is temporarily unavailable. Please try again in a moment.');
  });
});
