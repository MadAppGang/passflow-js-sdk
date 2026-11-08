import { type AxiosAdapter, AxiosError, type InternalAxiosRequestConfig } from 'axios';
import { afterEach, describe, expect, test, vi } from 'vitest';
import { PassflowEndpointPaths, PassflowError } from '../../lib/api/model';
import type { UpgradeAPI } from '../../lib/api/upgrade';
import { Passflow } from '../../lib/passflow';
import { StorageManager } from '../../lib/storage';
import { PassflowEvent } from '../../lib/store';
import type { Tokens } from '../../lib/types';
import { passkeyFactor } from '../../lib/upgrade/factors';
import { EXPIRED_TOKENS, TEST_CONFIG, VALID_TOKENS } from '../helpers/fixtures';
import { createMockPlatform } from '../helpers/mock-platform';

type Answer = {
  status: number;
  data: unknown;
  headers?: Record<string, string>;
};

type HttpBoundary = {
  axiosClient: { instance: { defaults: { adapter: AxiosAdapter } } };
};

const START_PATH = '/auth/session/upgrade/start';
const COMMIT_PATH = '/auth/session/upgrade';
const WRONG_CODE_ID = 'error.api.request.2fa_code.invalid';
const START_ANSWER = {
  challenge_id: 'c1',
  method: 'passkey',
  expires_at: '2030-01-01T00:00:00Z',
  webauthn: { challenge: 'x' },
};
const COMMIT_PROOF = { type: 'totp', assertion: { code: '123456' } };

const TOKEN_EVENTS = [
  PassflowEvent.RefreshStart,
  PassflowEvent.Refresh,
  PassflowEvent.SignIn,
  PassflowEvent.SignOut,
  PassflowEvent.SessionExpired,
];

const storedCases = [
  { name: 'valid stored tokens', tokens: VALID_TOKENS },
  { name: 'expired access token and valid refresh token', tokens: EXPIRED_TOKENS },
];

const hostedAnswer = (config: InternalAxiosRequestConfig): Answer => {
  if (config.url === START_PATH) return { status: 200, data: START_ANSWER };
  if (config.url === COMMIT_PATH) return { status: 204, data: '' };
  throw new Error(`Unexpected HTTP request: ${config.method} ${config.url}`);
};

const copyTokens = (tokens: Tokens): Tokens => ({ ...tokens, scopes: tokens.scopes && [...tokens.scopes] });

describe('hosted upgrade cookie-only transport', () => {
  let passflow: Passflow | undefined;
  let stopObserving: (() => void) | undefined;

  const start = (tokens?: Tokens, answer: (config: InternalAxiosRequestConfig) => Answer = hostedAnswer) => {
    localStorage.clear();
    sessionStorage.clear();
    const instance = new Passflow({
      ...TEST_CONFIG,
      keyStoragePrefix: '',
      refreshCoordination: 'none',
      platform: createMockPlatform({ storage: localStorage }),
    });
    passflow = instance;
    const sent: InternalAxiosRequestConfig[] = [];
    const adapter: AxiosAdapter = async (config) => {
      sent.push(config);
      const { status, data, headers = {} } = answer(config);
      const response = { data, status, statusText: String(status), headers, config };
      if (status >= 400) {
        throw new AxiosError(`Request failed with status code ${status}`, 'ERR_BAD_REQUEST', config, null, response);
      }
      return response;
    };

    // Reach only the HTTP boundary; all assertions use wire data and public SDK observations.
    const apis = instance as unknown as { upgradeApi: UpgradeAPI; authApi: unknown };
    for (const api of [apis.upgradeApi, apis.authApi]) {
      (api as HttpBoundary).axiosClient.instance.defaults.adapter = adapter;
    }

    if (tokens) instance.setTokens(copyTokens(tokens));
    const events: PassflowEvent[] = [];
    const subscriber = { onAuthChange: (event: PassflowEvent) => events.push(event) };
    instance.subscribe(subscriber, TOKEN_EVENTS);
    stopObserving = () => instance.unsubscribe(subscriber, TOKEN_EVENTS);
    const storage = new StorageManager({ storage: localStorage, prefix: '' });
    return { passflow: instance, api: apis.upgradeApi, sent, storage, events };
  };

  const expectCookiePost = (request: InternalAxiosRequestConfig, path: string, payload: unknown) => {
    expect(request.method).toBe('post');
    expect(request.url).toBe(path);
    expect(request.withCredentials).toBe(true);
    expect(request.headers.get('X-Passflow-ClientID')).toBe('test-app-id');
    expect(request.headers.get('Authorization')).toBeUndefined();
    expect(request.headers.get('X-CSRF-Token')).toBeUndefined();
    expect(JSON.parse(request.data as string)).toEqual(payload);
  };

  afterEach(() => {
    stopObserving?.();
    stopObserving = undefined;
    passflow?.dispose();
    passflow = undefined;
    vi.restoreAllMocks();
    localStorage.clear();
    sessionStorage.clear();
  });

  // TEST-1 and TEST-2; REQ-1, REQ-2, REQ-3, REQ-6.
  test.each(storedCases)('T1 startHostedUpgrade sends only a cookie-authenticated POST with $name', async ({ tokens }) => {
    const f = start(tokens);
    const payload = { method: 'passkey' };
    expect(f.storage.getTokens()).toEqual(tokens);

    const result = await f.api.startHostedUpgrade(payload);

    expect(PassflowEndpointPaths.hostedUpgradeStart).toBe(START_PATH);
    expect(result).toEqual(START_ANSWER);
    expect(f.sent).toHaveLength(1);
    expectCookiePost(f.sent[0]!, PassflowEndpointPaths.hostedUpgradeStart, payload);
    expect(f.passflow.getCachedTokens()).toEqual(tokens);
    expect(f.storage.getTokens()).toEqual(tokens);
    expect(f.events).toEqual([]);
  });

  // TEST-3 and TEST-4; REQ-1, REQ-2, REQ-3, REQ-6.
  test.each(storedCases)(
    'T1 commitHostedUpgrade sends the unwrapped proof and resolves void with $name',
    async ({ tokens }) => {
      const f = start(tokens);
      expect(f.storage.getTokens()).toEqual(tokens);

      await expect(f.api.commitHostedUpgrade(COMMIT_PROOF)).resolves.toBeUndefined();

      expect(PassflowEndpointPaths.hostedUpgrade).toBe(COMMIT_PATH);
      expect(f.sent).toHaveLength(1);
      expectCookiePost(f.sent[0]!, PassflowEndpointPaths.hostedUpgrade, COMMIT_PROOF);
      expect(f.passflow.getCachedTokens()).toEqual(tokens);
      expect(f.storage.getTokens()).toEqual(tokens);
      expect(f.events).toEqual([]);
    },
  );

  // TEST-5; REQ-4, REQ-6.
  test('T1 a wrong-code 401 rejects with PassflowError and preserves the token session', async () => {
    const f = start(VALID_TOKENS, (config) => {
      if (config.url !== COMMIT_PATH) return hostedAnswer(config);
      return {
        status: 401,
        data: {
          error: {
            id: WRONG_CODE_ID,
            message: 'Invalid verification code',
            status: 401,
            location: COMMIT_PATH,
            time: '2026-01-01T00:00:00Z',
          },
        },
      };
    });
    expect(f.passflow.getCachedTokens()).toEqual(VALID_TOKENS);
    expect(f.storage.getTokens()).toEqual(VALID_TOKENS);

    const result = f.api.commitHostedUpgrade(COMMIT_PROOF);

    await expect(result).rejects.toBeInstanceOf(PassflowError);
    await expect(result).rejects.toMatchObject({ id: WRONG_CODE_ID, status: 401 });
    expect(f.sent).toHaveLength(1);
    expectCookiePost(f.sent[0]!, COMMIT_PATH, COMMIT_PROOF);
    expect(f.passflow.getCachedTokens()).toEqual(VALID_TOKENS);
    expect(f.storage.getTokens()).toEqual(VALID_TOKENS);
    expect(f.events).toEqual([]);
  });

  // TEST-6; REQ-4, REQ-5, REQ-6.
  test('T1 a hosted start challenge rejects without presenting the token-session upgrade prompt', async () => {
    const f = start(VALID_TOKENS, (config) => {
      if (config.url !== START_PATH) return hostedAnswer(config);
      return {
        status: 401,
        headers: {
          'WWW-Authenticate': 'Bearer error="insufficient_user_authentication", acr_values="2"',
        },
        data: {
          error: {
            id: 'error.upgrade.required',
            message: 'Higher assurance required',
            status: 401,
            location: START_PATH,
            time: '2026-01-01T00:00:00Z',
          },
        },
      };
    });
    const presentedPrompts: unknown[] = [];
    const disable = f.passflow.upgrade.enable({
      prompt: async (request) => {
        presentedPrompts.push(request.challenge);
        return { type: 'cancel' };
      },
    });
    try {
      await expect(f.api.startHostedUpgrade({ method: 'passkey' })).rejects.toBeInstanceOf(PassflowError);

      expect(presentedPrompts).toEqual([]);
      expect(f.sent).toHaveLength(1);
      expectCookiePost(f.sent[0]!, START_PATH, { method: 'passkey' });
      expect(f.passflow.getCachedTokens()).toEqual(VALID_TOKENS);
      expect(f.storage.getTokens()).toEqual(VALID_TOKENS);
      expect(f.events).toEqual([]);
    } finally {
      disable();
    }
  });

  // TEST-7 and TEST-8; REQ-2, REQ-3, REQ-4, REQ-7.
  test.each([
    { name: 'no stored tokens', tokens: undefined },
    { name: 'an existing token session', tokens: VALID_TOKENS },
  ])('T2 hostedUpgrade.elevate completes start then commit without changing $name', async ({ tokens }) => {
    const f = start(tokens);
    const cached = f.passflow.getCachedTokens();
    const cachedBefore = cached && copyTokens(cached);
    const storedBefore = f.storage.getTokens();
    expect(cachedBefore).toEqual(tokens);
    expect(storedBefore).toEqual(tokens);
    const disable = f.passflow.hostedUpgrade.enable({
      factors: [passkeyFactor],
      relyingPartyId: 'test-hostname.com',
      prompt: async (request) => {
        request.onFactorSelected('passkey');
        return { type: 'submit', factor: 'passkey' };
      },
    });
    try {
      const elevation = await f.passflow.hostedUpgrade.elevate({ status: 401 }, { kind: 'imperative' });

      expect(elevation).toMatchObject({ waiter: { kind: 'imperative' } });
      expect(f.sent.map((config) => config.url)).toEqual([START_PATH, COMMIT_PATH]);
      expectCookiePost(f.sent[0]!, START_PATH, { method: 'passkey', relying_party_id: 'test-hostname.com' });
      expectCookiePost(f.sent[1]!, COMMIT_PATH, {
        type: 'passkey',
        assertion: { challenge_id: 'c1', credential: { id: 'auth-id' } },
      });
      expect(f.passflow.getCachedTokens()).toEqual(cachedBefore);
      expect(f.storage.getTokens()).toEqual(storedBefore);
      expect(f.events).toEqual([]);
    } finally {
      disable();
    }
  });
});
