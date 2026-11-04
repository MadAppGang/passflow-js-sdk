import { createHash, webcrypto } from 'node:crypto';
import { URLSearchParams as NativeURLSearchParams } from 'node:url';
import axios, { type AxiosAdapter, AxiosError, type InternalAxiosRequestConfig } from 'axios';
import { afterEach, beforeEach, expect, vi } from 'vitest';
import { AppAPI } from '../../lib/api';
import { Passflow, type PassflowConfig, PassflowEvent } from '../../lib/index';
import { TEST_CONFIG, VALID_TOKENS } from './fixtures';
import { createMockPlatform } from './mock-platform';

export const PATH = {
  start: '/auth/passwordless/start',
  complete: '/auth/passwordless/complete',
  status: '/auth/passwordless/status',
  info: '/auth/passwordless/approval/info',
  decide: '/auth/passwordless/approval/decide',
  exchange: '/auth/pkce_exchange',
};
export const PW_SLOT = 'passflow_pwless_pending';
export const FED_SLOT = 'passflow_federated_pkce';
export const OTP = '628194';
export const MATCH = '7391';
export const CODE = 'qa-authorization-code-secret';
export const TFA = { tfa_token: 'tfa.jwt.token', challenge_id: 'factor-challenge', requires_2fa: true };
export const startPayload = (challenge_type: 'otp' | 'magic_link' = 'magic_link') => ({
  email: 'qa@example.com',
  challenge_type,
  redirect_url: 'https://app.example/callback',
  scopes: ['id', 'offline', 'openid', 'qa:custom'],
});
export const fedPayload = () => ({
  provider: 'google' as import('../../lib/api').Providers,
  redirect_url: 'https://app.example/callback?appid=test-app-id&redirectto=https%3A%2F%2Frp.example%2F',
});
export type Request = InternalAxiosRequestConfig;
export const body = (request: Request): Record<string, unknown> =>
  typeof request.data === 'string' ? JSON.parse(request.data) : (request.data ?? {});
export const s256 = (verifier: string) => createHash('sha256').update(verifier).digest('base64url');
export type Fault = { kind: 'network' | 'http' | 'unreadable'; status?: number; data?: unknown };
type Reply = unknown | ((request: Request) => unknown | Promise<unknown>);
const clients: Passflow[] = [];
const originalAdapter = axios.defaults.adapter;
type LocalWrite = { key: string; value: string };
const localWriteObservers = new Set<LocalWrite[]>();
// setup.ts supplies a vi.fn: save its backing implementation, not the mutable mock.
// Capture it once, before this helper installs any storage observer.
const saveLocal = vi.isMockFunction(localStorage.setItem) ? localStorage.setItem.getMockImplementation() : localStorage.setItem;

beforeEach(() => {
  localWriteObservers.clear();
  localStorage.clear();
  sessionStorage.clear();
  if (!saveLocal) throw new Error('PKCE harness requires a working localStorage.setItem');
  // One observer per test, shared by every harness using this localStorage.
  vi.spyOn(localStorage, 'setItem').mockImplementation((key: string, value: string) => {
    for (const writes of localWriteObservers) writes.push({ key, value: String(value) });
    saveLocal.call(localStorage, key, value);
  });
  vi.stubGlobal('URLSearchParams', NativeURLSearchParams);
  vi.stubGlobal('crypto', webcrypto);
  vi.useFakeTimers({ toFake: ['Date', 'setTimeout', 'clearTimeout', 'setInterval', 'clearInterval'] });
});
afterEach(() => {
  for (const sdk of clients.splice(0)) sdk.dispose();
  axios.defaults.adapter = originalAdapter;
  localWriteObservers.clear();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

export function fault(kind: Fault['kind'], status?: number, data?: unknown): Fault {
  return { kind, status, data };
}
export function harness(options: { pkce?: boolean; config?: Partial<PassflowConfig>; url?: string } = {}) {
  vi.spyOn(AppAPI.prototype, 'getAppSettings').mockResolvedValue({ pkce_enabled: options.pkce ?? true } as never);
  const requests: Array<Request & { at: number }> = [];
  const replies = new Map<string, Reply>();
  const queues = new Map<string, Reply[]>();
  const writes: LocalWrite[] = [];
  localWriteObservers.add(writes);
  const navigations: string[] = [];
  const opened: string[] = [];
  const replacements: string[] = [];
  let current = new URL(options.url ?? 'https://app.example/callback');
  let popup: (url: string) => Promise<{ callbackSearch: string; callbackHash: string }> = async () => ({
    callbackSearch: '?code=' + CODE + '&user_state=qa',
    callbackHash: '',
  });
  const platform = createMockPlatform({
    storage: {
      getItem: (key: string) => localStorage.getItem(key),
      setItem: (key: string, value: string) => localStorage.setItem(key, value),
      removeItem: (key: string) => localStorage.removeItem(key),
    },
    getCurrentUrl: vi.fn(() => ({
      href: current.href,
      origin: current.origin,
      pathname: current.pathname,
      search: current.search,
      hash: current.hash,
      hostname: current.hostname,
    })),
    replaceUrl: vi.fn((url: string) => {
      replacements.push(url);
      current = new URL(url, current);
    }),
    navigateTo: vi.fn((url: string) => {
      navigations.push(url);
    }),
    openAuthUrl: vi.fn((url: string) => {
      opened.push(url);
      return popup(url);
    }),
  });
  replies.set(PATH.start, {
    challenge_id: 'challenge-a',
    match_code: MATCH,
    expires_at: new Date(Date.now() + 60_000).toISOString(),
  });
  replies.set(PATH.complete, { code: CODE });
  replies.set(PATH.status, { status: 'pending' });
  replies.set(PATH.exchange, { ...VALID_TOKENS });
  replies.set(PATH.info, {
    state: 'pending',
    app_name: 'QA app',
    requested_at: new Date().toISOString(),
    expires_at: new Date(Date.now() + 60_000).toISOString(),
    browser: 'Firefox',
    os: 'Linux',
    location: { city: 'Sydney', country: 'AU' },
    attempts_left: 5,
  });
  replies.set(PATH.decide, { state: 'approved' });
  replies.set('/auth/login', { code: CODE });
  replies.set('/auth/validate', { code: CODE });
  replies.set('/auth/2fa/verify', { success: true, code: CODE });
  replies.set('/auth/2fa/recovery', { success: true, code: CODE, remaining_recovery_codes: 5 });
  replies.set('/user/logout', { status: 'ok' });
  replies.set('/user/me', { id: 'user-123' });
  const adapter: AxiosAdapter = async (request) => {
    requests.push(Object.assign(request, { at: Date.now() }));
    const path = new URL(request.url ?? '', 'https://api.example').pathname;
    const queue = queues.get(path);
    let answer = queue?.length ? queue.shift() : replies.get(path);
    if (typeof answer === 'function') answer = await answer(request);
    if (answer && typeof answer === 'object' && 'kind' in answer) {
      const f = answer as Fault;
      const response =
        f.kind === 'network'
          ? undefined
          : {
              status: f.status ?? 503,
              statusText: 'Failure',
              data: f.kind === 'unreadable' ? '<html>upstream failure</html>' : (f.data ?? {}),
              headers: {},
              config: request,
            };
      throw new AxiosError(
        f.kind === 'network' ? 'Network Error' : 'Request failed',
        f.kind === 'network' ? 'ERR_NETWORK' : 'ERR_BAD_RESPONSE',
        request,
        { transport: 'qa' },
        response,
      );
    }
    if (answer === undefined) throw new Error('Unexpected HTTP request: ' + path);
    return { data: answer, status: 200, statusText: 'OK', headers: {}, config: request };
  };
  // Configure the external axios transport before construction, including constructor landings.
  // No SDK internals are accessed and no mock invocation details are asserted.
  axios.defaults.adapter = adapter;
  function client(config: Partial<PassflowConfig> = {}) {
    const sdk = new Passflow({
      ...TEST_CONFIG,
      parseQueryParams: false,
      refreshCoordination: 'none',
      platform,
      ...options.config,
      ...config,
    });
    clients.push(sdk);
    const events: Array<{ event: PassflowEvent; payload: unknown; cached: unknown }> = [];
    sdk.subscribe({
      onAuthChange: (event, payload) => {
        events.push({ event, payload, cached: sdk.getCachedTokens() });
      },
    });
    return {
      sdk,
      events,
      of: (event: PassflowEvent) => events.filter((e) => e.event === event).map((e) => e.payload),
      clearEvents: () => {
        events.length = 0;
      },
    };
  }
  const main = client();
  return {
    ...main,
    platform,
    requests,
    writes,
    navigations,
    opened,
    replacements,
    client,
    wire: (suffix: string) => requests.filter((r) => r.url?.endsWith(suffix)),
    reply: (path: string, reply: Reply) => {
      replies.set(path, reply);
    },
    queue: (path: string, ...answers: Reply[]) => {
      queues.set(path, answers);
    },
    popup: (handler: typeof popup) => {
      popup = handler;
    },
    land: (url: string) => {
      current = new URL(url, current);
    },
    url: () => new URL(current.href),
    async start(challenge_type: 'otp' | 'magic_link' = 'magic_link') {
      return main.sdk.passwordlessSignIn(startPayload(challenge_type));
    },
  };
}
export type Harness = ReturnType<typeof harness>;
export function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}
// Fake time waits are driven explicitly; do not run all background token-check intervals.
export async function until(check: () => boolean) {
  for (let i = 0; i < 100; i += 1) {
    if (check()) return;
    await vi.advanceTimersByTimeAsync(0);
  }
  expect(check(), 'observable result did not settle').toBe(true);
}
export async function proves(h: Harness, challenge: unknown) {
  const request = h.wire(PATH.exchange).at(-1);
  expect(request).toBeDefined();
  expect(body(request!)).toMatchObject({ authz_code: CODE, verifier: expect.any(String) });
  const verifier = String(body(request!).verifier);
  expect(verifier.length).toBeGreaterThanOrEqual(43);
  expect(s256(verifier)).toBe(challenge);
}
export function noSession(h: Pick<Harness, 'sdk' | 'of'>) {
  expect(h.sdk.getCachedTokens()?.access_token).toBeUndefined();
  expect(h.of(PassflowEvent.SignIn)).toEqual([]);
}
export function serialiseAll(value: unknown): string {
  const seen = new WeakSet<object>();
  const visit = (v: unknown): unknown => {
    if (!v || typeof v !== 'object') return v;
    if (seen.has(v)) return '[cycle]';
    seen.add(v);
    return Object.fromEntries(Object.getOwnPropertyNames(v).map((key) => [key, visit((v as Record<string, unknown>)[key])]));
  };
  return JSON.stringify(visit(value)) ?? '';
}
export function plain(value: unknown, secrets: unknown[]) {
  expect(value).toBeDefined();
  const serialized = serialiseAll(value);
  expect(serialized).not.toContain('"config"');
  expect(serialized).not.toContain('"request"');
  for (const secret of secrets) {
    if (typeof secret === 'string' && secret) expect(serialized).not.toContain(secret);
  }
}
export async function rejected(promise: Promise<unknown>) {
  const result = await promise.then(
    (value) => ({ ok: true, value }),
    (error: unknown) => ({ ok: false, value: error }),
  );
  expect(result.ok, 'call must reject, not silently succeed').toBe(false);
  return result.value;
}
