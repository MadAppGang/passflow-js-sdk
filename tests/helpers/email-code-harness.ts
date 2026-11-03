import { createHash } from 'node:crypto';
import { URLSearchParams as NativeURLSearchParams } from 'node:url';
import type { AxiosAdapter, InternalAxiosRequestConfig } from 'axios';
import { afterEach, beforeEach, vi } from 'vitest';
import { AppAPI, AuthAPI } from '../../lib/api';
import { Passflow, type PassflowConfig, PassflowEvent } from '../../lib/index';
import { TEST_CONFIG, VALID_TOKENS } from './fixtures';
import { createMockPlatform } from './mock-platform';

export const EMAIL = 'a@example.com';
export const PASSWORD = 'SecurePassword123!';
export const CODE_STEP = {
  challenge_id: 'ch-1',
  message: 'We sent a code to a***@example.com.',
  email_verification_required: true as const,
};
export const LINK_STEP = { message: 'We sent a link.', email_verification_required: true as const };
export const OTP = { challenge_id: 'ch-1', otp: '123456' };
export const TFA = { tfa_token: 'tfa.jwt.token', challenge_id: 'second-factor' };
export const AUTH_EVENTS = [
  PassflowEvent.SignInStart,
  PassflowEvent.RegisterStart,
  PassflowEvent.EmailVerificationRequired,
  PassflowEvent.SignIn,
  PassflowEvent.Register,
  PassflowEvent.TwoFactorRequired,
  PassflowEvent.Error,
];
export type Operation = 'sign-in' | 'sign-up' | 'reset-password';
export type Request = InternalAxiosRequestConfig;
export const body = (request: Request): Record<string, unknown> =>
  typeof request.data === 'string' ? JSON.parse(request.data) : (request.data ?? {});

const clients: Passflow[] = [];

beforeEach(() => {
  localStorage.clear();
  sessionStorage.clear();
  // tests/setup.ts replaces the standards parser with one that cannot parse "?token=".
  vi.stubGlobal('URLSearchParams', NativeURLSearchParams);
  vi.useFakeTimers({ toFake: ['Date', 'setTimeout', 'clearTimeout', 'setInterval', 'clearInterval'] });
});

afterEach(() => {
  for (const client of clients.splice(0)) client.dispose();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

export function harness(options: { pkce?: boolean; config?: Partial<PassflowConfig> } = {}) {
  let pkce = options.pkce ?? false;
  // Settings are an external input; no assertions inspect this stub's invocations.
  vi.spyOn(AppAPI.prototype, 'getAppSettings').mockImplementation(async () => ({ pkce_enabled: pkce }) as never);

  const writes: Array<{ key: string; value: string }> = [];
  const platform = createMockPlatform({
    storage: {
      getItem: (key: string) => localStorage.getItem(key),
      setItem: (key: string, value: string) => {
        writes.push({ key, value: String(value) });
        localStorage.setItem(key, value);
      },
      removeItem: (key: string) => localStorage.removeItem(key),
    },
  });
  const sdk = new Passflow({
    ...TEST_CONFIG,
    parseQueryParams: false,
    refreshCoordination: 'none',
    platform,
    ...options.config,
  });
  clients.push(sdk);

  let startAnswer: unknown = CODE_STEP;
  let validateAnswer: unknown = { ...VALID_TOKENS };
  let exchangeAnswer: unknown = { ...VALID_TOKENS };
  const requests: Request[] = [];
  const adapter: AxiosAdapter = async (request) => {
    requests.push(request);
    const path = request.url ?? '';
    let data: unknown;
    if (path.endsWith('/auth/validate')) {
      data = validateAnswer;
    } else if (path.endsWith('/auth/pkce_exchange')) data = exchangeAnswer;
    else if (path.endsWith('/auth/refresh')) data = { ...VALID_TOKENS };
    else if (path.endsWith('/user/logout')) data = { status: 'ok' };
    else if (path.endsWith('/auth/2fa/verify')) data = { success: true, code: 'after-second-factor' };
    else if (['/auth/login', '/auth/register', '/auth/password/change'].some((suffix) => path.endsWith(suffix))) {
      data = startAnswer;
    } else throw new Error(`Unexpected request: ${request.method} ${path}`);
    return { data, status: 200, statusText: 'OK', headers: {}, config: request };
  };
  // Injection only, copied from the existing capturing-adapter harness. No test
  // asserts private state, private calls, or mock invocation counts.
  const internals = sdk as unknown as Record<string, { axiosClient: { instance: { defaults: { adapter: AxiosAdapter } } } }>;
  for (const field of ['authApi', 'twoFactorApi']) {
    internals[field].axiosClient.instance.defaults.adapter = adapter;
  }

  const events: Array<{ event: PassflowEvent; payload: unknown }> = [];
  sdk.subscribe({ onAuthChange: (event, payload) => events.push({ event, payload }) });
  let created = 0;
  let expired = 0;

  return {
    sdk,
    platform,
    writes,
    requests,
    events,
    setPkce(value: boolean) {
      pkce = value;
    },
    startAnswer(value: unknown) {
      startAnswer = value;
    },
    validateAnswer(value: unknown) {
      validateAnswer = value;
    },
    exchangeAnswer(value: unknown) {
      exchangeAnswer = value;
    },
    validationError(value: unknown) {
      // Error identity is a service guarantee from its public API boundary, not
      // an assertion that axios preserves arbitrary adapter-thrown objects.
      if (value !== undefined) vi.spyOn(AuthAPI.prototype, 'validateEmailCode').mockRejectedValueOnce(value);
    },
    async callbacks() {
      await sdk.session({
        createSession: () => {
          created += 1;
        },
        expiredSession: () => {
          expired += 1;
        },
      });
      created = 0;
      expired = 0;
    },
    callbacksSeen: () => ({ created, expired }),
    names: () => events.filter(({ event }) => AUTH_EVENTS.includes(event)).map(({ event }) => event),
    of: (event: PassflowEvent) => events.filter((record) => record.event === event).map((record) => record.payload),
    wire: (suffix: string) => requests.filter((request) => request.url?.endsWith(suffix)),
    clearEvents() {
      events.length = 0;
    },
    start(operation: Operation, scopes?: string[], resetToken?: string) {
      if (operation === 'sign-up') return sdk.signUp({ user: { email: EMAIL, password: PASSWORD }, scopes });
      if (operation === 'sign-in') return sdk.signIn({ email: EMAIL, password: PASSWORD, scopes });
      return sdk.resetPassword(PASSWORD, scopes, resetToken);
    },
  };
}

export type EmailHarness = ReturnType<typeof harness>;

/** Independent S256 calculation, not an import of the library's PKCE implementation. */
export async function s256(value: string): Promise<string> {
  return createHash('sha256').update(value).digest('base64url');
}

/** Verify the exchange really proves the challenge sent on the initial HTTP request. */
export async function exchangeProvesChallenge(h: EmailHarness, startPath: string): Promise<boolean> {
  const challenge = body(h.wire(startPath).at(-1)!).code_challenge;
  if (typeof challenge !== 'string' || !challenge) return false;
  const exchange = h.wire('/auth/pkce_exchange').at(-1);
  if (!exchange) return false;
  for (const value of Object.values(body(exchange))) {
    if (typeof value === 'string' && (await s256(value)) === challenge) return true;
  }
  return false;
}
