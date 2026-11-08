/**
 * Helpers for the hosted sign-in hand-off modes (Simple and SDK) through the public API.
 *
 * `modeHarness()` is the PKCE harness with the app settings served on the wire (`GET /app/settings`
 * through the same axios adapter as every other request), so a test can count settings reads and
 * make the read fail. `/oidc/token` is a plain `fetch` form POST, so `stubTokenEndpoint()` replaces
 * the global `fetch` and records what was sent.
 */
import { URLSearchParams as NativeURLSearchParams } from 'node:url';
import { expect, vi } from 'vitest';
import { AppAPI } from '../../lib/api';
import { TEST_CONFIG } from './fixtures';
import { type Fault, harness, until } from './pkce-harness';
import {
  DISCOVERY_PATH,
  discoveryBody,
  generateSigningKey,
  JWKS_PATH,
  jwksBody,
  type SigningKey,
  signToken,
  tokenClaims,
} from './signed-tokens';

/** sessionStorage key of this tab's SDK-mode proof key record. */
export const OIDC_SLOT = 'passflow_oidc_pkce';
export const SETTINGS_PATH = '/app/settings';
export const AUTHORIZE_URL = `${TEST_CONFIG.url}/oidc/authorize`;
export const TOKEN_URL = `${TEST_CONFIG.url}/oidc/token`;
export const PAGE = 'https://app.example/callback';
export const OIDC_CODE = 'hosted-authorization-code';

export type OidcSlot = {
  verifier: string;
  state: string;
  nonce?: string;
  clientId: string;
  redirectUri: string;
  scopes: string[];
  expiresAt: number;
};

export const SDK_APP = { pkce_enabled: true, public_client: true, type: 'spa' };
export const SIMPLE_APP = { pkce_enabled: false, type: 'web' };

/**
 * The PKCE harness with `/app/settings` answered on the wire by `settings` (a body, or a `fault()`).
 * Use `h.client()` for the instance under test: it is built after the settings are served.
 */
export function modeHarness(settings: Record<string, unknown> | Fault, options: { url?: string } = {}) {
  const h = harness({ url: options.url ?? PAGE });
  // The PKCE harness answers settings in-process; here they go over the wire instead.
  vi.mocked(AppAPI.prototype.getAppSettings).mockRestore();
  h.reply(SETTINGS_PATH, settings);
  return {
    ...h,
    settingsReads: () => h.wire(SETTINGS_PATH).length,
    serveSettings: (next: Record<string, unknown> | Fault) => h.reply(SETTINGS_PATH, next),
  };
}
export type ModeHarness = ReturnType<typeof modeHarness>;
export type ModeClient = ReturnType<ModeHarness['client']>;

/** Settles a call under fake timers without ever leaving a rejection unhandled. */
export async function drive<T>(promise: Promise<T>): Promise<{ ok: true; value: T } | { ok: false; error: unknown }> {
  let result: { ok: true; value: T } | { ok: false; error: unknown } | undefined;
  promise.then(
    (value) => {
      result = { ok: true, value };
    },
    (error: unknown) => {
      result = { ok: false, error };
    },
  );
  await until(() => result !== undefined);
  return result!;
}

/** Lets background work run, for assertions that something never happens. */
export async function settle() {
  for (let i = 0; i < 10; i++) await vi.advanceTimersByTimeAsync(0);
}

/** Runs `authRedirect()` to completion and returns the navigated URL and the stored slot. */
export async function startSdkSignIn(
  h: ModeHarness,
  c: ModeClient,
  options?: Parameters<ModeClient['sdk']['authRedirect']>[0],
) {
  const before = h.navigations.length;
  const result = await drive(c.sdk.authRedirect(options));
  expect(result.ok, 'authRedirect must resolve').toBe(true);
  expect(h.navigations).toHaveLength(before + 1);
  return { url: new URL(h.navigations.at(-1)!), slot: readSlot() };
}

export function readSlot(): OidcSlot {
  const raw = sessionStorage.getItem(OIDC_SLOT);
  expect(raw, 'the proof key record is in sessionStorage').not.toBeNull();
  return JSON.parse(raw!) as OidcSlot;
}

/** Query params of a URL as a sorted list, for comparing two URLs whatever their encoding. */
export function paramsOf(url: URL) {
  return [...url.searchParams.entries()].sort(([a], [b]) => a.localeCompare(b));
}

// ---------------------------------------------------------------------------
// The token endpoint
// ---------------------------------------------------------------------------

export type TokenRequest = {
  url: string;
  method: string;
  headers: Record<string, string>;
  form: NativeURLSearchParams;
  rawBody: unknown;
};
export type TokenReply = { status: number; body: unknown; contentType?: string } | 'network';

function headersOf(headers: unknown): Record<string, string> {
  const out: Record<string, string> = {};
  if (!headers) return out;
  if (Array.isArray(headers)) {
    for (const [k, v] of headers as Array<[string, string]>) out[k.toLowerCase()] = String(v);
  } else if (typeof (headers as { forEach?: unknown }).forEach === 'function') {
    (headers as { forEach: (cb: (v: string, k: string) => void) => void }).forEach((v, k) => {
      out[k.toLowerCase()] = String(v);
    });
  } else {
    for (const [k, v] of Object.entries(headers as Record<string, unknown>)) out[k.toLowerCase()] = String(v);
  }
  return out;
}

function responseOf(status: number, body: unknown, contentType?: string) {
  const text = typeof body === 'string' ? body : JSON.stringify(body);
  const type = contentType ?? (typeof body === 'string' ? 'text/html' : 'application/json');
  const response = {
    ok: status >= 200 && status < 300,
    status,
    statusText: status >= 200 && status < 300 ? 'OK' : 'Error',
    headers: {
      get: (name: string) => (name.toLowerCase() === 'content-type' ? type : null),
      has: (name: string) => name.toLowerCase() === 'content-type',
    },
    json: async () => JSON.parse(text),
    text: async () => text,
    clone: () => response,
  };
  return response;
}

/**
 * Replaces global `fetch` with the token endpoint. Every call is recorded with its URL, so a test
 * can assert there was exactly one, to `/oidc/token`; `reply` answers it.
 */
export function stubTokenEndpoint(reply: TokenReply | (() => TokenReply)) {
  const calls: TokenRequest[] = [];
  let answer = reply;
  const fetchMock = vi.fn(async (input: unknown, init?: { method?: string; headers?: unknown; body?: unknown }) => {
    const url =
      typeof input === 'string' ? input : input instanceof URL ? input.href : String((input as { url?: string }).url ?? input);
    const rawBody = init?.body;
    calls.push({
      url,
      method: String(init?.method ?? 'GET').toUpperCase(),
      headers: headersOf(init?.headers),
      form: new NativeURLSearchParams(rawBody === undefined || rawBody === null ? '' : String(rawBody)),
      rawBody,
    });
    const current = typeof answer === 'function' ? answer() : answer;
    if (current === 'network') throw new TypeError('Failed to fetch');
    return responseOf(current.status, current.body, current.contentType);
  });
  vi.stubGlobal('fetch', fetchMock);
  return {
    calls,
    set: (next: TokenReply | (() => TokenReply)) => {
      answer = next;
    },
  };
}

/** Publishes a signing key on the harness (discovery and JWKS) and returns it. */
export async function publishKey(h: Pick<ModeHarness, 'reply'>): Promise<SigningKey> {
  const key = await generateSigningKey();
  h.reply(DISCOVERY_PATH, discoveryBody());
  h.reply(JWKS_PATH, jwksBody(key));
  return key;
}

/** A token endpoint answer issued with `key`; `idClaims` go on the ID token, `null` leaves it out. */
export async function tokenResponse(
  key: SigningKey,
  idClaims: Record<string, unknown> | null,
  scope = 'id offline email openid',
) {
  const claims = tokenClaims();
  const body: Record<string, unknown> = {
    access_token: await signToken(claims.access, key),
    refresh_token: await signToken(claims.refresh, key),
    token_type: 'Bearer',
    expires_in: 3600,
    scope,
  };
  if (idClaims) body.id_token = await signToken({ ...claims.id, ...idClaims }, key);
  return body as { access_token: string; refresh_token: string; id_token?: string } & Record<string, unknown>;
}

/** The landing URL the hosted login sends the browser to in SDK mode. */
export function landingUrl(params: Record<string, string>, page = PAGE, extra = '&keep=1', hash = '#tab=security') {
  return `${page}?${new NativeURLSearchParams(params).toString()}${extra}${hash}`;
}

/** None of the landing parameters are left in the URL; the page's own ones are. */
export function expectLandingCleaned(h: Pick<ModeHarness, 'url'>) {
  const url = h.url();
  for (const name of ['code', 'state', 'iss', 'error', 'error_description']) {
    expect(url.searchParams.has(name), `${name} left in the URL`).toBe(false);
  }
  expect(url.searchParams.get('keep')).toBe('1');
  expect(url.hash).toBe('#tab=security');
}

/** Whether `value` was ever written to localStorage. */
export const everStored = (h: Pick<ModeHarness, 'writes'>, value: string) => h.writes.some((w) => w.value.includes(value));
