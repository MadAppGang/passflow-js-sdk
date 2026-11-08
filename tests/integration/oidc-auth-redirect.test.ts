/**
 * `authRedirect()` follows the app's hand-off mode, read from the app settings.
 *
 * - Simple (`pkce_enabled` false or absent, or no app id): the `/web` URL of `authRedirectUrl()`,
 *   plus `state` when given; the default `redirectto` is the page's href.
 * - SDK (`pkce_enabled` true): `/oidc/authorize` with PKCE (S256), a generated `state`, a `nonce`
 *   when the effective scopes contain `openid`, `redirect_uri` defaulting to origin + pathname, and
 *   one proof key record per tab in sessionStorage (`passflow_oidc_pkce`), kept 10 minutes.
 *
 * Every failure emits one `Error` with operation `auth-redirect`, rejects, and does not navigate.
 */
import { describe, expect, test, vi } from 'vitest';
import { PassflowEvent } from '../../lib/index';
import { TEST_CONFIG } from '../helpers/fixtures';
import {
  AUTHORIZE_URL,
  drive,
  landingUrl,
  type ModeClient,
  type ModeHarness,
  modeHarness,
  OIDC_CODE,
  OIDC_SLOT,
  PAGE,
  paramsOf,
  SDK_APP,
  SIMPLE_APP,
  settle,
  startSdkSignIn,
  stubTokenEndpoint,
} from '../helpers/oidc-harness';
import { body, fault, fedPayload, PATH, s256, startPayload, until } from '../helpers/pkce-harness';

/** The call rejected, emitted exactly one `auth-redirect` Error, and did not navigate. */
async function expectRefused(h: ModeHarness, c: ModeClient, call: Promise<void>, code?: string) {
  const before = h.navigations.length;
  const result = await drive(call);
  expect(result.ok, 'authRedirect must reject').toBe(false);
  const errors = c.of(PassflowEvent.Error);
  expect(errors).toHaveLength(1);
  expect(errors[0]).toMatchObject({ operation: 'auth-redirect' });
  if (code) {
    expect((result as { error: unknown }).error).toMatchObject({ code });
    expect(errors[0]).toMatchObject({ code });
  }
  await settle();
  expect(h.navigations).toHaveLength(before);
  return {
    error: (result as { error: unknown }).error as Error & { code?: string },
    payload: errors[0] as { message: string },
  };
}

const scopeSet = (url: URL) => (url.searchParams.get('scope') ?? '').split(' ').filter(Boolean);

describe('Simple mode', () => {
  test.each([
    ['pkce_enabled false', SIMPLE_APP],
    ['pkce_enabled absent', { type: 'web' }],
  ])('%s: goes to the authRedirectUrl() /web URL, with redirectto = the page href', async (_name, settings) => {
    const h = modeHarness(settings, { url: `${PAGE}?deep=1#section` });
    const c = h.client();
    const result = await drive(c.sdk.authRedirect());
    expect(result.ok).toBe(true);
    expect(h.navigations).toHaveLength(1);
    const sent = new URL(h.navigations[0]);
    const expected = new URL(c.sdk.authRedirectUrl());
    expect(sent.origin + sent.pathname).toBe(expected.origin + expected.pathname);
    expect(sent.pathname).toBe('/web');
    expect(paramsOf(sent)).toEqual(paramsOf(expected));
    expect(sent.searchParams.get('redirectto')).toBe(`${PAGE}?deep=1#section`);
    expect(sessionStorage.getItem(OIDC_SLOT)).toBeNull();
    expect(c.of(PassflowEvent.Error)).toEqual([]);
  });

  test('options.state is added to the /web URL', async () => {
    const h = modeHarness(SIMPLE_APP);
    const c = h.client();
    expect((await drive(c.sdk.authRedirect({ state: 'app-state-7' }))).ok).toBe(true);
    const sent = new URL(h.navigations[0]);
    expect(sent.searchParams.get('state')).toBe('app-state-7');
    const withoutState = paramsOf(sent).filter(([k]) => k !== 'state');
    expect(withoutState).toEqual(paramsOf(new URL(c.sdk.authRedirectUrl())));
  });

  test('authRedirectUrl() stays synchronous and still accepts other url and appId values', () => {
    const h = modeHarness(SIMPLE_APP);
    const c = h.client();
    const built = c.sdk.authRedirectUrl({ url: 'https://other.example', appId: 'other-app' });
    expect(typeof built).toBe('string');
    expect(new URL(built).origin).toBe('https://other.example');
    expect(h.settingsReads()).toBe(0);
  });
});

describe('SDK mode: authorize URL and proof key record', () => {
  test('navigates to /oidc/authorize with S256 PKCE and stores the record with its clientId', async () => {
    const h = modeHarness(SDK_APP);
    const c = h.client();
    const before = Date.now();
    const { url, slot } = await startSdkSignIn(h, c);

    expect(url.origin + url.pathname).toBe(AUTHORIZE_URL);
    expect(url.searchParams.get('response_type')).toBe('code');
    expect(url.searchParams.get('client_id')).toBe(TEST_CONFIG.appId);
    expect(url.searchParams.get('redirect_uri')).toBe(PAGE);
    expect(url.searchParams.get('code_challenge_method')).toBe('S256');
    expect(url.searchParams.get('code_challenge')).toBe(s256(slot.verifier));
    expect(url.searchParams.get('state')).toBe(slot.state);
    expect(url.searchParams.get('nonce')).toBe(slot.nonce);
    const scopes = scopeSet(url);
    expect(new Set(scopes)).toEqual(new Set(TEST_CONFIG.scopes));
    expect(scopes).toHaveLength(new Set(scopes).size);

    expect(slot).toMatchObject({
      verifier: expect.any(String),
      state: expect.any(String),
      nonce: expect.any(String),
      clientId: TEST_CONFIG.appId,
      redirectUri: PAGE,
      expiresAt: before + 600_000,
    });
    expect(slot.verifier.length).toBeGreaterThanOrEqual(43);
    expect(slot.state.length).toBeGreaterThan(0);
    expect(new Set(slot.scopes)).toEqual(new Set(scopes));
    // The verifier never leaves the tab.
    expect(url.href).not.toContain(slot.verifier);
    expect(h.writes.some((w) => w.value.includes(slot.verifier))).toBe(false);
    expect(c.of(PassflowEvent.Error)).toEqual([]);
  });

  test('a newer start in the same tab replaces the record', async () => {
    const h = modeHarness(SDK_APP);
    const c = h.client();
    const first = await startSdkSignIn(h, c);
    const second = await startSdkSignIn(h, c);
    expect(second.slot.state).not.toBe(first.slot.state);
    expect(second.slot.verifier).not.toBe(first.slot.verifier);
    expect(second.url.searchParams.get('code_challenge')).toBe(s256(second.slot.verifier));
  });

  test('options.state is not sent: the SDK generates state itself', async () => {
    const h = modeHarness(SDK_APP);
    const c = h.client();
    const { url, slot } = await startSdkSignIn(h, c, { state: 'caller-state' });
    expect(url.searchParams.get('state')).not.toBe('caller-state');
    expect(url.href).not.toContain('caller-state');
    expect(url.searchParams.get('state')).toBe(slot.state);
  });

  test.each([
    ['id', ['id']],
    ['oidc', ['oidc', 'email']],
  ])('scopes with %s get openid added and a nonce, in the URL and the record', async (_name, asked) => {
    const h = modeHarness(SDK_APP);
    const c = h.client();
    const { url, slot } = await startSdkSignIn(h, c, { scopes: asked });
    const scopes = scopeSet(url);
    for (const scope of asked) expect(scopes).toContain(scope);
    expect(scopes).toContain('openid');
    expect(scopes.filter((s) => s === 'openid')).toHaveLength(1);
    expect(slot.scopes).toContain('openid');
    expect(slot.nonce).toEqual(expect.any(String));
    expect(url.searchParams.get('nonce')).toBe(slot.nonce);
  });

  test('scopes without id, oidc or openid send no nonce and do not add openid', async () => {
    const h = modeHarness(SDK_APP);
    const c = h.client();
    const { url, slot } = await startSdkSignIn(h, c, { scopes: ['email', 'offline'] });
    expect(new Set(scopeSet(url))).toEqual(new Set(['email', 'offline']));
    expect(url.searchParams.has('nonce')).toBe(false);
    expect(slot.nonce).toBeUndefined();
    expect(slot.scopes).not.toContain('openid');
  });

  test('scopes that already contain openid send a nonce', async () => {
    const h = modeHarness(SDK_APP);
    const c = h.client();
    const { url, slot } = await startSdkSignIn(h, c, { scopes: ['openid'] });
    expect(scopeSet(url)).toEqual(['openid']);
    expect(url.searchParams.get('nonce')).toBe(slot.nonce);
    expect(slot.nonce).toEqual(expect.any(String));
  });

  test('default redirect_uri is the page origin and pathname, without query or fragment', async () => {
    const h = modeHarness(SDK_APP, { url: `${PAGE}?deep=1&tab=2#section` });
    const c = h.client();
    const { url, slot } = await startSdkSignIn(h, c);
    expect(url.searchParams.get('redirect_uri')).toBe(PAGE);
    expect(slot.redirectUri).toBe(PAGE);
  });

  test('an explicit redirectUrl is sent and recorded as given', async () => {
    const h = modeHarness(SDK_APP, { url: `${PAGE}?deep=1` });
    const c = h.client();
    const { url, slot } = await startSdkSignIn(h, c, { redirectUrl: 'https://app.example/auth/return' });
    expect(url.searchParams.get('redirect_uri')).toBe('https://app.example/auth/return');
    expect(slot.redirectUri).toBe('https://app.example/auth/return');
  });
});

describe('SDK mode: public client check', () => {
  test.each([
    ['true', { ...SDK_APP, public_client: true }],
    ['absent (older server)', { pkce_enabled: true, type: 'spa' }],
  ])('public_client %s: redirects', async (_name, settings) => {
    const h = modeHarness(settings);
    const c = h.client();
    const { url } = await startSdkSignIn(h, c);
    expect(url.origin + url.pathname).toBe(AUTHORIZE_URL);
  });

  test('public_client false: refused before redirecting, with a message naming the app type and the fix', async () => {
    const h = modeHarness({ pkce_enabled: true, public_client: false, type: 'web' });
    const c = h.client();
    const { error, payload } = await expectRefused(h, c, c.sdk.authRedirect(), 'CONFIDENTIAL_CLIENT');
    for (const message of [error.message, payload.message]) {
      expect(message).toContain('confidential client');
      expect(message).toContain('web');
      expect(message).toContain('SPA');
    }
    expect(sessionStorage.getItem(OIDC_SLOT)).toBeNull();
  });

  test('settings read fails: rejects, one Error, no redirect; the next call reads again', async () => {
    const h = modeHarness(fault('http', 503));
    const c = h.client();
    await expectRefused(h, c, c.sdk.authRedirect());
    expect(sessionStorage.getItem(OIDC_SLOT)).toBeNull();
    expect(h.settingsReads()).toBe(1);

    h.serveSettings(SDK_APP);
    c.clearEvents();
    const { url } = await startSdkSignIn(h, c);
    expect(url.origin + url.pathname).toBe(AUTHORIZE_URL);
    expect(h.settingsReads()).toBe(2);
  });

  test('settings unreachable: rejects with one Error and no redirect', async () => {
    const h = modeHarness(fault('network'));
    const c = h.client();
    await expectRefused(h, c, c.sdk.authRedirect());
  });
});

describe('SDK mode: start-time checks', () => {
  test('no Web Crypto (not a secure context): SECURE_CONTEXT_REQUIRED, no navigation', async () => {
    const h = modeHarness(SDK_APP);
    const c = h.client();
    vi.stubGlobal('isSecureContext', false);
    vi.stubGlobal('crypto', {});
    await expectRefused(h, c, c.sdk.authRedirect(), 'SECURE_CONTEXT_REQUIRED');
    expect(sessionStorage.getItem(OIDC_SLOT)).toBeNull();
  });

  test('sessionStorage not writable: STORAGE_UNAVAILABLE, no navigation', async () => {
    const h = modeHarness(SDK_APP);
    const c = h.client();
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new Error('Storage unavailable');
    });
    await expectRefused(h, c, c.sdk.authRedirect(), 'STORAGE_UNAVAILABLE');
  });
});

describe('url and appId overrides must repeat the instance values', () => {
  test.each([
    ['absent', {}],
    ['equal url and appId', { url: TEST_CONFIG.url, appId: TEST_CONFIG.appId }],
    ['url with a trailing slash', { url: `${TEST_CONFIG.url}/` }],
    ['url with upper-case scheme and host and the default port', { url: 'HTTPS://API.PASSFLOW.CLOUD:443' }],
  ])('SDK mode, %s: accepted', async (_name, options) => {
    const h = modeHarness(SDK_APP);
    const c = h.client();
    const { url, slot } = await startSdkSignIn(h, c, options);
    expect(url.origin + url.pathname).toBe(AUTHORIZE_URL);
    expect(slot.clientId).toBe(TEST_CONFIG.appId);
  });

  test.each([
    ['equal url and appId', { url: TEST_CONFIG.url, appId: TEST_CONFIG.appId }],
    ['url with a trailing slash', { url: `${TEST_CONFIG.url}/` }],
  ])('Simple mode, %s: accepted', async (_name, options) => {
    const h = modeHarness(SIMPLE_APP);
    const c = h.client();
    expect((await drive(c.sdk.authRedirect(options))).ok).toBe(true);
    expect(new URL(h.navigations[0]).pathname).toBe('/web');
  });

  test.each([
    ['SDK', SDK_APP, { url: 'https://other.passflow.example' }],
    ['SDK', SDK_APP, { appId: 'another-app-id' }],
    ['SDK', SDK_APP, { url: `${TEST_CONFIG.url}/tenant-path` }],
    ['Simple', SIMPLE_APP, { url: 'https://other.passflow.example' }],
    ['Simple', SIMPLE_APP, { appId: 'another-app-id' }],
  ])('%s mode, a differing %o: OVERRIDE_NOT_SUPPORTED before any settings read', async (_mode, settings, options) => {
    const h = modeHarness(settings);
    const c = h.client();
    await expectRefused(h, c, c.sdk.authRedirect(options), 'OVERRIDE_NOT_SUPPORTED');
    expect(h.settingsReads()).toBe(0);
    expect(sessionStorage.getItem(OIDC_SLOT)).toBeNull();
  });
});

describe('one cached app settings read', () => {
  test('authRedirect, getAppSettings and a sign-in share one /app/settings request', async () => {
    const h = modeHarness(SDK_APP);
    const c = h.client();
    await startSdkSignIn(h, c);
    const settings = await c.sdk.getAppSettings();
    expect(settings).toMatchObject({ pkce_enabled: true, public_client: true });
    await c.sdk.passwordlessSignIn(startPayload());
    expect(h.settingsReads()).toBe(1);
    // The sign-in saw the same SDK-mode settings: it sent a PKCE challenge.
    expect(body(h.wire(PATH.start)[0]).code_challenge).toEqual(expect.any(String));
  });

  test('setAppId starts a new read for the new app', async () => {
    const h = modeHarness(SIMPLE_APP);
    const c = h.client();
    await c.sdk.getAppSettings();
    await c.sdk.getAppSettings();
    expect(h.settingsReads()).toBe(1);
    c.sdk.setAppId('second-app-id');
    await c.sdk.getAppSettings();
    expect(h.settingsReads()).toBe(2);
  });
});

describe('setAppId reaches the sign-in flows', () => {
  test('an instance built without an app id uses the one set later as client_id', async () => {
    const h = modeHarness(SDK_APP);
    const c = h.client({ appId: undefined });
    c.sdk.setAppId(TEST_CONFIG.appId);
    const { url, slot } = await startSdkSignIn(h, c);
    expect(url.searchParams.get('client_id')).toBe(TEST_CONFIG.appId);
    expect(slot.clientId).toBe(TEST_CONFIG.appId);
  });

  test('a federated redirect works after setAppId on an instance built without an app id', async () => {
    const h = modeHarness(SDK_APP);
    const c = h.client({ appId: undefined });
    expect(() => c.sdk.federatedAuthWithRedirect(fedPayload())).toThrow();
    c.sdk.setAppId(TEST_CONFIG.appId);
    expect(() => c.sdk.federatedAuthWithRedirect(fedPayload())).not.toThrow();
    await until(() => h.navigations.length === 1);
    expect(new URL(h.navigations[0]).pathname).toBe('/auth/federated/start/google');
  });

  test('a landing is taken once the app id is set', async () => {
    const h = modeHarness(SDK_APP);
    const starter = h.client();
    const { slot } = await startSdkSignIn(h, starter);
    stubTokenEndpoint({ status: 400, body: { error: 'invalid_grant' } });
    h.land(landingUrl({ code: OIDC_CODE, state: slot.state }));
    const lander = h.client({ appId: undefined, deferFederatedLanding: true });
    const before = h.url().href;
    expect(lander.sdk.completeFederatedLanding()).toBe(false);
    expect(h.url().href).toBe(before);
    expect(sessionStorage.getItem(OIDC_SLOT)).not.toBeNull();
    lander.sdk.setAppId(TEST_CONFIG.appId);
    expect(lander.sdk.completeFederatedLanding()).toBe(true);
    expect(h.url().searchParams.has('code')).toBe(false);
  });
});

describe('without an app id', () => {
  test('authRedirect takes the Simple leg', async () => {
    const h = modeHarness(SDK_APP);
    const c = h.client({ appId: undefined });
    expect((await drive(c.sdk.authRedirect())).ok).toBe(true);
    expect(new URL(h.navigations[0]).pathname).toBe('/web');
    expect(sessionStorage.getItem(OIDC_SLOT)).toBeNull();
    expect(c.of(PassflowEvent.Error)).toEqual([]);
  });

  test('a sign-in treats the app as not using PKCE', async () => {
    const h = modeHarness(SDK_APP);
    const c = h.client({ appId: undefined });
    h.reply(PATH.start, { challenge_id: 'challenge-a', expires_at: new Date(Date.now() + 60_000).toISOString() });
    await c.sdk.passwordlessSignIn(startPayload());
    expect(body(h.wire(PATH.start)[0])).not.toHaveProperty('code_challenge');
  });

  test('getAppSettings still reports a failed read through an Error with operation settings.app', async () => {
    const h = modeHarness(fault('http', 400, { error: { id: 'error.app.not_found', message: 'no app' } }));
    const c = h.client({ appId: undefined });
    const result = await drive(c.sdk.getAppSettings());
    expect(result.ok).toBe(false);
    expect(c.of(PassflowEvent.Error)).toEqual([expect.objectContaining({ operation: 'settings.app' })]);
  });

  // The URL-token gate's no-app-id refusal is in url-token-mode-gate.test.ts.
});
