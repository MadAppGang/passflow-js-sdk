/**
 * The SDK-mode landing: hosted sign-in returns `?code=&state=` and core redeems the code at
 * `/oidc/token` with PKCE, as a public client.
 *
 * Return contract of `completeFederatedLanding()` for this landing:
 * - `false`: not this tab's landing, or not ready (no app id). Nothing is touched, no event follows.
 * - `true`: this tab holds a proof key record. The URL is cleaned at once; `SignIn` with
 *   `source: 'oidc-landing'` or one `Error` with operation `oidc.redirect` follows after an await.
 *
 * Every refused landing clears the record, removes `code,state,iss,error,error_description` from the
 * URL, stores nothing and is not retried. The token request is a plain form POST with no secret and
 * none of the SDK's own `X-Passflow-*` headers.
 */
import { describe, expect, test, vi } from 'vitest';
import { PassflowEvent } from '../../lib/index';
import {
  everStored,
  expectLandingCleaned,
  landingUrl,
  type ModeClient,
  type ModeHarness,
  modeHarness,
  OIDC_CODE,
  OIDC_SLOT,
  type OidcSlot,
  publishKey,
  SDK_APP,
  settle,
  startSdkSignIn,
  stubTokenEndpoint,
  TOKEN_URL,
  type TokenReply,
  tokenResponse,
} from '../helpers/oidc-harness';
import { s256, until } from '../helpers/pkce-harness';
import type { SigningKey } from '../helpers/signed-tokens';

type Entry = 'completeFederatedLanding' | 'constructor' | 'handleTokensRedirect';

/** An SDK-mode app whose sign-in was started in this tab: the record is in sessionStorage. */
async function started(options?: Parameters<ModeClient['sdk']['authRedirect']>[0]) {
  const h = modeHarness(SDK_APP);
  const key = await publishKey(h);
  const starter = h.client();
  const { url: sent, slot } = await startSdkSignIn(h, starter, options);
  starter.sdk.dispose(); // The page leaves for the hosted login.
  return { h, key, sent, slot };
}

/** Builds the landing page's instance and lets it take the landing the way `entry` does. */
function take(h: ModeHarness, entry: Entry) {
  if (entry === 'completeFederatedLanding') {
    const c = h.client({ deferFederatedLanding: true });
    return { c, taken: c.sdk.completeFederatedLanding() as boolean | undefined };
  }
  if (entry === 'constructor') return { c: h.client({ parseQueryParams: true }), taken: undefined };
  const c = h.client();
  expect(c.sdk.handleTokensRedirect()).toBeUndefined();
  return { c, taken: undefined };
}

async function outcome(c: ModeClient) {
  await until(() => c.of(PassflowEvent.SignIn).length + c.of(PassflowEvent.Error).length > 0);
  await settle();
}

/** The landing ended in exactly one `oidc.redirect` Error with `code`, and nothing else happened. */
async function expectTerminal(h: ModeHarness, c: ModeClient, code: string, secrets: string[] = []) {
  await outcome(c);
  const errors = c.of(PassflowEvent.Error);
  expect(errors).toHaveLength(1);
  expect(errors[0]).toMatchObject({ operation: 'oidc.redirect', code });
  expect(c.of(PassflowEvent.SignIn)).toEqual([]);
  expect(c.sdk.getCachedTokens()?.access_token).toBeUndefined();
  expect(c.sdk.isAuthenticated()).toBe(false);
  for (const secret of secrets) expect(everStored(h, secret), 'a refused token was stored').toBe(false);
  expect(sessionStorage.getItem(OIDC_SLOT)).toBeNull();
  expectLandingCleaned(h);
  return errors[0] as { message: string; code: string };
}

/** The landing was left alone: false, same URL, same record, no request and no event. */
async function expectUntouched(h: ModeHarness, c: ModeClient, before: { url: string; slot: string | null }, calls: unknown[]) {
  await settle();
  expect(h.url().href).toBe(before.url);
  expect(sessionStorage.getItem(OIDC_SLOT)).toBe(before.slot);
  expect(calls).toEqual([]);
  expect(c.of(PassflowEvent.SignIn)).toEqual([]);
  expect(c.of(PassflowEvent.Error)).toEqual([]);
}

async function okTokens(key: SigningKey, slot: OidcSlot) {
  return tokenResponse(key, { nonce: slot.nonce });
}

describe('a landing this tab started is redeemed at /oidc/token', () => {
  test.each<Entry>(['completeFederatedLanding', 'constructor', 'handleTokensRedirect'])(
    'via %s: plain form POST with the record values, then SignIn with source oidc-landing',
    async (entry) => {
      const { h, key, sent, slot } = await started();
      const issued = await okTokens(key, slot);
      const endpoint = stubTokenEndpoint({ status: 200, body: issued });
      h.land(landingUrl({ code: OIDC_CODE, state: slot.state, iss: 'https://issuer.passflow.example' }));

      const { c, taken } = take(h, entry);
      if (entry === 'completeFederatedLanding') expect(taken).toBe(true);
      // Cleaned before any await; the outcome is not known yet.
      expectLandingCleaned(h);
      expect(c.of(PassflowEvent.SignIn)).toEqual([]);

      await outcome(c);
      expect(c.of(PassflowEvent.Error)).toEqual([]);
      expect(c.of(PassflowEvent.SignIn)).toEqual([
        expect.objectContaining({
          source: 'oidc-landing',
          tokens: expect.objectContaining({ access_token: issued.access_token }),
        }),
      ]);
      expect(c.sdk.getCachedTokens()?.access_token).toBe(issued.access_token);
      expect(everStored(h, issued.access_token)).toBe(true);
      expect(sessionStorage.getItem(OIDC_SLOT)).toBeNull();

      expect(endpoint.calls).toHaveLength(1);
      const request = endpoint.calls[0]!;
      expect(request.url).toBe(TOKEN_URL);
      expect(request.method).toBe('POST');
      expect(request.form.get('grant_type')).toBe('authorization_code');
      expect(request.form.get('code')).toBe(OIDC_CODE);
      expect(request.form.get('client_id')).toBe(slot.clientId);
      expect(request.form.get('redirect_uri')).toBe(slot.redirectUri);
      expect(request.form.get('code_verifier')).toBe(slot.verifier);
      expect(s256(request.form.get('code_verifier')!)).toBe(sent.searchParams.get('code_challenge'));
      expect(request.form.has('client_secret')).toBe(false);
      if (typeof request.rawBody === 'string') {
        expect(request.headers['content-type']).toContain('application/x-www-form-urlencoded');
      }
      // Outside the SDK's HTTP client: no X-Passflow-* header and no credentials header.
      expect(Object.keys(request.headers).filter((name) => name.startsWith('x-passflow'))).toEqual([]);
      expect(request.headers).not.toHaveProperty('authorization');
      expect(h.wire('/oidc/token')).toEqual([]);
    },
  );

  test('the code is redeemed with the recorded redirect URI, not the landing page address', async () => {
    const { h, key, slot } = await started({ redirectUrl: 'https://app.example/registered' });
    const endpoint = stubTokenEndpoint({ status: 200, body: await okTokens(key, slot) });
    h.land(landingUrl({ code: OIDC_CODE, state: slot.state }));
    const { c } = take(h, 'completeFederatedLanding');
    await outcome(c);
    expect(endpoint.calls[0]!.form.get('redirect_uri')).toBe('https://app.example/registered');
    expect(c.of(PassflowEvent.SignIn)).toHaveLength(1);
  });

  test('without openid in the scopes, an answer with no ID token signs in', async () => {
    const { h, key, slot } = await started({ scopes: ['email', 'offline'] });
    const issued = await tokenResponse(key, null, 'email offline');
    stubTokenEndpoint({ status: 200, body: issued });
    h.land(landingUrl({ code: OIDC_CODE, state: slot.state }));
    const { c } = take(h, 'completeFederatedLanding');
    await outcome(c);
    expect(c.of(PassflowEvent.Error)).toEqual([]);
    expect(c.of(PassflowEvent.SignIn)).toEqual([expect.objectContaining({ source: 'oidc-landing' })]);
  });

  test('the landing is taken once: a second call answers false and sends nothing', async () => {
    const { h, key, slot } = await started();
    const endpoint = stubTokenEndpoint({ status: 200, body: await okTokens(key, slot) });
    h.land(landingUrl({ code: OIDC_CODE, state: slot.state }));
    const { c, taken } = take(h, 'completeFederatedLanding');
    expect(taken).toBe(true);
    expect(c.sdk.completeFederatedLanding()).toBe(false);
    await outcome(c);
    expect(endpoint.calls).toHaveLength(1);
    expect(c.of(PassflowEvent.SignIn)).toHaveLength(1);
  });
});

describe('landings that are not this tab’s, or not ready', () => {
  test('no app id: false, URL and record untouched', async () => {
    const { h, slot } = await started();
    const endpoint = stubTokenEndpoint({ status: 500, body: { error: 'server_error' } });
    h.land(landingUrl({ code: OIDC_CODE, state: slot.state }));
    const before = { url: h.url().href, slot: sessionStorage.getItem(OIDC_SLOT) };
    const c = h.client({ appId: undefined, deferFederatedLanding: true });
    expect(c.sdk.completeFederatedLanding()).toBe(false);
    await expectUntouched(h, c, before, endpoint.calls);
  });

  test('no app id, parseQueryParams: the constructor leaves it too', async () => {
    const { h, slot } = await started();
    const endpoint = stubTokenEndpoint({ status: 500, body: { error: 'server_error' } });
    h.land(landingUrl({ code: OIDC_CODE, state: slot.state }));
    const before = { url: h.url().href, slot: sessionStorage.getItem(OIDC_SLOT) };
    const c = h.client({ appId: undefined, parseQueryParams: true });
    await expectUntouched(h, c, before, endpoint.calls);
  });

  test.each<Entry>(['completeFederatedLanding', 'constructor', 'handleTokensRedirect'])(
    'no record in this tab, via %s: false, URL untouched, no event',
    async (entry) => {
      const h = modeHarness(SDK_APP);
      const endpoint = stubTokenEndpoint({ status: 500, body: { error: 'server_error' } });
      h.land(landingUrl({ code: OIDC_CODE, state: 'state-from-elsewhere' }));
      const before = { url: h.url().href, slot: null };
      const { c, taken } = take(h, entry);
      if (entry === 'completeFederatedLanding') expect(taken).toBe(false);
      await expectUntouched(h, c, before, endpoint.calls);
    },
  );
});

describe('refused landings', () => {
  test('a state this tab did not send: STATE_MISMATCH, nothing exchanged', async () => {
    const { h } = await started();
    const endpoint = stubTokenEndpoint({ status: 500, body: { error: 'server_error' } });
    h.land(landingUrl({ code: OIDC_CODE, state: 'a-different-state', iss: 'https://issuer.passflow.example' }));
    const { c, taken } = take(h, 'completeFederatedLanding');
    expect(taken).toBe(true);
    expectLandingCleaned(h);
    await expectTerminal(h, c, 'STATE_MISMATCH');
    expect(endpoint.calls).toEqual([]);
  });

  test('a subscriber attached right after the constructor hears the refusal', async () => {
    const { h } = await started();
    stubTokenEndpoint({ status: 500, body: { error: 'server_error' } });
    h.land(landingUrl({ code: OIDC_CODE, state: 'a-different-state' }));
    const { c } = take(h, 'constructor');
    await expectTerminal(h, c, 'STATE_MISMATCH');
  });

  test.each([
    ['unreadable', () => '{not json'],
    ['missing its verifier', () => JSON.stringify({ state: 'landing-state', clientId: 'test-app-id' })],
  ])('a %s record: VERIFIER_MISSING', async (_name, record) => {
    const h = modeHarness(SDK_APP);
    const endpoint = stubTokenEndpoint({ status: 500, body: { error: 'server_error' } });
    sessionStorage.setItem(OIDC_SLOT, record());
    h.land(landingUrl({ code: OIDC_CODE, state: 'landing-state' }));
    const { c, taken } = take(h, 'completeFederatedLanding');
    expect(taken).toBe(true);
    await expectTerminal(h, c, 'VERIFIER_MISSING');
    expect(endpoint.calls).toEqual([]);
  });

  test('an expired record (older than 10 minutes): VERIFIER_MISSING', async () => {
    const { h, slot } = await started();
    const endpoint = stubTokenEndpoint({ status: 500, body: { error: 'server_error' } });
    await vi.advanceTimersByTimeAsync(600_000 + 1_000);
    h.land(landingUrl({ code: OIDC_CODE, state: slot.state }));
    const { c, taken } = take(h, 'completeFederatedLanding');
    expect(taken).toBe(true);
    await expectTerminal(h, c, 'VERIFIER_MISSING');
    expect(endpoint.calls).toEqual([]);
  });

  test('?error= with a live record: the OAuth error is the code', async () => {
    const { h, slot } = await started();
    const endpoint = stubTokenEndpoint({ status: 500, body: { error: 'server_error' } });
    h.land(landingUrl({ error: 'access_denied', error_description: 'The user cancelled', state: slot.state }));
    const { c, taken } = take(h, 'completeFederatedLanding');
    expect(taken).toBe(true);
    await expectTerminal(h, c, 'access_denied');
    expect(endpoint.calls).toEqual([]);
  });

  test('invalid_client from the token endpoint: the message names the confidential-client fix', async () => {
    const { h, key, slot } = await started();
    const issued = await okTokens(key, slot);
    stubTokenEndpoint({ status: 401, body: { error: 'invalid_client', error_description: 'client authentication failed' } });
    h.land(landingUrl({ code: OIDC_CODE, state: slot.state }));
    const { c } = take(h, 'completeFederatedLanding');
    const error = await expectTerminal(h, c, 'invalid_client', [issued.access_token]);
    expect(error.message).toContain('confidential client');
    expect(error.message).toContain('SPA');
  });

  test('invalid_grant from the token endpoint: "Sign in again."', async () => {
    const { h, slot } = await started();
    stubTokenEndpoint({ status: 400, body: { error: 'invalid_grant', error_description: 'code already used' } });
    h.land(landingUrl({ code: OIDC_CODE, state: slot.state }));
    const { c } = take(h, 'completeFederatedLanding');
    const error = await expectTerminal(h, c, 'invalid_grant');
    expect(error.message).toContain('Sign in again.');
  });

  test.each<[string, TokenReply]>([
    ['another OAuth error (server_error)', { status: 500, body: { error: 'server_error', error_description: 'boom' } }],
    ['another OAuth error (invalid_request)', { status: 400, body: { error: 'invalid_request' } }],
    ['a non-JSON error body', { status: 502, body: '<html>Bad gateway</html>' }],
    ['a JSON error body without an error member', { status: 500, body: { message: 'internal' } }],
    ['a network failure', 'network'],
  ])('%s: TOKEN_EXCHANGE_FAILED, "Sign in again.", no retry', async (_name, reply) => {
    const { h, slot } = await started();
    const endpoint = stubTokenEndpoint(reply);
    h.land(landingUrl({ code: OIDC_CODE, state: slot.state }));
    const { c, taken } = take(h, 'completeFederatedLanding');
    expect(taken).toBe(true);
    const error = await expectTerminal(h, c, 'TOKEN_EXCHANGE_FAILED');
    expect(error.message).toContain('Sign in again.');
    expect(endpoint.calls).toHaveLength(1);
  });

  test('an ID token whose nonce is not the one sent: ID_TOKEN_INVALID, nothing stored', async () => {
    const { h, key, slot } = await started();
    const issued = await tokenResponse(key, { nonce: 'a-nonce-this-tab-never-sent' });
    stubTokenEndpoint({ status: 200, body: issued });
    h.land(landingUrl({ code: OIDC_CODE, state: slot.state }));
    const { c } = take(h, 'completeFederatedLanding');
    await expectTerminal(h, c, 'ID_TOKEN_INVALID', [issued.access_token, issued.refresh_token]);
  });

  test('no ID token although openid was asked: ID_TOKEN_INVALID, nothing stored', async () => {
    const { h, key, slot } = await started();
    expect(slot.scopes).toContain('openid');
    const issued = await tokenResponse(key, null);
    stubTokenEndpoint({ status: 200, body: issued });
    h.land(landingUrl({ code: OIDC_CODE, state: slot.state }));
    const { c } = take(h, 'completeFederatedLanding');
    await expectTerminal(h, c, 'ID_TOKEN_INVALID', [issued.access_token, issued.refresh_token]);
  });
});
