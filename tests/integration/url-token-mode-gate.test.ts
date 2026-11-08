/**
 * Core accepts URL tokens only for apps in Simple mode.
 *
 * Tokens in the page URL are still taken and removed from the URL synchronously. The app settings
 * are then read, and only `pkce_enabled === false` goes on to verification and storage. An app in
 * SDK mode, settings without `pkce_enabled`, a failed read, or an instance with no app id ends in one
 * `Error` with operation `tokens.from-url` and code `TOKENS_IN_URL_NOT_ALLOWED`, with nothing stored.
 *
 * In Simple mode, a `state` that came with the tokens is put on the `SignIn` payload, and only the
 * token parameters and `state` leave the fragment; the other fragment parameters stay.
 */
import { describe, expect, test } from 'vitest';
import { PassflowEvent } from '../../lib/index';
import {
  everStored,
  type ModeClient,
  type ModeHarness,
  modeHarness,
  PAGE,
  publishKey,
  SDK_APP,
  SIMPLE_APP,
  settle,
} from '../helpers/oidc-harness';
import { fault, until } from '../helpers/pkce-harness';
import { type IssuedTokens, issuedTokens, JWKS_PATH, tokenParams } from '../helpers/signed-tokens';

async function issued(h: ModeHarness) {
  return issuedTokens(await publishKey(h));
}

function expectTokensGone(h: ModeHarness) {
  const url = h.url();
  for (const name of ['access_token', 'refresh_token', 'id_token']) {
    expect(url.searchParams.has(name), `${name} left in the query`).toBe(false);
    expect(url.hash.includes(name), `${name} left in the fragment`).toBe(false);
  }
}

async function outcome(c: ModeClient) {
  await until(() => c.of(PassflowEvent.SignIn).length + c.of(PassflowEvent.Error).length > 0);
  await settle();
}

async function expectNotAllowed(h: ModeHarness, c: ModeClient, tokens: IssuedTokens) {
  await outcome(c);
  expect(c.of(PassflowEvent.SignIn)).toEqual([]);
  expect(c.of(PassflowEvent.Error)).toEqual([
    expect.objectContaining({ operation: 'tokens.from-url', code: 'TOKENS_IN_URL_NOT_ALLOWED' }),
  ]);
  for (const token of Object.values(tokens)) expect(everStored(h, token)).toBe(false);
  expect(c.sdk.getCachedTokens()?.access_token).toBeUndefined();
  expect(c.sdk.isAuthenticated()).toBe(false);
  expectTokensGone(h);
}

describe('core accepts URL tokens only for apps in Simple mode', () => {
  test.each([
    ['an app in SDK mode', SDK_APP],
    ['settings without pkce_enabled', { type: 'web' }],
    ['a failed settings read', fault('http', 503)],
    ['unreachable settings', fault('network')],
  ])('#access_token on %s: TOKENS_IN_URL_NOT_ALLOWED, nothing stored, URL clean', async (_name, settings) => {
    const h = modeHarness(settings);
    const tokens = await issued(h);
    h.land(`${PAGE}?keep=1#${tokenParams(tokens)}`);
    const c = h.client();
    expect(c.sdk.handleTokensRedirect()).toBeUndefined();
    expectTokensGone(h);
    await expectNotAllowed(h, c, tokens);
    // Refused before verification: the keys were never fetched.
    expect(h.wire(JWKS_PATH)).toEqual([]);
    expect(h.url().searchParams.get('keep')).toBe('1');
  });

  test('query tokens on an app in SDK mode are refused too', async () => {
    const h = modeHarness(SDK_APP);
    const tokens = await issued(h);
    h.land(`${PAGE}?${tokenParams(tokens)}&keep=1`);
    const c = h.client();
    c.sdk.handleTokensRedirect();
    await expectNotAllowed(h, c, tokens);
  });

  test('parseQueryParams: the constructor refuses tokens for an app in SDK mode', async () => {
    const h = modeHarness(SDK_APP);
    const tokens = await issued(h);
    h.land(`${PAGE}#${tokenParams(tokens)}`);
    const c = h.client({ parseQueryParams: true });
    expectTokensGone(h);
    await expectNotAllowed(h, c, tokens);
  });

  test('an instance with no app id refuses them with TOKENS_IN_URL_NOT_ALLOWED', async () => {
    const h = modeHarness(SIMPLE_APP);
    const tokens = await issued(h);
    h.land(`${PAGE}#${tokenParams(tokens)}`);
    const c = h.client({ appId: undefined });
    c.sdk.handleTokensRedirect();
    expectTokensGone(h);
    await expectNotAllowed(h, c, tokens);
  });

  test('an app in Simple mode: verified and signed in', async () => {
    const h = modeHarness(SIMPLE_APP);
    const tokens = await issued(h);
    h.land(`${PAGE}?keep=1#${tokenParams(tokens)}`);
    const c = h.client();
    c.sdk.handleTokensRedirect();
    expectTokensGone(h);
    expect(c.sdk.isAuthenticated()).toBe(false);
    await outcome(c);
    expect(c.of(PassflowEvent.Error)).toEqual([]);
    expect(c.of(PassflowEvent.SignIn)).toEqual([
      expect.objectContaining({
        source: 'tokens-in-url',
        tokens: expect.objectContaining({ access_token: tokens.access_token }),
      }),
    ]);
    expect(c.sdk.getCachedTokens()?.access_token).toBe(tokens.access_token);
    expect(everStored(h, tokens.access_token)).toBe(true);
  });

  test('the landing and the sign-in share one settings read', async () => {
    const h = modeHarness(SIMPLE_APP);
    const tokens = await issued(h);
    h.land(`${PAGE}#${tokenParams(tokens)}`);
    const c = h.client();
    c.sdk.handleTokensRedirect();
    await outcome(c);
    await c.sdk.getAppSettings();
    expect(h.settingsReads()).toBe(1);
  });
});

describe('state on the Simple-mode return', () => {
  test('#access_token&id_token&state: SignIn.state is set; the tokens and state leave, the rest of the hash stays', async () => {
    const h = modeHarness(SIMPLE_APP);
    const tokens = await issued(h);
    const fragment = `${tokenParams({ access_token: tokens.access_token, id_token: tokens.id_token })}&state=x-return-1&tab=security`;
    h.land(`${PAGE}?keep=1#${fragment}`);
    const c = h.client();
    c.sdk.handleTokensRedirect();

    const url = h.url();
    expectTokensGone(h);
    expect(url.hash).not.toContain('state=');
    expect(url.hash).toContain('tab=security');
    expect(url.searchParams.get('keep')).toBe('1');

    await outcome(c);
    expect(c.of(PassflowEvent.Error)).toEqual([]);
    expect(c.of(PassflowEvent.SignIn)).toEqual([expect.objectContaining({ source: 'tokens-in-url', state: 'x-return-1' })]);
  });

  test('without a state the SignIn payload carries none', async () => {
    const h = modeHarness(SIMPLE_APP);
    const tokens = await issued(h);
    h.land(`${PAGE}#${tokenParams(tokens)}`);
    const c = h.client();
    c.sdk.handleTokensRedirect();
    await outcome(c);
    const signIn = c.of(PassflowEvent.SignIn)[0] as { state?: string };
    expect(signIn.state).toBeUndefined();
  });
});
