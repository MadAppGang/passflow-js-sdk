/**
 * Federated sign-in: `state` and `parent_challenge_id` on the start URL, and the popup's token
 * reader.
 *
 * - `PassflowFederatedAuthPayload.state` and `.parent_challenge_id` are added to the federated start
 *   URL when set, for the redirect and the popup alike.
 * - The popup reads tokens from its callback query, then its fragment, and follows the URL-token
 *   rule: a PKCE start requires a `code`; otherwise tokens are accepted only for an app known to be
 *   in Simple mode (`pkce_enabled === false`). Any other case is one `Error` with operation
 *   `tokens.from-url` and nothing stored. A `#tfa_token` callback asks for the second factor.
 */
import { describe, expect, test } from 'vitest';
import { PassflowEvent } from '../../lib/index';
import {
  everStored,
  type ModeClient,
  type ModeHarness,
  modeHarness,
  publishKey,
  SDK_APP,
  SIMPLE_APP,
  settle,
} from '../helpers/oidc-harness';
import { fault, fedPayload, harness, until } from '../helpers/pkce-harness';
import { generateSigningKey, type IssuedTokens, issuedTokens, tokenParams } from '../helpers/signed-tokens';

const TFA_TOKEN = 'eyJhbGciOiJIUzI1NiJ9.eyJ0eXBlIjoiMmZhIn0.sig';

describe('state and parent_challenge_id on the federated start URL', () => {
  test.each([true, false])('redirect (PKCE %s) carries both when set', async (pkce) => {
    const h = harness({ pkce });
    h.sdk.federatedAuthWithRedirect({ ...fedPayload(), state: 'app-state-3', parent_challenge_id: 'parent-42' });
    await until(() => h.navigations.length === 1);
    const url = new URL(h.navigations[0]);
    expect(url.pathname).toBe('/auth/federated/start/google');
    expect(url.searchParams.get('state')).toBe('app-state-3');
    expect(url.searchParams.get('parent_challenge_id')).toBe('parent-42');
    expect(url.searchParams.get('redirect_url')).toBe(fedPayload().redirect_url);
  });

  test('redirect without them sends neither', async () => {
    const h = harness();
    h.sdk.federatedAuthWithRedirect(fedPayload());
    await until(() => h.navigations.length === 1);
    const url = new URL(h.navigations[0]);
    expect(url.searchParams.has('state')).toBe(false);
    expect(url.searchParams.has('parent_challenge_id')).toBe(false);
  });

  test.each([true, false])('popup (PKCE %s) carries both when set', async (pkce) => {
    const h = harness({ pkce });
    h.popup(() => new Promise<never>(() => {}));
    h.sdk.federatedAuthWithPopup({ ...fedPayload(), state: 'app-state-4', parent_challenge_id: 'parent-43' });
    await until(() => h.opened.length === 1);
    const url = new URL(h.opened[0]);
    expect(url.searchParams.get('state')).toBe('app-state-4');
    expect(url.searchParams.get('parent_challenge_id')).toBe('parent-43');
  });
});

describe('the popup token reader and its mode gate', () => {
  async function popupReturns(h: ModeHarness, callback: { callbackSearch: string; callbackHash: string }) {
    h.popup(async () => callback);
    const c = h.client();
    c.sdk.federatedAuthWithPopup(fedPayload());
    await until(
      () =>
        c.of(PassflowEvent.SignIn).length + c.of(PassflowEvent.Error).length + c.of(PassflowEvent.TwoFactorRequired).length > 0,
    );
    await settle();
    return c;
  }

  function expectRefused(h: ModeHarness, c: ModeClient, tokens: IssuedTokens) {
    expect(c.of(PassflowEvent.SignIn)).toEqual([]);
    expect(c.of(PassflowEvent.Error)).toEqual([
      expect.objectContaining({ operation: 'tokens.from-url', code: 'TOKENS_IN_URL_NOT_ALLOWED' }),
    ]);
    for (const token of Object.values(tokens)) expect(everStored(h, token)).toBe(false);
    expect(c.sdk.getCachedTokens()?.access_token).toBeUndefined();
  }

  test.each([
    ['fragment', (t: IssuedTokens) => ({ callbackSearch: '', callbackHash: `#${tokenParams(t)}` })],
    ['query', (t: IssuedTokens) => ({ callbackSearch: `?${tokenParams(t)}`, callbackHash: '' })],
  ])('Simple app, tokens in the callback %s: verified and signed in', async (_where, callback) => {
    const h = modeHarness(SIMPLE_APP);
    const tokens = await issuedTokens(await publishKey(h));
    const c = await popupReturns(h, callback(tokens));
    expect(c.of(PassflowEvent.Error)).toEqual([]);
    expect(c.of(PassflowEvent.SignIn)).toHaveLength(1);
    expect(c.sdk.getCachedTokens()?.access_token).toBe(tokens.access_token);
  });

  test('Simple app, a fragment set signed with an unpublished key is still refused by verification', async () => {
    const h = modeHarness(SIMPLE_APP);
    await publishKey(h);
    const unpublished = await issuedTokens(await generateSigningKey('k1'));
    const c = await popupReturns(h, { callbackSearch: '', callbackHash: `#${tokenParams(unpublished)}` });
    expect(c.of(PassflowEvent.SignIn)).toEqual([]);
    expect(c.of(PassflowEvent.Error)).toHaveLength(1);
    expect(c.sdk.getCachedTokens()?.access_token).toBeUndefined();
  });

  test.each([
    ['fragment', (t: IssuedTokens) => ({ callbackSearch: '', callbackHash: `#${tokenParams(t)}` })],
    ['query', (t: IssuedTokens) => ({ callbackSearch: `?${tokenParams(t)}`, callbackHash: '' })],
  ])('SDK app (PKCE start), tokens in the callback %s and no code: refused, nothing stored', async (_where, callback) => {
    const h = modeHarness(SDK_APP);
    const tokens = await issuedTokens(await publishKey(h));
    const c = await popupReturns(h, callback(tokens));
    expect(new URL(h.opened[0]).searchParams.get('code_challenge')).toEqual(expect.any(String));
    expectRefused(h, c, tokens);
  });

  test.each([
    ['settings without pkce_enabled', { type: 'web' }],
    ['a failed settings read', fault('http', 503)],
  ])('mode unknown (%s), fragment tokens: refused, nothing stored', async (_name, settings) => {
    const h = modeHarness(settings);
    const tokens = await issuedTokens(await publishKey(h));
    const c = await popupReturns(h, { callbackSearch: '', callbackHash: `#${tokenParams(tokens)}` });
    expectRefused(h, c, tokens);
  });

  test('Simple app, #tfa_token in the callback: TwoFactorRequired, nothing stored', async () => {
    const h = modeHarness(SIMPLE_APP);
    const c = await popupReturns(h, { callbackSearch: '?user_state=xyz', callbackHash: `#tfa_token=${TFA_TOKEN}` });
    expect(c.of(PassflowEvent.TwoFactorRequired)).toEqual([expect.objectContaining({ tfaToken: TFA_TOKEN })]);
    expect(c.sdk.isTwoFactorVerificationRequired()).toBe(true);
    expect(c.of(PassflowEvent.SignIn)).toEqual([]);
    expect(c.sdk.getCachedTokens()?.access_token).toBeUndefined();
  });
});
