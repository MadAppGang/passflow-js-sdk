/**
 * A magic-link sign-in under an OIDC parent (the hosted login signing in for an app in SDK mode).
 *
 * The status poll then answers with the relying party's `redirect_url` (carrying the parent's code),
 * or with a `tfa_token` when a second factor is owed, instead of a native code. The wait ends on
 * either: `signed-in` with `tokens` carrying only `redirect_url`, or `second-factor-required`. This
 * tab's pending record is forgotten in both cases, and no `/auth/pkce_exchange` is sent.
 */
import { describe, expect, test } from 'vitest';
import { PassflowEvent } from '../../lib/index';
import { harness, noSession, PATH, PW_SLOT, rejected, TFA } from '../helpers/pkce-harness';

const RP_REDIRECT = 'https://rp.example/callback?code=parent-code&state=rp-state';

describe('passwordless wait under an OIDC parent', () => {
  test('an answer carrying redirect_url ends the wait as signed-in with only that address', async () => {
    const h = harness();
    await h.start();
    h.reply(PATH.status, { redirect_url: RP_REDIRECT });

    const result = await h.sdk.waitForPasswordlessSignIn('challenge-a');

    expect(result.status).toBe('signed-in');
    expect(result).toMatchObject({ status: 'signed-in', tokens: { redirect_url: RP_REDIRECT } });
    const tokens = (result as { tokens: Record<string, unknown> }).tokens;
    expect(tokens.access_token).toBeUndefined();
    expect(h.wire(PATH.status)).toHaveLength(1);
    expect(h.wire(PATH.exchange)).toEqual([]);
    expect(sessionStorage.getItem(PW_SLOT)).toBeNull();
    expect(h.sdk.getPendingPasswordlessSignIn('challenge-a')).toBeUndefined();
    expect(h.sdk.getCachedTokens()?.access_token).toBeUndefined();
    expect(h.of(PassflowEvent.Error)).toEqual([]);
  });

  test('after a redirect_url ending, the record is gone: waiting again rejects without polling', async () => {
    const h = harness();
    await h.start();
    h.reply(PATH.status, { redirect_url: RP_REDIRECT });
    await h.sdk.waitForPasswordlessSignIn('challenge-a');

    await rejected(h.sdk.waitForPasswordlessSignIn('challenge-a'));
    expect(h.wire(PATH.status)).toHaveLength(1);
  });

  test('an answer carrying tfa_token ends the wait as second-factor-required', async () => {
    const h = harness();
    await h.start();
    h.reply(PATH.status, { ...TFA });

    expect(await h.sdk.waitForPasswordlessSignIn('challenge-a')).toEqual({ status: 'second-factor-required' });
    expect(h.of(PassflowEvent.TwoFactorRequired)).toEqual([expect.objectContaining({ tfaToken: TFA.tfa_token })]);
    expect(h.sdk.isTwoFactorVerificationRequired()).toBe(true);
    expect(h.wire(PATH.exchange)).toEqual([]);
    expect(sessionStorage.getItem(PW_SLOT)).toBeNull();
    expect(h.sdk.getPendingPasswordlessSignIn('challenge-a')).toBeUndefined();
    noSession(h);
  });
});

describe('approval info', () => {
  test.each([true, false])('one_click %s is passed through to the approving page', async (oneClick) => {
    const h = harness();
    h.reply(PATH.info, {
      state: 'pending',
      app_name: 'QA app',
      requested_at: new Date().toISOString(),
      expires_at: new Date(Date.now() + 60_000).toISOString(),
      browser: 'Firefox',
      os: 'Linux',
      location: null,
      attempts_left: 5,
      one_click: oneClick,
    });
    const info = await h.sdk.getPasswordlessApproval('link-challenge');
    expect(info.one_click).toBe(oneClick);
    noSession(h);
  });
});
