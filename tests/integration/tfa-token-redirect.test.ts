/**
 * Landing on the app's redirect URL with `#tfa_token=` — a federated GET
 * callback on a non-PKCE app whose sign-in owes its second factor.
 *
 * The token is adopted for the TwoFactorService, nothing is saved as a
 * session, and the fragment leaves the URL.
 */
import { beforeEach, describe, expect, test, vi } from 'vitest';
import { Passflow } from '../../lib/passflow';
import { PassflowEvent } from '../../lib/store';
import { TEST_CONFIG, VALID_ACCESS_TOKEN } from '../helpers/fixtures';

const TFA_TOKEN = 'eyJhbGciOiJIUzI1NiJ9.eyJ0eXBlIjoiMmZhIn0.sig';

const landOn = (search: string, hash: string) => {
  Object.defineProperty(window, 'location', {
    value: {
      origin: 'https://app.example.com',
      hostname: 'app.example.com',
      pathname: '/callback',
      search,
      hash,
      href: `https://app.example.com/callback${search}${hash}`,
    },
    writable: true,
  });
};

describe('handleTokensRedirect — #tfa_token fragment', () => {
  let replaceState: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    localStorage.clear();
    sessionStorage.clear();
    replaceState = vi.fn();
    window.history.replaceState = replaceState;
  });

  test('adopts the token, saves no session and strips the fragment', () => {
    landOn('?user_state=xyz', `#tfa_token=${TFA_TOKEN}`);
    const passflow = new Passflow({ ...TEST_CONFIG, parseQueryParams: false });
    const events: PassflowEvent[] = [];
    passflow.subscribe({ onAuthChange: (event) => events.push(event) });

    const tokens = passflow.handleTokensRedirect();

    expect(tokens).toBeUndefined();
    expect(events).toContain(PassflowEvent.TwoFactorRequired);
    expect(events).not.toContain(PassflowEvent.SignIn);
    expect(localStorage.getItem('access')).toBeNull();
    expect(passflow.isTwoFactorVerificationRequired()).toBe(true);
    expect(replaceState).toHaveBeenCalledWith({}, expect.anything(), '/callback?user_state=xyz');
  });

  test('parseQueryParams: true adopts it on construction', () => {
    landOn('', `#tfa_token=${TFA_TOKEN}`);
    const passflow = new Passflow({ ...TEST_CONFIG, parseQueryParams: true });

    expect(passflow.isTwoFactorVerificationRequired()).toBe(true);
    expect(replaceState).toHaveBeenCalledWith({}, expect.anything(), '/callback');
  });

  test('keeps the other fragment parameters', () => {
    landOn('', `#tfa_token=${TFA_TOKEN}&tab=security`);
    new Passflow({ ...TEST_CONFIG, parseQueryParams: true });

    expect(replaceState).toHaveBeenCalledWith({}, expect.anything(), '/callback#tab=security');
  });

  test('a malformed token is stripped and reported, not adopted', () => {
    landOn('', '#tfa_token=not-a-jwt');
    const passflow = new Passflow({ ...TEST_CONFIG, parseQueryParams: false });
    const errors: unknown[] = [];
    passflow.subscribe({ onAuthChange: (_e, payload) => errors.push(payload) }, [PassflowEvent.Error]);

    passflow.handleTokensRedirect();

    expect(passflow.isTwoFactorVerificationRequired()).toBe(false);
    expect(errors).toEqual([expect.objectContaining({ code: 'INVALID_TOKEN_FORMAT' })]);
    expect(replaceState).toHaveBeenCalledWith({}, expect.anything(), '/callback');
  });

  test('tokens in the URL still sign in as before', () => {
    // No leading `?`: tests/setup.ts swaps in a URLSearchParams that does not strip it.
    landOn(`access_token=${VALID_ACCESS_TOKEN}`, '');
    const passflow = new Passflow({ ...TEST_CONFIG, parseQueryParams: false });

    expect(passflow.handleTokensRedirect()?.access_token).toBe(VALID_ACCESS_TOKEN);
    expect(passflow.isTwoFactorVerificationRequired()).toBe(false);
  });

  test('verifyTwoFactor sends the adopted token, with trust_device when asked', async () => {
    landOn('', `#tfa_token=${TFA_TOKEN}`);
    const passflow = new Passflow({ ...TEST_CONFIG, parseQueryParams: true });
    const verify = vi
      .spyOn(passflow.twoFactor['twoFactorApi'], 'verify')
      .mockResolvedValue({ success: true, access_token: VALID_ACCESS_TOKEN });

    await passflow.verifyTwoFactor('123456', { trustDevice: true });

    expect(verify).toHaveBeenCalledWith({ code: '123456', tfa_token: TFA_TOKEN, trust_device: true });
  });
});
