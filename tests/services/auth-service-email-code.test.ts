/**
 * Black-box coverage of AuthService behavior through the public facade and real
 * API transport. Only external settings/HTTP/time are controlled; no private
 * helper calls or mock invocation details are asserted.
 */
import { describe, expect, test, vi } from 'vitest';
import { PassflowError, PassflowEvent } from '../../lib/index';
import {
  body,
  CODE_STEP,
  EMAIL,
  type EmailHarness,
  exchangeProvesChallenge,
  harness,
  LINK_STEP,
  type Operation,
  OTP,
  PASSWORD,
  TFA,
} from '../helpers/email-code-harness';
import { VALID_TOKENS } from '../helpers/fixtures';

const flows: Array<{ operation: Operation; path: string; start: PassflowEvent }> = [
  { operation: 'sign-up', path: '/auth/register', start: PassflowEvent.RegisterStart },
  { operation: 'sign-in', path: '/auth/login', start: PassflowEvent.SignInStart },
  { operation: 'reset-password', path: '/auth/password/change', start: PassflowEvent.SignInStart },
];
const noSession = (h: EmailHarness) => {
  expect(h.sdk.getCachedTokens()).toBeUndefined();
  expect(h.sdk.isAuthenticated()).toBe(false);
  expect(h.sdk.areTokensExpired()).toBe(true);
  expect(localStorage.getItem('access')).toBeNull();
  expect(localStorage.getItem('refresh')).toBeNull();
};
const labelledError = (h: EmailHarness, code?: string) => {
  expect(h.names()).toEqual([PassflowEvent.Error]);
  expect(h.of(PassflowEvent.Error)).toEqual([
    expect.objectContaining({ operation: 'email-verification.complete', ...(code ? { code } : {}) }),
  ]);
};
const jwtWithEmail = () => {
  const encode = (v: unknown) => Buffer.from(JSON.stringify(v)).toString('base64url');
  return `${encode({ alg: 'none' })}.${encode({ email: EMAIL, exp: 4102444800 })}.sig`;
};

describe.each(flows)('email code steps from $operation', ({ operation, path, start }) => {
  test.each([
    ['code', CODE_STEP],
    ['link', LINK_STEP],
  ] as const)(
    'TEST-03 REQ-2 REQ-5 REQ-26 returns the %s answer unchanged without establishing a session',
    async (_name, answer) => {
      const h = harness();
      h.startAnswer(answer);
      await h.callbacks();
      const result = await h.start(operation);
      expect(result).toBe(answer);
      expect(result).toEqual(answer);
      noSession(h);
      expect(h.names()).toEqual([start, PassflowEvent.EmailVerificationRequired]);
      expect(h.of(PassflowEvent.EmailVerificationRequired)).toEqual([
        {
          email: operation === 'reset-password' ? undefined : EMAIL,
          challengeId: 'challenge_id' in answer ? answer.challenge_id : undefined,
          operation,
        },
      ]);
      expect(h.callbacksSeen()).toEqual({ created: 0, expired: 0 });
      expect(h.wire('/auth/pkce_exchange')).toEqual([]);
      await vi.advanceTimersByTimeAsync(60_000);
      expect(h.wire('/auth/refresh')).toEqual([]);
      expect(h.events.some(({ event }) => event === PassflowEvent.RefreshStart)).toBe(false);
      // Inspect writes, not storage spy invocations: even write-then-delete counts.
      const persisted = h.writes.map(({ value }) => value).join('\n');
      expect(persisted).not.toContain(PASSWORD);
      expect(persisted).not.toContain(answer.message);
      expect(persisted).not.toContain('email_verification_required');
    },
  );

  test('TEST-04 REQ-3 REQ-9 REQ-26 retains the original PKCE proof and scopes until verification', async () => {
    const h = harness({ pkce: true });
    const scopes = ['id', 'offline', 'custom:pkce-email-code'];
    await h.start(operation, scopes);
    h.validateAnswer({ code: 'email-authorization-code' });
    h.exchangeAnswer({ access_token: VALID_TOKENS.access_token, refresh_token: VALID_TOKENS.refresh_token });
    h.clearEvents();
    const result = await h.sdk.verifyEmailCode(OTP);
    expect(await exchangeProvesChallenge(h, path)).toBe(true);
    expect(Object.values(body(h.wire('/auth/pkce_exchange')[0]))).toContain('email-authorization-code');
    expect(result.access_token).toBe(VALID_TOKENS.access_token);
    expect(result).not.toHaveProperty('code');
    expect(h.sdk.getCachedTokens()?.access_token).toBe(VALID_TOKENS.access_token);
    expect(h.names()).toEqual([operation === 'sign-up' ? PassflowEvent.Register : PassflowEvent.SignIn]);
    expect(h.writes.map(({ value }) => value).join('\n')).not.toContain(OTP.otp);
    await h.sdk.refreshToken();
    expect(body(h.wire('/auth/refresh').at(-1)!).scopes).toEqual(scopes);
  });

  test('TEST-05 REQ-4 clears an earlier pending proof when a link is sent', async () => {
    const h = harness({ pkce: true });
    await h.start('sign-in');
    h.startAnswer(LINK_STEP);
    await h.start(operation);
    h.validateAnswer({ code: 'must-not-use-stale-proof' });
    h.clearEvents();
    await expect(h.sdk.verifyEmailCode({ ...OTP, challenge_id: 'unknown-link-challenge' })).rejects.toThrow(/verifier is gone/);
    expect(h.wire('/auth/pkce_exchange')).toEqual([]);
    labelledError(h);
    noSession(h);
  });

  test('TEST-06 REQ-4 REQ-10 has no proof to exchange on a non-PKCE app', async () => {
    const h = harness();
    await h.start(operation);
    expect(body(h.wire(path)[0])).not.toHaveProperty('code_challenge');
    h.validateAnswer({ code: 'unexpected-code' });
    h.clearEvents();
    await expect(h.sdk.verifyEmailCode(OTP)).rejects.toThrow(/verifier is gone/);
    labelledError(h);
    expect(h.wire('/auth/pkce_exchange')).toEqual([]);
    noSession(h);
  });

  test('TEST-23 REQ-20 preserves requested scopes in the later refresh', async () => {
    const h = harness();
    const scopes = ['id', 'offline', 'email', 'custom:email-code'];
    await h.start(operation, scopes);
    h.validateAnswer({ access_token: VALID_TOKENS.access_token, refresh_token: VALID_TOKENS.refresh_token });
    await h.sdk.verifyEmailCode(OTP);
    await h.sdk.refreshToken();
    expect(h.wire('/auth/refresh')).toHaveLength(1);
    expect(body(h.wire('/auth/refresh')[0]).scopes).toEqual(scopes);
  });

  test('TEST-28 REQ-4 REQ-5 treats an empty challenge as a link rather than a retained proof', async () => {
    const h = harness({ pkce: true });
    await h.start('sign-in');
    h.startAnswer({ ...CODE_STEP, challenge_id: '' });
    h.clearEvents();
    await h.start(operation);
    expect(h.of(PassflowEvent.EmailVerificationRequired)).toEqual([
      expect.objectContaining({ operation, challengeId: undefined }),
    ]);
    h.validateAnswer({ code: 'not-exchangeable' });
    await expect(h.sdk.verifyEmailCode({ ...OTP, challenge_id: 'unknown' })).rejects.toThrow(/verifier is gone/);
    expect(h.wire('/auth/pkce_exchange')).toEqual([]);
  });

  test('TEST-30 REQ-2 leaves an existing authenticated session unchanged at a step', async () => {
    const h = harness();
    h.sdk.setTokens({ ...VALID_TOKENS });
    const before = { ...h.sdk.getCachedTokens() };
    h.clearEvents();
    const result = await h.start(operation);
    expect(result).toBe(CODE_STEP);
    expect(h.sdk.getCachedTokens()).toEqual(before);
    expect(h.sdk.isAuthenticated()).toBe(true);
    expect(h.names()).toEqual([start, PassflowEvent.EmailVerificationRequired]);
  });

  test('TEST-31 REQ-28 branches on the email step before a second-factor flag', async () => {
    const h = harness({ pkce: true });
    const answer = { ...CODE_STEP, ...TFA };
    h.startAnswer(answer);
    const result = await h.start(operation);
    expect(result).toBe(answer);
    expect(h.names()).toEqual([start, PassflowEvent.EmailVerificationRequired]);
    expect(h.sdk.isTwoFactorVerificationRequired()).toBe(false);
    noSession(h);
  });
});

describe('email verification event payloads', () => {
  test('TEST-07 REQ-5 does not fabricate an email for username sign-in', async () => {
    const h = harness();
    await h.sdk.signIn({ username: 'alice', password: PASSWORD });
    expect(h.of(PassflowEvent.EmailVerificationRequired)).toEqual([
      { email: undefined, challengeId: 'ch-1', operation: 'sign-in' },
    ]);
  });

  test.each([
    ['email claim', jwtWithEmail(), EMAIL],
    ['unreadable token', 'not-a-jwt', undefined],
  ])('TEST-08 REQ-5 uses reset token email best-effort: %s', async (_name, token, email) => {
    const h = harness();
    h.platform.getCurrentUrl.mockReturnValue({
      href: `https://app.example/reset?token=${token}`,
      origin: 'https://app.example',
      pathname: '/reset',
      search: `?token=${token}`,
      hash: '',
    });
    await h.start('reset-password');
    expect(h.of(PassflowEvent.EmailVerificationRequired)).toEqual([
      { email, challengeId: 'ch-1', operation: 'reset-password' },
    ]);
    expect(h.of(PassflowEvent.Error)).toEqual([]);
  });
});

describe('verifyEmailCode completion', () => {
  test.each(['sign-up', 'sign-in', 'reset-password', 'unknown'] as const)(
    'TEST-09 REQ-6 REQ-8 REQ-22 applies direct tokens with the correct terminal event for %s and no new Start',
    async (origin) => {
      const h = harness();
      if (origin !== 'unknown') await h.start(origin);
      h.clearEvents();
      const result = await h.sdk.verifyEmailCode(OTP);
      expect(result.access_token).toBe(VALID_TOKENS.access_token);
      expect(h.sdk.getCachedTokens()?.access_token).toBe(VALID_TOKENS.access_token);
      expect(localStorage.getItem('access')).toBe(VALID_TOKENS.access_token);
      expect(h.sdk.isAuthenticated()).toBe(true);
      const terminal = origin === 'sign-up' ? PassflowEvent.Register : PassflowEvent.SignIn;
      expect(h.names()).toEqual([terminal]);
      expect(h.of(terminal)).toEqual([
        expect.objectContaining({
          tokens: expect.objectContaining({ access_token: VALID_TOKENS.access_token }),
          parsedTokens: expect.objectContaining({ access_token: expect.objectContaining({ sub: 'user-123' }) }),
        }),
      ]);
      // Post-construction session callbacks are not a reliable completion probe.
      // Token state and the terminal event above assert the public completion contract.
      expect(body(h.wire('/auth/validate')[0])).toEqual(OTP);
    },
  );

  test('TEST-10 REQ-9 clears the pending proof after successful exchange', async () => {
    const h = harness({ pkce: true });
    await h.start('sign-in');
    h.validateAnswer({ code: 'first-code' });
    await h.sdk.verifyEmailCode(OTP);
    expect(await exchangeProvesChallenge(h, '/auth/login')).toBe(true);
    h.clearEvents();
    h.validateAnswer({ code: 'another-code' });
    await expect(h.sdk.verifyEmailCode({ ...OTP, challenge_id: 'unknown' })).rejects.toThrow(/verifier is gone/);
    expect(h.wire('/auth/pkce_exchange')).toHaveLength(1);
    labelledError(h);
  });

  test.each([{}, { redirect_url: 'https://app.example/after-reset' }])(
    'TEST-11 REQ-10 REQ-13 rejects a code without a proof, even with redirect %j',
    async (extra) => {
      const h = harness({ pkce: true });
      h.validateAnswer({ code: 'code-without-verifier', ...extra });
      await expect(h.sdk.verifyEmailCode(OTP)).rejects.toThrow(/verifier is gone/);
      expect(h.wire('/auth/validate')).toHaveLength(1);
      expect(h.wire('/auth/pkce_exchange')).toEqual([]);
      labelledError(h);
      noSession(h);
    },
  );

  test('TEST-12 REQ-10 refuses an expired known PKCE challenge BEFORE spending the code', async () => {
    const h = harness({ pkce: true });
    await h.start('sign-up');
    await vi.advanceTimersByTimeAsync(300_001);
    h.clearEvents();
    await expect(h.sdk.verifyEmailCode(OTP)).rejects.toThrow(/verifier is gone/);
    expect(h.wire('/auth/validate')).toEqual([]);
    expect(h.wire('/auth/pkce_exchange')).toEqual([]);
    labelledError(h);
    noSession(h);
  });

  test.each([false, true])('TEST-13 REQ-11 REQ-22 keeps direct 2FA pending (PKCE=%s)', async (pkce) => {
    const h = harness({ pkce });
    await h.callbacks();
    await h.start('sign-in');
    h.validateAnswer(TFA);
    h.clearEvents();
    const result = await h.sdk.verifyEmailCode(OTP);
    expect(result).toBe(TFA);
    expect(h.names()).toEqual([PassflowEvent.TwoFactorRequired]);
    expect(h.of(PassflowEvent.TwoFactorRequired)).toEqual([
      { email: EMAIL, challengeId: TFA.challenge_id, tfaToken: TFA.tfa_token },
    ]);
    expect(h.sdk.isTwoFactorVerificationRequired()).toBe(true);
    noSession(h);
    expect(h.callbacksSeen()).toEqual({ created: 0, expired: 0 });
    expect(h.wire('/auth/pkce_exchange')).toEqual([]);
  });

  test('TEST-14 REQ-12 renews the five-minute proof lifetime when validate requests 2FA', async () => {
    const h = harness({ pkce: true });
    await h.start('sign-in');
    await vi.advanceTimersByTimeAsync(240_000);
    h.validateAnswer(TFA);
    await h.sdk.verifyEmailCode(OTP);
    await vi.advanceTimersByTimeAsync(240_000);
    const result = await h.sdk.verifyTwoFactor('654321');
    expect(result.access_token).toBe(VALID_TOKENS.access_token);
    expect(await exchangeProvesChallenge(h, '/auth/login')).toBe(true);
    expect(h.sdk.isTwoFactorVerificationRequired()).toBe(false);
  });

  test('TEST-15 REQ-12 handles a second-factor answer after the code exchange', async () => {
    const h = harness({ pkce: true });
    await h.start('sign-in');
    h.validateAnswer({ code: 'code-before-2fa' });
    h.exchangeAnswer(TFA);
    h.clearEvents();
    const result = await h.sdk.verifyEmailCode(OTP);
    expect(result).toBe(TFA);
    expect(await exchangeProvesChallenge(h, '/auth/login')).toBe(true);
    expect(h.names()).toEqual([PassflowEvent.TwoFactorRequired]);
    expect(h.sdk.isTwoFactorVerificationRequired()).toBe(true);
    noSession(h);
  });

  test.each([false, true])('TEST-16 REQ-13 preserves the raw redirect after completion (PKCE=%s)', async (pkce) => {
    const h = harness({ pkce });
    const redirect_url = 'https://app.example/after-reset';
    await h.start('reset-password');
    h.validateAnswer(pkce ? { code: 'reset-code', redirect_url } : { ...VALID_TOKENS, redirect_url });
    const result = await h.sdk.verifyEmailCode(OTP);
    expect(result).toMatchObject({ access_token: VALID_TOKENS.access_token, redirect_url });
    expect(result).not.toHaveProperty('code');
    if (pkce) expect(await exchangeProvesChallenge(h, '/auth/password/change')).toBe(true);
  });

  test('TEST-17 REQ-14 preserves error identity, labels one Error and keeps sign-up origin for retry', async () => {
    const h = harness();
    await h.start('sign-up');
    const error = new PassflowError({
      id: 'error.otp.incorrect',
      status: 400,
      message: 'Incorrect email code',
      location: '/auth/validate',
      time: '2026-11-03T00:00:00Z',
    });
    h.validationError(error);
    h.clearEvents();
    await expect(h.sdk.verifyEmailCode(OTP)).rejects.toBe(error);
    expect(error).toMatchObject({ id: 'error.otp.incorrect', status: 400, message: 'Incorrect email code' });
    labelledError(h, 'error.otp.incorrect');
    expect(h.of(PassflowEvent.Error)).toEqual([expect.objectContaining({ originalError: error })]);
    noSession(h);
    h.validationError(undefined);
    h.clearEvents();
    await h.sdk.verifyEmailCode(OTP);
    expect(h.names()).toEqual([PassflowEvent.Register]);
  });

  test('TEST-18 REQ-15 forgets challenge origin after a successful 200', async () => {
    const h = harness();
    await h.start('sign-up');
    h.clearEvents();
    await h.sdk.verifyEmailCode(OTP);
    expect(h.names()).toEqual([PassflowEvent.Register]);
    h.clearEvents();
    await h.sdk.verifyEmailCode(OTP);
    expect(h.names()).toEqual([PassflowEvent.SignIn]);
  });

  test('TEST-19 REQ-16 evicts the oldest of eleven origins but retains the newest', async () => {
    const h = harness();
    for (let index = 0; index < 11; index += 1) {
      h.startAnswer({ ...CODE_STEP, challenge_id: `c${index}` });
      await h.start('sign-up');
    }
    h.clearEvents();
    await h.sdk.verifyEmailCode({ ...OTP, challenge_id: 'c0' });
    expect(h.names()).toEqual([PassflowEvent.SignIn]);
    h.clearEvents();
    await h.sdk.verifyEmailCode({ ...OTP, challenge_id: 'c10' });
    expect(h.names()).toEqual([PassflowEvent.Register]);
  });

  test('TEST-20 REQ-17 forgets sign-up origin on logOut', async () => {
    const h = harness();
    await h.start('sign-up');
    await h.sdk.logOut();
    h.clearEvents();
    await h.sdk.verifyEmailCode(OTP);
    expect(h.names()).toEqual([PassflowEvent.SignIn]);
  });

  test('TEST-21 REQ-18 forgets sign-up origin on reset', async () => {
    const h = harness();
    await h.start('sign-up');
    h.sdk.reset();
    h.clearEvents();
    await h.sdk.verifyEmailCode(OTP);
    expect(h.names()).toEqual([PassflowEvent.SignIn]);
  });

  test('TEST-22 REQ-19 defaults to SignIn after recreating the instance', async () => {
    const first = harness();
    await first.start('sign-up');
    first.sdk.dispose();
    const second = harness();
    await second.sdk.verifyEmailCode(OTP);
    expect(second.names()).toEqual([PassflowEvent.SignIn]);
  });

  test('TEST-24 REQ-21 cannot borrow another sign-in proof for a known non-PKCE challenge', async () => {
    const h = harness();
    await h.start('sign-up');
    // Another instance writes a verifier to the shared 2FA PKCE slot after this
    // non-PKCE challenge was created; this instance must not borrow that proof.
    const other = harness({ pkce: true, config: { appId: 'pkce-other-app' } });
    other.startAnswer({ ...CODE_STEP, challenge_id: 'unrelated-pkce' });
    await other.start('sign-in');
    h.validateAnswer({ code: 'must-not-borrow-proof' });
    h.clearEvents();
    await expect(h.sdk.verifyEmailCode(OTP)).rejects.toThrow(/verifier is gone/);
    expect(h.wire('/auth/pkce_exchange')).toEqual([]);
    labelledError(h);
  });

  test('TEST-29 REQ-11 treats requires_2fa alone as pending rather than a session', async () => {
    const h = harness();
    await h.start('sign-in');
    h.validateAnswer({ requires_2fa: true, challenge_id: 'second' });
    h.clearEvents();
    await h.sdk.verifyEmailCode(OTP);
    expect(h.names()).toEqual([PassflowEvent.TwoFactorRequired]);
    noSession(h);
  });

  test('TEST-32 REQ-15 consumes origin even when validate 200 requests a second factor', async () => {
    const h = harness();
    await h.start('sign-up');
    h.validateAnswer(TFA);
    await h.sdk.verifyEmailCode(OTP);
    h.validateAnswer({ ...VALID_TOKENS });
    h.clearEvents();
    await h.sdk.verifyEmailCode(OTP);
    expect(h.names()).toEqual([PassflowEvent.SignIn]);
  });

  test('TEST-33 REQ-21 does not renew an unrelated verifier on non-PKCE 2FA', async () => {
    const h = harness();
    await h.start('sign-up');
    const other = harness({ pkce: true, config: { appId: 'pkce-other-app' } });
    other.startAnswer({ ...CODE_STEP, challenge_id: 'unrelated-pkce' });
    await other.start('sign-in');
    await vi.advanceTimersByTimeAsync(240_000);
    h.validateAnswer(TFA);
    await h.sdk.verifyEmailCode(OTP);
    await vi.advanceTimersByTimeAsync(120_000);
    h.clearEvents();
    // An unknown id uses the backstop. If the non-PKCE 2FA answer borrowed and
    // renewed the unrelated proof, this code would wrongly exchange successfully.
    h.validateAnswer({ code: 'after-original-proof-expiry' });
    await expect(h.sdk.verifyEmailCode({ ...OTP, challenge_id: 'unknown' })).rejects.toThrow(/verifier is gone/);
    expect(h.wire('/auth/pkce_exchange')).toEqual([]);
    labelledError(h);
  });

  test('TEST-34 REQ-17 clears the pending PKCE proof on logout', async () => {
    const h = harness({ pkce: true });
    await h.start('sign-up');
    await h.sdk.logOut();
    h.validateAnswer({ code: 'after-logout' });
    h.clearEvents();
    await expect(h.sdk.verifyEmailCode({ ...OTP, challenge_id: 'unknown' })).rejects.toThrow(/verifier is gone/);
    expect(h.wire('/auth/pkce_exchange')).toEqual([]);
    labelledError(h);
  });
});
