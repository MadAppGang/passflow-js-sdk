import { describe, expect, test, vi } from 'vitest';
import { PassflowError, PassflowEvent } from '../../lib/index';
import { VALID_TOKENS } from '../helpers/fixtures';
import {
  body,
  CODE,
  FED_SLOT,
  fault,
  fedPayload,
  harness,
  MATCH,
  noSession,
  OTP,
  PATH,
  PW_SLOT,
  plain,
  rejected,
  serialiseAll,
  TFA,
  until,
} from '../helpers/pkce-harness';

const secretsFromWire = (h: ReturnType<typeof harness>) => [
  OTP,
  MATCH,
  CODE,
  ...h.requests.flatMap((request) =>
    Object.entries(body(request))
      .filter(([key]) => ['verifier', 'authz_code', 'code_challenge', 'otp', 'match_code'].includes(key))
      .map(([, value]) => value),
  ),
];
function errorIsPlain(h: ReturnType<typeof harness>, error: unknown, operation: string) {
  expect(error).toBeInstanceOf(Error);
  plain(error, secretsFromWire(h));
  const events = h.of(PassflowEvent.Error);
  expect(events).toEqual([expect.objectContaining({ operation })]);
  plain(events, secretsFromWire(h));
  // Check normal host serialisation as well as non-enumerable Error properties.
  const json = JSON.stringify(events);
  expect(json).not.toContain('"config"');
  for (const secret of secretsFromWire(h)) {
    if (typeof secret === 'string' && secret) expect(json).not.toContain(secret);
  }
}

describe('plain boundary on every secret-bearing call', () => {
  test.each([
    { name: 'start network', path: PATH.start, operation: 'passwordless.start', failure: fault('network') },
    { name: 'start POST 429', path: PATH.start, operation: 'passwordless.start', failure: fault('http', 429) },
    { name: 'complete network', path: PATH.complete, operation: 'passwordless.complete', failure: fault('network') },
    { name: 'complete POST 429', path: PATH.complete, operation: 'passwordless.complete', failure: fault('http', 429) },
    { name: 'info network', path: PATH.info, operation: 'passwordless.approval', failure: fault('network') },
    { name: 'info POST 429', path: PATH.info, operation: 'passwordless.approval', failure: fault('http', 429) },
    { name: 'decide network', path: PATH.decide, operation: 'passwordless.approval', failure: fault('network') },
    { name: 'decide POST 429', path: PATH.decide, operation: 'passwordless.approval', failure: fault('http', 429) },
  ])('TEST-21 REQ-14 $name rejects without request config or secrets in value/event', async ({ path, operation, failure }) => {
    const h = harness();
    if (path === PATH.complete) await h.start('otp');
    h.reply(path, failure);
    h.clearEvents();
    let pending: Promise<unknown>;
    if (path === PATH.start) pending = h.start();
    else if (path === PATH.complete) pending = h.sdk.passwordlessSignInComplete({ challenge_id: 'challenge-a', otp: OTP });
    else if (path === PATH.info) pending = h.sdk.getPasswordlessApproval('device-b-challenge');
    else pending = h.sdk.decidePasswordlessApproval('device-b-challenge', OTP, true, MATCH);
    const error = await rejected(pending);
    errorIsPlain(h, error, operation);
    if (path === PATH.info || path === PATH.decide) {
      expect(error).toMatchObject({ id: 'error.passwordless.approval', status: 0 });
    }
    noSession(h);
  });

  test.each([fault('network'), fault('http', 429)])(
    'TEST-21 REQ-14 raw status $kind/$status never escapes via events or rejection',
    async (failure) => {
      const h = harness();
      await h.start();
      h.queue(PATH.status, failure, { status: 'denied' });
      h.clearEvents();
      const waiting = h.sdk.waitForPasswordlessSignIn('challenge-a');
      await until(() => h.wire(PATH.status).length === 1);
      await vi.advanceTimersByTimeAsync(3000);
      expect(await waiting).toEqual({ status: 'denied' });
      expect(h.of(PassflowEvent.Error)).toEqual([]);
      expect(h.wire(PATH.status)).toHaveLength(2);
      noSession(h);
    },
  );

  test('TEST-23 REQ-14 a structured approval refusal preserves safe id/status/message only', async () => {
    const h = harness();
    h.reply(
      PATH.decide,
      fault('http', 409, {
        error: { id: 'error.otp.already.used', message: 'Already decided.', status: 409, time: new Date().toISOString() },
      }),
    );
    const error = await rejected(h.sdk.decidePasswordlessApproval('challenge-a', OTP, true, MATCH));
    errorIsPlain(h, error, 'passwordless.approval');
    expect(error).toMatchObject({ id: 'error.otp.already.used', status: 409, message: 'Already decided.' });
  });
});

type Flow = 'otp' | 'popup' | 'landing' | 'wait' | 'password' | 'email-code' | '2fa-verify' | '2fa-recovery';
const flows: Array<{ flow: Flow; operation: string }> = [
  { flow: 'otp', operation: 'passwordless.complete' },
  { flow: 'popup', operation: 'federated.popup' },
  { flow: 'landing', operation: 'federated.redirect' },
  { flow: 'wait', operation: 'passwordless.wait' },
  { flow: 'password', operation: 'sign-in' },
  { flow: 'email-code', operation: 'email-verification.complete' },
  { flow: '2fa-verify', operation: '2fa.verify' },
  { flow: '2fa-recovery', operation: '2fa.recovery.use' },
];

async function exchangeFlow(h: ReturnType<typeof harness>, flow: Flow): Promise<unknown> {
  if (flow === 'otp') {
    await h.start('otp');
    h.clearEvents();
    return rejected(h.sdk.passwordlessSignInComplete({ challenge_id: 'challenge-a', otp: OTP }));
  }
  if (flow === 'popup') {
    // The facade does not guarantee a rejected promise; observe the Error event.
    h.sdk.federatedAuthWithPopup(fedPayload());
    await until(() => h.of(PassflowEvent.Error).length === 1);
    return undefined;
  }
  if (flow === 'landing') {
    h.sdk.federatedAuthWithRedirect(fedPayload());
    await until(() => h.navigations.length === 1);
    h.land('https://app.example/callback?code=' + CODE + '&user_state=qa');
    expect(h.sdk.handleTokensRedirect()).toBeUndefined();
    await until(() => h.of(PassflowEvent.Error).length === 1);
    // This API intentionally has no rejected promise: the plain failure is observable via Error.
    return undefined;
  }
  if (flow === 'wait') {
    await h.start();
    h.reply(PATH.status, { status: 'approved', code: CODE });
    h.clearEvents();
    return rejected(h.sdk.waitForPasswordlessSignIn('challenge-a'));
  }
  if (flow === 'password') return rejected(h.sdk.signIn({ email: 'qa@example.com', password: 'secret-password' }));
  if (flow === 'email-code') {
    h.reply('/auth/login', {
      challenge_id: 'challenge-a',
      email_verification_required: true,
      message: 'Check your email.',
    });
    await h.sdk.signIn({ email: 'qa@example.com', password: 'secret-password' });
    h.clearEvents();
    return rejected(h.sdk.verifyEmailCode({ challenge_id: 'challenge-a', otp: OTP }));
  }
  h.reply('/auth/login', TFA);
  await h.sdk.signIn({ email: 'qa@example.com', password: 'secret-password' });
  expect(h.sdk.isTwoFactorVerificationRequired()).toBe(true);
  h.clearEvents();
  return rejected(flow === '2fa-verify' ? h.sdk.verifyTwoFactor(OTP) : h.sdk.useTwoFactorRecoveryCode('QA-RECOVERY-CODE'));
}

describe.each(flows)('exchange errors through $flow', ({ flow, operation }) => {
  test.each([fault('network'), fault('http', 429)])(
    'TEST-22 REQ-15 $kind/$status cannot expose verifier or authorization code',
    async (failure) => {
      const h = harness();
      h.reply(PATH.exchange, failure);
      const error = await exchangeFlow(h, flow);
      expect(h.wire(PATH.exchange)).toHaveLength(1);
      const sent = body(h.wire(PATH.exchange)[0]);
      expect(sent).toMatchObject({ authz_code: CODE, verifier: expect.any(String) });
      expect(String(sent.verifier).length).toBeGreaterThanOrEqual(43);
      const secrets = [...secretsFromWire(h), 'QA-RECOVERY-CODE'];
      if (flow !== 'landing' && flow !== 'popup') {
        expect(error).toBeInstanceOf(PassflowError);
        errorIsPlain(h, error, operation);
      } else {
        expect(h.of(PassflowEvent.Error)).toEqual([expect.objectContaining({ operation })]);
        plain(h.of(PassflowEvent.Error), secrets);
      }
      plain(h.of(PassflowEvent.Error), secrets);
      expect(serialiseAll(h.of(PassflowEvent.Error))).not.toContain('"config"');
      noSession(h);
      if (flow === 'otp' || flow === 'wait') expect(sessionStorage.getItem(PW_SLOT)).toBeNull();
      if (flow === 'popup' || flow === 'landing') expect(sessionStorage.getItem(FED_SLOT)).toBeNull();
      await vi.advanceTimersByTimeAsync(6000);
      expect(h.wire(PATH.exchange)).toHaveLength(1);
      expect(h.wire('/auth/refresh')).toEqual([]);
    },
  );
});

test('TEST-23 REQ-14 exchange keeps server error id, message and status without secret request data', async () => {
  const h = harness();
  await h.start('otp');
  h.reply(
    PATH.exchange,
    fault('http', 403, {
      error: {
        id: 'error.pkce.code.invalid',
        message: 'Start again.',
        status: 403,
        time: new Date().toISOString(),
        location: PATH.exchange,
      },
    }),
  );
  h.clearEvents();
  const error = await rejected(h.sdk.passwordlessSignInComplete({ challenge_id: 'challenge-a', otp: OTP }));
  errorIsPlain(h, error, 'passwordless.complete');
  expect(error).toMatchObject({ id: 'error.pkce.code.invalid', message: 'Start again.', status: 403 });
  expect(sessionStorage.getItem(PW_SLOT)).toBeNull();
  expect(h.sdk.getCachedTokens()?.access_token).not.toBe(VALID_TOKENS.access_token);
});
