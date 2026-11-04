import { describe, expect, test, vi } from 'vitest';
import { PassflowEvent } from '../../lib/index';
import { VALID_TOKENS } from '../helpers/fixtures';
import {
  body,
  CODE,
  deferred,
  fault,
  harness,
  MATCH,
  noSession,
  OTP,
  PATH,
  PW_SLOT,
  plain,
  proves,
  rejected,
  startPayload,
  TFA,
  until,
} from '../helpers/pkce-harness';

describe('PKCE passwordless start and OTP', () => {
  test('TEST-1 REQ-1 adds an S256 challenge without mutating frozen caller input', async () => {
    const h = harness();
    const payload = Object.freeze(startPayload());
    const before = JSON.stringify(payload);
    const answer = await h.sdk.passwordlessSignIn(payload);
    const request = h.wire(PATH.start)[0];
    expect(request.method).toBe('post');
    expect(body(request)).toMatchObject({ ...payload, code_challenge: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/) });
    expect(JSON.stringify(payload)).toBe(before);
    expect(payload).not.toHaveProperty('code_challenge');
    expect(answer).toMatchObject({ challenge_id: 'challenge-a', match_code: MATCH });
    expect(h.sdk.getPendingPasswordlessSignIn(answer.challenge_id)).toEqual({
      matchCode: MATCH,
      expiresAt: expect.any(Number),
    });
    noSession(h);
  });

  test('TEST-2 REQ-2 stores one tab proof in sessionStorage, never localStorage, and resumes after reload', async () => {
    const h = harness();
    const answer = await h.start();
    const record = JSON.parse(sessionStorage.getItem(PW_SLOT)!);
    expect(record).toMatchObject({
      challengeId: answer.challenge_id,
      verifier: expect.any(String),
      codeChallenge: body(h.wire(PATH.start)[0]).code_challenge,
      matchCode: MATCH,
      email: startPayload().email,
      scopes: startPayload().scopes,
      expiresAt: expect.any(Number),
    });
    expect(localStorage.getItem(PW_SLOT)).toBeNull();
    expect(h.writes.some(({ value }) => value.includes(record.verifier) || value.includes(record.codeChallenge))).toBe(false);
    h.sdk.dispose();
    const reloaded = h.client();
    expect(reloaded.sdk.getPendingPasswordlessSignIn(answer.challenge_id)).toEqual({
      matchCode: MATCH,
      expiresAt: record.expiresAt,
    });
    await reloaded.sdk.passwordlessSignInComplete({ challenge_id: answer.challenge_id, otp: OTP });
    await proves(h, record.codeChallenge);
    expect(reloaded.sdk.getCachedTokens()?.access_token).toBe(VALID_TOKENS.access_token);
    expect(sessionStorage.getItem(PW_SLOT)).toBeNull();
  });

  test('TEST-2 REQ-2 does not give the starting tab proof to a tab with separate sessionStorage', async () => {
    const h = harness();
    await h.start();
    sessionStorage.clear(); // A second tab shares token localStorage, not the pending tab record.
    const tabB = h.client();
    expect(tabB.sdk.getPendingPasswordlessSignIn('challenge-a')).toBeUndefined();
    const error = await rejected(tabB.sdk.waitForPasswordlessSignIn('challenge-a'));
    expect(error).toBeInstanceOf(Error);
    expect(h.wire(PATH.status)).toEqual([]);
    expect(h.wire(PATH.exchange)).toEqual([]);
    noSession(tabB);
  });

  test('TEST-3 REQ-3 a new start replaces pending metadata and another challenge cannot read it', async () => {
    const h = harness();
    await h.start();
    const first = JSON.parse(sessionStorage.getItem(PW_SLOT)!);
    h.reply(PATH.start, {
      challenge_id: 'challenge-b',
      match_code: '4815',
      expires_at: new Date(Date.now() + 120_000).toISOString(),
    });
    await h.start();
    expect(h.sdk.getPendingPasswordlessSignIn('challenge-a')).toBeUndefined();
    expect(h.sdk.getPendingPasswordlessSignIn('challenge-b')).toEqual({ matchCode: '4815', expiresAt: Date.now() + 120_000 });
    expect(JSON.parse(sessionStorage.getItem(PW_SLOT)!).verifier).not.toBe(first.verifier);
  });

  test.each([
    { challenge_id: '', match_code: MATCH },
    { challenge_id: 'older-server', match_code: undefined },
  ])('TEST-3 REQ-3 no wait metadata for unknown user or older server: $challenge_id', async (answer) => {
    const h = harness();
    h.reply(PATH.start, { ...answer, expires_at: new Date(Date.now() + 60_000).toISOString() });
    await h.start();
    expect(h.sdk.getPendingPasswordlessSignIn(answer.challenge_id)).toBeUndefined();
    if (!answer.challenge_id) expect(sessionStorage.getItem(PW_SLOT)).toBeNull();
  });

  test('TEST-4 REQ-4 REQ-23 complete exchanges proof, applies tokens before SignIn and preserves redirect', async () => {
    const h = harness();
    await h.start('otp');
    const challenge = body(h.wire(PATH.start)[0]).code_challenge;
    const redirect = 'https://app.example/finished';
    h.reply(PATH.complete, { code: CODE, redirect_url: redirect });
    h.clearEvents();
    const result = await h.sdk.passwordlessSignInComplete({ challenge_id: 'challenge-a', otp: OTP });
    await proves(h, challenge);
    expect(result).toMatchObject({ access_token: VALID_TOKENS.access_token, redirect_url: redirect });
    expect(result).not.toHaveProperty('code');
    expect(h.sdk.getCachedTokens()?.access_token).toBe(VALID_TOKENS.access_token);
    expect(h.of(PassflowEvent.SignIn)).toEqual([
      expect.objectContaining({
        tokens: expect.objectContaining({ access_token: VALID_TOKENS.access_token, redirect_url: redirect }),
      }),
    ]);
    const signIn = h.events.find(({ event }) => event === PassflowEvent.SignIn)!;
    expect(signIn.cached).toMatchObject({ access_token: VALID_TOKENS.access_token });
    expect(signIn.payload).not.toHaveProperty('source');
    expect(sessionStorage.getItem(PW_SLOT)).toBeNull();
    expect(h.sdk.getPendingPasswordlessSignIn('challenge-a')).toBeUndefined();
    expect(h.wire(PATH.complete)[0].method).toBe('post');
    expect(body(h.wire(PATH.complete)[0])).toMatchObject({ challenge_id: 'challenge-a', otp: OTP });
    for (const request of h.requests.filter((r) => !r.url?.endsWith(PATH.exchange))) {
      expect(JSON.stringify(body(request))).not.toContain(String(body(h.wire(PATH.exchange)[0]).verifier));
    }
  });

  test.each(['complete', 'exchange'] as const)(
    'TEST-5 REQ-5 hands off second factor from %s without signing in',
    async (at) => {
      const h = harness();
      await h.start('otp');
      h.reply(at === 'complete' ? PATH.complete : PATH.exchange, TFA);
      h.clearEvents();
      const result = await h.sdk.passwordlessSignInComplete({ challenge_id: 'challenge-a', otp: OTP });
      expect(result).toMatchObject({ tfa_token: TFA.tfa_token });
      expect(h.sdk.isTwoFactorVerificationRequired()).toBe(true);
      expect(h.of(PassflowEvent.TwoFactorRequired)).toEqual([
        expect.objectContaining({ tfaToken: TFA.tfa_token, challengeId: TFA.challenge_id }),
      ]);
      expect(h.wire(PATH.exchange)).toHaveLength(at === 'complete' ? 0 : 1);
      expect(sessionStorage.getItem(PW_SLOT)).toBeNull();
      noSession(h);
    },
  );

  test.each([false, true])('TEST-6 REQ-6 rejects a code without matching proof (other record: %s)', async (other) => {
    const h = harness();
    if (other) await h.start();
    const error = await rejected(h.sdk.passwordlessSignInComplete({ challenge_id: 'not-this-tab', otp: OTP }));
    expect(error).toBeInstanceOf(Error);
    expect(String(error)).toMatch(/verifier is gone/i);
    expect(h.wire(PATH.complete)).toHaveLength(1); // Parent rows cannot be rejected before the server answers.
    expect(h.wire(PATH.exchange)).toEqual([]);
    expect(h.of(PassflowEvent.Error)).toEqual([expect.objectContaining({ operation: 'passwordless.complete' })]);
    noSession(h);
  });

  test.each([{ ...VALID_TOKENS }, { redirect_url: 'https://rp.example/cb?code=parent-result' }])(
    'TEST-7 REQ-6 allows direct parent completion on PKCE app with no record',
    async (answer) => {
      const h = harness();
      h.reply(PATH.complete, answer);
      const response = await h.sdk.passwordlessSignInComplete({ challenge_id: 'parent-row', otp: OTP });
      expect(response).toMatchObject(answer);
      expect(h.wire(PATH.exchange)).toEqual([]);
      expect(h.of(PassflowEvent.Error)).toEqual([]);
    },
  );

  test.each([fault('network'), fault('http', 400), fault('http', 403), fault('http', 429)])(
    'TEST-8 REQ-7 retains proof after complete refusal $kind/$status',
    async (failure) => {
      const h = harness();
      await h.start('otp');
      const before = sessionStorage.getItem(PW_SLOT);
      h.reply(PATH.complete, failure);
      await rejected(h.sdk.passwordlessSignInComplete({ challenge_id: 'challenge-a', otp: OTP }));
      expect(sessionStorage.getItem(PW_SLOT)).toBe(before);
      expect(h.sdk.getPendingPasswordlessSignIn('challenge-a')?.matchCode).toBe(MATCH);
      expect(h.wire(PATH.exchange)).toEqual([]);
      noSession(h);
    },
  );

  test('TEST-9 REQ-7 deletes proof if exchange fails after successful complete', async () => {
    const h = harness();
    await h.start('otp');
    h.reply(PATH.exchange, fault('network'));
    await rejected(h.sdk.passwordlessSignInComplete({ challenge_id: 'challenge-a', otp: OTP }));
    expect(sessionStorage.getItem(PW_SLOT)).toBeNull();
    expect(h.wire(PATH.exchange)).toHaveLength(1);
    noSession(h);
  });

  test('TEST-6 REQ-6 another challenge cannot hand its verifier to second-factor completion', async () => {
    const h = harness();
    await h.start();
    h.reply(PATH.complete, TFA);
    await h.sdk.passwordlessSignInComplete({ challenge_id: 'different-parent-row', otp: OTP });
    expect(h.sdk.isTwoFactorVerificationRequired()).toBe(true);
    // The factor returns a code, but this challenge never owned a verifier.
    await rejected(h.sdk.verifyTwoFactor(OTP));
    expect(h.wire(PATH.exchange)).toEqual([]);
    noSession(h);
  });

  test('TEST-19 REQ-2 logOut removes proof in this tab', async () => {
    const h = harness();
    await h.start();
    await h.sdk.logOut();
    expect(h.sdk.getPendingPasswordlessSignIn('challenge-a')).toBeUndefined();
    expect(sessionStorage.getItem(PW_SLOT)).toBeNull();
    await rejected(h.sdk.waitForPasswordlessSignIn('challenge-a'));
    expect(h.wire(PATH.status)).toEqual([]);
  });

  test('TEST-42 REQ-2 uses memory when sessionStorage is unavailable', async () => {
    const h = harness();
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new Error('Storage unavailable');
    });
    await h.start('otp');
    const challenge = body(h.wire(PATH.start)[0]).code_challenge;
    expect(h.sdk.getPendingPasswordlessSignIn('challenge-a')?.matchCode).toBe(MATCH);
    await h.sdk.passwordlessSignInComplete({ challenge_id: 'challenge-a', otp: OTP });
    await proves(h, challenge);
    expect(h.sdk.getCachedTokens()?.access_token).toBe(VALID_TOKENS.access_token);
  });
});

describe('passwordless wait loop', () => {
  test('TEST-10 REQ-8 pending waits 3 seconds then approved exchanges into SignIn', async () => {
    const h = harness();
    await h.start();
    const secret = body(h.wire(PATH.start)[0]).code_challenge;
    h.queue(PATH.status, { status: 'pending' }, { status: 'approved', code: CODE });
    h.clearEvents();
    const result = h.sdk.waitForPasswordlessSignIn('challenge-a');
    await until(() => h.wire(PATH.status).length === 1);
    await vi.advanceTimersByTimeAsync(2999);
    expect(h.wire(PATH.status)).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(1);
    expect(await result).toMatchObject({ status: 'signed-in', tokens: { access_token: VALID_TOKENS.access_token } });
    const polls = h.wire(PATH.status);
    expect(polls).toHaveLength(2);
    expect(polls[1].at - polls[0].at).toBe(3000);
    for (const poll of polls) {
      expect(poll.method).toBe('post');
      expect(body(poll)).toEqual({ challenge_id: 'challenge-a', code_challenge: secret });
      expect(poll.timeout).toBe(15_000);
      expect(poll.withCredentials).toBe(true);
      expect(poll.headers.Authorization).toBeUndefined();
    }
    await proves(h, secret);
    expect(h.of(PassflowEvent.SignIn)).toHaveLength(1);
    expect(h.of(PassflowEvent.SignIn)[0]).not.toHaveProperty('source');
    expect(h.events.find(({ event }) => event === PassflowEvent.SignIn)?.cached).toMatchObject({
      access_token: VALID_TOKENS.access_token,
    });
    expect(sessionStorage.getItem(PW_SLOT)).toBeNull();
    expect(h.wire('/auth/refresh')).toEqual([]);
  });

  test.each([fault('network'), fault('http', 429), fault('http', 503), fault('unreadable', 502)])(
    'TEST-11 REQ-9 keeps polling every 3 seconds after $kind/$status',
    async (failure) => {
      const h = harness();
      await h.start();
      h.queue(PATH.status, failure, { status: 'approved', code: CODE });
      h.clearEvents();
      const waiting = h.sdk.waitForPasswordlessSignIn('challenge-a');
      await until(() => h.wire(PATH.status).length === 1);
      await vi.advanceTimersByTimeAsync(2999);
      expect(h.wire(PATH.status)).toHaveLength(1);
      await vi.advanceTimersByTimeAsync(1);
      expect(await waiting).toMatchObject({ status: 'signed-in' });
      expect(h.of(PassflowEvent.Error)).toEqual([]);
    },
  );

  test.each([400, 403, 404])('TEST-12 REQ-10 a status %s deletes proof and rejects once', async (status) => {
    const h = harness();
    await h.start();
    const record = JSON.parse(sessionStorage.getItem(PW_SLOT)!);
    h.reply(
      PATH.status,
      fault('http', status, {
        error: { id: 'error.auth.passwordless.unavailable', message: 'Start again.', status, time: new Date().toISOString() },
      }),
    );
    const error = await rejected(h.sdk.waitForPasswordlessSignIn('challenge-a'));
    plain(error, [record.verifier, record.codeChallenge, OTP, MATCH, CODE]);
    expect(h.of(PassflowEvent.Error)).toEqual([expect.objectContaining({ operation: 'passwordless.wait' })]);
    plain(h.of(PassflowEvent.Error), [record.verifier, record.codeChallenge, OTP, MATCH, CODE]);
    expect(sessionStorage.getItem(PW_SLOT)).toBeNull();
    await vi.advanceTimersByTimeAsync(6000);
    expect(h.wire(PATH.status)).toHaveLength(1);
    noSession(h);
  });

  test.each(['denied', 'expired', 'completed'])('TEST-13 REQ-11 resolves %s without claiming a session', async (status) => {
    const h = harness();
    await h.start();
    h.reply(PATH.status, { status });
    expect(await h.sdk.waitForPasswordlessSignIn('challenge-a')).toEqual({ status });
    expect(sessionStorage.getItem(PW_SLOT)).toBeNull();
    expect(h.of(PassflowEvent.Error)).toEqual([]);
    expect(h.wire(PATH.exchange)).toEqual([]);
    noSession(h);
  });

  test('TEST-14 REQ-11 checks local expiry before another status claim', async () => {
    const h = harness();
    h.reply(PATH.start, {
      challenge_id: 'challenge-a',
      match_code: MATCH,
      expires_at: new Date(Date.now() + 3000).toISOString(),
    });
    await h.start();
    const waiting = h.sdk.waitForPasswordlessSignIn('challenge-a');
    await until(() => h.wire(PATH.status).length === 1);
    await vi.advanceTimersByTimeAsync(3000);
    expect(await waiting).toEqual({ status: 'expired' });
    expect(h.wire(PATH.status)).toHaveLength(1);
    expect(h.wire(PATH.exchange)).toEqual([]);
    expect(sessionStorage.getItem(PW_SLOT)).toBeNull();
  });

  test('TEST-14 REQ-11 reading an already-expired record deletes it', async () => {
    const h = harness();
    await h.start();
    await vi.advanceTimersByTimeAsync(60_000);
    expect(h.sdk.getPendingPasswordlessSignIn('challenge-a')).toBeUndefined();
    expect(sessionStorage.getItem(PW_SLOT)).toBeNull();
  });

  test.each(['sleep', 'poll'] as const)(
    'TEST-15 REQ-12 abort during %s keeps proof and rejects exact reason',
    async (phase) => {
      const h = harness();
      await h.start();
      if (phase === 'poll') {
        h.reply(
          PATH.status,
          (request: import('../helpers/pkce-harness').Request) =>
            new Promise((_resolve, reject) => {
              request.signal?.addEventListener?.('abort', () => reject(new Error('Transport aborted')), { once: true });
            }),
        );
      }
      const controller = new AbortController();
      const before = sessionStorage.getItem(PW_SLOT);
      const reason = new Error('Host cancelled wait');
      h.clearEvents();
      const outcome = rejected(h.sdk.waitForPasswordlessSignIn('challenge-a', { signal: controller.signal }));
      await until(() => h.wire(PATH.status).length === 1);
      await vi.advanceTimersByTimeAsync(0);
      controller.abort(reason);
      expect(await outcome).toBe(reason);
      expect(sessionStorage.getItem(PW_SLOT)).toBe(before);
      expect(h.of(PassflowEvent.Error)).toEqual([]);
      expect(h.wire(PATH.exchange)).toEqual([]);
    },
  );

  test('TEST-16 REQ-12 abort after approval does not interrupt exchange', async () => {
    const h = harness();
    await h.start();
    const exchange = deferred<unknown>();
    h.reply(PATH.status, { status: 'approved', code: CODE });
    h.reply(PATH.exchange, () => exchange.promise);
    const controller = new AbortController();
    const waiting = h.sdk.waitForPasswordlessSignIn('challenge-a', { signal: controller.signal });
    await until(() => h.wire(PATH.exchange).length === 1);
    controller.abort(new Error('Too late'));
    exchange.resolve({ ...VALID_TOKENS });
    expect(await waiting).toMatchObject({ status: 'signed-in', tokens: { access_token: VALID_TOKENS.access_token } });
    expect(h.of(PassflowEvent.SignIn)).toHaveLength(1);
    expect(h.of(PassflowEvent.Error)).toEqual([]);
  });

  test('TEST-17 REQ-5 approved exchange can require the second factor in tab A', async () => {
    const h = harness();
    await h.start();
    h.reply(PATH.status, { status: 'approved', code: CODE });
    h.reply(PATH.exchange, TFA);
    expect(await h.sdk.waitForPasswordlessSignIn('challenge-a')).toEqual({ status: 'second-factor-required' });
    expect(h.sdk.isTwoFactorVerificationRequired()).toBe(true);
    expect(h.of(PassflowEvent.TwoFactorRequired)).toHaveLength(1);
    expect(sessionStorage.getItem(PW_SLOT)).toBeNull();
    noSession(h);
  });

  test.each(['new start', 'logOut'] as const)(
    'TEST-3 TEST-19 REQ-2 REQ-3 running wait rejects when %s removes its record',
    async (change) => {
      const h = harness();
      await h.start();
      h.clearEvents();
      const outcome = rejected(h.sdk.waitForPasswordlessSignIn('challenge-a'));
      await until(() => h.wire(PATH.status).length === 1);
      await vi.advanceTimersByTimeAsync(0);
      if (change === 'new start') {
        h.reply(PATH.start, {
          challenge_id: 'challenge-b',
          match_code: '4815',
          expires_at: new Date(Date.now() + 60_000).toISOString(),
        });
        await h.start();
      } else await h.sdk.logOut();
      await vi.advanceTimersByTimeAsync(3000);
      const error = await outcome;
      expect(String(error)).toMatch(/verifier is gone/i);
      expect(h.of(PassflowEvent.Error)).toEqual([expect.objectContaining({ operation: 'passwordless.wait' })]);
      expect(h.wire(PATH.status)).toHaveLength(1);
      expect(h.wire(PATH.exchange)).toEqual([]);
      expect(h.sdk.getPendingPasswordlessSignIn('challenge-a')).toBeUndefined();
      if (change === 'new start') {
        expect(h.sdk.getPendingPasswordlessSignIn('challenge-b')?.matchCode).toBe('4815');
      }
    },
  );

  test.each(['absent', 'other'])('TEST-18 REQ-10 missing/mismatched proof (%s) rejects without polling', async (record) => {
    const h = harness();
    if (record === 'other') await h.start();
    const error = await rejected(h.sdk.waitForPasswordlessSignIn('not-this-tab'));
    expect(String(error)).toMatch(/verifier is gone/i);
    expect(h.wire(PATH.status)).toEqual([]);
    expect(h.of(PassflowEvent.Error)).toEqual([expect.objectContaining({ operation: 'passwordless.wait' })]);
  });
});

describe('device B approval and non-PKCE compatibility', () => {
  test('TEST-20 REQ-13 info sends only challenge id and returns context without signing in', async () => {
    const h = harness();
    const info = await h.sdk.getPasswordlessApproval('link-challenge');
    expect(info).toMatchObject({
      state: 'pending',
      app_name: 'QA app',
      browser: 'Firefox',
      os: 'Linux',
      location: { city: 'Sydney', country: 'AU' },
      attempts_left: 5,
    });
    expect(info).not.toHaveProperty('match_code');
    expect(info).not.toHaveProperty('email');
    const request = h.wire(PATH.info)[0];
    expect(request.method).toBe('post');
    expect(body(request)).toEqual({ challenge_id: 'link-challenge' });
    expect(request.headers.Authorization).toBeUndefined();
    expect(h.wire(PATH.decide)).toEqual([]);
    expect(h.wire(PATH.complete)).toEqual([]);
    expect(h.wire(PATH.exchange)).toEqual([]);
    noSession(h);
  });

  test.each([true, false])(
    'TEST-20 REQ-13 deciding approve=%s resolves void and leaves device B signed out',
    async (approve) => {
      const h = harness();
      h.reply(PATH.decide, { state: approve ? 'approved' : 'denied' });
      const result = await h.sdk.decidePasswordlessApproval('link-challenge', OTP, approve, approve ? MATCH : undefined);
      expect(result).toBeUndefined();
      const request = h.wire(PATH.decide)[0];
      expect(request.method).toBe('post');
      expect(body(request)).toEqual({
        challenge_id: 'link-challenge',
        otp: OTP,
        approve,
        ...(approve ? { match_code: MATCH } : {}),
      });
      expect(request.headers.Authorization).toBeUndefined();
      expect(h.wire(PATH.exchange)).toEqual([]);
      expect(sessionStorage.getItem(PW_SLOT)).toBeNull();
      noSession(h);
    },
  );

  test('TEST-39 REQ-25 non-PKCE start/complete keeps legacy wire and direct tokens', async () => {
    const h = harness({ pkce: false });
    h.reply(PATH.start, { challenge_id: 'legacy', expires_at: new Date(Date.now() + 60_000).toISOString() });
    const payload = startPayload('otp');
    await h.sdk.passwordlessSignIn(payload);
    expect(body(h.wire(PATH.start)[0])).toMatchObject(payload);
    expect(body(h.wire(PATH.start)[0])).not.toHaveProperty('code_challenge');
    expect(sessionStorage.getItem(PW_SLOT)).toBeNull();
    expect(h.sdk.getPendingPasswordlessSignIn('legacy')).toBeUndefined();
    h.reply(PATH.complete, { ...VALID_TOKENS });
    const answer = await h.sdk.passwordlessSignInComplete({ challenge_id: 'legacy', otp: OTP });
    expect(answer.access_token).toBe(VALID_TOKENS.access_token);
    expect(h.sdk.getCachedTokens()?.access_token).toBe(VALID_TOKENS.access_token);
    expect(h.wire(PATH.exchange)).toEqual([]);
    expect(h.of(PassflowEvent.SignIn)[0]).not.toHaveProperty('source');
  });

  test('TEST-41 REQ-26 pending approval and success never trigger an unsolicited refresh', async () => {
    const h = harness();
    await h.start();
    h.reply(PATH.status, { status: 'approved', code: CODE });
    await h.sdk.waitForPasswordlessSignIn('challenge-a');
    await vi.advanceTimersByTimeAsync(6000);
    expect(h.wire('/auth/refresh')).toEqual([]);
  });
});
