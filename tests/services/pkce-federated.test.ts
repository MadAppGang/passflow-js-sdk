import { describe, expect, test, vi } from 'vitest';
import { PassflowEvent } from '../../lib/index';
import { AuthService } from '../../lib/services/auth-service';
import { VALID_TOKENS } from '../helpers/fixtures';
import {
  createMockAuthApi,
  createMockDeviceService,
  createMockPassflowStore,
  createMockStorageManager,
  createMockTokenCacheService,
} from '../helpers/mocks';
import {
  CODE,
  deferred,
  FED_SLOT,
  fedPayload,
  harness,
  noSession,
  PATH,
  proves,
  s256,
  TFA,
  until,
} from '../helpers/pkce-harness';
import { DISCOVERY_PATH, discoveryBody, generateSigningKey, issuedTokens, JWKS_PATH, jwksBody } from '../helpers/signed-tokens';

/** Publishes a signing key on the harness and returns a token set issued with it. */
async function serveSigned(h: ReturnType<typeof harness>) {
  const key = await generateSigningKey();
  h.reply(DISCOVERY_PATH, discoveryBody());
  h.reply(JWKS_PATH, jwksBody(key));
  return issuedTokens(key);
}

const landing = (extra = '') =>
  'https://app.example/callback?code=' +
  CODE +
  '&user_state=provider-state&appid=test-app-id' +
  '&redirectto=https%3A%2F%2Frp.example%2F&keep=retained' +
  extra +
  '#tab=security';

async function startRedirect(h: ReturnType<typeof harness>) {
  const count = h.navigations.length;
  expect(h.sdk.federatedAuthWithRedirect(fedPayload())).toBeUndefined();
  await until(() => h.navigations.length === count + 1);
  return new URL(h.navigations.at(-1)!);
}

describe('federated URLs, redirect and popup', () => {
  test('TEST-24 REQ-16 synchronous URL builder appends caller challenge and preserves redirect', () => {
    const h = harness();
    const payload = Object.freeze({
      ...fedPayload(),
      code_challenge: 'explicit-s256-challenge',
      code_challenge_method: 'S256' as const,
    });
    // The contract names this public AuthService method, not a facade method.
    const dependencies = [
      createMockAuthApi(),
      createMockDeviceService(),
      createMockStorageManager(),
      createMockPassflowStore(),
      createMockTokenCacheService(),
      ['id', 'openid'],
      false,
      'https://api.example',
      {},
      'test-app-id',
      undefined,
      h.platform,
    ] as unknown as ConstructorParameters<typeof AuthService>;
    const service = new AuthService(...dependencies);
    const result = service.createFederatedAuthUrl(payload);
    expect(typeof result).toBe('string');
    const url = new URL(result);
    expect(url.pathname).toBe('/auth/federated/start/google');
    expect(url.searchParams.get('code_challenge')).toBe(payload.code_challenge);
    expect(url.searchParams.get('code_challenge_method')).toBe('S256');
    expect(url.searchParams.get('redirect_url')).toBe(payload.redirect_url);
    expect(sessionStorage.getItem(FED_SLOT)).toBeNull();
  });

  test('TEST-25 REQ-17 REQ-19 redirect returns void now and later navigates with a 10-minute session proof', async () => {
    const h = harness();
    const before = Date.now();
    const result = h.sdk.federatedAuthWithRedirect(fedPayload());
    expect(result).toBeUndefined();
    expect(h.navigations).toEqual([]);
    await until(() => h.navigations.length === 1);
    const url = new URL(h.navigations[0]);
    const slot = JSON.parse(sessionStorage.getItem(FED_SLOT)!);
    expect(slot).toMatchObject({ verifier: expect.any(String), scopes: expect.any(Array), expiresAt: before + 600_000 });
    expect(url.searchParams.get('code_challenge')).toBe(s256(slot.verifier));
    expect(url.searchParams.get('code_challenge_method')).toBe('S256');
    expect(url.searchParams.get('redirect_url')).toBe(fedPayload().redirect_url);
    expect(url.href).not.toContain(slot.verifier);
    expect(localStorage.getItem(FED_SLOT)).toBeNull();
    expect(h.writes.some(({ value }) => value.includes(slot.verifier))).toBe(false);
  });

  test('TEST-26 REQ-17 a missing appId still throws synchronously without navigation', () => {
    const h = harness({ config: { appId: undefined } });
    expect(() => h.sdk.federatedAuthWithRedirect(fedPayload())).toThrow();
    expect(h.navigations).toEqual([]);
  });

  test('TEST-26 REQ-17 asynchronous proof failure reports federated.redirect without navigation', async () => {
    const h = harness();
    vi.spyOn(crypto.subtle, 'digest').mockRejectedValueOnce(new Error('S256 unavailable'));
    expect(h.sdk.federatedAuthWithRedirect(fedPayload())).toBeUndefined();
    await until(() => h.of(PassflowEvent.Error).length > 0);
    expect(h.of(PassflowEvent.Error)).toEqual([expect.objectContaining({ operation: 'federated.redirect' })]);
    expect(h.navigations).toEqual([]);
    noSession(h);
  });

  test('TEST-27 REQ-18 REQ-23 popup redeems code in opener and emits ordinary SignIn without source', async () => {
    const h = harness();
    // The public call starts the flow; SignIn, not its return value, signals completion.
    h.sdk.federatedAuthWithPopup(fedPayload());
    await until(() => h.of(PassflowEvent.SignIn).length === 1);
    expect(h.opened).toHaveLength(1);
    const url = new URL(h.opened[0]);
    expect(url.searchParams.get('code_challenge_method')).toBe('S256');
    await proves(h, url.searchParams.get('code_challenge'));
    expect(h.sdk.getCachedTokens()?.access_token).toBe(VALID_TOKENS.access_token);
    expect(h.of(PassflowEvent.SignIn)).toHaveLength(1);
    expect(h.of(PassflowEvent.SignIn)[0]).not.toHaveProperty('source');
    expect(sessionStorage.getItem(FED_SLOT)).toBeNull();
    expect(h.of(PassflowEvent.Error)).toEqual([]);
  });

  test('TEST-28 REQ-18 slot is absent when popup opens and present before its callback resolves', async () => {
    const h = harness();
    await startRedirect(h); // Even an older slot must not be copied into a newly opened popup.
    const callback = deferred<{ callbackSearch: string; callbackHash: string }>();
    let slotAtOpen: string | null | undefined;
    let slotAtNextMicrotask: string | null | undefined;
    h.popup(() => {
      slotAtOpen = sessionStorage.getItem(FED_SLOT);
      queueMicrotask(() => {
        slotAtNextMicrotask = sessionStorage.getItem(FED_SLOT);
      });
      return callback.promise;
    });
    const result = h.sdk.federatedAuthWithPopup(fedPayload());
    await until(() => h.opened.length === 1);
    expect(slotAtOpen).toBeNull();
    expect(slotAtNextMicrotask).toBeTypeOf('string');
    const slot = JSON.parse(sessionStorage.getItem(FED_SLOT)!);
    expect(s256(slot.verifier)).toBe(new URL(h.opened[0]).searchParams.get('code_challenge'));
    callback.resolve({ callbackSearch: '?code=' + CODE + '&user_state=qa', callbackHash: '' });
    await result;
    expect(sessionStorage.getItem(FED_SLOT)).toBeNull();
  });

  test('TEST-28 REQ-18 blocked popup fallback can finish on a reloaded redirect landing', async () => {
    const h = harness();
    h.popup(async (url) => {
      h.navigations.push(url); // Adapter falls back to navigation when popup is blocked.
      return new Promise<never>(() => {}); // Browser unloads; no popup result is delivered.
    });
    h.sdk.federatedAuthWithPopup(fedPayload());
    await until(() => h.navigations.length === 1);
    expect(sessionStorage.getItem(FED_SLOT)).not.toBeNull();
    const challenge = new URL(h.navigations[0]).searchParams.get('code_challenge');
    h.sdk.dispose();
    h.land(landing());
    const returned = h.client({ parseQueryParams: true });
    await until(() => returned.of(PassflowEvent.SignIn).length === 1);
    await proves(h, challenge);
    expect(returned.of(PassflowEvent.SignIn)[0]).toMatchObject({ source: 'federated-landing' });
  });

  test.each(['popup', 'landing'] as const)('TEST-29 REQ-5 %s exchange can owe a second factor', async (path) => {
    const h = harness();
    h.reply(PATH.exchange, TFA);
    if (path === 'popup') {
      h.sdk.federatedAuthWithPopup(fedPayload());
      await until(() => h.of(PassflowEvent.TwoFactorRequired).length === 1);
    } else {
      await startRedirect(h);
      h.land(landing());
      expect(h.sdk.handleTokensRedirect()).toBeUndefined();
      await until(() => h.of(PassflowEvent.TwoFactorRequired).length === 1);
    }
    expect(h.sdk.isTwoFactorVerificationRequired()).toBe(true);
    expect(h.of(PassflowEvent.TwoFactorRequired)).toEqual([expect.objectContaining({ tfaToken: TFA.tfa_token })]);
    expect(sessionStorage.getItem(FED_SLOT)).toBeNull();
    noSession(h);
  });
});

describe('federated redirect landing', () => {
  test('TEST-30 REQ-20 REQ-23 default constructor takes slot and later emits sourced SignIn to new subscriber', async () => {
    const h = harness();
    const sent = await startRedirect(h);
    h.sdk.dispose();
    h.land(landing());
    const returned = h.client({ parseQueryParams: true });
    expect(sessionStorage.getItem(FED_SLOT)).toBeNull();
    expect(h.url().searchParams.has('code')).toBe(false);
    expect(h.url().searchParams.has('user_state')).toBe(false);
    expect(h.url().searchParams.get('appid')).toBe('test-app-id');
    expect(h.url().searchParams.get('redirectto')).toBe('https://rp.example/');
    expect(h.url().searchParams.get('keep')).toBe('retained');
    expect(h.url().hash).toBe('#tab=security');
    await until(() => returned.of(PassflowEvent.SignIn).length === 1);
    await proves(h, sent.searchParams.get('code_challenge'));
    expect(returned.of(PassflowEvent.SignIn)[0]).toMatchObject({
      source: 'federated-landing',
      tokens: { access_token: VALID_TOKENS.access_token },
    });
    expect(returned.events.find(({ event }) => event === PassflowEvent.SignIn)?.cached).toMatchObject({
      access_token: VALID_TOKENS.access_token,
    });
    expect(h.wire('/auth/refresh')).toEqual([]);
  });

  test('TEST-31 REQ-21 explicit handleTokensRedirect stays synchronous and takes slot only once', async () => {
    const h = harness();
    await startRedirect(h);
    h.land(landing());
    expect(h.sdk.handleTokensRedirect()).toBeUndefined();
    expect(h.sdk.handleTokensRedirect()).toBeUndefined();
    expect(h.sdk.completeFederatedLanding()).toBe(false);
    await until(() => h.of(PassflowEvent.SignIn).length === 1);
    expect(h.wire(PATH.exchange)).toHaveLength(1);
    expect(sessionStorage.getItem(FED_SLOT)).toBeNull();
  });

  test('TEST-32 REQ-21 defer leaves URL and slot until completeFederatedLanding returns true once', async () => {
    const h = harness();
    await startRedirect(h);
    const slot = sessionStorage.getItem(FED_SLOT);
    h.land(landing());
    const url = h.url().href;
    const deferredClient = h.client({ parseQueryParams: true, deferFederatedLanding: true });
    expect(deferredClient.sdk.handleTokensRedirect()).toBeUndefined();
    await vi.advanceTimersByTimeAsync(0);
    expect(sessionStorage.getItem(FED_SLOT)).toBe(slot);
    expect(h.url().href).toBe(url);
    expect(h.wire(PATH.exchange)).toEqual([]);
    expect(deferredClient.sdk.completeFederatedLanding()).toBe(true);
    expect(deferredClient.sdk.completeFederatedLanding()).toBe(false);
    expect(sessionStorage.getItem(FED_SLOT)).toBeNull();
    await until(() => deferredClient.of(PassflowEvent.SignIn).length === 1);
    expect(deferredClient.of(PassflowEvent.SignIn)[0]).toMatchObject({ source: 'federated-landing' });
    expect(h.wire(PATH.exchange)).toHaveLength(1);
  });

  test('TEST-33 REQ-22 no-appId instance leaves slot/URL for instance built after discovery', async () => {
    const h = harness();
    await startRedirect(h);
    h.land(landing());
    const slot = sessionStorage.getItem(FED_SLOT);
    const url = h.url().href;
    const undiscovered = h.client({ appId: undefined, parseQueryParams: true });
    expect(undiscovered.sdk.completeFederatedLanding()).toBe(false);
    expect(undiscovered.sdk.handleTokensRedirect()).toBeUndefined();
    await vi.advanceTimersByTimeAsync(0);
    expect(sessionStorage.getItem(FED_SLOT)).toBe(slot);
    expect(h.url().href).toBe(url);
    expect(h.wire(PATH.exchange)).toEqual([]);
    const discovered = h.client({ appId: 'test-app-id', parseQueryParams: true });
    await until(() => discovered.of(PassflowEvent.SignIn).length === 1);
    expect(h.wire(PATH.exchange)).toHaveLength(1);
    expect(discovered.of(PassflowEvent.SignIn)[0]).toMatchObject({ source: 'federated-landing' });
  });

  test.each(['missing', 'expired', 'another-tab'] as const)(
    'TEST-34 REQ-22 REQ-23 crafted callback with %s slot cannot exchange or mark later password SignIn',
    async (mode) => {
      const h = harness();
      if (mode !== 'missing') {
        await startRedirect(h);
        h.sdk.dispose();
        if (mode === 'expired') await vi.advanceTimersByTimeAsync(600_000);
        else sessionStorage.clear();
      }
      h.land(landing());
      const url = h.url().href;
      const returned = h.client({ parseQueryParams: true });
      expect(returned.sdk.completeFederatedLanding()).toBe(false);
      expect(returned.sdk.handleTokensRedirect()).toBeUndefined();
      await vi.advanceTimersByTimeAsync(0);
      expect(h.url().href).toBe(url);
      expect(h.wire(PATH.exchange)).toEqual([]);
      expect(returned.of(PassflowEvent.SignIn)).toEqual([]);
      h.reply('/auth/login', { ...VALID_TOKENS });
      await returned.sdk.signIn({ email: 'qa@example.com', password: 'correct-password' });
      expect(returned.of(PassflowEvent.SignIn)).toHaveLength(1);
      expect(returned.of(PassflowEvent.SignIn)[0]).not.toHaveProperty('source');
    },
  );

  test.each(['?code=' + CODE, '?user_state=provider-state'])(
    'TEST-35 REQ-20 partial landing %s leaves URL and slot unchanged',
    async (search) => {
      const h = harness();
      await startRedirect(h);
      h.land('https://app.example/callback' + search);
      const slot = sessionStorage.getItem(FED_SLOT);
      const url = h.url().href;
      expect(h.sdk.completeFederatedLanding()).toBe(false);
      expect(sessionStorage.getItem(FED_SLOT)).toBe(slot);
      expect(h.url().href).toBe(url);
      expect(h.wire(PATH.exchange)).toEqual([]);
    },
  );

  test('TEST-36 REQ-19 slot can land just before ten-minute expiry, not at expiry', async () => {
    const h = harness();
    await startRedirect(h);
    const before = sessionStorage.getItem(FED_SLOT);
    h.sdk.dispose();
    await vi.advanceTimersByTimeAsync(599_999);
    h.land(landing());
    const justBefore = h.client();
    expect(justBefore.sdk.completeFederatedLanding()).toBe(true);
    await until(() => justBefore.of(PassflowEvent.SignIn).length === 1);
    justBefore.sdk.dispose();
    sessionStorage.setItem(FED_SLOT, before!); // Re-use public persisted record only to exercise the exact time boundary.
    await vi.advanceTimersByTimeAsync(1);
    h.land(landing());
    const expired = h.client();
    const url = h.url().href;
    expect(expired.sdk.completeFederatedLanding()).toBe(false);
    expect(h.url().href).toBe(url);
    expect(h.wire(PATH.exchange)).toHaveLength(1);
  });

  test('TEST-37 REQ-19 newer federated start replaces the proof', async () => {
    const h = harness();
    const first = await startRedirect(h);
    const second = await startRedirect(h);
    expect(second.searchParams.get('code_challenge')).not.toBe(first.searchParams.get('code_challenge'));
    h.land(landing());
    expect(h.sdk.completeFederatedLanding()).toBe(true);
    await until(() => h.of(PassflowEvent.SignIn).length === 1);
    await proves(h, second.searchParams.get('code_challenge'));
  });

  test.each([false, true])('TEST-38 REQ-24 defer=%s leaves token landing behavior and user_state intact', async (defer) => {
    // Core accepts URL tokens only for apps in Simple mode.
    const h = harness({ pkce: false, config: { deferFederatedLanding: defer } });
    const issued = await serveSigned(h);
    await startRedirect(h);
    const search = new URLSearchParams({
      access_token: issued.access_token,
      id_token: issued.id_token,
      user_state: 'legacy-state',
      code: CODE,
      appid: 'test-app-id',
    });
    h.land('https://app.example/callback?' + search);
    h.sdk.handleTokensRedirect();
    await until(() => h.of(PassflowEvent.SignIn).length === 1);
    expect(h.sdk.getCachedTokens()?.access_token).toBe(issued.access_token);
    expect(h.url().searchParams.get('user_state')).toBe('legacy-state');
    expect(h.wire(PATH.exchange)).toEqual([]);
    for (const event of h.of(PassflowEvent.SignIn)) expect(event).toHaveProperty('source', 'tokens-in-url');
  });

  test.each([false, true])('TEST-38 REQ-24 defer=%s still handles #tfa_token without a federated proof', (defer) => {
    const h = harness({ config: { deferFederatedLanding: defer } });
    const encode = (v: unknown) => Buffer.from(JSON.stringify(v)).toString('base64url');
    const token = encode({ alg: 'none' }) + '.' + encode({ type: '2fa' }) + '.sig';
    h.land('https://app.example/callback?user_state=keep#tfa_token=' + token + '&tab=security');
    expect(h.sdk.handleTokensRedirect()).toBeUndefined();
    expect(h.sdk.isTwoFactorVerificationRequired()).toBe(true);
    expect(h.of(PassflowEvent.TwoFactorRequired)).toHaveLength(1);
    expect(h.url().hash).toBe('#tab=security');
    expect(h.url().searchParams.get('user_state')).toBe('keep');
    noSession(h);
  });

  test('TEST-39 REQ-25 non-PKCE federated redirect/popup sends no proof and uses direct callback tokens', async () => {
    const h = harness({ pkce: false });
    const issued = await serveSigned(h);
    const redirect = await startRedirect(h);
    expect(redirect.searchParams.has('code_challenge')).toBe(false);
    expect(redirect.searchParams.has('code_challenge_method')).toBe(false);
    expect(sessionStorage.getItem(FED_SLOT)).toBeNull();
    h.popup(async () => ({
      callbackSearch: '?access_token=' + issued.access_token + '&id_token=' + issued.id_token,
      callbackHash: '',
    }));
    h.sdk.federatedAuthWithPopup(fedPayload());
    await until(() => h.of(PassflowEvent.SignIn).length === 1);
    expect(h.opened).toHaveLength(1);
    expect(new URL(h.opened[0]).searchParams.has('code_challenge')).toBe(false);
    expect(sessionStorage.getItem(FED_SLOT)).toBeNull();
    expect(h.wire(PATH.exchange)).toEqual([]);
    expect(h.sdk.getCachedTokens()?.access_token).toBe(issued.access_token);
    expect(h.of(PassflowEvent.SignIn)[0]).not.toHaveProperty('source');
  });

  test('TEST-40 REQ-23 ordinary password exchange SignIn has no federated source', async () => {
    const h = harness();
    await h.sdk.signIn({ email: 'qa@example.com', password: 'correct-password' });
    expect(h.of(PassflowEvent.SignIn)).toHaveLength(1);
    expect(h.of(PassflowEvent.SignIn)[0]).not.toHaveProperty('source');
  });
});
