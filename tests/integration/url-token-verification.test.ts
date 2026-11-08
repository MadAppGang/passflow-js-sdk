// REGRESSION: tokens taken from the URL are verified before they are stored.
/**
 * Tokens that arrive in a URL (`?access_token=`, `#access_token=`, or a federated popup's callback)
 * are stored only after their signature is checked against the server's published keys
 * (`<url>/.well-known/jwks.json`) and their claims are checked: `iss` equals the discovery
 * `issuer`, `aud` includes the app id, `exp` is in the future, and the access and refresh tokens
 * carry the right `type`.
 *
 * The URL is stripped synchronously on every path. The outcome is reported asynchronously: `SignIn`
 * with `source: 'tokens-in-url'`, or one `Error` with operation `tokens.from-url` and nothing stored.
 *
 * Core accepts URL tokens only for apps in Simple mode, so every app here is served with
 * `pkce_enabled: false`; the mode rule itself is covered by url-token-mode-gate.test.ts.
 */
import { describe, expect, test, vi } from 'vitest';
import { PassflowEvent } from '../../lib/index';
import { TEST_CONFIG, VALID_TOKENS } from '../helpers/fixtures';
import { fault, fedPayload, type Harness, harness, until } from '../helpers/pkce-harness';
import {
  DISCOVERY_PATH,
  discoveryBody,
  generateSigningKey,
  ISSUER,
  type IssuedTokens,
  issuedTokens,
  JWKS_PATH,
  jwksBody,
  type SigningKey,
  signToken,
  tokenClaims,
  tokenParams,
  unsignedToken,
} from '../helpers/signed-tokens';

type Client = ReturnType<Harness['client']>;
type Where = 'query' | 'hash';

const CALLBACK = 'https://app.example/callback';

/** Serves discovery and JWKS from the configured url, publishing `keys`. */
function serve(h: Harness, ...keys: SigningKey[]) {
  h.reply(DISCOVERY_PATH, discoveryBody());
  h.reply(JWKS_PATH, jwksBody(...keys));
}

function landWith(h: Harness, tokens: Partial<IssuedTokens>, where: Where) {
  h.land(where === 'query' ? `${CALLBACK}?${tokenParams(tokens)}&keep=1` : `${CALLBACK}?keep=1#${tokenParams(tokens)}`);
}

/** Whether `token` was ever written to storage. */
const stored = (h: Harness, token: string) => h.writes.some((w) => w.value.includes(token));

function expectStripped(h: Harness) {
  const url = h.url();
  for (const name of ['access_token', 'refresh_token', 'id_token']) {
    expect(url.searchParams.has(name), `${name} left in the query`).toBe(false);
    expect(url.hash.includes(name), `${name} left in the fragment`).toBe(false);
  }
  expect(url.searchParams.get('keep')).toBe('1');
}

/** Waits (bounded) until the landing reports an outcome on `c`. */
async function outcome(c: Pick<Client, 'of'>) {
  await until(() => c.of(PassflowEvent.SignIn).length + c.of(PassflowEvent.Error).length > 0);
}

/** The landing ended in exactly one `tokens.from-url` Error, no SignIn and nothing stored. */
async function expectRefused(h: Harness, c: Pick<Client, 'of' | 'sdk'>, tokens: Partial<IssuedTokens>) {
  await outcome(c);
  expect(c.of(PassflowEvent.SignIn)).toEqual([]);
  expect(c.of(PassflowEvent.Error)).toEqual([expect.objectContaining({ operation: 'tokens.from-url' })]);
  for (const token of Object.values(tokens)) expect(stored(h, token as string)).toBe(false);
  expect(c.sdk.getCachedTokens()?.access_token).toBeUndefined();
  expect(c.sdk.isAuthenticated()).toBe(false);
}

/** Lands `tokens` on the main instance and asserts the URL is stripped before any await. */
function landAndHandle(h: Harness, tokens: Partial<IssuedTokens>, where: Where = 'query') {
  landWith(h, tokens, where);
  const returned = h.sdk.handleTokensRedirect();
  expectStripped(h);
  return returned;
}

describe('tokens in the page URL are verified before they are stored', () => {
  test.each<Where>(['query', 'hash'])('a valid issued set in the %s signs in after verification', async (where) => {
    const h = harness({ pkce: false });
    const key = await generateSigningKey();
    serve(h, key);
    const tokens = await issuedTokens(key);

    // Nothing is verified when it returns, so it hands back no tokens.
    expect(landAndHandle(h, tokens, where)).toBeUndefined();
    expect(h.sdk.isAuthenticated()).toBe(false);
    expect(stored(h, tokens.access_token)).toBe(false);
    expect(h.of(PassflowEvent.SignIn)).toEqual([]);

    await outcome(h);
    expect(h.of(PassflowEvent.Error)).toEqual([]);
    expect(h.of(PassflowEvent.SignIn)).toEqual([
      expect.objectContaining({ source: 'tokens-in-url', tokens: expect.objectContaining(tokens) }),
    ]);
    expect(stored(h, tokens.access_token)).toBe(true);
    expect(stored(h, tokens.refresh_token)).toBe(true);
    expect(h.sdk.getCachedTokens()?.access_token).toBe(tokens.access_token);
    expect(h.sdk.isAuthenticated()).toBe(true);
    // Keys and issuer come from the configured url, not from anything in the token.
    for (const path of [DISCOVERY_PATH, JWKS_PATH]) {
      expect(h.wire(path).map((r) => new URL(r.url ?? '', 'https://unset.example').origin)).toEqual([
        new URL(TEST_CONFIG.url).origin,
      ]);
    }
  });

  test('parseQueryParams: true strips at construction and stores only after verification', async () => {
    const h = harness({ pkce: false });
    const key = await generateSigningKey();
    serve(h, key);
    const tokens = await issuedTokens(key);
    landWith(h, tokens, 'query');

    const c = h.client({ parseQueryParams: true });
    expectStripped(h);
    expect(stored(h, tokens.access_token)).toBe(false);
    expect(c.sdk.isAuthenticated()).toBe(false);

    await outcome(c);
    expect(c.of(PassflowEvent.SignIn)).toEqual([expect.objectContaining({ source: 'tokens-in-url' })]);
    expect(c.sdk.isAuthenticated()).toBe(true);
  });

  test('an RS256 issued set is accepted too', async () => {
    const h = harness({ pkce: false });
    const key = await generateSigningKey('rsa-1', 'RS256');
    serve(h, key);
    const tokens = await issuedTokens(key);

    landAndHandle(h, tokens);
    await outcome(h);
    expect(h.of(PassflowEvent.SignIn)).toEqual([expect.objectContaining({ source: 'tokens-in-url' })]);
    expect(h.sdk.isAuthenticated()).toBe(true);
  });

  test.each<Where>(['query', 'hash'])(
    'a forged signature (same kid, another key) in the %s is refused; URL stripped synchronously',
    async (where) => {
      const h = harness({ pkce: false });
      const server = await generateSigningKey('k1');
      const forger = await generateSigningKey('k1');
      serve(h, server);
      const tokens = await issuedTokens(forger);

      landAndHandle(h, tokens, where);
      await expectRefused(h, h, tokens);
    },
  );

  test('parseQueryParams: true refuses forged tokens at construction', async () => {
    const h = harness({ pkce: false });
    const server = await generateSigningKey('k1');
    const forger = await generateSigningKey('k1');
    serve(h, server);
    const tokens = await issuedTokens(forger);
    landWith(h, tokens, 'query');

    const c = h.client({ parseQueryParams: true });
    expectStripped(h);
    expect(stored(h, tokens.access_token)).toBe(false);
    await expectRefused(h, c, tokens);
  });

  test.each([
    ['another app in aud', { aud: ['another-app-id'] }],
    ['an issuer other than the discovery issuer', { iss: `${ISSUER}.attacker` }],
    ['the configured url as issuer when discovery says otherwise', { iss: TEST_CONFIG.url }],
    ['an exp in the past', { exp: Math.floor(Date.now() / 1000) - 60 }],
    ['no exp', { exp: undefined }],
  ])('a validly signed set with %s is refused', async (_name, overrides) => {
    const h = harness({ pkce: false });
    const key = await generateSigningKey();
    serve(h, key);
    const tokens = await issuedTokens(key, overrides);

    landAndHandle(h, tokens);
    await expectRefused(h, h, tokens);
  });

  test.each([
    ['access token typed refresh', 'access', 'refresh'],
    ['refresh token typed access', 'refresh', 'access'],
  ] as const)('a validly signed %s is refused', async (_name, which, type) => {
    const h = harness({ pkce: false });
    const key = await generateSigningKey();
    serve(h, key);
    const claims = tokenClaims();
    const tokens = await issuedTokens(key);
    const retyped = await signToken({ ...claims[which], type }, key);
    const landed = { ...tokens, [`${which}_token`]: retyped };

    landAndHandle(h, landed);
    await expectRefused(h, h, landed);
  });

  test.each(['refresh_token', 'id_token'] as const)(
    'a valid access token with a forged %s is refused as a whole',
    async (forgedName) => {
      const h = harness({ pkce: false });
      const server = await generateSigningKey('k1');
      const forger = await generateSigningKey('k1');
      serve(h, server);
      const genuine = await issuedTokens(server);
      const forged = await issuedTokens(forger);
      const landed = { ...genuine, [forgedName]: forged[forgedName] };

      landAndHandle(h, landed);
      await expectRefused(h, h, landed);
    },
  );

  test.each(['HS256', 'none'])('a token with alg %s and otherwise valid claims is refused', async (alg) => {
    const h = harness({ pkce: false });
    serve(h, await generateSigningKey('k1'));
    const claims = tokenClaims();
    const landed = {
      access_token: unsignedToken(claims.access, alg),
      refresh_token: unsignedToken(claims.refresh, alg),
    };

    landAndHandle(h, landed);
    await expectRefused(h, h, landed);
  });

  test('the HS256 fixture tokens are refused', async () => {
    const h = harness({ pkce: false });
    serve(h, await generateSigningKey('k1'));
    const landed = {
      access_token: VALID_TOKENS.access_token as string,
      refresh_token: VALID_TOKENS.refresh_token as string,
      id_token: VALID_TOKENS.id_token as string,
    };

    landAndHandle(h, landed);
    await expectRefused(h, h, landed);
  });

  test('a token whose kid is not published is refused', async () => {
    const h = harness({ pkce: false });
    const published = await generateSigningKey('k1');
    const other = await generateSigningKey('k2');
    serve(h, published);
    const tokens = await issuedTokens(other);

    landAndHandle(h, tokens);
    await expectRefused(h, h, tokens);
  });

  test('without an app id, valid tokens are refused and still stripped', async () => {
    const h = harness({ pkce: false });
    const key = await generateSigningKey();
    serve(h, key);
    const tokens = await issuedTokens(key);
    const c = h.client({ appId: undefined });

    landWith(h, tokens, 'query');
    c.sdk.handleTokensRedirect();
    expectStripped(h);
    await expectRefused(h, c, tokens);
  });

  test.each([
    ['discovery unreachable', DISCOVERY_PATH, fault('network')],
    ['discovery 503', DISCOVERY_PATH, fault('http', 503)],
    ['JWKS unreachable', JWKS_PATH, fault('network')],
    ['JWKS 500', JWKS_PATH, fault('http', 500)],
  ])('%s: one Error, nothing stored, URL already stripped', async (_name, path, reply) => {
    const h = harness({ pkce: false });
    const key = await generateSigningKey();
    serve(h, key);
    h.reply(path, reply);
    const tokens = await issuedTokens(key);

    landAndHandle(h, tokens);
    await expectRefused(h, h, tokens);
  });

  test.each([
    ['refresh_token only', ['refresh_token']],
    ['id_token only', ['id_token']],
    ['refresh_token and id_token', ['refresh_token', 'id_token']],
  ] as const)('a URL with %s and no access_token is stripped and nothing is stored', async (_name, names) => {
    const h = harness({ pkce: false });
    const key = await generateSigningKey();
    serve(h, key);
    const all = await issuedTokens(key);
    const landed = Object.fromEntries(names.map((n) => [n, all[n]])) as Partial<IssuedTokens>;

    landAndHandle(h, landed);
    for (const token of Object.values(landed)) expect(stored(h, token as string)).toBe(false);
    expect(h.of(PassflowEvent.SignIn)).toEqual([]);
  });

  test.each(['refresh_token', 'id_token'] as const)(
    'a fragment with only %s is stripped and nothing is stored',
    async (name) => {
      const h = harness({ pkce: false });
      const key = await generateSigningKey();
      serve(h, key);
      const landed = { [name]: (await issuedTokens(key))[name] };

      landAndHandle(h, landed, 'hash');
      expect(stored(h, landed[name] as string)).toBe(false);
      expect(h.of(PassflowEvent.SignIn)).toEqual([]);
    },
  );

  test('a fragment access token with a refresh token in the query strips both and signs in with the fragment set', async () => {
    const h = harness({ pkce: false });
    const key = await generateSigningKey();
    serve(h, key);
    const tokens = await issuedTokens(key);
    const queryRefresh = (await issuedTokens(key, { sub: 'someone-else' })).refresh_token;

    h.land(`${CALLBACK}?refresh_token=${queryRefresh}&keep=1#${tokenParams(tokens)}`);
    h.sdk.handleTokensRedirect();
    expectStripped(h);

    await outcome(h);
    expect(h.of(PassflowEvent.Error)).toEqual([]);
    expect(h.of(PassflowEvent.SignIn)).toEqual([
      expect.objectContaining({ source: 'tokens-in-url', tokens: expect.objectContaining(tokens) }),
    ]);
    expect(stored(h, queryRefresh)).toBe(false);
  });

  test('a verified set that cannot be saved ends in one tokens.from-url Error and no SignIn', async () => {
    const h = harness({ pkce: false });
    const key = await generateSigningKey();
    serve(h, key);
    const tokens = await issuedTokens(key);
    vi.spyOn(localStorage, 'setItem').mockImplementation(() => {
      throw new Error('Storage is full');
    });

    landAndHandle(h, tokens);
    await outcome(h);
    expect(h.of(PassflowEvent.SignIn)).toEqual([]);
    expect(h.of(PassflowEvent.Error)).toEqual([
      expect.objectContaining({ operation: 'tokens.from-url', message: 'Storage is full' }),
    ]);
  });
});

describe('tokens in a federated popup callback are verified before they are stored', () => {
  async function popupWith(h: Harness, tokens: Partial<IssuedTokens>) {
    h.popup(async () => ({ callbackSearch: `?${tokenParams(tokens)}`, callbackHash: '' }));
    const done = h.sdk.federatedAuthWithPopup(fedPayload());
    await outcome(h);
    await done;
  }

  test('a valid issued set signs in', async () => {
    const h = harness({ pkce: false });
    const key = await generateSigningKey();
    serve(h, key);
    const tokens = await issuedTokens(key);

    await popupWith(h, tokens);
    expect(h.of(PassflowEvent.Error)).toEqual([]);
    expect(h.of(PassflowEvent.SignIn)).toHaveLength(1);
    expect(h.sdk.getCachedTokens()?.access_token).toBe(tokens.access_token);
    expect(h.wire(JWKS_PATH)).toHaveLength(1);
  });

  test('a forged set is refused with the federated.popup Error and nothing stored', async () => {
    const h = harness({ pkce: false });
    const server = await generateSigningKey('k1');
    const forger = await generateSigningKey('k1');
    serve(h, server);
    const tokens = await issuedTokens(forger);

    await popupWith(h, tokens);
    expect(h.of(PassflowEvent.SignIn)).toEqual([]);
    expect(h.of(PassflowEvent.Error)).toEqual([expect.objectContaining({ operation: 'federated.popup' })]);
    for (const token of Object.values(tokens)) expect(stored(h, token)).toBe(false);
    expect(h.sdk.getCachedTokens()?.access_token).toBeUndefined();
  });

  test('a set for another app is refused with the federated.popup Error', async () => {
    const h = harness({ pkce: false });
    const key = await generateSigningKey();
    serve(h, key);
    const tokens = await issuedTokens(key, { aud: ['another-app-id'] });

    await popupWith(h, tokens);
    expect(h.of(PassflowEvent.SignIn)).toEqual([]);
    expect(h.of(PassflowEvent.Error)).toEqual([expect.objectContaining({ operation: 'federated.popup' })]);
    expect(h.sdk.getCachedTokens()?.access_token).toBeUndefined();
  });
});
