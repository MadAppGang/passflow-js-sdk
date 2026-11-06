/**
 * Really signed JWTs for tests: ES256 (P-256) and RS256 key pairs made with node's WebCrypto, the
 * discovery and JWKS bodies a Passflow server publishes, and an issued token set signed with them.
 *
 * ES256 signatures are raw r||s, the JWS format WebCrypto produces, so no DER conversion is needed.
 */
import { webcrypto } from 'node:crypto';
import { URLSearchParams as NativeURLSearchParams } from 'node:url';
import { TEST_CONFIG } from './fixtures';

const subtle = webcrypto.subtle;

/** The issuer the server's discovery document publishes. Deliberately not the configured SDK url. */
export const ISSUER = 'https://issuer.passflow.example';
export const DISCOVERY_PATH = '/.well-known/openid-configuration';
export const JWKS_PATH = '/.well-known/jwks.json';

export type SigningAlg = 'ES256' | 'RS256';
export type SigningKey = {
  kid: string;
  alg: SigningAlg;
  privateKey: webcrypto.CryptoKey;
  publicJwk: webcrypto.JsonWebKey;
};
export type Claims = Record<string, unknown>;
export type IssuedTokens = { access_token: string; refresh_token: string; id_token: string };

const b64url = (data: string | ArrayBuffer | Uint8Array) =>
  (typeof data === 'string' ? Buffer.from(data, 'utf8') : Buffer.from(data as ArrayBuffer)).toString('base64url');

const nowSeconds = () => Math.floor(Date.now() / 1000);

/** A new key pair. Two keys made with the same kid model a forger who copies the server's kid. */
export async function generateSigningKey(kid = 'k1', alg: SigningAlg = 'ES256'): Promise<SigningKey> {
  const pair =
    alg === 'ES256'
      ? await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
      : await subtle.generateKey(
          { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
          true,
          ['sign', 'verify'],
        );
  const publicJwk = await subtle.exportKey('jwk', pair.publicKey);
  return { kid, alg, privateKey: pair.privateKey, publicJwk };
}

/** Signs `claims` with `key`. `header` overrides header members (for example a different kid). */
export async function signToken(claims: Claims, key: SigningKey, header: Claims = {}): Promise<string> {
  const head = b64url(JSON.stringify({ alg: key.alg, typ: 'JWT', kid: key.kid, ...header }));
  const body = b64url(JSON.stringify(claims));
  const algorithm = key.alg === 'ES256' ? { name: 'ECDSA', hash: 'SHA-256' } : { name: 'RSASSA-PKCS1-v1_5' };
  const signature = await subtle.sign(algorithm, key.privateKey, new TextEncoder().encode(`${head}.${body}`));
  return `${head}.${body}.${b64url(signature)}`;
}

/** A well-formed JWT that carries no verifiable signature (`alg: none`, HS256, ...). */
export function unsignedToken(claims: Claims, alg = 'HS256', kid = 'k1'): string {
  return `${b64url(JSON.stringify({ alg, typ: 'JWT', kid }))}.${b64url(JSON.stringify(claims))}.${b64url('not-a-signature')}`;
}

/** Claims a server puts on every token it issues for this app. */
export function baseClaims(overrides: Claims = {}): Claims {
  const iat = nowSeconds();
  return {
    sub: 'user-signed-1',
    sid: 'session-signed-1',
    iss: ISSUER,
    aud: [TEST_CONFIG.appId],
    iat,
    exp: iat + 3600,
    ...overrides,
  };
}

/** Claims for each token of a set, with the `type` the server sets (none on the ID token). */
export function tokenClaims(overrides: Claims = {}) {
  return {
    access: baseClaims({ type: 'access', jti: 'signed-access', ...overrides }),
    refresh: baseClaims({ type: 'refresh', jti: 'signed-refresh', exp: nowSeconds() + 86_400, ...overrides }),
    id: baseClaims({ jti: 'signed-id', email: 'signed@example.com', ...overrides }),
  };
}

/** An issued token set signed by `key`. `overrides` apply to the claims of all three tokens. */
export async function issuedTokens(key: SigningKey, overrides: Claims = {}): Promise<IssuedTokens> {
  const claims = tokenClaims(overrides);
  return {
    access_token: await signToken(claims.access, key),
    refresh_token: await signToken(claims.refresh, key),
    id_token: await signToken(claims.id, key),
  };
}

/** `/.well-known/openid-configuration` reply body. */
export const discoveryBody = (issuer = ISSUER) => ({
  issuer,
  jwks_uri: `${issuer}${JWKS_PATH}`,
  id_token_signing_alg_values_supported: ['ES256', 'RS256'],
});

/** `/.well-known/jwks.json` reply body, members as the server publishes them. */
export const jwksBody = (...keys: SigningKey[]) => ({
  keys: keys.map((k) => ({ ...k.publicJwk, kid: k.kid, alg: k.alg, use: 'sig' })),
});

/** Query or fragment string carrying `tokens`. */
export const tokenParams = (tokens: Partial<IssuedTokens>) =>
  new NativeURLSearchParams(Object.entries(tokens).filter((e): e is [string, string] => typeof e[1] === 'string')).toString();
