/**
 * Verifies tokens received from a redirect URL before they are stored: each signature is checked
 * against the keys the configured server publishes, and the claims against its discovery document
 * and this app.
 */
import axios from 'axios';

import { isTokenExpired, parseToken } from './service';
import { TokenType } from './token';

type UrlTokens = { access_token?: string; refresh_token?: string; id_token?: string };
type Jwk = JsonWebKey & { kid?: string };

const ALGORITHMS = {
  ES256: {
    kty: 'EC',
    key: (k: Jwk): JsonWebKey => ({ kty: k.kty, crv: k.crv, x: k.x, y: k.y }),
    imported: { name: 'ECDSA', namedCurve: 'P-256' },
    signature: { name: 'ECDSA', hash: 'SHA-256' },
  },
  RS256: {
    kty: 'RSA',
    key: (k: Jwk): JsonWebKey => ({ kty: k.kty, n: k.n, e: k.e }),
    imported: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    signature: { name: 'RSASSA-PKCS1-v1_5' },
  },
} as const;

const base64UrlBytes = (value: string): Uint8Array<ArrayBuffer> => {
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/');
  const binary = globalThis.atob(base64 + '='.repeat((4 - (base64.length % 4)) % 4));
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
};

// `crypto.subtle` exists only in a secure context, so a plain-http page lands here.
const webCrypto = (): Crypto => {
  const crypto = globalThis.crypto;
  if (!crypto?.subtle) {
    throw new Error('Verifying tokens needs the Web Crypto API, available only in a secure context (https or localhost)');
  }
  return crypto;
};

async function verifyToken(token: string, keys: Jwk[], issuer: string, appId: string, type?: TokenType) {
  const [head = '', body = '', signature = ''] = token.split('.');
  const header = JSON.parse(new TextDecoder().decode(base64UrlBytes(head))) as { alg?: string; kid?: string };
  const algorithm = header.alg === 'ES256' || header.alg === 'RS256' ? ALGORITHMS[header.alg] : undefined;
  if (!algorithm) throw new Error(`Token signing algorithm ${String(header.alg)} is not accepted`);

  const jwk = keys.find((k) => k.kid === header.kid && k.kty === algorithm.kty && (k.kty !== 'EC' || k.crv === 'P-256'));
  if (!jwk) throw new Error('Token signing key is not published by the server');

  const subtle = webCrypto().subtle;
  const key = await subtle.importKey('jwk', algorithm.key(jwk), algorithm.imported, false, ['verify']);
  const signed = new TextEncoder().encode(`${head}.${body}`);
  if (!(await subtle.verify(algorithm.signature, key, base64UrlBytes(signature), signed))) {
    throw new Error('Token signature is not valid');
  }

  const claims = parseToken(token);
  const audience: unknown[] = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (claims.iss !== issuer) throw new Error('Token issuer does not match the server');
  if (!audience.includes(appId)) throw new Error('Token is not issued for this app');
  if (typeof claims.exp !== 'number' || isTokenExpired(claims, 0)) throw new Error('Token has expired');
  if (type && claims.type !== type) throw new Error('Token type is not valid');
}

/**
 * Throws unless every token present is signed by the server at `url` and issued for `appId`.
 */
export async function verifyUrlTokens(url: string, appId: string | undefined, tokens: UrlTokens): Promise<void> {
  if (!appId) throw new Error('An app id is required to accept tokens from the URL');
  if (!tokens.access_token) throw new Error('No access token received');
  webCrypto();

  const base = url.replace(/\/+$/, '');
  const [discovery, jwks] = await Promise.all([
    axios.get<{ issuer?: string }>(`${base}/.well-known/openid-configuration`),
    axios.get<{ keys?: Jwk[] }>(`${base}/.well-known/jwks.json`),
  ]);
  const issuer = discovery.data?.issuer;
  const keys = jwks.data?.keys ?? [];
  if (!issuer) throw new Error('The server did not publish an issuer');

  await verifyToken(tokens.access_token, keys, issuer, appId, TokenType.access_token);
  if (tokens.refresh_token) await verifyToken(tokens.refresh_token, keys, issuer, appId, TokenType.refresh_token);
  // The server leaves `type` off ID tokens, so no type is checked.
  if (tokens.id_token) await verifyToken(tokens.id_token, keys, issuer, appId);
}
