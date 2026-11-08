/**
 * Start of the hosted sign-in in SDK mode: an OAuth 2.0 authorization-code request with PKCE
 * (RFC 7636, S256) to `{url}/oidc/authorize`, as a public client. The proof key, `state` and
 * `nonce` stay in this tab's sessionStorage for the page the redirect lands on.
 */
import { createPkcePair, hasWebCrypto, randomBase64Url } from '../pkce';
import { PassflowOidcError } from './errors';

export const OIDC_SLOT_STORAGE_KEY = 'passflow_oidc_pkce';
export const OIDC_SLOT_TIMEOUT_MS = 10 * 60 * 1000;

/** What this tab keeps for its landing. One per tab: a newer start overwrites it. */
export type OidcSlot = {
  verifier: string;
  state: string;
  nonce?: string;
  clientId: string;
  redirectUri: string;
  /** The scope list sent to `/oidc/authorize`, after `openid` was added. */
  scopes: string[];
  expiresAt: number;
};

/**
 * Origin and pathname of a URL, compared as equal when they name the same place: URL parsing
 * lower-cases scheme and host and drops a default port; a trailing slash is dropped here. A value
 * that is not a URL is returned as it is.
 */
export const normaliseUrl = (value: string): string => {
  try {
    const url = new URL(value);
    return `${url.protocol}//${url.host}${url.pathname.replace(/\/+$/, '')}`;
  } catch {
    return value;
  }
};

/** The scopes sent: the list as given, plus `openid` when it asks for `id` or `oidc`, so an ID token is issued. */
export const effectiveOidcScopes = (scopes: string[]): string[] =>
  !scopes.includes('openid') && (scopes.includes('id') || scopes.includes('oidc')) ? [...scopes, 'openid'] : [...scopes];

/**
 * Builds the slot and the authorize URL, and writes the slot. Nothing navigates here.
 *
 * @throws PassflowOidcError `SECURE_CONTEXT_REQUIRED` without Web Crypto, `STORAGE_UNAVAILABLE`
 * when sessionStorage cannot be written
 */
export const startOidcAuthorization = async (options: {
  url: string;
  clientId: string;
  redirectUri: string;
  scopes: string[];
}): Promise<string> => {
  if (!hasWebCrypto()) {
    throw new PassflowOidcError(
      'SECURE_CONTEXT_REQUIRED',
      'Sign-in needs the Web Crypto API, which is available only in a secure context (https or localhost)',
    );
  }

  const scopes = effectiveOidcScopes(options.scopes);
  const pkce = await createPkcePair();
  const slot: OidcSlot = {
    verifier: pkce.verifier,
    state: randomBase64Url(),
    ...(scopes.includes('openid') ? { nonce: randomBase64Url() } : {}),
    clientId: options.clientId,
    redirectUri: options.redirectUri,
    scopes,
    expiresAt: Date.now() + OIDC_SLOT_TIMEOUT_MS,
  };

  try {
    sessionStorage.setItem(OIDC_SLOT_STORAGE_KEY, JSON.stringify(slot));
  } catch {
    throw new PassflowOidcError('STORAGE_UNAVAILABLE', 'Sign-in needs sessionStorage, which cannot be written here');
  }

  const authorize = new URL(`${options.url.replace(/\/+$/, '')}/oidc/authorize`);
  authorize.search = new URLSearchParams({
    response_type: 'code',
    client_id: slot.clientId,
    redirect_uri: slot.redirectUri,
    scope: scopes.join(' '),
    state: slot.state,
    code_challenge: pkce.challenge,
    code_challenge_method: 'S256',
    ...(slot.nonce ? { nonce: slot.nonce } : {}),
  }).toString();
  return authorize.toString();
};
