/**
 * Landing of the hosted sign-in in SDK mode: hosted sign-in returns an authorization code
 * (`?code=&state=`), which this tab redeems at `{url}/oidc/token` with the proof key it kept.
 *
 * The token request is a plain `fetch` form POST, not an API client call: the OIDC endpoints
 * admit only the `Authorization` and `Content-Type` headers, and their errors are OAuth error
 * bodies (`{error, error_description}`), not Passflow errors.
 */
import { parseToken } from '../token';
import type { Tokens } from '../types';
import { OIDC_SLOT_STORAGE_KEY, type OidcSlot } from './authorize';
import { INVALID_CLIENT_MESSAGE, PassflowOidcError, SIGN_IN_AGAIN_MESSAGE } from './errors';

/** No slot; a slot that is unreadable or expired; or a slot this landing can use. */
export type OidcSlotRead = { status: 'none' } | { status: 'unusable' } | { status: 'live'; slot: OidcSlot };

const isSlot = (value: unknown): value is OidcSlot => {
  const slot = value as Partial<OidcSlot> | null;
  return (
    typeof slot === 'object' &&
    slot !== null &&
    typeof slot.verifier === 'string' &&
    typeof slot.state === 'string' &&
    typeof slot.clientId === 'string' &&
    typeof slot.redirectUri === 'string' &&
    Array.isArray(slot.scopes) &&
    typeof slot.expiresAt === 'number'
  );
};

export const readOidcSlot = (): OidcSlotRead => {
  let raw: string | null;
  try {
    raw = sessionStorage.getItem(OIDC_SLOT_STORAGE_KEY);
  } catch {
    return { status: 'none' };
  }
  if (!raw) return { status: 'none' };
  try {
    const slot: unknown = JSON.parse(raw);
    if (isSlot(slot) && Date.now() < slot.expiresAt) return { status: 'live', slot };
  } catch {
    // Unreadable: reported as unusable below.
  }
  return { status: 'unusable' };
};

export const forgetOidcSlot = (): void => {
  try {
    sessionStorage.removeItem(OIDC_SLOT_STORAGE_KEY);
  } catch {
    // Nothing to do: it expires on its own.
  }
};

const readJson = async (response: Response): Promise<Record<string, unknown> | undefined> => {
  try {
    const body: unknown = await response.json();
    return typeof body === 'object' && body !== null ? (body as Record<string, unknown>) : undefined;
  } catch {
    return undefined;
  }
};

/**
 * Redeems `code` with the slot's verifier, client id and redirect URI, and checks the ID token's
 * `nonce` when `openid` was asked.
 *
 * @throws PassflowOidcError `invalid_client`, `invalid_grant`, `ID_TOKEN_INVALID` or
 * `TOKEN_EXCHANGE_FAILED`
 */
export const redeemOidcCode = async (url: string, code: string, slot: OidcSlot): Promise<Tokens> => {
  let response: Response;
  try {
    response = await fetch(`${url.replace(/\/+$/, '')}/oidc/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: slot.redirectUri,
        client_id: slot.clientId,
        code_verifier: slot.verifier,
      }).toString(),
    });
  } catch {
    throw new PassflowOidcError('TOKEN_EXCHANGE_FAILED', SIGN_IN_AGAIN_MESSAGE);
  }

  const body = await readJson(response);
  if (!response.ok) {
    if (body?.error === 'invalid_client') throw new PassflowOidcError('invalid_client', INVALID_CLIENT_MESSAGE);
    if (body?.error === 'invalid_grant') throw new PassflowOidcError('invalid_grant', SIGN_IN_AGAIN_MESSAGE);
    throw new PassflowOidcError('TOKEN_EXCHANGE_FAILED', SIGN_IN_AGAIN_MESSAGE);
  }
  if (typeof body?.access_token !== 'string') {
    throw new PassflowOidcError('TOKEN_EXCHANGE_FAILED', SIGN_IN_AGAIN_MESSAGE);
  }

  const idToken = typeof body.id_token === 'string' ? body.id_token : undefined;
  if (slot.scopes.includes('openid')) {
    let nonce: unknown;
    try {
      nonce = idToken ? (parseToken(idToken) as { nonce?: unknown }).nonce : undefined;
    } catch {
      nonce = undefined;
    }
    if (!idToken || nonce !== slot.nonce) {
      throw new PassflowOidcError(
        'ID_TOKEN_INVALID',
        `The ID token is missing or not issued for this sign-in. ${SIGN_IN_AGAIN_MESSAGE}`,
      );
    }
  }

  return {
    access_token: body.access_token,
    ...(typeof body.refresh_token === 'string' ? { refresh_token: body.refresh_token } : {}),
    ...(idToken ? { id_token: idToken } : {}),
    scopes: slot.scopes,
  };
};
