/**
 * Codes of the errors the hosted sign-in in SDK mode (authorization code + PKCE) reports, both as
 * `PassflowOidcError.code` on a rejected `authRedirect()` and as `ErrorPayload.code` on the
 * `Error` event. A landing whose token endpoint answered with an OAuth error other than
 * `invalid_client` or `invalid_grant` reports `TOKEN_EXCHANGE_FAILED`; an `?error=` landing reports
 * the OAuth error code the server sent.
 */
export type OidcErrorCode =
  /** `authRedirect()` got a `url` or `appId` that differs from the instance's. */
  | 'OVERRIDE_NOT_SUPPORTED'
  /** The page is not a secure context, so the Web Crypto API that PKCE needs is missing. */
  | 'SECURE_CONTEXT_REQUIRED'
  /** sessionStorage cannot be written, so the proof key cannot survive the redirect. */
  | 'STORAGE_UNAVAILABLE'
  /** The app is a confidential client (it has a secret), so a browser cannot redeem its code. */
  | 'CONFIDENTIAL_CLIENT'
  /** The landing's `state` is not the one this tab sent. */
  | 'STATE_MISMATCH'
  /** This tab's stored proof key is unreadable or expired. */
  | 'VERIFIER_MISSING'
  /** The ID token is missing although `openid` was asked, or its `nonce` is not the one sent. */
  | 'ID_TOKEN_INVALID'
  /** The token endpoint could not be reached or answered with an unexpected error. */
  | 'TOKEN_EXCHANGE_FAILED'
  /** The token endpoint refused the client: it needs a secret. */
  | 'invalid_client'
  /** The token endpoint refused the code. */
  | 'invalid_grant'
  /** URL tokens were received but the app is not known to be in Simple mode. */
  | 'TOKENS_IN_URL_NOT_ALLOWED';

/** An error of the hosted sign-in in SDK mode, with a code a caller can branch on. */
export class PassflowOidcError extends Error {
  constructor(
    readonly code: OidcErrorCode | (string & {}),
    message: string,
  ) {
    super(message);
    this.name = 'PassflowOidcError';
  }
}

export const SIGN_IN_AGAIN_MESSAGE = 'Sign in again.';

/** The early refusal, before any redirect, of an app whose settings say it has a secret. */
export const confidentialClientMessage = (type: string): string =>
  `This app is type ${type} and is a confidential client (it has a secret). For a browser app set its type to SPA; a server-side app redeems the code on its server with the secret.`;

/** The token endpoint's `invalid_client`, for a server that does not report `public_client`. */
export const INVALID_CLIENT_MESSAGE =
  'This app is a confidential client. For a browser app set its type to SPA (or token_endpoint_auth_method to none); a server-side app must redeem the code on its server with the client secret.';

/** Refusal of tokens received in a URL by an app that is not known to be in Simple mode. */
export const tokensInUrlNotAllowed = (): PassflowOidcError =>
  new PassflowOidcError('TOKENS_IN_URL_NOT_ALLOWED', 'Tokens in the URL are accepted only for apps in Simple mode');
