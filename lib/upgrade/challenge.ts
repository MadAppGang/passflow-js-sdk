/**
 * RFC 9470 step-up challenge parsing.
 *
 * A upgrade challenge is the server saying "this session is valid, but not
 * strong enough". It arrives in two shapes, both carrying the same
 * `WWW-Authenticate` vocabulary:
 *
 *   - `401` from a protected resource (RFC 9470 §3), emitted by the
 *     RequireAuthLevel / RequireFreshAuth middleware.
 *   - `403` from `/auth/session/exchange`, which keeps its ADR-2 JSON body
 *     (`{"error": "upgrade_required", ...}`) alongside the same header.
 *
 * Telling this apart from an ordinary `401` matters more than it looks: an
 * expired session and an insufficient one are the same status code with
 * opposite remedies. Clearing tokens on a upgrade challenge logs the user out
 * at the exact moment they were asked to prove *more*.
 */

/** The error code RFC 9470 §3 defines for an insufficient authentication event. */
export const INSUFFICIENT_USER_AUTHENTICATION = 'insufficient_user_authentication';

/** The ADR-2 error code `/auth/session/exchange` returns in its 403 body. */
export const UPGRADE_REQUIRED = 'upgrade_required';

/**
 * What the server demands before it will serve the original request.
 *
 * Both fields are optional because the two middlewares challenge on different
 * axes: RequireAuthLevel names an `acrValues` and omits `maxAge`, while
 * RequireFreshAuth does the reverse. A challenge carrying neither is still
 * valid — it means "re-prove a factor" without further qualification.
 */
export type UpgradeChallenge = {
  /** Required authentication context class (`acr`), e.g. `'2'`. */
  acrValues?: string;
  /** Maximum permitted age of the authentication event, in seconds. */
  maxAge?: number;
  /** The status that carried the challenge: 401 (protected resource) or 403 (session exchange). */
  status: number;
};

/**
 * Matches one `auth-param` (RFC 9110 §11.2): a token, `=`, then either a
 * quoted-string or a bare token. Quoted values are captured separately from
 * bare ones so an embedded comma (legal inside quotes) does not split a value.
 */
const AUTH_PARAM = /([A-Za-z0-9!#$%&'*+\-.^_`|~]+)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|([^\s,]*))/g;

/** Unescapes a quoted-string body per RFC 9110 §5.6.4 (`\X` → `X`). */
const unescapeQuoted = (value: string): string => value.replace(/\\(.)/g, '$1');

/**
 * Parses the auth-params out of a `WWW-Authenticate` value.
 *
 * Scans params across the whole header rather than isolating a single
 * challenge. Passflow only ever emits one `Bearer` challenge, and scanning
 * broadly means an unexpected additional scheme degrades to "we still found
 * the Bearer params" instead of failing shut.
 */
const parseAuthParams = (header: string): Record<string, string> => {
  const params: Record<string, string> = {};
  // `matchAll` needs the regex reset; AUTH_PARAM is module-level and stateful.
  AUTH_PARAM.lastIndex = 0;
  for (const match of header.matchAll(AUTH_PARAM)) {
    const name = match[1];
    if (!name) {
      continue;
    }
    const quoted = match[2];
    const bare = match[3];
    params[name.toLowerCase()] = quoted !== undefined ? unescapeQuoted(quoted) : (bare ?? '');
  }
  return params;
};

/** Parses `max_age` defensively — a non-numeric or negative value is treated as absent. */
const parseMaxAge = (raw: unknown): number | undefined => {
  const n = typeof raw === 'number' ? raw : Number.parseInt(String(raw ?? ''), 10);
  return Number.isFinite(n) && n > 0 ? n : undefined;
};

/**
 * Reads a upgrade challenge out of a `WWW-Authenticate` header, or returns
 * `undefined` when the header is absent or describes some other failure.
 *
 * The header must both use the `Bearer` scheme and carry
 * `error="insufficient_user_authentication"`. A bare `WWW-Authenticate: Bearer`
 * (what an expired token produces) is deliberately NOT a upgrade challenge.
 */
export const parseChallengeHeader = (header: string | undefined | null, status: number): UpgradeChallenge | undefined => {
  if (!header || !/(^|[\s,])Bearer\b/i.test(header)) {
    return undefined;
  }

  const params = parseAuthParams(header);
  if (params.error !== INSUFFICIENT_USER_AUTHENTICATION) {
    return undefined;
  }

  return {
    acrValues: params.acr_values || undefined,
    maxAge: parseMaxAge(params.max_age),
    status,
  };
};

/**
 * Reads a upgrade challenge out of the ADR-2 `403` body. Used as a fallback
 * for `/auth/session/exchange`, whose JSON body is the documented SDK contract
 * even though it also sets the standard header.
 */
export const parseChallengeBody = (body: unknown, status: number): UpgradeChallenge | undefined => {
  if (!body || typeof body !== 'object') {
    return undefined;
  }

  const data = body as Record<string, unknown>;
  if (data.error !== UPGRADE_REQUIRED) {
    return undefined;
  }

  return {
    acrValues: typeof data.acr_values === 'string' && data.acr_values ? data.acr_values : undefined,
    maxAge: parseMaxAge(data.max_age),
    status,
  };
};

/**
 * Resolves a upgrade challenge from a response, checking the standard header
 * first and falling back to the session-exchange body.
 *
 * Returns `undefined` for every response that is not a upgrade challenge —
 * including ordinary `401`s, which callers must keep treating as "session
 * expired".
 */
export const parseUpgradeChallenge = (
  status: number,
  getHeader: (name: string) => string | undefined | null,
  body?: unknown,
): UpgradeChallenge | undefined => {
  if (status !== 401 && status !== 403) {
    return undefined;
  }
  return parseChallengeHeader(getHeader('www-authenticate'), status) ?? parseChallengeBody(body, status);
};
