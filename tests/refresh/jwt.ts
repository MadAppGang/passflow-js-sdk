/**
 * Unsigned JWT helpers for refresh tests. Only the claims matter: the SDK never verifies a
 * signature client-side, it orders refresh tokens by `sub`, `sid` and `iat`.
 */
import { orderOf, type RefreshTokenOrder } from '../../lib/refresh/lineage';

function base64Url(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}

export function jwt(claims: Record<string, unknown>): string {
  return `${base64Url({ alg: 'none', typ: 'JWT' })}.${base64Url(claims)}.sig`;
}

let issued = 0;

/** A refresh JWT with a fresh `jti`, so two calls with the same claims give two tokens. */
export function refreshJwt(iat: number | undefined, sid: string | undefined = 's1', sub = 'user-1'): string {
  issued += 1;
  return jwt({ sub, sid, iat, jti: `jti-${issued}`, type: 'refresh' });
}

/** An access JWT for `sub` that expires at `exp` (epoch seconds; default far future). */
export function accessJwt(sub = 'user-1', exp = 4_102_444_800): string {
  issued += 1;
  return jwt({ sub, exp, iat: 1_700_000_000, jti: `access-${issued}`, type: 'access' });
}

/** The order of a new refresh token with these claims. */
export function token(iat: number | undefined, sid = 's1', sub = 'user-1'): RefreshTokenOrder {
  const order = orderOf(refreshJwt(iat, sid, sub));
  if (!order) throw new Error('no order');
  return order;
}

/** A stored token pair: access for `sub`, refresh with the given claims. */
export function pair(iat: number | undefined, sid = 's1', sub = 'user-1') {
  return { access_token: accessJwt(sub), refresh_token: refreshJwt(iat, sid, sub), scopes: ['id', 'offline'] };
}
