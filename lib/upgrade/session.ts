/**
 * Session and user identity pinning for an upgrade flight (§13.4 revision 6).
 *
 * ## The rule
 *
 * An upgrade flight is bound to the **session and user identity it began
 * under**, and that identity is verified **at the moment tokens are applied** —
 * not only around `prepare` and `commit`. On mismatch the rotated tokens are
 * discarded, never applied, and the flight settles as `session changed
 * mid-flight`.
 *
 * ## Why the epoch counter was not enough
 *
 * The round-1 epoch check wraps the two rounds that talk to the server. It does
 * not wrap token APPLICATION, which happens inside `AuthService.refreshToken`
 * after the commit returns. A logout and re-login during an in-flight upgrade
 * therefore let user A's flight write its rotated tokens over user B's live
 * session: the request was authorized as A, the storage belongs to B, and
 * nothing in between compared the two principals.
 *
 * An epoch tells you something changed. An identity check tells you **whether
 * it is still the same principal**, which is the property actually required.
 * Both run, and they are complementary rather than redundant.
 *
 * ## Why this module is pure
 *
 * It imports nothing and reads no storage, so the token-applying path can be
 * given a pin by value and the comparison can be tested with literals. Reading
 * the identity is the host's job — it is the only code that knows where the
 * session lives in each delivery mode.
 */

/**
 * The principal an upgrade flight is pinned to.
 *
 * `sub` is the user. `sid` is the session when the server issues one; it is
 * absent in tokens that carry no session claim, and the field is then simply
 * not part of the comparison — a missing claim cannot be made to prove
 * anything, and inventing a value would make two different sessions compare
 * equal or unequal arbitrarily.
 */
export type UpgradeSessionPin = {
  readonly sub: string;
  readonly sid?: string;
};

/** Claims the pin is read from. Deliberately `unknown`-typed: it is a parsed JWT body. */
export type UpgradeSessionClaims = { sub?: unknown; sid?: unknown } | null | undefined;

/**
 * Reads a pin from token claims, or `undefined` when there is no identity to
 * pin to.
 *
 * `sub` is mandatory: without a user there is no principal, and a pin that
 * compares nothing would report "unchanged" for every change.
 */
export const readSessionPin = (claims: UpgradeSessionClaims): UpgradeSessionPin | undefined => {
  if (!claims || typeof claims.sub !== 'string' || claims.sub === '') {
    return undefined;
  }
  return typeof claims.sid === 'string' && claims.sid !== '' ? { sub: claims.sub, sid: claims.sid } : { sub: claims.sub };
};

/**
 * Is `current` the same principal the flight was pinned to?
 *
 * `false` when `current` is absent: a pin exists, so the identity WAS readable
 * when the flight began, and an identity that has since become unreadable is a
 * change — the session was torn down. That is fail-closed on token
 * APPLICATION (nothing is written) and still fail-open on session STATE
 * (nothing is invalidated, nobody is logged out). §13.4 revision 6 keeps those
 * two axes separate on purpose.
 *
 * When both sides carry a `sid` it must match as well, which is what catches a
 * logout and re-login as the SAME user.
 */
export const sessionPinMatches = (pin: UpgradeSessionPin, current: UpgradeSessionPin | undefined): boolean => {
  if (!current || current.sub !== pin.sub) {
    return false;
  }
  if (pin.sid !== undefined && current.sid !== undefined) {
    return pin.sid === current.sid;
  }
  return true;
};
