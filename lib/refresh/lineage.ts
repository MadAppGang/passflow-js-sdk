/**
 * Refresh token ordering. Port of the portal's `refresh-lineage.ts` (PFL-764 rounds 14-19).
 *
 * Cross-tab messages name refresh tokens by fingerprint and their issue time, never by extra
 * tokens, so a tab can tell which session and which link of the rotation a message is about.
 * Each tab orders the refresh tokens it meets by the token's own claims, which the engine signs:
 *   - sub: the user;
 *   - iat: the issue time, in whole seconds;
 *   - sid: the auth session the lineage is anchored to, kept by every rotation;
 *   - jti: random per token (not used: it orders nothing).
 * From them:
 *   - forward only: a tab moves its cache only to a token issued no earlier than the one it holds
 *     (isForward). A lower iat is older: a delayed or rebroadcast message, or a lagging view of
 *     storage, can never roll the cache back, however many rotations ago it was.
 *   - same-second ties: iat has one-second resolution, so back-to-back rotations can share it. A
 *     small set holds only the fingerprints retired within the newest retired second; a strictly
 *     newer second clears it. A tie is forward only once the token it would replace is known
 *     retired: a tab never trades the token it holds for a same-second one it has not seen proven
 *     newer.
 *   - per session: that floor and set are kept per sid, so a rotation of one session never makes
 *     another session's tokens (the same user signing in again) count as retired.
 *   - the engine's clock: iat ordering assumes it never steps back between two rotations of one
 *     session. If it does, the successor looks like a predecessor; the held-tab send recovers it.
 *   - ended: a session end records that session (sub, sid, and the iat and fingerprint of its
 *     token), in a bound of ENDED_MEMORY entries. A token of that session issued no later is dead:
 *     never sent, its late result never saved. A new sign-in (another sid) or a later token is not.
 * No memory grows with the number of rotations.
 *
 * @module refresh/lineage
 */

import { getDefaultLogger } from '../services/logger';
import { parseToken } from '../token/service';
import { ENDED_MEMORY, SESSION_MEMORY, TIE_MEMORY } from './constants';

/**
 * A short, stable fingerprint of a refresh token: 53-bit cyrb53, as lowercase hex. Identical to
 * the portal's, so fingerprints agree across tabs on either code during a rollout. Not a
 * secret-safe hash, and it need not be: the channel and the storage it stands in for are both
 * same-origin. It only has to tell tokens apart.
 */
export function fingerprint(token: string | undefined): string | undefined {
  if (!token) return undefined;
  let h1 = 0xdeadbeef;
  let h2 = 0x41c6ce57;
  for (let i = 0; i < token.length; i++) {
    const ch = token.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 2654435761);
    h2 = Math.imul(h2 ^ ch, 1597334677);
  }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507);
  h1 ^= Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507);
  h2 ^= Math.imul(h1 ^ (h1 >>> 13), 3266489909);
  return (4294967296 * (2097151 & h2) + (h1 >>> 0)).toString(16);
}

/**
 * A refresh token's place in the rotation: its fingerprint and the claims that order it. `iat` is
 * undefined when the token is no JWT or carries no numeric iat (unordered: never newer than an
 * ordered token, see isAfter).
 */
export interface RefreshTokenOrder {
  fp: string;
  sub?: string;
  sid?: string;
  iat?: number;
}

/** A session that ended (session-ended, signed-out), as a message names it. */
export type EndedSession = RefreshTokenOrder;

function claimString(value: unknown): string | undefined {
  return typeof value === 'string' && value !== '' ? value : undefined;
}

/** The order of a refresh token, or undefined for no token. A token that is no JWT is unordered. */
export function orderOf(token: string | undefined): RefreshTokenOrder | undefined {
  const fp = fingerprint(token);
  if (!token || !fp) return undefined;
  let claims: Record<string, unknown> = {};
  try {
    const parsed = parseToken(token) as unknown;
    if (typeof parsed === 'object' && parsed !== null) {
      claims = parsed as Record<string, unknown>;
    }
  } catch {
    // No JWT: unordered.
  }
  const iat = typeof claims.iat === 'number' && Number.isFinite(claims.iat) ? claims.iat : undefined;
  const order: RefreshTokenOrder = { fp };
  const sub = claimString(claims.sub);
  const sid = claimString(claims.sid);
  if (sub !== undefined) order.sub = sub;
  if (sid !== undefined) order.sid = sid;
  if (iat !== undefined) order.iat = iat;
  return order;
}

export interface RefreshLineage {
  /**
   * `token` was replaced: rotated by a refresh, superseded by newer stored tokens, the `from` of
   * an adopted tokens-refreshed, or refused by the engine as already used.
   */
  retire(token: RefreshTokenOrder | undefined): void;
  isRetired(token: RefreshTokenOrder | undefined): boolean;
  /**
   * `token` comes after `ref` in the rotation: a later second, or the same second when `ref` is
   * known retired and `token` is not (across sessions, a later second only).
   */
  isAfter(token: RefreshTokenOrder, ref: RefreshTokenOrder): boolean;
  /**
   * Forward only: `candidate` may replace `held` (undefined: nothing held) in this tab's cache.
   * Never retired, never ended, never older.
   */
  isForward(candidate: RefreshTokenOrder | undefined, held: RefreshTokenOrder | undefined): boolean;
  end(session: EndedSession): void;
  isEnded(token: RefreshTokenOrder | undefined): boolean;
}

const UNORDERED_WARNING =
  '[passflow] A refresh token carries no iat claim: it is never taken over an ordered one, and cross-tab adoption falls back to fingerprints';

export function createRefreshLineage(
  warn: (message: string) => void = (message) => getDefaultLogger().warn(message),
): RefreshLineage {
  // Per session (sid; "" for tokens without one): the newest second a retired token was issued
  // in, and the tokens of that second retired so far. Everything of that session issued before it
  // is older than a token this tab saw replaced. Map order is recency of retirement.
  const floors = new Map<string, { floor: number; atFloor: Set<string>; full: boolean }>();
  // Unordered tokens (no iat) retired: the same bound and fail-safe.
  const retiredUnordered = new Set<string>();
  let unorderedFull = false;
  const ended: EndedSession[] = [];
  let warnedUnordered = false;

  const noteUnordered = (): void => {
    if (warnedUnordered) return;
    warnedUnordered = true;
    warn(UNORDERED_WARNING);
  };

  const addBounded = (set: Set<string>, fp: string): boolean => {
    if (set.has(fp)) return true;
    if (set.size >= TIE_MEMORY) return false;
    set.add(fp);
    return true;
  };

  const retire = (token: RefreshTokenOrder | undefined): void => {
    if (!token) return;
    if (token.iat === undefined) {
      if (!addBounded(retiredUnordered, token.fp)) unorderedFull = true;
      return;
    }
    const key = token.sid ?? '';
    let entry = floors.get(key);
    if (!entry || token.iat > entry.floor) {
      entry = { floor: token.iat, atFloor: new Set(), full: false };
    }
    floors.delete(key);
    floors.set(key, entry);
    if (floors.size > SESSION_MEMORY) {
      const oldest = floors.keys().next().value;
      if (oldest !== undefined) floors.delete(oldest);
    }
    if (token.iat < entry.floor) return;
    if (!addBounded(entry.atFloor, token.fp)) entry.full = true;
  };

  const isRetired = (token: RefreshTokenOrder | undefined): boolean => {
    if (!token) return false;
    if (token.iat === undefined) {
      return unorderedFull || retiredUnordered.has(token.fp);
    }
    const entry = floors.get(token.sid ?? '');
    if (!entry || token.iat > entry.floor) return false;
    if (token.iat < entry.floor) return true;
    return entry.full || entry.atFloor.has(token.fp);
  };

  const sameUser = (a: RefreshTokenOrder, b: RefreshTokenOrder): boolean => !a.sub || !b.sub || a.sub === b.sub;

  const isEnded = (token: RefreshTokenOrder | undefined): boolean => {
    if (!token) return false;
    return ended.some(
      (session) =>
        session.fp === token.fp ||
        (session.iat !== undefined &&
          token.iat !== undefined &&
          sameUser(session, token) &&
          session.sid === token.sid &&
          token.iat < session.iat),
    );
  };

  const isAfter = (token: RefreshTokenOrder, ref: RefreshTokenOrder): boolean => {
    if (token.fp === ref.fp) return false;
    if (token.iat === undefined) {
      noteUnordered();
      // Never over an ordered token; among unordered ones, a token not seen replaced (the
      // fingerprint fallback).
      return ref.iat === undefined && !isRetired(token);
    }
    if (ref.iat === undefined) return true;
    if (token.iat !== ref.iat) return token.iat > ref.iat;
    // Same second: the claims cannot order them. Another session's token never wins a tie. This
    // session's does only when `ref` is known retired and `token` is not: otherwise `token` may
    // be a link before `ref` that this tab never saw replaced.
    return token.sid === ref.sid && isRetired(ref) && !isRetired(token);
  };

  const isForward = (candidate: RefreshTokenOrder | undefined, held: RefreshTokenOrder | undefined): boolean => {
    if (!candidate) return false;
    if (isEnded(candidate) || isRetired(candidate)) return false;
    if (!held) {
      if (candidate.iat === undefined) noteUnordered();
      return true;
    }
    return isAfter(candidate, held);
  };

  const end = (session: EndedSession): void => {
    // One entry per session: the latest end of it.
    const index = ended.findIndex(
      (each) => each.fp === session.fp || (each.sid !== undefined && each.sid === session.sid && sameUser(each, session)),
    );
    if (index !== -1) {
      const known = ended[index];
      if (known?.iat !== undefined && (session.iat === undefined || known.iat > session.iat)) {
        return;
      }
      ended.splice(index, 1);
    }
    ended.push({ ...session });
    if (ended.length > ENDED_MEMORY) ended.shift();
  };

  return { retire, isRetired, isAfter, isForward, end, isEnded };
}
