// Ported from passflow-saas-portal src/state/refresh-lineage.test.ts (PFL-764 round 18-19).
// Refresh tokens are ordered by their own claims (sub, iat in seconds, sid), not by a remembered
// list of retired fingerprints, so no rotation count can make an old token adoptable again.
import { describe, expect, it, vi } from 'vitest';
import { ENDED_MEMORY, SESSION_MEMORY, TIE_MEMORY } from '../../lib/refresh/constants';
import { createRefreshLineage, fingerprint, orderOf, type RefreshTokenOrder } from '../../lib/refresh/lineage';
import { jwt, token } from './jwt';

describe('fingerprint', () => {
  it('should be the portal cyrb53 fingerprint, as lowercase hex (rollout interop)', () => {
    // Values computed with the portal's refresh-lineage.ts fingerprint (seeds 0xdeadbeef, 0x41c6ce57).
    expect(fingerprint('')).toBeUndefined();
    expect(fingerprint(undefined)).toBeUndefined();
    expect(fingerprint('a')).toBe('1c2ba782c97901');
    expect(fingerprint('refresh-token')).toBe('1c2b4185e11bc0');
    expect(fingerprint('eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyLTEifQ.sig')).toBe('138a3eca9aa53e');
    expect(fingerprint('a')).toMatch(/^[0-9a-f]+$/);
    expect(fingerprint('refresh-token-1')).not.toBe(fingerprint('refresh-token-2'));
  });
});

describe('orderOf', () => {
  it('should read sub, sid and iat from the refresh token, with its fingerprint', () => {
    const raw = jwt({ sub: 'user-1', sid: 's1', iat: 1700000000, jti: 'x' });
    expect(orderOf(raw)).toEqual({
      fp: fingerprint(raw),
      sub: 'user-1',
      sid: 's1',
      iat: 1700000000,
    });
  });

  it('should leave a token that is no JWT, or has no numeric iat, unordered', () => {
    expect(orderOf('opaque')).toEqual({ fp: fingerprint('opaque') });
    expect(orderOf(jwt({ sub: 'user-1', iat: 'soon' }))?.iat).toBeUndefined();
    expect(orderOf(undefined)).toBeUndefined();
  });
});

describe('refresh lineage ordered by iat', () => {
  it('should move forward to a later second and never back to an earlier one, whatever was remembered', () => {
    const lineage = createRefreshLineage(() => undefined);
    const old = token(100);
    const held = token(200);
    const later = token(300);
    expect(lineage.isForward(later, held)).toBe(true);
    expect(lineage.isForward(old, held)).toBe(false);
    expect(lineage.isForward(held, held)).toBe(false);
    expect(lineage.isForward(held, undefined)).toBe(true);
  });

  it('should take a same-second token forward until it is retired, and clear the tie set at a newer second', () => {
    const lineage = createRefreshLineage(() => undefined);
    const a = token(100);
    const b = token(100);
    const c = token(100);
    // Round 19: a tie is forward only once the held token is known retired; before that the
    // order of a and b is unknown.
    expect(lineage.isForward(b, a)).toBe(false);
    lineage.retire(a);
    expect(lineage.isForward(b, a)).toBe(true);
    expect(lineage.isRetired(a)).toBe(true);
    expect(lineage.isRetired(b)).toBe(false);
    expect(lineage.isForward(a, c)).toBe(false);
    // A strictly newer second: everything before it is older.
    const d = token(101);
    lineage.retire(c);
    lineage.retire(d);
    expect(lineage.isRetired(a)).toBe(true);
    expect(lineage.isRetired(b)).toBe(true);
    expect(lineage.isRetired(token(102))).toBe(false);
  });

  // Round 19. A tab never replaces a token it holds with a same-second one it has not seen
  // proven newer: the held token must be known retired first. Nor does the tie retire anything.
  it('should never take a same-second token over a held one that is not known retired, nor retire the held one', () => {
    const lineage = createRefreshLineage(() => undefined);
    const rt1 = token(100);
    const rt2 = token(100);
    expect(lineage.isAfter(rt1, rt2)).toBe(false);
    expect(lineage.isAfter(rt2, rt1)).toBe(false);
    expect(lineage.isForward(rt1, rt2)).toBe(false);
    expect(lineage.isRetired(rt2)).toBe(false);
    // RT1 refused as already used: RT2, held, is then after it.
    lineage.retire(rt1);
    expect(lineage.isAfter(rt2, rt1)).toBe(true);
    expect(lineage.isForward(rt1, rt2)).toBe(false);
  });

  // Round 19. Retirement is per session: retiring a token of one session says nothing about
  // another session's tokens (a sign-in again of the same user, issued in an earlier second).
  it("should keep each session's retired floor to that session", () => {
    const lineage = createRefreshLineage(() => undefined);
    lineage.retire(token(200, 's1'));
    expect(lineage.isRetired(token(100, 's1'))).toBe(true);
    expect(lineage.isRetired(token(100, 's2'))).toBe(false);
    expect(lineage.isRetired(token(200, 's2'))).toBe(false);
    lineage.retire(token(150, 's2'));
    expect(lineage.isRetired(token(100, 's2'))).toBe(true);
    expect(lineage.isRetired(token(199, 's1'))).toBe(true);
  });

  it(`should remember retired floors for at most ${SESSION_MEMORY} sessions, the least recently retired forgotten first`, () => {
    const lineage = createRefreshLineage(() => undefined);
    lineage.retire(token(200, 'first'));
    for (let i = 0; i < SESSION_MEMORY - 1; i++) {
      lineage.retire(token(200, `other-${i}`));
    }
    expect(lineage.isRetired(token(100, 'first'))).toBe(true);
    lineage.retire(token(200, 'one-more'));
    expect(lineage.isRetired(token(100, 'first'))).toBe(false);
    expect(lineage.isRetired(token(100, 'one-more'))).toBe(true);
  });

  it('should never let another session win a same-second tie', () => {
    const lineage = createRefreshLineage(() => undefined);
    expect(lineage.isForward(token(100, 's2'), token(100, 's1'))).toBe(false);
    expect(lineage.isForward(token(101, 's2'), token(100, 's1'))).toBe(true);
  });

  it(`should count every token of the floor second as retired once more than ${TIE_MEMORY} are (fail safe)`, () => {
    const lineage = createRefreshLineage(() => undefined);
    for (let i = 0; i <= TIE_MEMORY; i++) lineage.retire(token(100));
    expect(lineage.isRetired(token(100))).toBe(true);
    expect(lineage.isRetired(token(101))).toBe(false);
    lineage.retire(token(101));
    expect(lineage.isRetired(token(101))).toBe(false);
  });

  it('should end a session up to its ended token: a late answer for it is refused, a later token or a new sign-in is not', () => {
    const lineage = createRefreshLineage(() => undefined);
    const before = token(100);
    const ended = token(200);
    lineage.end({ ...ended, sub: 'user-1' });
    expect(lineage.isEnded(ended)).toBe(true);
    expect(lineage.isEnded(before)).toBe(true);
    // A tab behind on the rotation said so: the session's later tokens live.
    expect(lineage.isEnded(token(300))).toBe(false);
    // Another session of the same user (a sign-in again), even earlier.
    expect(lineage.isEnded(token(100, 's2'))).toBe(false);
    expect(lineage.isForward(before, undefined)).toBe(false);
  });

  it('should end by fingerprint alone a session named without claims (a tab on older code)', () => {
    const lineage = createRefreshLineage(() => undefined);
    const ended = token(200);
    lineage.end({ fp: ended.fp });
    expect(lineage.isEnded(ended)).toBe(true);
    expect(lineage.isEnded(token(100))).toBe(false);
  });

  it(`should remember at most ${ENDED_MEMORY} ended sessions, one entry per session`, () => {
    const lineage = createRefreshLineage(() => undefined);
    const first = token(100, 'first');
    lineage.end(first);
    lineage.end(token(150, 'first'));
    for (let i = 0; i < ENDED_MEMORY - 1; i++) {
      lineage.end(token(100, `other-${i}`));
    }
    expect(lineage.isEnded(first)).toBe(true);
    lineage.end(token(100, 'one-more'));
    expect(lineage.isEnded(first)).toBe(false);
  });

  it('should keep the later end of one session when an earlier end of it arrives late', () => {
    const lineage = createRefreshLineage(() => undefined);
    const later = token(300);
    lineage.end(later);
    lineage.end(token(200));
    expect(lineage.isEnded(token(250))).toBe(true);
    expect(lineage.isEnded(later)).toBe(true);
  });

  it('should never take an unordered token over an ordered one, fall back to fingerprints among unordered ones, and warn once', () => {
    const warn = vi.fn();
    const lineage = createRefreshLineage(warn);
    const ordered = token(100);
    const a: RefreshTokenOrder = token(undefined);
    const b: RefreshTokenOrder = token(undefined);
    expect(lineage.isForward(a, ordered)).toBe(false);
    expect(lineage.isForward(ordered, a)).toBe(true);
    expect(lineage.isForward(b, a)).toBe(true);
    lineage.retire(b);
    expect(lineage.isForward(b, a)).toBe(false);
    expect(warn).toHaveBeenCalledTimes(1);
  });
});
