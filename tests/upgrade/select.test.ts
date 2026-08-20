/// <reference types="vitest" />

import { describe, expect, test } from 'vitest';
import type { UpgradeChallenge } from '../../lib/upgrade/challenge';
import { DEFAULT_UPGRADE_FACTORS, passkeyFactor, recoveryCodesFactor, totpFactor } from '../../lib/upgrade/factors';
import { selectFactors } from '../../lib/upgrade/select';

const challenge = (acrValues?: string, maxAge?: number): UpgradeChallenge => ({
  acrValues,
  maxAge,
  status: 401,
});

/** The factor types offered, in order — the shape every assertion here cares about. */
const order = (acrValues?: string, maxAge?: number) =>
  selectFactors(DEFAULT_UPGRADE_FACTORS, challenge(acrValues, maxAge)).map((f) => f.type);

describe('selectFactors', () => {
  test('leads with passkey for an ordinary challenge', () => {
    expect(order('2')[0]).toBe('passkey');
  });

  test('demotes code factors when AAL3 is demanded — only a passkey reaches it unaided', () => {
    expect(order('3')[0]).toBe('passkey');
    expect(order('3').indexOf('totp')).toBeGreaterThan(0);
  });

  // The asymmetry that drives the whole module: a factor wrongly offered costs a
  // retry, a factor wrongly hidden tells the user to re-authenticate. So an AAL3
  // challenge still offers code factors — the base session may already carry the
  // level — it just does not suggest them.
  test('never drops a factor, even when it cannot reach the demanded level', () => {
    expect(order('3')).toHaveLength(DEFAULT_UPGRADE_FACTORS.length);
    expect(order('3')).toContain('totp');
    expect(order('3')).toContain('recovery_codes');
  });

  test('recovery codes are always last — single-use credentials are an escape hatch', () => {
    for (const acr of [undefined, '1', '2', '3']) {
      expect(order(acr).at(-1)).toBe('recovery_codes');
    }
  });

  test('a max_age-only freshness challenge still orders by ceremony cost', () => {
    expect(order(undefined, 300)).toEqual(['passkey', 'totp', 'recovery_codes']);
  });

  test('a challenge naming no level at all is handled', () => {
    expect(order()).toEqual(['passkey', 'totp', 'recovery_codes']);
  });

  // OIDC acr_values is a space-separated list and satisfying ANY member is
  // enough, so the bar is the LOWEST — "2 3" must not be treated as demanding 3.
  test('takes the lowest level from a space-separated acr_values list', () => {
    expect(order('2 3')[0]).toBe('passkey');
    expect(order('2 3').indexOf('totp')).toBe(1);
  });

  test('ignores unparseable acr_values rather than over-constraining', () => {
    expect(order('gold')).toEqual(['passkey', 'totp', 'recovery_codes']);
  });

  test('does not mutate the caller’s array', () => {
    const input = [totpFactor, passkeyFactor, recoveryCodesFactor];
    const snapshot = [...input];

    selectFactors(input, challenge('2'));

    expect(input).toEqual(snapshot);
  });

  test('returns empty for an empty registry', () => {
    expect(selectFactors([], challenge('2'))).toEqual([]);
  });
});
