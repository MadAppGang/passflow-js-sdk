/// <reference types="vitest" />

import { describe, expect, test } from 'vitest';
import { parseChallengeBody, parseChallengeHeader, parseUpgradeChallenge } from '../../lib/upgrade/challenge';

/** Convenience: builds the header getter `parseUpgradeChallenge` expects. */
const headers = (map: Record<string, string>) => (name: string) => map[name.toLowerCase()];

describe('parseChallengeHeader', () => {
  test('parses the acr_values challenge RequireAuthLevel emits', () => {
    const challenge = parseChallengeHeader('Bearer error="insufficient_user_authentication", acr_values="2"', 401);

    expect(challenge).toEqual({ acrValues: '2', maxAge: undefined, status: 401 });
  });

  test('parses the max_age challenge RequireFreshAuth emits', () => {
    const challenge = parseChallengeHeader('Bearer error="insufficient_user_authentication", max_age=300', 401);

    expect(challenge).toEqual({ acrValues: undefined, maxAge: 300, status: 401 });
  });

  test('parses both parameters together', () => {
    const challenge = parseChallengeHeader('Bearer error="insufficient_user_authentication", acr_values="3", max_age=60', 401);

    expect(challenge).toEqual({ acrValues: '3', maxAge: 60, status: 401 });
  });

  test('accepts a space-separated acr_values list', () => {
    const challenge = parseChallengeHeader('Bearer error="insufficient_user_authentication", acr_values="2 3"', 401);

    expect(challenge?.acrValues).toBe('2 3');
  });

  // The whole point of the module: an ordinary 401 must NOT read as a upgrade,
  // or the SDK elevates when it should be re-authenticating.
  test('a bare Bearer challenge is not a upgrade', () => {
    expect(parseChallengeHeader('Bearer', 401)).toBeUndefined();
    expect(parseChallengeHeader('Bearer realm="api"', 401)).toBeUndefined();
  });

  test('a different Bearer error is not a upgrade', () => {
    expect(parseChallengeHeader('Bearer error="invalid_token"', 401)).toBeUndefined();
    expect(parseChallengeHeader('Bearer error="insufficient_scope", scope="admin"', 401)).toBeUndefined();
  });

  test('a non-Bearer scheme is ignored', () => {
    expect(parseChallengeHeader('Basic realm="api"', 401)).toBeUndefined();
  });

  test('missing or empty headers are ignored', () => {
    expect(parseChallengeHeader(undefined, 401)).toBeUndefined();
    expect(parseChallengeHeader(null, 401)).toBeUndefined();
    expect(parseChallengeHeader('', 401)).toBeUndefined();
  });

  test('is case-insensitive on the scheme and parameter names', () => {
    const challenge = parseChallengeHeader('bearer ERROR="insufficient_user_authentication", ACR_VALUES="2"', 401);

    expect(challenge?.acrValues).toBe('2');
  });

  test('ignores a non-numeric or non-positive max_age', () => {
    expect(parseChallengeHeader('Bearer error="insufficient_user_authentication", max_age=abc', 401)?.maxAge).toBeUndefined();
    expect(parseChallengeHeader('Bearer error="insufficient_user_authentication", max_age=0', 401)?.maxAge).toBeUndefined();
    expect(parseChallengeHeader('Bearer error="insufficient_user_authentication", max_age=-5', 401)?.maxAge).toBeUndefined();
  });

  // Repeated parsing must not be affected by the module-level regex's lastIndex.
  test('is stable across repeated calls', () => {
    const header = 'Bearer error="insufficient_user_authentication", acr_values="2"';

    expect(parseChallengeHeader(header, 401)).toEqual(parseChallengeHeader(header, 401));
  });
});

describe('parseChallengeBody', () => {
  test('parses the ADR-2 403 upgrade_required body', () => {
    const challenge = parseChallengeBody({ error: 'upgrade_required', acr_values: '2', max_age: 300 }, 403);

    expect(challenge).toEqual({ acrValues: '2', maxAge: 300, status: 403 });
  });

  test('parses a body carrying only the error code', () => {
    const challenge = parseChallengeBody({ error: 'upgrade_required' }, 403);

    expect(challenge).toEqual({ acrValues: undefined, maxAge: undefined, status: 403 });
  });

  test('ignores unrelated bodies', () => {
    expect(parseChallengeBody({ error: 'access_denied' }, 403)).toBeUndefined();
    expect(parseChallengeBody({}, 403)).toBeUndefined();
    expect(parseChallengeBody(undefined, 403)).toBeUndefined();
    expect(parseChallengeBody('upgrade_required', 403)).toBeUndefined();
  });
});

describe('parseUpgradeChallenge', () => {
  test('prefers the header when both are present', () => {
    const challenge = parseUpgradeChallenge(
      403,
      headers({ 'www-authenticate': 'Bearer error="insufficient_user_authentication", acr_values="3"' }),
      { error: 'upgrade_required', acr_values: '2' },
    );

    expect(challenge?.acrValues).toBe('3');
  });

  test('falls back to the body when the header is absent', () => {
    const challenge = parseUpgradeChallenge(403, headers({}), { error: 'upgrade_required', acr_values: '2' });

    expect(challenge).toEqual({ acrValues: '2', maxAge: undefined, status: 403 });
  });

  test('only 401 and 403 can carry a challenge', () => {
    const header = headers({ 'www-authenticate': 'Bearer error="insufficient_user_authentication", acr_values="2"' });

    expect(parseUpgradeChallenge(401, header)).toBeDefined();
    expect(parseUpgradeChallenge(403, header)).toBeDefined();
    expect(parseUpgradeChallenge(200, header)).toBeUndefined();
    expect(parseUpgradeChallenge(500, header)).toBeUndefined();
  });
});
