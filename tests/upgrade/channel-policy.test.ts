// @vitest-environment node
// Coverage map: REQ-2 (FR2), REQ-13 (Policy-diagnostic), REQ-33 (C19), REQ-34 (C20), REQ-35 (C21), REQ-36 (C22), REQ-43 (C29), REQ-44 (C30), REQ-64 (C21a), REQ-65 (C22a)
import { describe, expect, test } from 'vitest';
import { parseMaxAge, parseUpgradeChallenge, readUpgradeChallenge } from '../../lib/upgrade/challenge';

const header = (params = '') => `Bearer error="insufficient_user_authentication"${params ? ', ' + params : ''}`;
const input = (h?: string, body?: unknown, status = 401) => ({
  status,
  getHeader: (name: string) => (name.toLowerCase() === 'www-authenticate' ? h : undefined),
  body,
});
const body = (acr_values?: string, max_age?: number) => ({ error: 'upgrade_required', acr_values, max_age });

describe('amendment channel policy', () => {
  test('REQ-C19 REQ-C29 joins max-over-min, preserves channels and the shipped three-argument API', () => {
    const value = input(header('acr_values="2 3"'), body('1'));
    const reading = readUpgradeChallenge(value);
    expect(reading.challenge).toMatchObject({ requiredLevel: 2, acrValues: '2 3', channels: ['header', 'body'] });
    expect(reading.diagnostics.filter((d) => d.reason === 'channels-disagree')).toHaveLength(1);
    expect(parseUpgradeChallenge(value.status, value.getHeader, value.body)).toEqual(reading.challenge);
  });

  test('REQ-C20 merges independent assurance and freshness axes', () => {
    expect(readUpgradeChallenge(input(header('acr_values="3"'), body(undefined, 60))).challenge).toMatchObject({
      requiredLevel: 3,
      maxAge: 60,
    });
  });

  test.each([
    ['C21', 'max_age=0', body(undefined, 300), 'max_age', { maxAge: 300 }],
    ['C21a', 'acr_values="0"', body('2'), 'acr_values', { requiredLevel: 2, acrValues: '2' }],
  ] as const)('REQ-%s ignores zero without lowering the other channel', (_, params, b, field, expected) => {
    const result = readUpgradeChallenge(input(header(params), b));
    expect(result.challenge).toMatchObject(expected);
    expect(result.diagnostics.filter((d) => d.reason === 'zero-constraint-ignored')).toEqual([
      expect.objectContaining({ detail: expect.objectContaining({ field }) }),
    ]);
  });

  test.each([
    ['C22', 'urn:example:gold', '2', 2],
    ['C22a', '2gold', '1', 1],
    ['C22a', '-1', '2', 2],
    ['C22a', '2.0', '2', 2],
    ['C22a', '+2', '2', 2],
    ['C22a', '1e2', '2', 2],
  ])('REQ-%s discards opaque/prefix token %s, not the numeric body', (_, raw, b, level) => {
    const result = readUpgradeChallenge(input(header(`acr_values="${raw}"`), body(b)));
    expect(result.challenge).toMatchObject({ requiredLevel: level, acrValues: b, channels: ['header', 'body'] });
    expect(result.diagnostics.filter((d) => d.reason === 'channels-unorderable')).toEqual([
      expect.objectContaining({ detail: expect.objectContaining({ header: raw }) }),
    ]);
  });

  test.each([
    ['02', '1', 2, '02'],
    ['2 3', '1', 2, '2 3'],
    ['2 3', '2', 2, '2 3'],
    ['9', '10', 10, '10'],
    ['urn:example:gold 2', '1', 2, 'urn:example:gold 2'],
    ['0 2', '2', 2, '2'],
    ['4', '3', 4, '4'],
  ])('REQ-C19 whole-token numeric list %s vs %s yields %i', (h, b, level, raw) => {
    expect(readUpgradeChallenge(input(header(`acr_values="${h}"`), body(b))).challenge).toMatchObject({
      requiredLevel: level,
      acrValues: raw,
    });
  });

  test('REQ-C23 strict header policy ignores a stronger body and disagreement diagnostics', () => {
    const result = readUpgradeChallenge(input(header('acr_values="2"'), body('3')), { requireChallengeChannel: 'header' });
    expect(result.challenge).toMatchObject({ requiredLevel: 2, acrValues: '2', channels: ['header'] });
    expect(result.diagnostics.some((d) => d.reason === 'channels-disagree')).toBe(false);
    expect(readUpgradeChallenge(input(undefined, body('2')), { requireChallengeChannel: 'header' }).challenge).toBeUndefined();
  });

  test.each([
    [undefined, { kind: 'absent' }],
    ['abc', { kind: 'invalid', raw: 'abc' }],
    [-1, { kind: 'invalid', raw: -1 }],
    [0, { kind: 'invalid', raw: 0 }],
    [300, { kind: 'valid', value: 300 }],
  ])('REQ-C30 parseMaxAge(%s) retains absent/invalid/valid distinction', (raw, expected) => {
    expect(parseMaxAge(raw)).toEqual(expected);
  });

  test.each([200, 302, 400, 404, 500])('REQ-FR2 status %i never becomes an upgrade challenge', (status) => {
    const result = readUpgradeChallenge(input(header('acr_values="2"'), body('3'), status));
    expect(result.challenge).toBeUndefined();
    expect(result.diagnostics).toEqual([]);
  });

  test('REQ-C5 accepts body-only challenges by default, without calling them a fallback', () => {
    expect(readUpgradeChallenge(input(undefined, body('2'), 403)).challenge).toMatchObject({
      status: 403,
      requiredLevel: 2,
      acrValues: '2',
      channels: ['body'],
    });
  });
});
