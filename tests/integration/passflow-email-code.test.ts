import { describe, expect, test } from 'vitest';
import { PassflowEvent } from '../../lib/index';
import { CODE_STEP, harness, OTP, PASSWORD, TFA } from '../helpers/email-code-harness';

describe('resetPassword token routing through Passflow', () => {
  const cases = [
    {
      name: 'explicit token beats both URL sources',
      explicit: 'explicit',
      search: '?token=search',
      hash: '#/password/reset?token=hash',
      expected: 'explicit',
    },
    {
      name: 'search beats hash',
      explicit: undefined,
      search: '?token=search',
      hash: '#/password/reset?token=hash',
      expected: 'search',
    },
    {
      name: 'hash router token is used without a search token',
      explicit: undefined,
      search: '',
      hash: '#/password/reset?token=hash',
      expected: 'hash',
    },
    {
      name: 'null current URL preserves an undefined token',
      explicit: undefined,
      search: '',
      hash: '',
      expected: undefined,
      noUrl: true,
    },
    { name: 'no token anywhere preserves an undefined token', explicit: undefined, search: '', hash: '', expected: undefined },
  ];
  test.each(cases)('TEST-27 REQ-24 REQ-22 $name', async ({ explicit, search, hash, expected, noUrl }) => {
    const h = harness();
    h.platform.getCurrentUrl.mockReturnValue(
      noUrl
        ? null
        : {
            origin: 'https://app.example',
            hostname: 'app.example',
            pathname: '/password/reset',
            href: `https://app.example/password/reset${search}${hash}`,
            search,
            hash,
          },
    );

    const result = await h.sdk.resetPassword(PASSWORD, undefined, explicit);

    expect(result).toBe(CODE_STEP);
    expect(h.wire('/auth/password/change')).toHaveLength(1);
    expect(h.wire('/auth/password/change')[0].headers.Authorization).toBe(`Bearer ${expected}`);
  });
});

describe('email completion through the facade and event store', () => {
  // TEST-13 / TEST-09 / REQ-22: exercise facade behavior rather than spying on
  // AuthService delegation, which would only assert an implementation detail.
  test('REQ-22 verifyEmailCode returns the answer and exposes the required second-factor state', async () => {
    const h = harness();
    await h.start('sign-in');
    h.validateAnswer(TFA);
    h.clearEvents();

    const result = await h.sdk.verifyEmailCode(OTP);

    expect(result).toBe(TFA);
    expect(h.sdk.isTwoFactorVerificationRequired()).toBe(true);
    expect(h.names()).toEqual([PassflowEvent.TwoFactorRequired]);
  });
});
