/// <reference types="vitest" />

/**
 * Admin settings secrets (PFL-770): write-only app secrets and masked server settings values.
 * Imports come from the package entry point so the test also proves these names are exported.
 */

import { describe, expect, expectTypeOf, test } from 'vitest';
import type { AppSecretName, AppSettings, MaskedSecret } from '../../lib/index';
import {
  APP_SECRET_NAMES,
  isMaskedSecret,
  MASKED_SECRET_PREFIX,
  SETTINGS_MASKED_VALUE_UNKNOWN_ERROR_ID,
} from '../../lib/index';

describe('app secrets', () => {
  test('APP_SECRET_NAMES lists the three clearable secrets in order', () => {
    expect(APP_SECRET_NAMES).toEqual(['debug_otp_code_for_registration', 'fcm_server_key', 'webpush_vapid_private_key']);
  });

  test('APP_SECRET_NAMES cannot be changed at runtime', () => {
    expect(Object.isFrozen(APP_SECRET_NAMES)).toBe(true);
  });

  test('APP_SECRET_NAMES is typed as the AppSecretName union', () => {
    expectTypeOf(APP_SECRET_NAMES).toEqualTypeOf<readonly AppSecretName[]>();
    expectTypeOf<AppSecretName>().toEqualTypeOf<
      'debug_otp_code_for_registration' | 'fcm_server_key' | 'webpush_vapid_private_key'
    >();
  });

  test('AppSettings carries the debug OTP code as write-only and its presence as read-only', () => {
    expectTypeOf<AppSettings['debug_otp_code_for_registration']>().toEqualTypeOf<string | undefined>();
    expectTypeOf<AppSettings['debug_otp_code_set']>().toEqualTypeOf<boolean | undefined>();
  });
});

describe('masked server settings secrets', () => {
  test('constants hold the server values', () => {
    expect(MASKED_SECRET_PREFIX).toBe('mask://');
    expect(SETTINGS_MASKED_VALUE_UNKNOWN_ERROR_ID).toBe('error.server.update.settings.masked.value.unknown');
  });

  test.each([
    ['mask://********', true],
    ['mask://********/0123456789abcdef', true],
    ['', false],
    ['postgres://user:pass@db:5432/passflow', false],
    ['https://dynamodb.us-east-1.amazonaws.com', false],
    ['MASK://********', false],
    [' mask://********', false],
  ])('isMaskedSecret(%j) is %s', (value, expected) => {
    expect(isMaskedSecret(value)).toBe(expected);
  });

  test.each([undefined, null, 0, 1, true, {}, ['mask://********'], { value: 'mask://********' }])(
    'isMaskedSecret(%j) is false for a non-string',
    (value) => {
      expect(isMaskedSecret(value)).toBe(false);
    },
  );

  test('isMaskedSecret narrows unknown to MaskedSecret', () => {
    const value: unknown = 'mask://********';
    if (isMaskedSecret(value)) {
      expectTypeOf(value).toEqualTypeOf<MaskedSecret>();
    }
    expectTypeOf<MaskedSecret>().toEqualTypeOf<string>();
  });
});
