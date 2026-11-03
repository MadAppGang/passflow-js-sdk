import { describe, expect, expectTypeOf, test } from 'vitest';
import {
  isEmailVerificationStep,
  type PassflowAuthorizationResponse,
  type PassflowEmailCodePayload,
  type PassflowEmailVerificationOperation,
  type PassflowEmailVerificationStep,
  PassflowEvent,
  type PassflowEventPayload,
  type PassflowOperation,
} from '../../lib/index';
import { VALID_TOKENS } from '../helpers/fixtures';

describe('email verification public contract', () => {
  // TEST-01 / REQ-1: the flag alone discriminates; message must not be required at runtime.
  test.each([
    ['code step', { email_verification_required: true, message: 'Code sent', challenge_id: 'c' }, true],
    ['link step', { email_verification_required: true, message: 'Link sent' }, true],
    ['missing message', { email_verification_required: true }, true],
    ['empty challenge', { email_verification_required: true, message: '', challenge_id: '' }, true],
    ['tokens', VALID_TOKENS, false],
    ['second factor', { tfa_token: 'tfa' }, false],
    ['string flag', { email_verification_required: 'true' }, false],
    ['false flag', { email_verification_required: false }, false],
    ['numeric flag', { email_verification_required: 1 }, false],
    ['null flag', { email_verification_required: null }, false],
    ['empty object', {}, false],
    ['boolean false', false, false],
    ['boolean true', true, false],
    ['null', null, false],
    ['undefined', undefined, false],
    ['string', 'email_verification_required', false],
    ['number', 1, false],
  ])('TEST-01 REQ-1 returns the expected guard result for %s', (_name, input, expected) => {
    expect(isEmailVerificationStep(input)).toBe(expected);
  });

  test('TEST-02 REQ-1 REQ-5 exposes usable public types and the stable event literal', () => {
    const step: PassflowEmailVerificationStep = { email_verification_required: true, message: 'Check your email' };
    const code: PassflowEmailCodePayload = { challenge_id: 'c', otp: '000123' };
    const operations: PassflowEmailVerificationOperation[] = ['sign-up', 'sign-in', 'reset-password'];
    const operation: PassflowOperation = 'email-verification.complete';
    const response: PassflowAuthorizationResponse = { email_verification_required: true, message: step.message };
    const payload: PassflowEventPayload[PassflowEvent.EmailVerificationRequired] = {
      operation: operations[0]!,
      email: 'a@example.com',
      challengeId: code.challenge_id,
    };
    const unknownResponse: unknown = response;
    if (isEmailVerificationStep(unknownResponse)) {
      expectTypeOf(unknownResponse).toEqualTypeOf<PassflowEmailVerificationStep>();
    }
    expectTypeOf<PassflowEmailVerificationStep['message']>().toEqualTypeOf<string>();
    expect(PassflowEvent.EmailVerificationRequired).toBe('email-verification:required');
    expect(payload).toEqual({ operation: 'sign-up', email: 'a@example.com', challengeId: 'c' });
    expect(operation).toBe('email-verification.complete');
    expect(code.otp).toBe('000123');
  });
});
