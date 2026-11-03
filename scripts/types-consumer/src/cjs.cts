// Consumer fixture for scripts/check-types-consumer.mjs (CJS, the `require` condition).
// A .cts file under node16 resolves @passflow/core through `exports.require.types`, which
// must not point at a file TypeScript reads as ESM-only (TS1479).
import {
  APP_SECRET_NAMES,
  type AppSecretName,
  isEmailVerificationStep,
  isMaskedSecret,
  M2MClient,
  type MaskedSecret,
  Passflow,
  type PassflowAuthorizationResponse,
  type PassflowConfig,
  type PassflowEmailCodePayload,
  type PassflowEmailVerificationOperation,
  type PassflowEmailVerificationStep,
  PassflowEvent,
  PassflowRefreshError,
  RefreshErrorId,
  SETTINGS_MASKED_VALUE_UNKNOWN_ERROR_ID,
  TokenDeliveryMode,
} from '@passflow/core';

const config: PassflowConfig = { appId: 'app' };
export const pf: Passflow = new Passflow(config);
export const mode: TokenDeliveryMode = TokenDeliveryMode.Cookie;
export const m2m: M2MClient = new M2MClient({ url: 'u', clientId: 'c', clientSecret: 's' });
export const refreshConfig: PassflowConfig = { refreshCoordination: 'web-locks', refreshStrikes: 2 };
export const refreshError: PassflowRefreshError = new PassflowRefreshError(RefreshErrorId.disposed);
export const dispose: () => void = () => pf.dispose();

// Email verification code step (PFL-724).
declare const answer: PassflowAuthorizationResponse;
export const step: PassflowEmailVerificationStep | undefined = isEmailVerificationStep(answer) ? answer : undefined;
export const emailOp: PassflowEmailVerificationOperation = 'reset-password';
export const emailEv: PassflowEvent = PassflowEvent.EmailVerificationRequired;
export const codePayload: PassflowEmailCodePayload = { challenge_id: 'c', otp: '123456' };
export const verified: Promise<PassflowAuthorizationResponse> = pf.verifyEmailCode(codePayload);

// Admin settings secrets (PFL-770).
export const secretNames: readonly AppSecretName[] = APP_SECRET_NAMES;
export const masked: MaskedSecret = 'mask://********/0123456789abcdef';
export const isMasked: boolean = isMaskedSecret(masked);
export const maskedErrorId: string = SETTINGS_MASKED_VALUE_UNKNOWN_ERROR_ID;
