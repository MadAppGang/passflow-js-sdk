// Consumer fixture for scripts/check-types-consumer.mjs (ESM, the `import` condition).
// It touches representative exports by value and by type, so the shipped declarations are
// resolved and checked (skipLibCheck: false) under node16, nodenext and bundler.
import {
  type ErrorPayload,
  isEmailVerificationStep,
  M2MClient,
  type M2MClientConfig,
  Passflow,
  type PassflowAuthorizationResponse,
  type PassflowConfig,
  type PassflowEmailCodePayload,
  type PassflowEmailVerificationOperation,
  type PassflowEmailVerificationStep,
  PassflowEvent,
  type PassflowEventPayload,
  type PassflowOperation,
  PassflowRefreshError,
  type PassflowSubscriber,
  parseUpgradeChallenge,
  REFRESH_AUTH_FAILURE_IDS,
  type RefreshCoordinator,
  RefreshErrorId,
  SDK_VERSION,
  type SessionExpiredReason,
  type Token,
  TokenDeliveryMode,
  type UpgradeChallenge,
  UpgradeCommitInterruptedError,
} from '@passflow/core';

const config: PassflowConfig = { appId: 'app', url: 'https://example.com' };
export const pf: Passflow = new Passflow(config);
export const mode: TokenDeliveryMode = TokenDeliveryMode.JsonBody;
export const m2mConfig: M2MClientConfig = { url: 'https://example.com', clientId: 'id', clientSecret: 's' };
export const m2m: M2MClient = new M2MClient(m2mConfig);
export const sub: PassflowSubscriber = { onAuthChange: () => undefined };
export const ev: PassflowEvent = PassflowEvent.SignIn;
export const tok = null as Token | null;
export const ch: UpgradeChallenge | undefined = parseUpgradeChallenge(401, () => null);
export const v: string = SDK_VERSION;

// Multi-tab-safe token refresh (PFL-792): config, coordinator transports, events, errors.
declare const coordinator: RefreshCoordinator;
export const refreshConfig: PassflowConfig = { appId: 'app', refreshCoordination: coordinator, refreshStrikes: 3 };
export const localConfig: PassflowConfig = { refreshCoordination: 'none' };
export const failing: PassflowEventPayload[PassflowEvent.RefreshFailing] = { since: 0, origin: 'other-tab' };
export const reason: SessionExpiredReason = 'successor_timeout';
export const op: PassflowOperation = 'refresh';
export const errPayload: ErrorPayload = {
  message: 'm',
  operation: 'refresh',
  source: 'pre-request',
  refresh: { classification: 'transient', willRetry: true, strikes: 0, maxStrikes: 3 },
};
export const refreshError: PassflowRefreshError = new PassflowRefreshError(RefreshErrorId.unavailable, { nextRetryAt: 1 });
export const refreshErrorId: RefreshErrorId = refreshError.id;
export const interrupted: UpgradeCommitInterruptedError = new UpgradeCommitInterruptedError('lock-timeout');
export const authIds: readonly string[] = REFRESH_AUTH_FAILURE_IDS;
export const dispose: () => void = () => pf.dispose();
export const signedOut: PassflowEventPayload[PassflowEvent.SignOut] = { origin: 'this-tab', userId: 'u' };

// Email verification code step (PFL-724): guard, step and code types, event, verifyEmailCode.
declare const answer: PassflowAuthorizationResponse;
export const step: PassflowEmailVerificationStep | undefined = isEmailVerificationStep(answer) ? answer : undefined;
export const emailOp: PassflowEmailVerificationOperation = 'sign-up';
export const emailEvent: PassflowEventPayload[PassflowEvent.EmailVerificationRequired] = {
  email: 'a@example.com',
  challengeId: 'c',
  operation: emailOp,
};
export const emailEv: PassflowEvent = PassflowEvent.EmailVerificationRequired;
export const codePayload: PassflowEmailCodePayload = { challenge_id: 'c', otp: '123456' };
export const verified: Promise<PassflowAuthorizationResponse> = pf.verifyEmailCode(codePayload);
