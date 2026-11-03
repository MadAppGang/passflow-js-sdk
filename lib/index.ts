// Re-export from API
export * from './api';
// Re-export CLI Authentication API client
export { CLIAuthAPI } from './api/cli-auth';
// Re-export Two-Factor Authentication types (explicitly for clarity)
export type {
  CLIAuthCompleteRequest,
  CLIAuthStatusResponse,
  TwoFactorCompletionOptions,
  TwoFactorConfirmRequest,
  TwoFactorConfirmResponse,
  TwoFactorDisableRequest,
  TwoFactorDisableResponse,
  TwoFactorErrorCode,
  TwoFactorPolicy,
  TwoFactorRecoveryRequest,
  TwoFactorRecoveryResponse,
  TwoFactorRegenerateRequest,
  TwoFactorRegenerateResponse,
  TwoFactorSetupMagicLinkError,
  TwoFactorSetupMagicLinkErrorCode,
  TwoFactorSetupMagicLinkSession,
  TwoFactorSetupMagicLinkValidationResponse,
  TwoFactorSetupResponse,
  TwoFactorStatusResponse,
  TwoFactorTrustedDevice,
  TwoFactorTrustedDevicesResponse,
  TwoFactorVerifyRequest,
  TwoFactorVerifyResponse,
} from './api/model';
// Re-export Two-Factor Authentication API client and service
export { TwoFactorApiClient } from './api/two-factor';
// Re-export constants
export * from './constants';
export type { FetchMiddleware, RegisterOptions } from './interceptors/fetch-registry';
// Re-export the fetch registry: ONE `fetch` patch point, many middlewares,
// reference-counted. Two features that each capture and restore
// `globalThis.fetch` lose one interceptor non-deterministically, which is why
// the global patch (`interceptFetch`) goes through here and never through a
// bare assignment. Teardown is the registry's, not any caller's.
export {
  FETCH_PRIORITY_OIDC,
  FETCH_PRIORITY_UPGRADE,
  FetchMiddlewareContractError,
  fetchRegistryState,
  registerFetchMiddleware,
} from './interceptors/fetch-registry';
export type {
  M2MClientConfig,
  M2MErrorCode,
  M2MErrorResponse,
  M2MRateLimitInfo,
  M2MTokenCache,
  M2MTokenClaims,
  M2MTokenRequestInfo,
  M2MTokenRequestOptions,
  M2MTokenResponse,
  RetryStrategy,
} from './m2m';
// Re-export M2M (Machine-to-Machine) Authentication module
export { M2M_DEFAULTS, M2MClient, M2MConfigError, M2MError, M2MErrorCodes, M2MNetworkError, M2MTokenParseError } from './m2m';
// Export Passflow class
export { Passflow } from './passflow';
// Re-export platform types and WebAdapter for custom adapter implementations
export type {
  AuthCallbackResult,
  CurrentUrlInfo,
  OpenAuthUrlOptions,
  PasskeySupport,
  PlatformAdapter,
  PlatformStorage,
} from './platform';
export { PopupClosedError, WebAdapter, webAdapter } from './platform';
// Multi-tab-safe token refresh (PFL-792): configuration, coordinator transports, event payload
// vocabulary and the errors a refresh caller can receive. The controller itself is internal.
export {
  type EventOrigin,
  PassflowRefreshError,
  type PassflowRefreshErrorOptions,
  REFRESH_AUTH_FAILURE_IDS,
  type RefreshChannel,
  type RefreshClock,
  type RefreshCoordination,
  type RefreshCoordinator,
  RefreshErrorId,
  type RefreshErrorInfo,
  type RefreshFailureKind,
  type RefreshLockManager,
  type RefreshLockOptions,
  type RefreshTrigger,
  type SessionExpiredReason,
  UpgradeCommitInterruptedError,
  type UpgradeCommitInterruptedReason,
} from './refresh';
// Export service interfaces for extensibility
export * from './services';
export { TwoFactorService } from './services/two-factor-service';
// Re-export events
export {
  type ErrorPayload,
  type OperationErrorPayload,
  PassflowEvent,
  type PassflowEventPayload,
  type PassflowOperation,
  type PassflowSubscriber,
} from './store';
// Re-export token utilities
export {
  type Group,
  type GroupMembership,
  type InvitationToken,
  isTokenExpired,
  parseToken,
  type RawUserMembership,
  type Tenant,
  type TenantMembership,
  type Token,
  TokenType,
  type UserMembership,
} from './token';
// Re-export types
export * from './types';
// Re-export Token Delivery and Session State (explicitly for clarity)
export { SessionState, TokenDeliveryMode } from './types';
export type {
  AssuranceBar,
  BodyKind,
  // `ChallengeChannel` and `UpgradeSessionPin` are the two members of §13's
  // internal vocabulary that a PUBLIC signature still exposes, so they stay
  // nameable: `UpgradeChallenge.channels` is a `ChallengeChannel[]` on the type
  // `parseUpgradeChallenge` returns and `UpgradeFacade.elevate` accepts, and
  // `AuthService.readSessionPin()` returns an `UpgradeSessionPin`. Withdrawing
  // either leaves a consumer writing `NonNullable<UpgradeChallenge['channels']>[number]`
  // or re-spelling `'header' | 'body'` at the call site — a second copy of the
  // union, which is the drift the named type exists to prevent.
  ChallengeChannel,
  CreateClientConfig,
  FetchLike,
  ReplayPolicy,
  RequestSnapshot,
  ResponseInterceptorHost,
  SnapshotHeader,
  UpgradeAssertContext,
  UpgradeAssertion,
  UpgradeChallenge,
  UpgradeControllerOptions,
  UpgradeDiagnostic,
  UpgradeDiagnosticReason,
  UpgradeDiagnosticSink,
  UpgradeElevation,
  UpgradeEnableOptions,
  UpgradeEndpoint,
  UpgradeErrorKind,
  UpgradeFacade,
  UpgradeFactor,
  UpgradeFactorInput,
  UpgradeFactorType,
  UpgradeFlightState,
  UpgradeFlightSummary,
  UpgradeOptions,
  UpgradePrepared,
  UpgradePromptHandler,
  UpgradePromptRequest,
  UpgradePromptResult,
  UpgradeProof,
  UpgradeReplayInfo,
  UpgradeResult,
  UpgradeSessionPin,
  UpgradeTransport,
  UpgradeTransportErrorInit,
  UpgradeWaiterSummary,
  Waiter,
  WaiterEntry,
  WaiterOutcome,
  WaiterReport,
} from './upgrade';
// Re-export Upgrade (step-up authentication) module
export {
  // Error classification is `@passflow/core`'s to own, and the react layer maps
  // a dialog state from it rather than re-deriving a parallel table. These were
  // reachable from `lib/upgrade/index.ts` but NOT from the package entry,
  // so a consumer had to import source through a bundler to get them — which is
  // how the divergence this contract exists to prevent started.
  classifyUpgradeError,
  DEFAULT_UPGRADE_FACTORS,
  factorRegistry,
  INSUFFICIENT_USER_AUTHENTICATION,
  invalidatesSessionOnCommit,
  isRecoverableCommitFailure,
  isRetryableUpgradeKind,
  isUpgradeCancelled,
  isUpgradeExhausted,
  isUpgradeInsufficient,
  isUpgradeSessionChanged,
  isUpgradeTransportError,
  isUpgradeTransportFailure,
  isUpgradeUnavailable,
  isUpgradeUnsatisfiable,
  parseChallengeBody,
  parseChallengeHeader,
  parseUpgradeChallenge,
  passkeyFactor,
  RECOVERABLE_COMMIT_ERROR_IDS,
  recoveryCodesFactor,
  // ACR parsing belongs to the core for the same reason error classification
  // does: `passflow-react-sdk`'s UpgradeProvider derives a required level from
  // `options.acrValues` and must not grow a second parser. It is the one member
  // of §13's assembly set with a live out-of-tree consumer, and the single `.`
  // export condition means there is no deep-import route to it.
  requiredAcrLevel,
  SESSION_INVALIDATING_COMMIT_ERROR_IDS,
  selectFactors,
  totpFactor,
  UPGRADE_REQUIRED,
  UpgradeCancelledError,
  UpgradeController,
  UpgradeErrorIds,
  UpgradeFactorError,
  UpgradeInsufficientError,
  UpgradeSessionChangedError,
  UpgradeTransportError,
  UpgradeUnavailableError,
  UpgradeUnsatisfiableError,
} from './upgrade';
// Re-export validation utilities
export { isValidEmail, isValidJWTFormat, isValidPhoneNumber, isValidUsername, sanitizeErrorMessage } from './utils/validation';
