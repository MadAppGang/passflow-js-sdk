// Re-export from API
export * from './api';

// Re-export constants
export * from './constants';
// Export Passflow class
export { Passflow } from './passflow';
// Export service interfaces for extensibility
export * from './services';
// Re-export events
export { type ErrorPayload, PassflowEvent, type PassflowEventPayload, type PassflowSubscriber } from './store';
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
// Re-export validation utilities
export { isValidEmail, isValidJWTFormat, isValidPhoneNumber, isValidUsername, sanitizeErrorMessage } from './utils/validation';

// Re-export Two-Factor Authentication types (explicitly for clarity)
export type {
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
  TwoFactorVerifyRequest,
  TwoFactorVerifyResponse,
} from './api/model';

// Re-export Two-Factor Authentication API client and service
export { TwoFactorApiClient } from './api/two-factor';
export { TwoFactorService } from './services/two-factor-service';

// Re-export CLI Authentication API client
export { CLIAuthAPI } from './api/cli-auth';
export type { CLIAuthStatusResponse, CLIAuthCompleteRequest } from './api/model';

// Re-export M2M (Machine-to-Machine) Authentication module
export { M2MClient, M2MError, M2MNetworkError, M2MTokenParseError, M2MConfigError, M2MErrorCodes, M2M_DEFAULTS } from './m2m';
export type {
  M2MClientConfig,
  M2MTokenRequestOptions,
  M2MTokenRequestInfo,
  M2MTokenResponse,
  M2MErrorResponse,
  M2MTokenClaims,
  M2MErrorCode,
  M2MTokenCache,
  RetryStrategy,
  M2MRateLimitInfo,
} from './m2m';

// Re-export Upgrade (step-up authentication) module
export {
  INSUFFICIENT_USER_AUTHENTICATION,
  UPGRADE_REQUIRED,
  parseChallengeBody,
  parseChallengeHeader,
  parseUpgradeChallenge,
  DEFAULT_UPGRADE_FACTORS,
  factorRegistry,
  passkeyFactor,
  recoveryCodesFactor,
  UpgradeFactorError,
  totpFactor,
  UpgradeCancelledError,
  UpgradeController,
  UpgradeUnsatisfiableError,
  selectFactors,
  // Error classification is `@passflow/core`'s to own, and the react layer maps
  // a dialog state from it rather than re-deriving a parallel table. These four
  // were reachable from `lib/upgrade/index.ts` but NOT from the package entry,
  // so a consumer had to import source through a bundler to get them — which is
  // how the divergence this contract exists to prevent started.
  classifyUpgradeError,
  invalidatesSessionOnCommit,
  isRecoverableCommitFailure,
  isRetryableUpgradeKind,
  isUpgradeTransportError,
  RECOVERABLE_COMMIT_ERROR_IDS,
  SESSION_INVALIDATING_COMMIT_ERROR_IDS,
  UpgradeErrorIds,
  UpgradeTransportError,
  // §13's core, its supporting pure modules, and the four adapters over it.
  // The developer-facing names are `withAuth`, `attachAuth`, `createClient` and
  // `interceptFetch`, all reached through a configured `Passflow` instance;
  // these are the pieces they are assembled from.
  attachUpgradeAuth,
  barOf,
  coreOutcomeToError,
  handleChallenge,
  isUpgradeCancelled,
  isUpgradeExhausted,
  isUpgradeInsufficient,
  isUpgradeSessionChanged,
  isUpgradeTransportFailure,
  isUpgradeUnavailable,
  isUpgradeUnsatisfiable,
  mergeChallenges,
  parseAcrToken,
  parseMaxAge,
  planReplay,
  readAcrValues,
  readUpgradeChallenge,
  requiredAcrLevel,
  createUpgradeClient,
  createUpgradeFacade,
  settleAxiosOutcome,
  settleFetchOutcome,
  tagUpgradeOutcome,
  upgradeFetch,
  UpgradeInsufficientError,
  UpgradeSessionChangedError,
  UpgradeUnavailableError,
} from './upgrade';
export type {
  CreateClientConfig,
  FetchLike,
  ResponseInterceptorHost,
  Settlement,
  UpgradeEnableOptions,
  UpgradeEndpoint,
  UpgradeErrorKind,
  UpgradeFacade,
  UpgradeFacadeDeps,
  UpgradeOptions,
  UpgradeResult,
  UpgradeSessionPin,
  UpgradeTransportErrorInit,
  RequestSnapshot,
  SnapshotHeader,
  UpgradeChallenge,
  UpgradeAssertion,
  UpgradeAssertContext,
  UpgradeFactor,
  UpgradeFactorInput,
  UpgradeFactorType,
  UpgradePrepared,
  UpgradeControllerOptions,
  UpgradePromptHandler,
  UpgradePromptRequest,
  UpgradePromptResult,
  UpgradeTransport,
  AssuranceBar,
  BodyKind,
  ChallengeChannel,
  ChallengeContext,
  ChallengeInput,
  ChallengeReadOptions,
  ChallengeReading,
  CoreOutcome,
  InterceptionScope,
  MaxAgeReading,
  ReplayHints,
  ReplayPlan,
  ReplayPolicy,
  UpgradeDiagnostic,
  UpgradeDiagnosticReason,
  UpgradeDiagnosticSink,
  UpgradeElevation,
  UpgradeFlightState,
  UpgradeFlightSummary,
  UpgradeInterceptorOptions,
  UpgradeProof,
  UpgradeReplayInfo,
  UpgradeWaiterSummary,
  Waiter,
  WaiterEntry,
  WaiterOutcome,
  WaiterReport,
} from './upgrade';

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
export type { FetchMiddleware, RegisterOptions } from './interceptors/fetch-registry';

// Re-export Token Delivery and Session State (explicitly for clarity)
export { TokenDeliveryMode, SessionState } from './types';

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
