export {
  INSUFFICIENT_USER_AUTHENTICATION,
  UPGRADE_REQUIRED,
  parseChallengeBody,
  parseChallengeHeader,
  parseUpgradeChallenge,
  type UpgradeChallenge,
} from './challenge';

export {
  DEFAULT_UPGRADE_FACTORS,
  factorRegistry,
  passkeyFactor,
  recoveryCodesFactor,
  UpgradeFactorError,
  totpFactor,
  type UpgradeAssertion,
  type UpgradeAssertContext,
  type UpgradeFactor,
  type UpgradeFactorInput,
  type UpgradeFactorType,
  type UpgradePrepared,
} from './factors';

export {
  UpgradeCancelledError,
  UpgradeController,
  UpgradeUnsatisfiableError,
  type UpgradeControllerOptions,
  type UpgradePromptHandler,
  type UpgradePromptRequest,
  type UpgradePromptResult,
  type UpgradeTransport,
} from './controller';

export {
  RECOVERABLE_COMMIT_ERROR_IDS,
  SESSION_INVALIDATING_COMMIT_ERROR_IDS,
  UpgradeErrorIds,
  UpgradeTransportError,
  classifyUpgradeError,
  invalidatesSessionOnCommit,
  isRecoverableCommitFailure,
  isRetryableUpgradeKind,
  isUpgradeTransportError,
  type UpgradeEndpoint,
  type UpgradeErrorKind,
  type UpgradeTransportErrorInit,
} from './errors';

export {
  UPGRADE_REPLAYED_MARKER,
  UPGRADE_TRANSACTION_MARKER,
  hasUpgradeReplayedMarker,
  hasUpgradeTransactionMarker,
  markUpgradeReplayed,
  markUpgradeTransaction,
  type UpgradeRequestMarkers,
} from './markers';

export { selectFactors } from './select';

export {
  RELATIVE_BASE,
  captureHeaders,
  createRequestSnapshot,
  headersToObject,
  normaliseUrl,
  snapshotHeader,
  swapAuthorization,
  type NormalisedUrl,
  type RequestSnapshot,
  type RequestSnapshotInit,
  type SnapshotHeader,
} from './snapshot';

export {
  readSessionPin,
  sessionPinMatches,
  type UpgradeSessionClaims,
  type UpgradeSessionPin,
} from './session';

export { createUpgradeTransport, toPrepared, type UpgradeTransportDeps } from './transport';

export { parseAcrToken, readAcrValues, requiredAcrLevel, type AcrReading } from './acr';

export {
  parseMaxAge,
  readUpgradeChallenge,
  type AssuranceBar,
  type ChallengeChannel,
  type ChallengeInput,
  type ChallengeReadOptions,
  type ChallengeReading,
  type MaxAgeReading,
  type UpgradeDiagnostic,
  type UpgradeDiagnosticReason,
  type UpgradeDiagnosticSink,
} from './challenge';

export {
  barMeets,
  barOf,
  mergeChallenges,
  type UpgradeElevation,
  type UpgradeFlightState,
  type UpgradeFlightSummary,
  type UpgradeProof,
  type UpgradeWaiterSummary,
  type Waiter,
  type WaiterEntry,
  type WaiterOutcome,
  type WaiterReport,
} from './controller';

export {
  UpgradeInsufficientError,
  UpgradeSessionChangedError,
  UpgradeUnavailableError,
} from './errors';

export {
  coreOutcomeToError,
  handleChallenge,
  isInterceptionScope,
  isUpgradeCancelled,
  isUpgradeExhausted,
  isUpgradeInsufficient,
  isUpgradeSessionChanged,
  isUpgradeTransportFailure,
  isUpgradeUnavailable,
  isUpgradeUnsatisfiable,
  settleAxiosOutcome,
  settleFetchOutcome,
  tagUpgradeOutcome,
  type ChallengeContext,
  type CoreOutcome,
  type InterceptionScope,
  type Settlement,
  type UpgradeInterceptorOptions,
} from './core';

export {
  methodOf,
  planReplay,
  policyPermits,
  urlOf,
  type BodyKind,
  type FetchLike,
  type ReplayHints,
  type ReplayPlan,
  type ReplayPolicy,
  type UpgradeReplayInfo,
} from './replay';

export {
  attachUpgradeAuth,
  createAxiosUpgradeHandler,
  type AxiosConfigLike,
  type AxiosReissue,
  type ResponseInterceptorHost,
} from './axios-adapter';

export { upgradeFetch } from './fetch-adapter';

export { createUpgradeClient, type CreateClientConfig } from './client';

export {
  createUpgradeFacade,
  type PassflowUpgradeDomain,
  type UpgradeEnableOptions,
  type UpgradeFacade,
  type UpgradeFacadeDeps,
  type UpgradeOptions,
  type UpgradeResult,
} from './facade';
