/**
 * Multi-tab-safe token refresh (PFL-792).
 *
 * The public surface (re-exported from the package entry, `lib/index.ts`) is the types in
 * `types.ts`, {@link PassflowRefreshError}, {@link RefreshErrorId},
 * {@link UpgradeCommitInterruptedError} and {@link REFRESH_AUTH_FAILURE_IDS}. Everything else here
 * is internal to the SDK.
 *
 * @module refresh
 */

export {
  BLOCKED_REFRESH_TOKEN_ID,
  classifyRefreshFailure,
  parseRetryAfter,
  REFRESH_AUTH_FAILURE_IDS,
  type RefreshFailureClass,
  readRetryAfterHeader,
  retryDelay,
} from './classify';
export * from './constants';
export {
  PassflowRefreshError,
  type PassflowRefreshErrorOptions,
  RefreshErrorId,
  UpgradeCommitInterruptedError,
  type UpgradeCommitInterruptedReason,
} from './errors';
export {
  type CredentialFence,
  type CredentialFenceDeps,
  createCredentialFence,
  type FailureVerdict,
  IdentityChanged,
  type SaveVerdict,
  type SendVerdict,
  type SentCredentials,
  SessionEnded,
  type SessionLostCause,
  type StoredVerdict,
} from './fence';
export {
  createRefreshLineage,
  type EndedSession,
  fingerprint,
  orderOf,
  type RefreshLineage,
  type RefreshTokenOrder,
} from './lineage';
export {
  buildMessage,
  type LockWantedPurpose,
  type OutgoingMessageBody,
  parseMessage,
  parseRetryInfo,
  type RefreshMessage,
  type RefreshMessageType,
  type RefreshNames,
  type RetryInfo,
  refreshNames,
  type WireLineage,
  type WireTokens,
} from './protocol';
export type {
  EventOrigin,
  RefreshChannel,
  RefreshClock,
  RefreshCoordination,
  RefreshCoordinator,
  RefreshErrorInfo,
  RefreshFailureKind,
  RefreshLockManager,
  RefreshLockOptions,
  RefreshTrigger,
  SessionExpiredReason,
} from './types';
