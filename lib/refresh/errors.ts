/**
 * Errors a refresh caller can receive that no server sent (architecture §2.8).
 *
 * @module refresh/errors
 */

import { PassflowError } from '../api/model';

/** Ids of {@link PassflowRefreshError}. */
export const RefreshErrorId = {
  /** Joined another tab's cycle whose attempt failed transiently (status 503). */
  unavailable: 'error.refresh.unavailable',
  /** Joined another tab's cycle whose attempt failed on auth with strikes left (status 401). */
  authRetry: 'error.refresh.auth_retry',
  /** The session ended (strikes exhausted here or elsewhere). */
  sessionEnded: 'error.refresh.session_ended',
  /** A sign-out (this tab or another tab of the user). */
  signedOut: 'error.refresh.signed_out',
  /** `error.token.blocked` and no successor within 20 s. */
  successorTimeout: 'error.refresh.successor_timeout',
  /** Storage now holds another user's tokens. */
  identityChanged: 'error.refresh.identity_changed',
  /** `Passflow.dispose()` was called. */
  disposed: 'error.refresh.disposed',
} as const;

export type RefreshErrorId = (typeof RefreshErrorId)[keyof typeof RefreshErrorId];

/**
 * HTTP-shaped status of each id. `disposed` has no server meaning: 499 ("client closed request")
 * keeps it out of the 5xx (transient) and plain 4xx (auth) ranges a classifier might read.
 */
const STATUS_BY_ID: Record<RefreshErrorId, number> = {
  'error.refresh.unavailable': 503,
  'error.refresh.auth_retry': 401,
  'error.refresh.session_ended': 401,
  'error.refresh.signed_out': 401,
  'error.refresh.successor_timeout': 401,
  'error.refresh.identity_changed': 401,
  'error.refresh.disposed': 499,
};

const DEFAULT_MESSAGE: Record<RefreshErrorId, string> = {
  'error.refresh.unavailable': 'Token refresh is unavailable; a retry is scheduled',
  'error.refresh.auth_retry': 'Token refresh was refused; a retry is scheduled',
  'error.refresh.session_ended': 'The session has ended',
  'error.refresh.signed_out': 'Signed out',
  'error.refresh.successor_timeout': 'The refresh token was already used and no successor arrived',
  'error.refresh.identity_changed': "Storage holds another user's tokens",
  'error.refresh.disposed': 'The Passflow instance was disposed',
};

export interface PassflowRefreshErrorOptions {
  message?: string;
  /** Epoch ms of the shared pending retry, for `unavailable` / `auth_retry`. */
  nextRetryAt?: number;
  /** The failure this error stands for (another tab's attempt, the request's own error). */
  cause?: unknown;
}

/** A refresh outcome the SDK decided, not the server: joined a failed cycle, or the session ended. */
export class PassflowRefreshError extends PassflowError {
  declare readonly id: RefreshErrorId;
  readonly nextRetryAt?: number;
  readonly cause?: unknown;

  constructor(id: RefreshErrorId, options: PassflowRefreshErrorOptions = {}) {
    super({
      id,
      message: options.message ?? DEFAULT_MESSAGE[id],
      status: STATUS_BY_ID[id],
      location: '/auth/refresh',
      time: new Date().toISOString(),
    });
    this.name = 'PassflowRefreshError';
    if (options.nextRetryAt !== undefined) this.nextRetryAt = options.nextRetryAt;
    if (options.cause !== undefined) this.cause = options.cause;
  }
}

/** Why an upgrade commit was not sent, or its answer not applied. */
export type UpgradeCommitInterruptedReason = 'lock-timeout' | 'superseded';

/**
 * Upgrade commit only: the commit could not be sent (lock wait over 10 s) or its answer arrived
 * after storage moved to another token. A plain Error with no `status` and no `response`: the
 * upgrade transport's classifier reads it as `network` (retryable, no invalidation).
 */
export class UpgradeCommitInterruptedError extends Error {
  readonly reason: UpgradeCommitInterruptedReason;

  constructor(reason: UpgradeCommitInterruptedReason, message?: string) {
    super(
      message ??
        (reason === 'lock-timeout'
          ? 'Step-up commit could not take the refresh lock in time'
          : 'Step-up commit answer arrived after the stored session moved on'),
    );
    this.name = 'UpgradeCommitInterruptedError';
    this.reason = reason;
  }
}
