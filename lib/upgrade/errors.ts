/**
 * Upgrade transport error classification.
 *
 * The server speaks two languages about the same failure: an exact
 * `PassflowError.id` and an HTTP status. The id is read FIRST and the status only
 * as a fallback, because the id names the cause while the status is a bucket —
 * `refreshErrorStatus` maps four unrelated upgrade errors onto one bare 401, and
 * three of them want the prompt kept open while the fourth ends the elevation.
 *
 * This module is pure: it imports nothing and touches no transport. It
 * duck-types whatever it is handed — a `PassflowError`, a raw `AxiosError`, or a
 * bare object — so it can be tested with literals and reused from any surface.
 */

/** What kind of failure the server reported, in remedy terms rather than status terms. */
export type UpgradeErrorKind =
  /** The user typed the wrong code. Retry with a FRESH prepare round; the modal stays open. */
  | 'wrong_code'
  /** Bad, expired, spent or foreign challenge. Same remedy as `wrong_code`. */
  | 'challenge_spent'
  /** The server's per-challenge attempt budget is burned. Stop; a fresh prepare will not help. */
  | 'exhausted'
  /**
   * The CONTROLLER's local attempt budget is burned: the user has answered
   * wrongly `maxAttempts` times and the elevation gives up.
   *
   * Terminal, and distinct from the four retryable kinds for one specific
   * reason: the loop's last failure is usually a `wrong_code`, which IS
   * retryable, and returning that error as the flight's outcome told every
   * surface above "ask them again" for a flight that will never ask again — so
   * the UI re-prompted forever against a budget the server had already closed.
   * The budget being spent is the fact that must travel, not the last answer
   * that spent it; the answer travels on `cause`.
   */
  | 'attempts_exhausted'
  /** This FACTOR is not enrolled for this user. Drop it for this flight, offer the others. */
  | 'not_registered'
  /** Our static `requiresPrepare` disagrees with the server. Recover by asserting directly. */
  | 'prepare_not_required'
  /** Unsupported factor, or no session at all. Not retryable; surface it, do not log the user out. */
  | 'fatal'
  /** The deployment cannot serve an upgrade at all (no challenge storage, or a BFF commit). */
  | 'unavailable'
  /** A malformed response from a server that claimed success. */
  | 'protocol'
  /** No response: the request never completed. */
  | 'network'
  /**
   * A genuine session failure DURING the elevation — a commit 401 that is none of
   * the four recoverable upgrade errors, so it is an expired or revoked refresh
   * token rather than a bad answer. Terminates the elevation instead of
   * re-prompting, and the transport invalidates the session itself.
   */
  | 'session_changed';

/** Server error ids this module classifies. Verified against `src/l/messages_const.go`. */
export const UpgradeErrorIds = {
  twoFactorCodeInvalid: 'error.api.request.2fa_code.invalid',
  challengeInvalid: 'error.upgrade.challenge_invalid',
  challengeSessionMismatch: 'error.upgrade.challenge_session_mismatch',
  challengeTooManyAttempts: 'error.upgrade.challenge_too_many_attempts',
  unsupportedFactor: 'error.upgrade.unsupported_factor',
  noSession: 'error.upgrade.no_session',
  unavailable: 'error.upgrade.unavailable',
  methodNotRegistered: 'error.upgrade.method_not_registered',
  prepareNotRequired: 'error.upgrade.prepare_not_required',
  methodNotSupported: 'error.2fa.method_not_supported',
  twoFactorNotEnabled: 'error.2fa.not_enabled',
  notImplemented: 'error.not.implemented',
  tokenInvalid: 'error.api.request.token.invalid',
} as const;

/**
 * **Every** error `refreshErrorStatus` maps to a 401 on the commit path, as
 * enumerated by `src/web/api/refresh_token.go:157-178`.
 *
 * All five are "recoverable" in the session sense: every one of them is the
 * upgrade protocol talking, so none of them means the session died. Note that
 * `challenge_too_many_attempts` is in here yet is NOT retryable — it ends the
 * elevation while leaving the session intact. The two axes are independent and
 * are deliberately not collapsed.
 *
 * `error.2fa.not_enabled` was missing from this list, which signed out a user
 * who had no 2FA enrolled the moment an elevation reached the commit round —
 * the exact lock-out PFL-497 exists to prevent. The set is kept complete for
 * documentation and for callers, but the invalidation decision no longer rests
 * on it: see `invalidatesSessionOnCommit`, which is the inverse predicate.
 */
export const RECOVERABLE_COMMIT_ERROR_IDS: readonly string[] = Object.freeze([
  UpgradeErrorIds.twoFactorCodeInvalid,
  UpgradeErrorIds.twoFactorNotEnabled,
  UpgradeErrorIds.challengeInvalid,
  UpgradeErrorIds.challengeSessionMismatch,
  UpgradeErrorIds.challengeTooManyAttempts,
]);

/**
 * Error ids that positively mean the SESSION is gone, not merely the elevation.
 *
 * This is the predicate the transport invalidates on, and it is deliberately a
 * POSITIVE list rather than the complement of the recoverable one. The server's
 * 401 set on the commit path is enumerated and small, so a list of "ids that
 * mean the session died" can be complete in a way that "everything else" never
 * is; and when a future server adds a sixth 401 id, an allow-list of expiries
 * fails toward "I don't know" rather than toward "log them out", which is this
 * feature's governing rule. A client-side miss costs a stale session that the
 * next ordinary 401 clears; a false positive costs the user their session in
 * the middle of proving who they are.
 */
export const SESSION_INVALIDATING_COMMIT_ERROR_IDS: readonly string[] = Object.freeze([UpgradeErrorIds.tokenInvalid]);

/** Kinds the user can recover from by answering again, possibly with another factor. */
const RETRYABLE_KINDS: readonly UpgradeErrorKind[] = Object.freeze([
  'wrong_code',
  'challenge_spent',
  'not_registered',
  'prepare_not_required',
]);

/** True when a kind leaves the elevation alive. Single source for `retryable`. */
export const isRetryableUpgradeKind = (kind: UpgradeErrorKind): boolean => RETRYABLE_KINDS.includes(kind);

export type UpgradeTransportErrorInit = {
  kind: UpgradeErrorKind;
  message?: string;
  status?: number;
  /** The `PassflowError.id`, verbatim, when the server supplied one. */
  errorId?: string;
  cause?: unknown;
};

/** Which round of the transaction failed. The same status means different things on each. */
export type UpgradeEndpoint = 'start' | 'refresh';

const DEFAULT_MESSAGES: Record<UpgradeErrorKind, string> = {
  wrong_code: 'That code was not accepted. Try again.',
  challenge_spent: 'That verification challenge is no longer valid. Start again.',
  exhausted: 'Too many attempts. Try again later.',
  attempts_exhausted: 'Too many incorrect attempts. Verification was not completed.',
  not_registered: 'That verification method is not set up for this account.',
  prepare_not_required: 'This verification method needs no preparation round.',
  fatal: 'This verification method cannot be used right now.',
  unavailable: 'Step-up verification is not available on this deployment.',
  protocol: 'The server returned an unexpected upgrade response.',
  network: 'The verification request did not reach the server.',
  session_changed: 'The session ended during verification.',
};

/**
 * A classified transport failure.
 *
 * `code` is the literal, bundling-proof discriminant every upgrade error class
 * carries; the server's own id lives in `errorId`. (The design's §3.3 called the
 * latter `code`, which §13.3 then claimed for the literal tag — `errorId` keeps
 * both without one shadowing the other.)
 */
export class UpgradeTransportError extends Error {
  readonly name = 'UpgradeTransportError';
  readonly code = 'upgrade_transport' as const;
  readonly kind: UpgradeErrorKind;
  readonly status?: number;
  readonly errorId?: string;
  readonly retryable: boolean;
  /** Declared here rather than inherited: `Error.cause` is ES2022 and this build targets ES2021 libs. */
  readonly cause?: unknown;

  constructor(init: UpgradeTransportErrorInit) {
    super(init.message || DEFAULT_MESSAGES[init.kind]);
    this.kind = init.kind;
    this.status = init.status;
    this.errorId = init.errorId;
    this.retryable = isRetryableUpgradeKind(init.kind);
    if (init.cause !== undefined) {
      this.cause = init.cause;
    }
  }
}

/**
 * Every literal `code` an upgrade error class carries, including the two that
 * live in `controller.ts` (`upgrade_cancelled`, `upgrade_unsatisfiable`).
 *
 * The codes are listed rather than imported because this module imports nothing
 * — `controller.ts` imports it, so naming those classes here would be a cycle —
 * and because `code` is the discriminant that survives bundling, a duplicated
 * package copy and a cross-realm boundary, which is exactly the property a
 * pass-through guard needs.
 */
const UPGRADE_ERROR_CODES: readonly string[] = Object.freeze([
  'upgrade_transport',
  'upgrade_insufficient',
  'upgrade_unavailable',
  'upgrade_session_changed',
  'upgrade_cancelled',
  'upgrade_unsatisfiable',
]);

/**
 * Reports whether a value is one of the SDK's own upgrade error classes — an
 * outcome that has already been decided, on any surface.
 *
 * Used where a lower layer must not re-bucket a settled outcome: classifying an
 * `UpgradeSessionChangedError` as a bare network failure (which is what
 * happened, because it carries no `response`) turned §13.3's `session changed
 * mid-flight` row into `upgrade_transport` on all four adapters.
 */
export const isUpgradeSdkError = (e: unknown): e is Error & { code: string } =>
  typeof e === 'object' &&
  e !== null &&
  typeof (e as { code?: unknown }).code === 'string' &&
  UPGRADE_ERROR_CODES.includes((e as { code: string }).code);

/** Reports whether a value is an already-classified transport failure. */
export const isUpgradeTransportError = (e: unknown): e is UpgradeTransportError =>
  e instanceof UpgradeTransportError ||
  (typeof e === 'object' && e !== null && (e as { code?: unknown }).code === 'upgrade_transport');

type ErrorFacts = { status?: number; errorId?: string; message?: string; hasResponse: boolean };

/**
 * Pulls status, error id and message out of whatever the API layer rejected with.
 *
 * Three shapes reach here: a `PassflowError` (what `AxiosClient` normally
 * produces), a raw `AxiosError` whose body carries the Passflow envelope, and a
 * plain `Error` from a non-HTTP failure.
 */
const readErrorFacts = (e: unknown): ErrorFacts => {
  if (typeof e !== 'object' || e === null) {
    return { hasResponse: false, message: typeof e === 'string' ? e : undefined };
  }

  const candidate = e as {
    id?: unknown;
    status?: unknown;
    message?: unknown;
    response?: { status?: unknown; data?: unknown };
  };

  const response = candidate.response;
  const body = response?.data as { error?: { id?: unknown } } | undefined;
  const envelopeId = typeof body?.error?.id === 'string' ? body.error.id : undefined;

  const status =
    typeof candidate.status === 'number'
      ? candidate.status
      : typeof response?.status === 'number'
        ? response.status
        : undefined;

  return {
    status,
    errorId: typeof candidate.id === 'string' ? candidate.id : envelopeId,
    message: typeof candidate.message === 'string' ? candidate.message : undefined,
    hasResponse: response !== undefined || typeof candidate.status === 'number',
  };
};

/**
 * The id → kind table. `undefined` means "this id says nothing; fall back to status".
 *
 * `endpoint` is a parameter because one id genuinely means different things on
 * the two rounds — see `tokenInvalid` below. Everything else is round-independent.
 */
const kindFromErrorId = (errorId: string | undefined, endpoint: UpgradeEndpoint): UpgradeErrorKind | undefined => {
  switch (errorId) {
    case UpgradeErrorIds.twoFactorCodeInvalid:
      return 'wrong_code';
    case UpgradeErrorIds.challengeInvalid:
    case UpgradeErrorIds.challengeSessionMismatch:
      return 'challenge_spent';
    case UpgradeErrorIds.challengeTooManyAttempts:
      return 'exhausted';
    case UpgradeErrorIds.methodNotRegistered:
      return 'not_registered';
    // `error.2fa.not_enabled` is the same statement from the account's side —
    // the factor is not set up — and it is ROUND-DEPENDENT.
    //
    // On the PREPARE round it is the server refusing one factor while the
    // flight is still choosing, which §13.4 makes flight-local pruning plus a
    // re-prompt: retryable with another factor, never an expiry.
    //
    // On the COMMIT round C26c governs, and it is explicit: a commit 401
    // carrying any other id, `error.2fa.not_enabled` included, terminates the
    // elevation as `session changed mid-flight` while `setSessionInvalid()` is
    // NOT called and `SessionState` is untouched. Mapping it to
    // `not_registered` there made it retryable, so the controller pruned TOTP
    // and re-prompted against a commit that can only refuse again — the user
    // sat in front of a modal that never resolved. Terminal settlement with the
    // session left alone is the lock-out-free outcome the ticket exists for;
    // invalidation stays off because this id is not on
    // `SESSION_INVALIDATING_COMMIT_ERROR_IDS`.
    case UpgradeErrorIds.twoFactorNotEnabled:
      return endpoint === 'refresh' ? 'session_changed' : 'not_registered';
    case UpgradeErrorIds.prepareNotRequired:
      return 'prepare_not_required';
    case UpgradeErrorIds.unavailable:
    case UpgradeErrorIds.notImplemented:
      return 'unavailable';
    case UpgradeErrorIds.unsupportedFactor:
    case UpgradeErrorIds.noSession:
    case UpgradeErrorIds.methodNotSupported:
      return 'fatal';
    // The one round-dependent id. §13.4's table maps a `start` 401 carrying it
    // to `fatal`; §13.4 revision 5 specifies the COMMIT round's occurrence as
    // *session changed mid-flight* — it is the single id on the positive
    // allow-list `invalidatesSessionOnCommit` reads, so classifying it `fatal`
    // on that round contradicted the predicate that acts on it.
    case UpgradeErrorIds.tokenInvalid:
      return endpoint === 'refresh' ? 'session_changed' : 'fatal';
    default:
      // An id we do not recognise — the normal case against a newer server.
      // `undefined` hands the decision to the status fallback.
      return undefined;
  }
};

/** The status → kind fallback, which differs per round. */
const kindFromStatus = (status: number | undefined, endpoint: UpgradeEndpoint): UpgradeErrorKind => {
  if (status === undefined) {
    return 'network';
  }
  if (status === 501) {
    return 'unavailable';
  }
  if (status === 400) {
    return 'fatal';
  }
  if (status === 401 || status === 403) {
    // On the prepare round an unrecognised 401 is the challenge going stale, and
    // a fresh prepare fixes it. On the commit round an unrecognised id is a
    // server this SDK does not know: the five ids `refreshErrorStatus` can emit
    // as a 401 are all mapped by `kindFromErrorId`, so nothing enumerated
    // reaches here. The elevation ends — there is no sane way to continue it —
    // but the SESSION does not: `invalidatesSessionOnCommit` is a positive list
    // and says nothing about an id it has never seen.
    return endpoint === 'start' ? 'challenge_spent' : 'session_changed';
  }
  if (status >= 500) {
    return 'network';
  }
  return 'fatal';
};

/**
 * Classifies a rejection from either upgrade round into an `UpgradeTransportError`.
 *
 * Already-classified errors pass through unchanged, so a nested call cannot
 * re-bucket a `prepare_not_required` into something terminal.
 */
export const classifyUpgradeError = (e: unknown, endpoint: UpgradeEndpoint): UpgradeTransportError => {
  if (e instanceof UpgradeTransportError) {
    return e;
  }

  const facts = readErrorFacts(e);
  if (!facts.hasResponse) {
    return new UpgradeTransportError({ kind: 'network', message: facts.message, cause: e });
  }

  const kind = kindFromErrorId(facts.errorId, endpoint) ?? kindFromStatus(facts.status, endpoint);

  return new UpgradeTransportError({
    kind,
    message: facts.message,
    status: facts.status,
    errorId: facts.errorId,
    cause: e,
  });
};

/**
 * Reports whether a classified commit failure is a KNOWN upgrade-protocol error
 * that leaves the session intact.
 *
 * Informational: it answers "is this one of the server's enumerated commit
 * 401s". It is NOT the invalidation decision — `invalidatesSessionOnCommit` is,
 * and an unrecognised id is not an expiry just because this list has not heard
 * of it.
 */
export const isRecoverableCommitFailure = (error: UpgradeTransportError): boolean =>
  error.errorId !== undefined && RECOVERABLE_COMMIT_ERROR_IDS.includes(error.errorId);

/**
 * Reports whether a classified commit failure means the SESSION has ended.
 *
 * The one predicate the transport invalidates on, and the inverse of what this
 * module used to ask. `undefined` — no id at all — is explicitly NOT an expiry:
 * a 401 the SDK cannot explain is "I don't know", and "I don't know" must never
 * resolve to signing the user out mid-verification.
 */
export const invalidatesSessionOnCommit = (error: UpgradeTransportError): boolean =>
  error.errorId !== undefined && SESSION_INVALIDATING_COMMIT_ERROR_IDS.includes(error.errorId);

/* ────────────────────────────────────────────────────────────────────────────
 * The remaining §13.3 error classes.
 *
 * Every upgrade error carries a literal `code` discriminant as well as being
 * `instanceof`-checkable, because `code` is what survives bundling, a duplicated
 * package copy and a cross-realm boundary — the three situations in which an
 * `instanceof` check quietly returns `false` on a genuine failure.
 *
 * They live beside `UpgradeTransportError` rather than in an adapter so that the
 * axios and imperative surfaces can be pure translation: the core decides which
 * class an outcome maps to (`coreOutcomeToError`), the adapter only throws it.
 * ──────────────────────────────────────────────────────────────────────────── */

/** The bar a challenge demanded, or an elevation reached, on both axes. */
export type AssuranceBar = {
  /** The raw winning `acr_values` list, for display and diagnostics. */
  acrValues?: string;
  /** The parsed bar. `undefined` = unknown, or not constrained on this axis. */
  level?: number;
  /** The freshness constraint, when that is what was demanded. */
  maxAge?: number;
};

/**
 * The elevation completed, and the protected operation's replay was challenged
 * again: the proof was real but did not reach this operation's bar.
 *
 * This is the outcome that makes the AAL3-with-only-TOTP path honest. It is
 * per-operation, never per-proof — a requestless `passflow.upgrade()` with no
 * stated bar can never produce it, because it has nothing to replay.
 */
export class UpgradeInsufficientError extends Error {
  readonly name = 'UpgradeInsufficientError';
  readonly code = 'upgrade_insufficient' as const;
  readonly obtained: AssuranceBar;
  readonly required: AssuranceBar;

  constructor(obtained: AssuranceBar, required: AssuranceBar, message?: string) {
    super(message ?? 'The session was elevated, but this action requires a higher assurance level');
    this.obtained = obtained;
    this.required = required;
  }
}

/** The deployment cannot serve an upgrade at all — no challenge storage, or a BFF commit. */
export class UpgradeUnavailableError extends Error {
  readonly name = 'UpgradeUnavailableError';
  readonly code = 'upgrade_unavailable' as const;

  constructor(message = 'Step-up verification is not available on this deployment') {
    super(message);
  }
}

/** The session ended or changed while the elevation was running (§7.4). */
export class UpgradeSessionChangedError extends Error {
  readonly name = 'UpgradeSessionChangedError';
  readonly code = 'upgrade_session_changed' as const;

  constructor(message = 'The session changed during verification') {
    super(message);
  }
}
