/**
 * The HTTP adapter behind the `UpgradeTransport` port.
 *
 * It owns no axios instance. Both rounds arrive as narrow, function-shaped
 * dependencies, which keeps HTTP vocabulary one level away from the controller
 * and lets every test here be a synchronous fake instead of an HTTP mock.
 *
 * It is also STATELESS by design: no cached challenge id, no cached prepare
 * result, no attempt counter. A challenge is single-use and the server consumes
 * it atomically, so there is nothing a second attempt could legitimately reuse.
 * Statelessness is the whole of this module's obligation to "never reuse a spent
 * challenge_id", and it is checkable by calling `prepare()` twice.
 */

import type { UpgradeRefreshField, UpgradeStartWire } from '../api/model';

import type { UpgradeTransport } from './controller';
import {
  UpgradeTransportError,
  classifyUpgradeError,
  invalidatesSessionOnCommit,
  isUpgradeSdkError,
  isUpgradeTransportError,
} from './errors';
import { DEFAULT_UPGRADE_FACTORS, type UpgradeAssertion, type UpgradeFactorType, type UpgradePrepared } from './factors';
import type { UpgradeSessionPin } from './session';

export type UpgradeTransportDeps = {
  /** `POST /auth/upgrade/start`. Returns the raw snake_case body; rejects with `PassflowError`. */
  startUpgrade(payload: { method: string; relying_party_id?: string }): Promise<UpgradeStartWire>;
  /**
   * `POST /auth/refresh` carrying `upgrade`. Resolves once the elevated tokens
   * are STORED.
   *
   * `pin` is the session and user identity the flight began under (§13.4
   * revision 6). The host verifies it immediately before it applies the rotated
   * tokens and discards them on mismatch — the check has to live inside the
   * token-applying path, because that is the only place it cannot be bypassed
   * by another entry point. The transport only carries the value; the facade
   * supplies it, since the flight's start is what it is pinned to.
   */
  commitRefresh(upgrade: UpgradeRefreshField, pin?: UpgradeSessionPin): Promise<void>;
  /** Reports whether this delivery mode can carry an upgrade at all. BFF cannot. */
  canCommit(): { ok: true } | { ok: false; reason: string };
  /** Optional relying-party id for passkey upgrades; forwarded verbatim. */
  relyingPartyId?: () => string | undefined;
  /**
   * Invalidates the session. Called ONLY for a commit 401 whose error id
   * positively means the session died (`invalidatesSessionOnCommit`) — a
   * genuine expiry during an elevation is still an expiry, and the transport is
   * the only code that can tell, because it knows it issued the request and can
   * read the error id. Everything else, including an id this SDK does not
   * recognise, leaves the session alone.
   */
  markSessionInvalid?: () => void;
};

/**
 * Factors that need no prepare round, derived from the factor table rather than
 * restated, so adding a factor cannot leave this set stale.
 */
const ONE_SHOT_METHODS: ReadonlySet<string> = new Set(
  DEFAULT_UPGRADE_FACTORS.filter((factor) => !factor.requiresPrepare).map((factor) => factor.type),
);

/**
 * Normalises the prepare round's wire body.
 *
 * `webauthn` is passed through by reference, never re-serialised: the ceremony
 * hands those exact bytes to the authenticator and the server re-parses them on
 * the way back.
 *
 * A missing `challenge_id` or `expires_at` is a protocol violation, not an
 * optional field. Producing `challengeId: undefined` would surface two round
 * trips later as an opaque 401 with nothing to point at.
 */
export const toPrepared = (wire: UpgradeStartWire): UpgradePrepared => {
  if (!wire || typeof wire !== 'object' || !wire.challenge_id || !wire.expires_at) {
    throw new UpgradeTransportError({
      kind: 'protocol',
      message: 'The upgrade start response is missing challenge_id or expires_at',
    });
  }

  return {
    challengeId: wire.challenge_id,
    method: wire.method,
    expiresAt: wire.expires_at,
    webauthn: wire.webauthn,
    codeSentTo: wire.code_sent_to,
  };
};

/**
 * A rejection that is already one of the SDK's own upgrade outcomes, other than
 * a classified transport failure.
 *
 * `UpgradeTransportError` is excluded because `classifyUpgradeError` passes it
 * through on its own and the commit round still has to read its id for the
 * invalidation predicate.
 */
const isAlreadySettled = (e: unknown): boolean => isUpgradeSdkError(e) && !isUpgradeTransportError(e);

/** Builds the transport. Returns the port type, so the controller stays HTTP-agnostic. */
export const createUpgradeTransport = (deps: UpgradeTransportDeps): UpgradeTransport => ({
  async prepare(method: UpgradeFactorType): Promise<UpgradePrepared | undefined> {
    // The server actively REJECTS a prepare call for a one-shot factor, so
    // "call it and see" costs a guaranteed round trip and a 400 on every TOTP
    // upgrade. The controller already gates on `requiresPrepare`; this is the
    // second line of that same defence, for a caller that does not.
    if (ONE_SHOT_METHODS.has(method)) {
      return undefined;
    }

    try {
      const relyingPartyId = deps.relyingPartyId?.();
      const wire = await deps.startUpgrade(relyingPartyId ? { method, relying_party_id: relyingPartyId } : { method });
      return toPrepared(wire);
    } catch (e) {
      if (isAlreadySettled(e)) {
        throw e;
      }
      const error = classifyUpgradeError(e, 'start');
      // `prepare_not_required` is a recovery, not a failure: our static
      // `requiresPrepare` disagreed with the server's, which is version skew.
      // Resolving `undefined` lets the factor assert directly, turning a future
      // backend rename into one wasted round trip instead of a dead elevation.
      if (error.kind === 'prepare_not_required') {
        return undefined;
      }
      throw error;
    }
  },

  async commit(factor: UpgradeFactorType, assertion: UpgradeAssertion): Promise<void> {
    // Checked before the network, so a delivery mode that can never commit says
    // so instead of taking a code from the user and discarding it.
    const permitted = deps.canCommit();
    if (!permitted.ok) {
      throw new UpgradeTransportError({ kind: 'unavailable', message: permitted.reason });
    }

    try {
      await deps.commitRefresh({ type: factor, assertion });
    } catch (e) {
      // An outcome the SDK has already decided is NOT an HTTP failure to
      // classify. The host's token-application pin check and the facade's
      // epoch guard both raise session-change outcomes from inside this call,
      // and neither carries a `response`, so `classifyUpgradeError` read them
      // as `network` — §13.3's `session changed mid-flight` row reached every
      // waiter tagged `upgrade_transport`. Re-thrown untouched, and before the
      // invalidation decision: a mid-flight identity change must never
      // invalidate (§13.4 revision 6, C38/C41).
      if (isAlreadySettled(e)) {
        throw e;
      }

      const error = classifyUpgradeError(e, 'refresh');

      // Invalidate only on an id that POSITIVELY means the session died.
      //
      // The commit path's 401s are not ambiguous: `LocalizedRouter.HTTPError`
      // always writes a `PassflowError.id` into the body, and
      // `refreshErrorStatus` (`src/web/api/refresh_token.go:157-178`) returns
      // 401 for exactly five enumerated ids, every one of them the upgrade
      // protocol talking. A dead or refused refresh token is NOT among them —
      // it falls to that switch's `default: http.StatusInternalServerError`.
      //
      // So the old "anything else on a 401 is a real expiry" reasoning was
      // defending against a response this server cannot send, while admitting
      // one it can: `error.2fa.not_enabled` is a 401, was absent from the
      // recoverable list, and signed out a user who simply had no 2FA enrolled.
      // Inverted, the default is fail-open, which is the rule this feature is
      // built on: fail toward "I don't know" rather than "log them out".
      if (error.status === 401 && invalidatesSessionOnCommit(error)) {
        deps.markSessionInvalid?.();
      }

      throw error;
    }
  },
});
