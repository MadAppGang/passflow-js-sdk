/**
 * Upgrade factor abstraction.
 *
 * A factor knows two things: whether proving it needs a server round-trip
 * first, and how to turn whatever the user did into the `upgrade.assertion`
 * blob `POST /auth/refresh` expects.
 *
 * `requiresPrepare` is declared statically rather than discovered by trying.
 * The server actively REJECTS a prepare call for one-shot factors
 * (`ErrorUpgradePrepareNotRequired`), so "call /begin and see what happens"
 * costs a guaranteed round-trip and a 400 on every TOTP upgrade.
 */

import type { AuthenticationResponseJSON, PublicKeyCredentialRequestOptionsJSON } from '@simplewebauthn/types';
import type { PlatformAdapter } from '../platform';

/** Factor types the upgrade protocol understands, named as `upgrade.type` on the wire. */
export type UpgradeFactorType = 'totp' | 'recovery_codes' | 'passkey' | 'email_otp' | 'sms_otp';

/** The prepare round's result — `POST /auth/upgrade/begin`, normalised to camelCase. */
export type UpgradePrepared = {
  challengeId: string;
  method: string;
  /** RFC 3339. The server gives a challenge five minutes; treat it as a hard deadline. */
  expiresAt: string;
  /** WebAuthn assertion options, present only for a passkey upgrade. */
  webauthn?: PublicKeyCredentialRequestOptionsJSON;
  /** Masked delivery target (`j***@x.com`), present only for email / SMS OTP. */
  codeSentTo?: string;
};

/**
 * The `upgrade.assertion` payload. Deliberately an open record: the server
 * types this field as `json.RawMessage` so new factors can extend the shape
 * without a wire-format change.
 */
export type UpgradeAssertion = {
  challenge_id?: string;
  code?: string;
  credential?: AuthenticationResponseJSON;
};

/** What a factor needs from the UI before it can be asserted. */
export type UpgradeFactorInput =
  /** A user-typed value: an OTP or a recovery code. */
  | 'code'
  /** Nothing typed — the ceremony itself collects the proof (a passkey prompt). */
  | 'none';

export type UpgradeAssertContext = {
  /** The value the user typed, for factors whose `input` is `'code'`. */
  code?: string;
  /** The prepare round's result, for factors where `requiresPrepare` is true. */
  prepared?: UpgradePrepared;
  /** Platform seam for the WebAuthn ceremony — keeps non-web adapters working. */
  platform: PlatformAdapter;
};

export type UpgradeFactor = {
  type: UpgradeFactorType;
  /** Whether `POST /auth/upgrade/begin` must run before the user can produce proof. */
  requiresPrepare: boolean;
  /** What the UI must collect before `assert` can run. */
  input: UpgradeFactorInput;
  /** Turns the user's response into the assertion blob sent as `upgrade.assertion`. */
  assert(ctx: UpgradeAssertContext): Promise<UpgradeAssertion>;
};

/** Thrown when a factor cannot produce proof — a cancelled prompt, or missing prerequisites. */
export class UpgradeFactorError extends Error {
  readonly factor: UpgradeFactorType;
  /** True when the user dismissed the ceremony rather than failing it. */
  readonly cancelled: boolean;

  constructor(factor: UpgradeFactorType, message: string, cancelled = false) {
    super(message);
    this.name = 'UpgradeFactorError';
    this.factor = factor;
    this.cancelled = cancelled;
  }
}

/** Requires a typed value, rejecting the empty string that an untouched input yields. */
const requireCode = (factor: UpgradeFactorType, code: string | undefined): string => {
  const trimmed = code?.trim();
  if (!trimmed) {
    throw new UpgradeFactorError(factor, 'A verification code is required');
  }
  return trimmed;
};

/**
 * TOTP — the canonical one-shot factor. The code is derived from a shared
 * secret and the clock, so nothing needs to be fetched first.
 */
export const totpFactor: UpgradeFactor = {
  type: 'totp',
  requiresPrepare: false,
  input: 'code',
  assert: async ({ code }) => ({ code: requireCode('totp', code) }),
};

/**
 * Recovery codes — also one-shot. Verified against the user's stored code set,
 * so like TOTP there is no challenge to issue.
 */
export const recoveryCodesFactor: UpgradeFactor = {
  type: 'recovery_codes',
  requiresPrepare: false,
  input: 'code',
  assert: async ({ code }) => ({ code: requireCode('recovery_codes', code) }),
};

/**
 * Passkey — the challenge-response factor. The prepare round supplies the
 * server nonce and, critically, an `allowCredentials` list scoped to the
 * signed-in user; the ceremony signs it and the assertion goes back with the
 * challenge id that binds it to this session.
 */
export const passkeyFactor: UpgradeFactor = {
  type: 'passkey',
  requiresPrepare: true,
  input: 'none',
  assert: async ({ prepared, platform }) => {
    if (!prepared?.webauthn) {
      throw new UpgradeFactorError('passkey', 'The upgrade challenge carried no WebAuthn options');
    }
    // `passkeys` is optional on the adapter: a platform without WebAuthn cannot
    // run this ceremony at all. Fail before the prepare round is spent rather
    // than after, so the user can fall back to another factor with the
    // challenge budget intact.
    const passkeys = platform.passkeys;
    if (!passkeys) {
      throw new UpgradeFactorError('passkey', 'This platform does not support passkeys');
    }

    let credential: AuthenticationResponseJSON | undefined;
    try {
      credential = await passkeys.startAuthentication(prepared.webauthn);
    } catch (e) {
      // A dismissed or timed-out WebAuthn prompt rejects. That is a cancel, not
      // a failure: the caller should let the user retry or back out, never
      // treat it as a bad credential.
      throw new UpgradeFactorError('passkey', (e as Error)?.message || 'Passkey verification was cancelled', true);
    }
    if (!credential) {
      throw new UpgradeFactorError('passkey', 'Passkey verification was cancelled', true);
    }

    return { challenge_id: prepared.challengeId, credential };
  },
};

/**
 * The factors this SDK can actually complete.
 *
 * `email_otp` and `sms_otp` are intentionally ABSENT. The server routes them
 * (`upgradePrepareMethod` accepts both) but has no OTP transport, so no user can
 * enrol them and `upgradeMethodRegistered` refuses the prepare round. Adding
 * them later is one entry here plus a factor whose assert returns
 * `{ challenge_id, code }` — no change to anything that consumes this registry.
 */
export const DEFAULT_UPGRADE_FACTORS: readonly UpgradeFactor[] = Object.freeze([
  totpFactor,
  passkeyFactor,
  recoveryCodesFactor,
]);

/** Indexes a factor list by type for lookup during a challenge. */
export const factorRegistry = (
  factors: readonly UpgradeFactor[] = DEFAULT_UPGRADE_FACTORS,
): Map<UpgradeFactorType, UpgradeFactor> => new Map(factors.map((f) => [f.type, f]));
