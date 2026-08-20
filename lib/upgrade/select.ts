/**
 * Which factor do we put in front of the user, and in what order?
 *
 * The challenge names what the server wants (`acrValues`, `maxAge`); this
 * module decides which of the SDK's registered factors to offer and which one
 * leads. The first entry is the "suggested" method the UI renders immediately
 * — everything after it sits behind "use another way" (PFL-509).
 *
 * ## Rank, never filter
 *
 * It is tempting to drop factors that "cannot reach" the demanded level. The
 * SDK cannot know that. The server computes `acr` from the *combination* of the
 * session's base methods and the verified factor, so a code factor DOES satisfy
 * an AAL3 challenge when the base session already reaches AAL3 — and for a
 * passkey the level depends on what the assertion reports, which is unknowable
 * until the ceremony runs.
 *
 * Getting that wrong is asymmetric. Offering a factor that turns out to be
 * insufficient costs one round-trip and a retry. Hiding one that would have
 * worked tells the user to re-authenticate when they did not have to, and
 * there is no way back from that. So every factor stays on the list; the
 * ordering carries the opinion, and the server stays the authority.
 *
 * ## Enrolment is filtered upstream, not here
 *
 * `available` is what this SDK can complete, not what the user has. The server
 * refuses a prepare round for an unenrolled factor
 * (`ErrorUpgradeMethodNotRegistered`). Narrowing `available` to the user's
 * actual credentials belongs to the caller — see the note at the bottom.
 */

import type { UpgradeChallenge } from './challenge';
import type { UpgradeFactor, UpgradeFactorType } from './factors';

/** The assurance level a challenge demands, when it names one at all. */
const AAL3 = 3;

/**
 * Ceremony preference among factors that are equally suitable, lowest first.
 *
 * Passkey leads because it is the cheapest ceremony for the user — one gesture,
 * nothing to read or type, nothing to mistype — and the strongest: it is the
 * only factor that can carry a session to AAL3 on its own, and the only one
 * that is phishing-resistant.
 *
 * Recovery codes sit last on purpose. They verify perfectly well, but each one
 * is single-use and the user's supply is finite and usually inconvenient to
 * reach. Spending one on a routine elevation is a bad trade when a repeatable
 * factor is available, so they are an escape hatch rather than a suggestion.
 */
const CEREMONY_ORDER: Record<UpgradeFactorType, number> = {
  passkey: 0,
  totp: 1,
  email_otp: 2,
  sms_otp: 3,
  recovery_codes: 9,
};

/**
 * Parses `acr_values` into the level the challenge actually demands.
 *
 * OIDC Core §3.1.2.1 makes `acr_values` a space-separated list in preference
 * order, and RFC 9470 §3 reuses it to name the values the resource server will
 * accept. Satisfying ANY listed value is enough, so the bar to clear is the
 * LOWEST one — taking the highest would over-constrain the ordering and demote
 * factors that would in fact have been accepted.
 *
 * Returns undefined when the challenge names no level (a `max_age`-only
 * freshness challenge), in which case any factor re-proves recency equally.
 */
const requiredLevel = (acrValues: string | undefined): number | undefined => {
  if (!acrValues) {
    return undefined;
  }
  const levels = acrValues
    .split(/\s+/)
    .map((v) => Number.parseInt(v, 10))
    .filter((n) => Number.isFinite(n));
  return levels.length > 0 ? Math.min(...levels) : undefined;
};

/**
 * Ranks a factor against the demanded level. Lower sorts first.
 *
 * Only one rule applies beyond ceremony preference: when the challenge demands
 * AAL3, a factor that cannot reach it unaided is demoted out of the suggested
 * slot. It is still offered — the base session may carry the level — but it
 * should not be the thing the user is shown first, because for most sessions it
 * will not be enough.
 */
const rank = (factor: UpgradeFactor, demanded: number | undefined): number => {
  const ceremony = CEREMONY_ORDER[factor.type] ?? 5;
  const needsAAL3 = demanded !== undefined && demanded >= AAL3;
  // `psk` + `hwk` + `user` is the only marker set ComputeACR scores as AAL3,
  // and only a passkey ceremony can report it.
  const reachesAAL3Unaided = factor.type === 'passkey';
  const demoted = needsAAL3 && !reachesAAL3Unaided ? 100 : 0;
  return demoted + ceremony;
};

/**
 * Orders the factors to offer for a challenge. Index 0 is the suggested
 * method; the rest are the "use another way" alternatives.
 *
 * The suggested slot is not only a UX choice: PFL-510 treats a non-suggested
 * choice as a minor risk signal, so whatever leads here becomes the behavioural
 * baseline deviation is measured against.
 *
 * @param available - Factors this SDK can complete. Narrow to the user's
 *                    enrolled credentials before calling, when known.
 * @param challenge - What the server demanded (`acrValues`, `maxAge`).
 * @returns The factors to offer, most-preferred first. Empty only when
 *          `available` was empty — this never drops a factor of its own accord.
 */
export const selectFactors = (available: readonly UpgradeFactor[], challenge: UpgradeChallenge): readonly UpgradeFactor[] => {
  const demanded = requiredLevel(challenge.acrValues);
  // Sort a copy: `available` may be the caller's registry, and a stable sort
  // keeps registration order as the tie-break for equally ranked factors.
  return [...available].sort((a, b) => rank(a, demanded) - rank(b, demanded));
};

/*
 * TODO(PFL-497): narrow `available` to the user's enrolled factors before this
 * runs. Today the SDK would need two calls — `GET /user/passkey` and
 * `GET /v2/user/2fa/methods` — and would have to reimplement the union rule the
 * server already owns privately in `upgradeMethodRegistered`. That rule is
 * scheduled to change (passkeys move into the method registry), so duplicating
 * it client-side would break on a backend release. Wire this to the single
 * `?purpose=upgrade` discovery endpoint once it exists; until then an
 * unenrolled suggestion costs one refused prepare round.
 */
