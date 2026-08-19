/**
 * Which factor do we put in front of the user, and in what order?
 *
 * The challenge names what the server wants (`acrValues`, `maxAge`); this
 * module decides which of the SDK's registered factors to offer and which one
 * leads. The first entry is the "suggested" method the UI renders immediately
 * — everything after it sits behind "use another way" (PFL-509).
 *
 * ## Why this cannot be a pure acr calculation
 *
 * It is tempting to filter factors by "can this reach acr >= N". The SDK
 * cannot know that. The server computes `acr` from the *combination* of the
 * session's base methods and the verified factor (`ComputeACR(amr)`), and for
 * a passkey the level also depends on what the assertion reports — a
 * user-verified device-bound credential reaches AAL3, a syncable one caps at
 * AAL2. None of that is knowable before the ceremony runs.
 *
 * So selection is advisory: offer what plausibly satisfies the challenge, let
 * the server be the authority, and surface its refusal as a retry.
 *
 * ## Enrolment is also unknown here
 *
 * The SDK does not know which factors the user actually has. The server
 * refuses a prepare round for an unenrolled factor
 * (`ErrorUpgradeMethodNotRegistered`), so suggesting a passkey to someone who
 * has none costs a wasted round-trip and an error the user did not cause.
 */

import type { UpgradeChallenge } from './challenge';
import type { UpgradeFactor } from './factors';

/**
 * Orders the factors to offer for a challenge. Index 0 is the suggested
 * method; the rest are the "use another way" alternatives.
 *
 * @param available - Factors this SDK can complete, in registration order.
 * @param _challenge - What the server demanded (`acrValues`, `maxAge`).
 * @returns The factors to offer, most-preferred first. Empty means the
 *          challenge cannot be satisfied and the user must re-authenticate.
 *
 * TODO(jack): implement the ordering policy. See the trade-offs below.
 */
export const selectFactors = (available: readonly UpgradeFactor[], _challenge: UpgradeChallenge): readonly UpgradeFactor[] => {
  // Placeholder: offer everything in registration order. Replace with the
  // real policy — see the note in this file's header and the trade-offs
  // recorded alongside this TODO.
  return available;
};
