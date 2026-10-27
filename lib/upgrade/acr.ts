/**
 * The one implementation of "what level does this `acr_values` string demand".
 *
 * `challenge.ts` and `select.ts` both import it, so there is exactly one answer
 * in this package (§13.2.1b). It is consistent with the Go model *where the Go
 * model parses a single value* (`Level("2") === 2`) and deliberately diverges
 * where Go parses a list as a scalar: `token_acr.go`'s `Level()` is
 * `strconv.Atoi` over the whole string, so `Level("2 3")` is 0 — the weakest
 * possible reading of the stronger demand, which inverts channel precedence in
 * exactly the third-party interop case the precedence rule exists for.
 *
 * ## The lexical contract
 *
 * `acr_values` is a space-delimited list of values the server will accept (OIDC
 * Core §3.1.2.1, RFC 9470 §3), and satisfying ANY listed value suffices. So the
 * bar to clear is the list's MINIMUM participating level — the weakest value
 * that satisfies the server, which is by definition what it is demanding.
 *
 * A token PARTICIPATES iff the whole token is decimal digits (`/^[0-9]+$/`).
 * `"02"` participates as 2, matching `strconv.Atoi`. Everything else does not:
 * `"2gold"`, `"gold"`, `"2.0"`, `"-1"`, `"+2"`, `"1e2"`, `"urn:example:gold"`,
 * the empty token. Two deliberate narrowings:
 *
 *   - **Whole-token only.** `Number.parseInt("2gold", 10)` reads 2, which would
 *     contradict the rule that opaque values do not participate — and would let
 *     a hostile or buggy channel smuggle a bar out of a value nobody meant as a
 *     level.
 *   - **Negatives excluded**, even though `strconv.Atoi` accepts them. A
 *     negative assurance level has no meaning in the Passflow scale or in OIDC,
 *     and admitting one would hand an attacker a bar below every real level.
 *
 * Every non-negative integer is in domain. Passflow's scale is 0..3, but a
 * third-party server may legally demand 4; the SDK never refuses a demand
 * client-side (§13.4) — it ranks factors for the highest bar it knows and lets
 * the server's verdict on the replay decide.
 *
 * ## "unknown" is not zero, and zero is not absent
 *
 * An opaque issuer-defined value (`urn:…`, `"gold"`) is legal OIDC and is NOT a
 * level at all: scoring it 0 would make it the weakest possible requirement, so
 * the other channel would always win and the anti-downgrade rule would itself
 * produce a downgrade. A literal `"0"`, by contrast, IS a participating level
 * that happens to demand nothing — OIDC defines `acr` 0 as authentication not
 * meeting even ISO/IEC 29115 level 1, so a server listing it is stating it
 * accepts unelevated authentication. Same net contribution (no constraint),
 * different diagnostics.
 */

/** A token participates iff the WHOLE token is decimal digits. */
const PARTICIPATING_TOKEN = /^[0-9]+$/;

/** What an `acr_values` list demands, plus what it discarded getting there. */
export type AcrReading = {
  /**
   * The bar this list demands: the minimum participating level, when that is a
   * real constraint. `undefined` means this list contributes no `acr`
   * constraint — it was absent, every token was non-participating, or the
   * minimum participating level was `0`.
   */
  level?: number;
  /** The raw list, verbatim, when one was present at all. */
  raw?: string;
  /** True when a list was present but no token participated (`"urn:example:gold"`). */
  unorderable: boolean;
  /** True when the minimum participating level was `0` — a demand of nothing. */
  zero: boolean;
};

/** The empty reading: no list, no constraint, nothing to report. */
const ABSENT: AcrReading = Object.freeze({ unorderable: false, zero: false });

/**
 * Parses one `acr_values` token. Returns `undefined` for every value that does
 * not participate, which is the only distinction the comparator needs.
 */
export const parseAcrToken = (token: string): number | undefined =>
  PARTICIPATING_TOKEN.test(token) ? Number.parseInt(token, 10) : undefined;

/**
 * Reduces an `acr_values` list to the bar it demands.
 *
 * The reducer is `min` over participating tokens; the cross-channel comparator
 * (`challenge.ts`) then takes the `max` over per-channel minima, which is the
 * monotonic lattice join and therefore can never resolve below a correctly
 * parsed channel.
 */
export const readAcrValues = (raw: string | undefined | null): AcrReading => {
  if (!raw) {
    return ABSENT;
  }

  const tokens = raw.split(/\s+/).filter((token) => token !== '');
  if (tokens.length === 0) {
    return ABSENT;
  }

  const levels: number[] = [];
  for (const token of tokens) {
    const level = parseAcrToken(token);
    if (level !== undefined) {
      levels.push(level);
    }
  }

  if (levels.length === 0) {
    // A list of opaque values: unknown, not zero. It contributes no constraint
    // and must be reported, because only something that saw and discarded it
    // can say so.
    return { raw, unorderable: true, zero: false };
  }

  const bar = Math.min(...levels);
  // `acr_values="0"` or `"0 2"`: the server accepts unelevated authentication,
  // so this list is identical in effect to an absent one. Reported rather than
  // left inert, so an accidental `"0"` is visible.
  return bar === 0 ? { raw, unorderable: false, zero: true } : { level: bar, raw, unorderable: false, zero: false };
};

/**
 * The level an `acr_values` list demands, or `undefined` for no constraint.
 *
 * The convenience form `select.ts` wants: it ranks factors and has no use for
 * the diagnostics.
 */
export const requiredAcrLevel = (raw: string | undefined | null): number | undefined => readAcrValues(raw).level;
