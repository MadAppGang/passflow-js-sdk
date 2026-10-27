/**
 * RFC 9470 step-up challenge parsing.
 *
 * A upgrade challenge is the server saying "this session is valid, but not
 * strong enough". It arrives in two shapes, both carrying the same
 * `WWW-Authenticate` vocabulary:
 *
 *   - `401` from a protected resource (RFC 9470 §3), emitted by the
 *     RequireAuthLevel / RequireFreshAuth middleware.
 *   - `403` from `/auth/session/exchange`, which keeps its ADR-2 JSON body
 *     (`{"error": "upgrade_required", ...}`) alongside the same header.
 *
 * Telling this apart from an ordinary `401` matters more than it looks: an
 * expired session and an insufficient one are the same status code with
 * opposite remedies. Clearing tokens on a upgrade challenge logs the user out
 * at the exact moment they were asked to prove *more*.
 */

import { type AcrReading, readAcrValues } from './acr';

/** The error code RFC 9470 §3 defines for an insufficient authentication event. */
export const INSUFFICIENT_USER_AUTHENTICATION = 'insufficient_user_authentication';

/** The ADR-2 error code `/auth/session/exchange` returns in its 403 body. */
export const UPGRADE_REQUIRED = 'upgrade_required';

/**
 * What the server demands before it will serve the original request.
 *
 * Both fields are optional because the two middlewares challenge on different
 * axes: RequireAuthLevel names an `acrValues` and omits `maxAge`, while
 * RequireFreshAuth does the reverse. A challenge carrying neither is still
 * valid — it means "re-prove a factor" without further qualification.
 */
export type UpgradeChallenge = {
  /**
   * Required authentication context class (`acr`), e.g. `'2'`.
   *
   * After a two-channel merge this is the raw list of the channel that SET THE
   * BAR, with the header preferred on a numeric tie. A channel that contributed
   * no level never supplies it — showing `"2gold"` as the bar would
   * misrepresent what the server demanded.
   */
  acrValues?: string;
  /**
   * The parsed bar: `max` over each channel's `min` participating level
   * (§13.2.1a). `undefined` means unknown or unconstrained on this axis.
   *
   * Optional, and absent from the single-channel parsers' output, so
   * `parseChallengeHeader` / `parseChallengeBody` keep the exact shape they
   * ship with. `readUpgradeChallenge` always sets it when a level was parsed.
   */
  requiredLevel?: number;
  /** Maximum permitted age of the authentication event, in seconds. */
  maxAge?: number;
  /** The status that carried the challenge: 401 (protected resource) or 403 (session exchange). */
  status: number;
  /**
   * Every channel that PARSED AS A CHALLENGE in any field — not only the
   * channels that won a comparison. An opaque header contributes no constraint
   * yet must still be counted, because only something that saw and discarded it
   * can report it. `length === 2` means "both channels carried a challenge".
   *
   * Set by `readUpgradeChallenge`; absent from the single-channel parsers.
   */
  channels?: ChallengeChannel[];
};

/** Which wire channel a challenge was read from. */
export type ChallengeChannel = 'header' | 'body';

/**
 * Matches one `auth-param` (RFC 9110 §11.2): a token, `=`, then either a
 * quoted-string or a bare token. Quoted values are captured separately from
 * bare ones so an embedded comma (legal inside quotes) does not split a value.
 */
const AUTH_PARAM = /([A-Za-z0-9!#$%&'*+\-.^_`|~]+)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|([^\s,]*))/g;

/** Unescapes a quoted-string body per RFC 9110 §5.6.4 (`\X` → `X`). */
const unescapeQuoted = (value: string): string => value.replace(/\\(.)/g, '$1');

/**
 * Parses the auth-params out of a `WWW-Authenticate` value.
 *
 * Scans params across the whole header rather than isolating a single
 * challenge. Passflow only ever emits one `Bearer` challenge, and scanning
 * broadly means an unexpected additional scheme degrades to "we still found
 * the Bearer params" instead of failing shut.
 */
const parseAuthParams = (header: string): Record<string, string> => {
  const params: Record<string, string> = {};
  // `matchAll` needs the regex reset; AUTH_PARAM is module-level and stateful.
  AUTH_PARAM.lastIndex = 0;
  for (const match of header.matchAll(AUTH_PARAM)) {
    const name = match[1];
    if (!name) {
      continue;
    }
    const quoted = match[2];
    const bare = match[3];
    params[name.toLowerCase()] = quoted !== undefined ? unescapeQuoted(quoted) : (bare ?? '');
  }
  return params;
};

/**
 * `max_age` has three outcomes, not two, so it gets a three-valued return.
 *
 * - **absent** — the field was not sent. Silent; it contributes nothing and
 *   there is nothing to report.
 * - **invalid** — `<= 0`, or non-numeric. It contributes nothing AND raises
 *   `'zero-constraint-ignored'`, because a literal `0` cannot be both "absent"
 *   and "invalid" while the parser is required to tell them apart.
 * - **valid** — a positive number of seconds.
 *
 * Treating `0` as invalid is a deliberate narrowing of RFC 9470 §3, which
 * permits `max_age=0` as a maximally strict freshness demand. Two reasons: this
 * parser already accepted only values `> 0` before §13, so preserving zero
 * would be a behaviour change on a shipped parser rather than a gap in it; and
 * under "smaller positive wins" a literal `0` from a buggy serializer or a
 * hostile body would force re-proof on EVERY request — an unauthenticated
 * denial-of-service against the user's own session. Recorded as a known
 * deviation so a later reader does not "fix" it.
 */
export type MaxAgeReading = { kind: 'absent' } | { kind: 'invalid'; raw: unknown } | { kind: 'valid'; value: number };

/** Reads `max_age` into its three outcomes. See `MaxAgeReading`. */
export const parseMaxAge = (raw: unknown): MaxAgeReading => {
  if (raw === undefined || raw === null || raw === '') {
    return { kind: 'absent' };
  }
  const n = typeof raw === 'number' ? raw : Number.parseInt(String(raw), 10);
  return Number.isFinite(n) && n > 0 ? { kind: 'valid', value: n } : { kind: 'invalid', raw };
};

/** The valid-only view, for the two single-channel parsers whose shape is shipped. */
const maxAgeValue = (raw: unknown): number | undefined => {
  const reading = parseMaxAge(raw);
  return reading.kind === 'valid' ? reading.value : undefined;
};

/**
 * Reads a upgrade challenge out of a `WWW-Authenticate` header, or returns
 * `undefined` when the header is absent or describes some other failure.
 *
 * The header must both use the `Bearer` scheme and carry
 * `error="insufficient_user_authentication"`. A bare `WWW-Authenticate: Bearer`
 * (what an expired token produces) is deliberately NOT a upgrade challenge.
 */
export const parseChallengeHeader = (header: string | undefined | null, status: number): UpgradeChallenge | undefined => {
  if (!header || !/(^|[\s,])Bearer\b/i.test(header)) {
    return undefined;
  }

  const params = parseAuthParams(header);
  if (params.error !== INSUFFICIENT_USER_AUTHENTICATION) {
    return undefined;
  }

  return {
    acrValues: params.acr_values || undefined,
    maxAge: maxAgeValue(params.max_age),
    status,
  };
};

/**
 * Reads a upgrade challenge out of the ADR-2 `403` body. Used as a fallback
 * for `/auth/session/exchange`, whose JSON body is the documented SDK contract
 * even though it also sets the standard header.
 */
export const parseChallengeBody = (body: unknown, status: number): UpgradeChallenge | undefined => {
  if (!body || typeof body !== 'object') {
    return undefined;
  }

  const data = body as Record<string, unknown>;
  if (data.error !== UPGRADE_REQUIRED) {
    return undefined;
  }

  return {
    acrValues: typeof data.acr_values === 'string' && data.acr_values ? data.acr_values : undefined,
    maxAge: maxAgeValue(data.max_age),
    status,
  };
};

/* ────────────────────────────────────────────────────────────────────────────
 * Both channels, merged (§13.2)
 *
 * The shipped parser chained header → body and returned the first hit: safe by
 * accident, not by design. Accepting two channels for a security-relevant value
 * creates a DOWNGRADE surface — from Passflow the two cannot disagree, both
 * being rendered from one `model.PolicyResult`, but a third-party resource
 * server, a header-rewriting intermediary or a CDN can make them disagree — so
 * first-match is withdrawn and replaced by STRONGEST-WINS:
 *
 *   - a channel's bar is the MINIMUM participating level of its `acr_values`
 *     list (`acr.ts`), and the winner is the LARGER bar: `max` over per-channel
 *     `min`, which is the monotonic lattice join;
 *   - `max_age` merges independently, smaller positive winning;
 *   - absence and invalidity are the identity element: a value that contributes
 *     nothing leaves the other channel's value standing, and a contributing
 *     value can only tighten.
 *
 * Per-attribute composition is intended: the strongest `acr` from one channel
 * plus the smallest positive `max_age` from the other yields a requirement
 * neither channel stated in full, which is a hybrid stricter than either.
 * Tightening is the safe direction for a client-side hint whose enforcement is
 * server-side. The normal case is exactly this — `RequireAuthLevel` emits
 * `acr_values` and omits `max_age`, `RequireFreshAuth` the reverse.
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

/** The reasons the SDK can decline to act on a challenge, or act on a suspect one. */
export type UpgradeDiagnosticReason =
  | 'no-channel'
  | 'header-required-but-absent'
  | 'channels-disagree'
  | 'channels-unorderable'
  | 'zero-constraint-ignored'
  | 'challenge-out-of-scope'
  | 'elevated-insufficient'
  | 'replay-unsupported';

/**
 * One diagnostic record.
 *
 * A diagnostic is the only observable signal of the response-rewriting and the
 * misconfiguration this design warns about, so it routes through a callback
 * whose DEFAULT sink is `console.warn` — never `debug`, which is invisible in
 * every default configuration. A deployment where step-up silently never fires
 * must be distinguishable from one where it was never required.
 */
export type UpgradeDiagnostic = {
  status: number;
  /**
   * The request's URL. The parser does not know it — it is handed a status, a
   * header reader and a body — so it emits `''` and the core, which owns the
   * request context, fills it in before forwarding to the sink.
   */
  url: string;
  reason: UpgradeDiagnosticReason;
  detail?: {
    obtained?: AssuranceBar;
    required?: AssuranceBar;
    /** Raw channel inputs, including values discarded as unorderable. */
    header?: string;
    body?: string;
    /** Which field was discarded, for `'zero-constraint-ignored'`. */
    field?: 'acr_values' | 'max_age';
    /** Which operation, for per-waiter reasons. */
    method?: string;
    /** A human-readable sentence naming the fix. The default sink prints it. */
    message?: string;
  };
};

/** Where diagnostics go. `console.warn` is the default sink, not the only one. */
export type UpgradeDiagnosticSink = (diagnostic: UpgradeDiagnostic) => void;

/** What `readUpgradeChallenge` is given. The CALLER decides whether reading the body is in scope. */
export type ChallengeInput = {
  status: number;
  getHeader: (name: string) => string | undefined | null;
  /** Pre-read. Omit it — do not pass `undefined` lazily — when the body must not be read. */
  body?: unknown;
};

export type ChallengeReadOptions = {
  /**
   * `'header'` takes the challenge from the header ONLY: the body is not read
   * for challenge purposes at all, and a 401/403 with no parseable header is a
   * non-challenge. For an integrator whose compliance rule names RFC 9470, or
   * who does not consider a third-party server's body authoritative. Two
   * intended consequences: a strictly stronger body is ignored, and since no
   * body is resolved the disagreement diagnostic never fires.
   *
   * There is deliberately no `'body'` value. Excluding a third-party API's
   * standard header is what `shouldIntercept` is for, and a `'body'` setting
   * would mandate a non-standard channel, which §13.1a forbids.
   */
  requireChallengeChannel?: 'header';
};

/**
 * What a parse found, and what it had to discard finding it.
 *
 * A pure parser returning its findings beats a sink parameter: it is
 * side-effect-free and directly testable against a fixture corpus, and
 * `'channels-disagree'`, `'zero-constraint-ignored'` and
 * `'channels-unorderable'` are knowable ONLY inside the parse — the shipped
 * parser discarded them before returning, which is why they could not be
 * surfaced at all.
 */
export type ChallengeReading = {
  challenge?: UpgradeChallenge;
  /** `[]` when there is nothing to report. Never `undefined`. */
  diagnostics: UpgradeDiagnostic[];
};

/** Reads one channel's fields, keeping the raw values for the diagnostics. */
type ChannelReading = {
  channel: ChallengeChannel;
  acr: AcrReading;
  maxAge: MaxAgeReading;
  /** The raw `acr_values` list as it arrived, for `detail.header` / `detail.body`. */
  raw?: string;
};

const readChannel = (channel: ChallengeChannel, challenge: UpgradeChallenge, rawMaxAge: unknown): ChannelReading => ({
  channel,
  acr: readAcrValues(challenge.acrValues),
  maxAge: parseMaxAge(rawMaxAge),
  raw: challenge.acrValues,
});

/** Picks the `acr_values` auth-param out of a header, without re-parsing semantics. */
const rawHeaderParams = (header: string | undefined | null): Record<string, string> => (header ? parseAuthParams(header) : {});

/**
 * Reads a step-up challenge from both channels at once, merging them field-wise
 * and reporting everything it discarded.
 *
 * The additive sibling of `parseUpgradeChallenge`, which keeps its shipped
 * three-parameter signature and delegates here. It keeps the `getHeader`
 * callback form — the reason the function works from both the fetch surface and
 * the axios surface, where `AxiosError.response` hands back a plain object
 * rather than a DOM `Headers`.
 */
export const readUpgradeChallenge = (input: ChallengeInput, options?: ChallengeReadOptions): ChallengeReading => {
  const { status } = input;
  if (status !== 401 && status !== 403) {
    return { diagnostics: [] };
  }

  const headerOnly = options?.requireChallengeChannel === 'header';
  const rawHeader = input.getHeader('www-authenticate');
  const headerChallenge = parseChallengeHeader(rawHeader, status);
  // Under `'header'` the body is not read for challenge purposes AT ALL — not
  // read-then-ignored. The caller is expected not to have read it either.
  const bodyChallenge = headerOnly ? undefined : parseChallengeBody(input.body, status);

  const diagnostics: UpgradeDiagnostic[] = [];
  const report = (reason: UpgradeDiagnosticReason, detail?: UpgradeDiagnostic['detail']): void => {
    diagnostics.push({ status, url: '', reason, ...(detail ? { detail } : {}) });
  };

  if (!headerChallenge && !bodyChallenge) {
    if (headerOnly) {
      // The flag asserts `Access-Control-Expose-Headers: WWW-Authenticate` is in
      // place. When it is not, this is what says so — warn, never block.
      report('header-required-but-absent', rawHeader ? { header: rawHeader } : undefined);
    }
    return { diagnostics };
  }

  const channels: ChannelReading[] = [];
  if (headerChallenge) {
    channels.push(readChannel('header', headerChallenge, rawHeaderParams(rawHeader).max_age));
  }
  if (bodyChallenge) {
    const body = input.body as Record<string, unknown> | undefined;
    channels.push(readChannel('body', bodyChallenge, body?.max_age));
  }

  const rawOf = (channel: ChallengeChannel): 'header' | 'body' => channel;

  for (const reading of channels) {
    if (reading.acr.unorderable) {
      // An opaque issuer-defined ACR is legal OIDC and contributes nothing. The
      // discarded value travels in the detail, which is what that field is for.
      report('channels-unorderable', { [rawOf(reading.channel)]: reading.raw });
    }
    if (reading.acr.zero) {
      report('zero-constraint-ignored', { field: 'acr_values', [rawOf(reading.channel)]: reading.raw });
    }
    if (reading.maxAge.kind === 'invalid') {
      report('zero-constraint-ignored', { field: 'max_age', [rawOf(reading.channel)]: String(reading.maxAge.raw) });
    }
  }

  // ── the `acr` axis: max over per-channel min, header preferred on a tie ──
  const contributing = channels.filter((reading) => reading.acr.level !== undefined);
  let requiredLevel: number | undefined;
  let acrValues: string | undefined;
  for (const reading of contributing) {
    const level = reading.acr.level as number;
    if (requiredLevel === undefined || level > requiredLevel) {
      requiredLevel = level;
      acrValues = reading.raw;
    }
    // On a numeric tie the HEADER's raw string is preserved: it is the standards
    // channel and the one a server operator can be held to. The parsed level is
    // identical either way, so the choice is only about which string a developer
    // sees in a diagnostic.
    else if (level === requiredLevel && reading.channel === 'header') {
      acrValues = reading.raw;
    }
  }

  // ── the freshness axis: smaller positive wins, independently of `acr` ──
  let maxAge: number | undefined;
  for (const reading of channels) {
    if (reading.maxAge.kind === 'valid' && (maxAge === undefined || reading.maxAge.value < maxAge)) {
      maxAge = reading.maxAge.value;
    }
  }

  // A disagreement is compared FIELD-WISE, so two channels constraining
  // different axes — the normal case — is never reported as one.
  if (channels.length === 2) {
    const [first, second] = channels as [ChannelReading, ChannelReading];
    const acrDisagrees =
      first.acr.level !== undefined && second.acr.level !== undefined && first.acr.level !== second.acr.level;
    const freshnessDisagrees =
      first.maxAge.kind === 'valid' && second.maxAge.kind === 'valid' && first.maxAge.value !== second.maxAge.value;
    if (acrDisagrees || freshnessDisagrees) {
      report('channels-disagree', { header: first.raw ?? second.raw, body: second.raw ?? first.raw });
    }
  }

  return {
    challenge: {
      acrValues,
      requiredLevel,
      maxAge,
      status,
      channels: channels.map((reading) => reading.channel),
    },
    diagnostics,
  };
};

/**
 * Resolves a upgrade challenge from a response, from either channel.
 *
 * The SHIPPED export: same name, same three parameters, same return, published
 * in `@passflow/core@0.14.1`. It is now a thin delegate over
 * `readUpgradeChallenge`, so there is one merge rule rather than two parsers
 * that can drift — but it discards the diagnostics, which is why a caller that
 * needs them (the core) calls the sibling directly.
 *
 * Returns `undefined` for every response that is not a upgrade challenge —
 * including ordinary `401`s, which callers must keep treating as "session
 * expired".
 */
export const parseUpgradeChallenge = (
  status: number,
  getHeader: (name: string) => string | undefined | null,
  body?: unknown,
): UpgradeChallenge | undefined => readUpgradeChallenge({ status, getHeader, body }).challenge;
