/**
 * The request snapshot: ONE normalised, immutable description of the request
 * that carried a challenge, captured before dispatch.
 *
 * ## Why this module exists
 *
 * Every authorization decision the upgrade feature makes — is this URL in scope,
 * what does the diagnostic name, what does the replay re-send — must be made on
 * the SAME description of the request, and that description must be the one the
 * platform will actually act on. Three defects in this feature were the same
 * defect from three angles:
 *
 *   1. the scope check hand-parsed the caller's URL *string*, while the browser
 *      normalises it before dispatch;
 *   2. the challenge context re-read the caller's live `input` at challenge
 *      time, while the replay was pinned to the plan-time URL and body;
 *   3. the replay could re-send a different header set than the one that was
 *      examined.
 *
 * So the request is normalised and frozen ONCE, here, and the snapshot is the
 * only thing the scope check, the challenge context, the diagnostics and the
 * replay are given. Nothing downstream holds a live reference to the caller's
 * `Request`, `RequestInit` or axios config.
 *
 * ## The normalisation rule, and why it is the platform's own parser
 *
 * **Resolve with `new URL(raw, base)` and compare `origin` on the result.**
 *
 * WHATWG URL parsing is not a string scan. For a special scheme it converts
 * backslashes to forward slashes and strips ASCII tab (0x09), LF (0x0A) and CR
 * (0x0D) *before* parsing. A scope check that inspects the raw string therefore
 * sees a same-origin relative path where the browser resolves a foreign origin:
 * `'/\\evil.example/x'`, `'/\t/evil.example/x'` and `'\\\\evil.example/x'` all
 * resolve to `https://evil.example` (§13.4's SF-3, SF-4, SF-7). Each one would
 * attach a step-up-elevated credential to a request leaving for an
 * attacker-controlled host.
 *
 * **The percent-encoded forms are the mirror image, and they are POSITIVES.**
 * `'/%5Cevil.example/x'`, `'/%09/evil.example/x'` and `'/%2F%2Fevil.example/x'`
 * all resolve to the page's OWN origin and must stay in scope (SF-9..SF-12):
 * the parser decodes nothing that could change the authority, so `%5C` is not a
 * backslash, `%09` stays an ordinary path character and `%2F%2F` does not begin
 * an authority. They are legitimate same-origin requests with odd-looking paths.
 *
 * That asymmetry is the entire argument for resolving rather than filtering. A
 * list of rejected characters is a denylist against a parser, and the parser is
 * the authority: it is bypassed by the raw forms, whose bytes it rewrites before
 * it parses them, AND it is wrong in the opposite direction on the encoded
 * forms, which it refuses as hostile when the platform treats them as plain
 * path text. Resolving first gets both directions — and the vectors nobody has
 * thought of yet — for free.
 *
 * The operative consequence for anyone editing this file: hand the input to
 * `new URL` **undecoded and un-normalised**. Any decoding, trimming or
 * rewriting before that call reintroduces one half of the defect or the other.
 *
 * Off the browser there is no document, so there is no "same origin" to resolve
 * against. A relative URL is then resolved against a RESERVED sentinel origin
 * (`.invalid` is reserved by RFC 2606 and can never be a real host), which keeps
 * exactly one code path: a URL that resolves to the sentinel's origin is a
 * genuinely relative one, and anything that steers the authority elsewhere —
 * `//evil.example/x` included — resolves away from it and is no longer relative.
 * The sentinel is `https:` precisely because it must be a SPECIAL scheme: the
 * backslash and tab rules above apply only to special schemes, so a custom
 * scheme would be a different parser and would miss the vectors.
 */

import type { BodyKind } from './replay';

/** One captured header. Lower-cased name, value verbatim. */
export type SnapshotHeader = readonly [name: string, value: string];

/**
 * The frozen description of one request.
 *
 * Immutable by construction: `Object.freeze` on the snapshot and on its header
 * list, and the body already captured by value where the shape is mutable. It
 * carries no live reference to anything the caller can still change.
 */
export type RequestSnapshot = {
  /** Exactly what the caller passed, for diagnostics only. NEVER for a decision. */
  readonly raw: string;
  /**
   * The absolute, platform-normalised URL the request will actually be sent to,
   * or `raw` when it could not be resolved at all (a malformed URL).
   *
   * This is the value every decision and the replay use.
   */
  readonly href: string;
  /**
   * The URL to actually DISPATCH a replay to.
   *
   * Identical to `href` wherever a real base existed — a browser, or any host
   * that resolved the URL absolutely — which is the case every decision cares
   * about. It falls back to `raw` only when resolution used the reserved
   * sentinel base, i.e. a relative URL on a host with no document: the
   * sentinel's origin is a reserved name that resolves to nothing, so sending
   * `href` there would send the request into a hole. The transport's own base
   * (axios' `baseURL`, the runtime's fetch base) then resolves the captured
   * string, exactly as it did for the original send.
   *
   * It is still a captured STRING, never the caller's object, so the TOCTOU
   * this module exists to close stays closed on that path too.
   */
  readonly dispatchUrl: string;
  /** The resolved origin, or `undefined` when the URL could not be resolved. */
  readonly origin?: string;
  /** The resolved pathname, or the raw path when the URL could not be resolved. */
  readonly pathname: string;
  /** False when the URL could not be parsed even against the base. */
  readonly resolved: boolean;
  /**
   * True when the resolved origin is the base's own — the page's origin on a
   * browser, the sentinel's off it, which means "genuinely relative".
   *
   * This is what a same-origin path-prefix pattern (`backend: '/api'`) tests,
   * and it is the one bit that makes `'/\\evil.example/x'` fail where `'/api/x'`
   * passes.
   */
  readonly relativeToBase: boolean;
  /** Upper-cased, with the same precedence the transport itself applies. */
  readonly method: string;
  /** The effective header set, captured once. Frozen. */
  readonly headers: readonly SnapshotHeader[];
  /** How the body can be re-sent, which is what decides replayability. */
  readonly bodyKind: BodyKind;
  /**
   * The already-captured body. `undefined` means "the caller passed no body
   * key", which is distinct from an explicit `null`.
   */
  readonly body?: unknown;
};

/**
 * The reserved origin a relative URL is resolved against when there is no
 * document. RFC 2606 reserves `.invalid`, so no real deployment can collide
 * with it, and `https:` keeps the parser on its special-scheme rules.
 */
export const RELATIVE_BASE = 'https://passflow-relative.invalid';

/**
 * The base relative URLs resolve against, read at CALL time.
 *
 * `document.baseURI` first, because that — not `location.href` — is what `fetch`
 * and XHR resolve a relative URL against, and a `<base href>` moves it.
 * Reading a global at module scope is the SSR failure this feature avoids
 * everywhere, so this is a function.
 */
const resolutionBase = (): string => {
  const scope = globalThis as {
    document?: { baseURI?: unknown };
    location?: { href?: unknown };
  };
  const baseUri = scope.document?.baseURI;
  if (typeof baseUri === 'string' && baseUri !== '') {
    return baseUri;
  }
  const href = scope.location?.href;
  return typeof href === 'string' && href !== '' && href !== 'about:blank' ? href : RELATIVE_BASE;
};

/** What a URL normalised to. Pure: it takes the base, it does not read one. */
export type NormalisedUrl = {
  href: string;
  origin?: string;
  pathname: string;
  resolved: boolean;
  relativeToBase: boolean;
  /** True when no real base existed and the reserved sentinel was used. */
  sentinelBase: boolean;
};

/**
 * Resolves one URL with the platform's own parser.
 *
 * `base` defaults to the document base (or the sentinel off the browser). The
 * ONLY comparison any caller may make afterwards is on `origin` — never on the
 * raw string.
 */
export const normaliseUrl = (raw: string, base: string = resolutionBase()): NormalisedUrl => {
  const sentinelBase = base === RELATIVE_BASE;
  let baseOrigin: string | undefined;
  try {
    baseOrigin = new URL(base).origin;
  } catch {
    baseOrigin = undefined;
  }

  let resolved: URL | undefined;
  try {
    resolved = new URL(raw, base);
  } catch {
    resolved = undefined;
  }

  if (!resolved) {
    // Unparseable even against a base. It is not relative and it is not any
    // origin, so every origin comparison below fails and the request is out of
    // scope — the conservative reading used throughout this feature.
    const path = raw.split(/[?#]/)[0] ?? raw;
    return { href: raw, pathname: path, resolved: false, relativeToBase: false, sentinelBase };
  }

  return {
    href: resolved.href,
    origin: resolved.origin,
    pathname: resolved.pathname,
    resolved: true,
    relativeToBase: baseOrigin !== undefined && resolved.origin === baseOrigin,
    sentinelBase,
  };
};

/** Lower-cases a header name once, so every later comparison is a plain `===`. */
const headerEntry = (name: string, value: unknown): SnapshotHeader | undefined =>
  typeof value === 'string' ? ([name.toLowerCase(), value] as const) : undefined;

/**
 * Captures a header bag by value.
 *
 * Every shape the two transports produce arrives here: a DOM `Headers`, an
 * `AxiosHeaders`, a plain object, an entry array, or an array-valued node bag.
 * Copying is the point — the caller may still hold and mutate the original.
 */
export const captureHeaders = (headers: unknown): readonly SnapshotHeader[] => {
  const captured: SnapshotHeader[] = [];

  if (headers === undefined || headers === null) {
    return Object.freeze(captured);
  }

  // A `Headers` (or anything with the same iteration contract) enumerates
  // lower-cased, already-combined entries.
  const iterable = headers as { forEach?: unknown; entries?: unknown };
  if (typeof iterable.forEach === 'function' && typeof iterable.entries === 'function') {
    (headers as Headers).forEach((value, name) => {
      const entry = headerEntry(name, value);
      if (entry) {
        captured.push(entry);
      }
    });
    return Object.freeze(captured);
  }

  if (Array.isArray(headers)) {
    for (const pair of headers as unknown[]) {
      if (Array.isArray(pair) && pair.length >= 2) {
        const entry = headerEntry(String(pair[0]), pair[1]);
        if (entry) {
          captured.push(entry);
        }
      }
    }
    return Object.freeze(captured);
  }

  if (typeof headers === 'object') {
    for (const [name, value] of Object.entries(headers as Record<string, unknown>)) {
      // axios' node bag can hold an array per name; join it the way the wire does.
      const flat = Array.isArray(value) ? value.join(', ') : value;
      const entry = headerEntry(name, flat);
      if (entry) {
        captured.push(entry);
      }
    }
  }

  return Object.freeze(captured);
};

/** Reads a captured header. Case is already normalised, so this is exact. */
export const snapshotHeader = (snapshot: RequestSnapshot, name: string): string | undefined => {
  const wanted = name.toLowerCase();
  for (const [header, value] of snapshot.headers) {
    if (header === wanted) {
      return value;
    }
  }
  return undefined;
};

/** What a caller must supply to take a snapshot. Everything else is derived. */
export type RequestSnapshotInit = {
  url: string;
  method?: string;
  headers?: unknown;
  bodyKind: BodyKind;
  /** Pass the key only when the caller supplied a body, so `undefined` stays meaningful. */
  body?: unknown;
  /** Overrides the document base. Tests and non-browser hosts only. */
  base?: string;
};

/**
 * Takes the snapshot. Call it ONCE per request, BEFORE dispatch.
 *
 * Frozen on the way out: a snapshot that could be edited after the scope
 * decision would reintroduce the very TOCTOU this module removes.
 */
export const createRequestSnapshot = (init: RequestSnapshotInit): RequestSnapshot => {
  const normalised = init.base === undefined ? normaliseUrl(init.url) : normaliseUrl(init.url, init.base);

  const snapshot: RequestSnapshot = {
    raw: init.url,
    href: normalised.href,
    dispatchUrl: normalised.sentinelBase || !normalised.resolved ? init.url : normalised.href,
    ...(normalised.origin === undefined ? {} : { origin: normalised.origin }),
    pathname: normalised.pathname,
    resolved: normalised.resolved,
    relativeToBase: normalised.relativeToBase,
    method: (init.method ?? 'GET').toUpperCase(),
    headers: captureHeaders(init.headers),
    bodyKind: init.bodyKind,
    ...('body' in init ? { body: init.body } : {}),
  };

  return Object.freeze(snapshot);
};

/**
 * Applies the §5.5 credential swap to a captured header set, by EXACT match.
 *
 * Equality with the token we hold is what proves the header was ours; any other
 * value is forwarded untouched, because rewriting a header we do not own would
 * be a security bug. Returns the same frozen array when nothing changed, so the
 * common path allocates nothing.
 */
export const swapAuthorization = (
  headers: readonly SnapshotHeader[],
  swap?: { from: string; to: string },
): readonly SnapshotHeader[] => {
  if (!swap || swap.from === swap.to) {
    return headers;
  }
  let changed = false;
  const next = headers.map<SnapshotHeader>(([name, value]) => {
    if (name === 'authorization' && value === swap.from) {
      changed = true;
      return [name, swap.to] as const;
    }
    return [name, value] as const;
  });
  return changed ? Object.freeze(next) : headers;
};

/** The captured headers as the plain object both transports accept. */
export const headersToObject = (headers: readonly SnapshotHeader[]): Record<string, string> => {
  const bag: Record<string, string> = {};
  for (const [name, value] of headers) {
    bag[name] = value;
  }
  return bag;
};
