/**
 * The replay planner.
 *
 * Pure, no I/O, and it runs BEFORE the first call — a `Request` body must be
 * cloned while it is still unread, so by the time a 401 has come back it is too
 * late to decide whether a replay is possible. Planning first is also what lets
 * the core fail BEFORE opening a prompt: prompting the user, elevating their
 * session and only then discovering we cannot honour it is the worst possible
 * ordering, because it spends a server challenge and a user interaction for
 * nothing.
 *
 * ## Why replaying a challenged request is safe at all
 *
 * An RFC 9470 challenge is emitted by the authorization middleware —
 * `RequireAuthLevel` / `RequireFreshAuth` — BEFORE the handler runs, so the
 * request had no effect. That is categorically different from a 429 or a 502,
 * where the request may have partially executed, which is why
 * `AxiosClient.handleRateLimitError` correctly refuses to retry non-idempotent
 * requests and why this correctly does the opposite.
 *
 * The guarantee depends on the CUSTOMER's middleware placement, though, so
 * there is an escape hatch rather than an assumption: a backend that emits an
 * `insufficient_user_authentication` challenge after a side effect is violating
 * RFC 9470, and such a backend sets `'idempotent-only'`. Stating the
 * precondition is the design; silently assuming it would not be.
 *
 * ## Per-waiter binding
 *
 * A plan is bound to the request that carried the challenge: its own URL, its
 * own method and its own pre-captured body. No waiter's challenge, outcome or
 * response ever changes what another waiter replays, or where — requirement
 * AGGREGATION across waiters sharing a session is permitted and happens in the
 * controller; replay SUBSTITUTION is prohibited, and that prohibition is this
 * module's whole job.
 */

import { type RequestSnapshot, createRequestSnapshot, headersToObject, swapAuthorization } from './snapshot';

/** Our own `fetch` shape. Declared here rather than imported so no DOM lib is required. */
export type FetchLike = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

/** How a body can be re-sent, which is the only thing that decides replayability. */
export type BodyKind =
  /** No body at all. Re-issue the same input. */
  | 'none'
  /** A value the caller still holds and `fetch` re-reads: string, Blob, buffer, FormData, params. */
  | 'reusable'
  /** A `Request` with a body, cloned before the first send. */
  | 'request-clone'
  /** Consumed by the first send and unrecoverable: a `ReadableStream`, or a failed clone. */
  | 'one-shot';

/** What the policy predicate is told about a request. */
export type UpgradeReplayInfo = { url: string; method: string; bodyKind: BodyKind };

/**
 * Replay policy.
 *
 * The object form is §13.5's: size and streaming limits. The three string and
 * function forms are §5.1's escape hatch, kept because `'idempotent-only'`
 * expresses a constraint the object form cannot — a backend whose challenge may
 * arrive after a side effect.
 */
export type ReplayPolicy =
  | {
      /** Refuse to buffer a `Request` body larger than this many bytes, when the size is known. */
      maxBodyBytes?: number;
      /** A stream is never replayable; the field exists so the intent is written down. */
      allowStreamingBody?: false;
    }
  | 'always'
  | 'idempotent-only'
  | ((info: UpgradeReplayInfo) => boolean);

/** Hints the core passes at replay time. The planner applies them; it decides nothing. */
export type ReplayHints = {
  /**
   * The §5.5 credential swap, already resolved by the core.
   *
   * Applied if and only if the outgoing `Authorization` header value EXACTLY
   * equals `from`: equality with the token we hold in storage is what proves the
   * header was ours. Any other value is forwarded untouched, because rewriting a
   * header we do not own would be a security bug.
   *
   * Without this the replay re-sends the stale `Authorization` header, every
   * elevation ends in a surfaced second 401, and the feature silently never
   * works. Cookie mode needs none of it: the browser attaches the current —
   * now elevated — cookie by itself.
   */
  authorizationSwap?: { from: string; to: string };
};

export type ReplayPlan = {
  /** False when the body cannot be re-sent, or the policy refused. */
  replayable: boolean;
  bodyKind: BodyKind;
  /** Why it is not replayable, for the `'replay-unsupported'` diagnostic. */
  reason?: string;
  /** What to pass to `next()` on the FIRST call. */
  forwardInput: RequestInfo | URL;
  forwardInit?: RequestInit;
  /**
   * The normalised, immutable snapshot of this request — §13.4 revision 6.
   *
   * EXPOSED rather than hidden as a plan-time url, so the scope check, the
   * challenge context, the diagnostics and the replay all read the same object
   * and the request that is *authorized* cannot differ from the one that is
   * *sent*.
   */
  snapshot: RequestSnapshot;
  /** Re-issues the original request, once. Rejects if `!replayable`. */
  replay: (next: FetchLike, hints?: ReplayHints) => Promise<Response>;
};

const IDEMPOTENT_METHODS: ReadonlySet<string> = new Set(['GET', 'HEAD', 'OPTIONS']);

/** Duck-typed so no DOM lib is needed and a polyfilled `Request` still matches. */
const isRequest = (input: unknown): input is Request =>
  typeof input === 'object' &&
  input !== null &&
  typeof (input as Request).url === 'string' &&
  typeof (input as Request).clone === 'function' &&
  'method' in (input as Request);

/** The URL of whatever shape the caller passed, without touching the network. */
export const urlOf = (input: RequestInfo | URL): string => {
  if (typeof input === 'string') {
    return input;
  }
  if (isRequest(input)) {
    return input.url;
  }
  return String(input);
};

/** The method of whatever shape the caller passed. `init` wins, as `fetch` itself has it. */
export const methodOf = (input: RequestInfo | URL, init?: RequestInit): string => {
  const method = init?.method ?? (isRequest(input) ? input.method : undefined);
  return (method ?? 'GET').toUpperCase();
};

/**
 * Classifies an `init` body.
 *
 * `reusable` is every value the caller still holds and `fetch` re-reads from:
 * strings, `Blob`, `ArrayBuffer`, typed arrays, `DataView`, `URLSearchParams`
 * and `FormData`. A `ReadableStream` is the one shape that is consumed by the
 * first send, and the `duplex: 'half'` form is no different.
 */
const classifyInitBody = (body: BodyInit | null | undefined): BodyKind => {
  if (body === null || body === undefined) {
    return 'none';
  }
  if (typeof body === 'string') {
    return 'reusable';
  }
  // A stream exposes `getReader`; nothing else in the BodyInit union does.
  if (typeof (body as ReadableStream).getReader === 'function') {
    return 'one-shot';
  }
  return 'reusable';
};

/** The byte length of a body when it is knowable without consuming it. */
const knownBodyBytes = (body: BodyInit | null | undefined): number | undefined => {
  if (typeof body === 'string') {
    // Close enough for a guard rail, and it never under-counts for ASCII.
    return body.length;
  }
  const sized = body as { size?: unknown; byteLength?: unknown } | null | undefined;
  if (typeof sized?.size === 'number') {
    return sized.size;
  }
  if (typeof sized?.byteLength === 'number') {
    return sized.byteLength;
  }
  return undefined;
};

/**
 * Applies the policy. The planner asks; it never decides what the policy means.
 *
 * Exported because the axios adapter needs the same answer about an
 * `AxiosRequestConfig`, which has no `Request` and no `BodyInit` to plan over.
 * Two readings of `'idempotent-only'` — one here and one there — is exactly the
 * per-surface drift the single core forbids, so there is one reading and both
 * surfaces call it.
 */
export const policyPermits = (policy: ReplayPolicy | undefined, info: UpgradeReplayInfo, bodyBytes?: number): boolean => {
  if (policy === undefined || policy === 'always') {
    return true;
  }
  if (policy === 'idempotent-only') {
    return IDEMPOTENT_METHODS.has(info.method);
  }
  if (typeof policy === 'function') {
    return policy(info);
  }
  if (policy.maxBodyBytes !== undefined && bodyBytes !== undefined && bodyBytes > policy.maxBodyBytes) {
    return false;
  }
  return true;
};

/** A plan that refuses, so the core can return the original response untouched. */
const refuse = (
  bodyKind: BodyKind,
  reason: string,
  forwardInput: RequestInfo | URL,
  snapshot: RequestSnapshot,
  forwardInit?: RequestInit,
): ReplayPlan => ({
  replayable: false,
  bodyKind,
  reason,
  forwardInput,
  forwardInit,
  snapshot,
  replay: () => Promise.reject(new Error(`This request cannot be replayed: ${reason}`)),
});

/**
 * The header set the replay sends: the snapshot's, with the credential swapped.
 *
 * ## Why precedence is resolved ONCE, here
 *
 * `fetch(input, init)` does not merge header sets. When `init.headers` is
 * present it **replaces** a `Request`'s headers entirely; when it is absent the
 * `Request`'s own headers are used. Applying the §5.5 swap to one of the two
 * objects and letting `fetch` pick the other is how a replay went out carrying
 * the PRE-elevation `Authorization` and the whole feature silently did nothing:
 * the elevated credential was written into the set that was then discarded.
 *
 * So the snapshot captures the EFFECTIVE set once, before dispatch, by the
 * `fetch` rule above, the swap is applied to that one set, and the replay sends
 * it explicitly. There is no second set left for anything to prefer.
 */
const replayHeaders = (snapshot: RequestSnapshot, hints?: ReplayHints): Record<string, string> =>
  headersToObject(swapAuthorization(snapshot.headers, hints?.authorizationSwap));

/** The caller's `init` minus `headers`, which `replayHeaders` now owns outright. */
const initWithoutHeaders = (init: RequestInit | undefined): RequestInit | undefined => {
  if (!init || !('headers' in init)) {
    return init;
  }
  const { headers: _headers, ...rest } = init;
  return rest;
};

/**
 * The effective header set `fetch` itself would use, per the rule above.
 *
 * An explicit `undefined` counts as absent, which is how WebIDL reads a
 * dictionary member set to `undefined`.
 */
const effectiveHeaders = (input: RequestInfo | URL, init?: RequestInit): unknown => {
  if (init && 'headers' in init && init.headers !== undefined) {
    return init.headers;
  }
  return isRequest(input) ? input.headers : undefined;
};

/**
 * Captures an `init` body by VALUE, once, before the first send.
 *
 * Snapshotting the URL and the method was not enough: a `FormData` the caller
 * still holds is a live object, and `fetch` re-reads it on every send. A
 * transfer planned to Alice, `form.set('to', 'Mallory')` while the prompt is
 * open, and the replay carries Mallory — with the freshly elevated credential
 * attached, against a request no scope or policy decision ever saw. Same TOCTOU
 * class as the re-pointable `URL`, on the other half of the request.
 *
 * Only the MUTABLE shapes are copied. Strings and `Blob`s are immutable, so
 * holding the reference already is a snapshot; `ArrayBuffer`s, views,
 * `URLSearchParams` and `FormData` are not. The `FormData` copy is shallow by
 * design: its values are strings and `Blob`s, both immutable, so re-appending
 * them costs no buffering. A `ReadableStream` never reaches here —
 * `classifyInitBody` has already refused it as `one-shot`.
 *
 * The copy happens inside `planReplay`, AFTER `policyPermits`, so the existing
 * `maxBodyBytes` limit still governs what the SDK is willing to hold.
 */
const snapshotBody = (body: BodyInit | null): BodyInit | null => {
  if (body === null || typeof body === 'string') {
    return body;
  }
  if (typeof FormData !== 'undefined' && body instanceof FormData) {
    const copy = new FormData();
    for (const [name, value] of body as unknown as Iterable<[string, FormDataEntryValue]>) {
      copy.append(name, value as string | Blob);
    }
    return copy;
  }
  if (typeof URLSearchParams !== 'undefined' && body instanceof URLSearchParams) {
    return new URLSearchParams(body);
  }
  if (body instanceof ArrayBuffer) {
    return body.slice(0);
  }
  if (ArrayBuffer.isView(body)) {
    return new Uint8Array(body.buffer, body.byteOffset, body.byteLength).slice();
  }
  // A `Blob` (and anything exotic a polyfill hands us) is forwarded as given.
  return body;
};

/**
 * A `Request` carrying the snapshot's effective, credential-swapped headers.
 *
 * `Request` headers are immutable once constructed, so applying them means
 * building a new `Request` from the clone. Everything else is copied by the
 * `Request` constructor's own init form, which is the only way to preserve
 * `mode`, `credentials`, `cache`, `redirect`, `referrer`, `integrity` and the
 * signal without naming them.
 */
const requestWithSnapshotHeaders = (request: Request, snapshot: RequestSnapshot, hints?: ReplayHints): Request =>
  new Request(request, { headers: replayHeaders(snapshot, hints) });

/**
 * Decides whether a request can be replayed, and produces the thunk that does it.
 *
 * Call it BEFORE the first send. The returned `forwardInput` / `forwardInit` are
 * what the first send must use: for a `Request` with a body they are the
 * original, with the spare clone held for the replay.
 */
export const planReplay = (input: RequestInfo | URL, init?: RequestInit, policy?: ReplayPolicy): ReplayPlan => {
  const url = urlOf(input);
  const method = methodOf(input, init);
  const headers = effectiveHeaders(input, init);

  /** One snapshot per plan, taken before the first send. */
  const snapshotFor = (bodyKind: BodyKind, body?: unknown): RequestSnapshot =>
    createRequestSnapshot({ url, method, headers, bodyKind, ...(body === undefined ? {} : { body }) });

  if (isRequest(input)) {
    // `body === null` covers GET/HEAD and any bodyless request: the same
    // `Request` can simply be re-issued.
    if (input.body === null || input.body === undefined) {
      const snapshot = snapshotFor('none');
      const info: UpgradeReplayInfo = { url, method, bodyKind: 'none' };
      if (!policyPermits(policy, info)) {
        return refuse('none', 'the replay policy refused this request', input, snapshot, init);
      }
      return {
        replayable: true,
        bodyKind: 'none',
        forwardInput: input,
        forwardInit: init,
        snapshot,
        // The snapshot's effective header set is applied to the `Request` and
        // `init.headers` is dropped, so `fetch` has only one set to choose
        // from. See `replayHeaders` for why that matters.
        replay: (next, hints) => next(requestWithSnapshotHeaders(input, snapshot, hints), initWithoutHeaders(init)),
      };
    }

    const snapshot = snapshotFor('request-clone');
    const info: UpgradeReplayInfo = { url, method, bodyKind: 'request-clone' };
    if (!policyPermits(policy, info)) {
      return refuse('request-clone', 'the replay policy refused this request', input, snapshot, init);
    }

    // The clone must be taken NOW, while the body is unread. We pay the buffering
    // cost only for `Request`-with-body inputs, which are the minority; string +
    // init is the common shape and costs nothing.
    let spare: Request;
    try {
      spare = input.clone();
    } catch {
      // `bodyUsed` already — nothing to recover. Degrade rather than throw: the
      // caller still gets their original response, just no step-up.
      return refuse('one-shot', 'the Request body was already consumed and cannot be cloned', input, snapshot, init);
    }

    return {
      replayable: true,
      bodyKind: 'request-clone',
      forwardInput: input,
      forwardInit: init,
      snapshot,
      replay: (next, hints) => next(requestWithSnapshotHeaders(spare, snapshot, hints), initWithoutHeaders(init)),
    };
  }

  const bodyKind = classifyInitBody(init?.body);
  if (bodyKind === 'one-shot') {
    return refuse('one-shot', 'a streaming request body is consumed by the first send', input, snapshotFor('one-shot'), init);
  }

  const info: UpgradeReplayInfo = { url, method, bodyKind };
  if (!policyPermits(policy, info, knownBodyBytes(init?.body))) {
    return refuse(bodyKind, 'the replay policy refused this request', input, snapshotFor(bodyKind), init);
  }

  // Captured ONCE, here, before the first send — not reread from the caller's
  // live `init` when the replay goes out. See `snapshotBody`.
  const body = init && 'body' in init ? snapshotBody(init.body ?? null) : undefined;
  const snapshot = snapshotFor(bodyKind, body);

  return {
    replayable: true,
    bodyKind,
    forwardInput: input,
    forwardInit: init,
    snapshot,
    // The SNAPSHOT is re-issued, never the caller's live `input`.
    //
    // The url is the snapshot's NORMALISED `href` — the absolute URL the scope
    // decision was actually made on. Dispatching the caller's object instead
    // would let a `URL` instance be re-pointed (`input.href = …`) while the
    // prompt is open, sending the elevated credential somewhere no scope
    // decision ever saw; dispatching the raw string would re-resolve it, and a
    // `<base href>` changing mid-flight would move it. The `Request` branches
    // above need no equivalent: a `Request`'s url and method are immutable and
    // its body clone is taken eagerly.
    //
    // The BODY and the HEADERS are snapshotted for the same reason and by the
    // same rule: every `reusable` body shape is reread by `fetch` on each send,
    // and a `Headers` instance the caller still holds is mutable. The rest of
    // `init` is re-sent as given — the caller's `signal` is forwarded
    // unchanged, so an abort during the replay behaves identically to an abort
    // during the original.
    replay: (next, hints) =>
      next(snapshot.dispatchUrl, {
        ...initWithoutHeaders(init),
        ...(body === undefined ? {} : { body: body as BodyInit | null }),
        headers: replayHeaders(snapshot, hints),
        method: snapshot.method,
      }),
  };
};
