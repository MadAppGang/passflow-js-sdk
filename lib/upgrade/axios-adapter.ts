/**
 * The AXIOS adapter over `handleChallenge`. Two of the four surfaces use it.
 *
 * **NO LOGIC IN AN ADAPTER.** It builds a `ChallengeContext` from an
 * `AxiosError` and settles through `settleAxiosOutcome`; it parses no
 * challenge, compares no bar, decides no scope, counts no retry and chooses no
 * error class. The replay-once guard in particular is NOT here: the replay goes
 * back through `request(config)` and re-enters this very interceptor, so the
 * guard has to be surface-independent, and it is — the core reads and writes
 * `markers.replayed`, and this file only says where that marker lives (on the
 * request config, where axios hands it back unchanged).
 *
 * ## Why the parameter is structurally typed
 *
 * `ResponseInterceptorHost` is declared by us and satisfied by any axios
 * instance. We never name axios' own types in the signature, so a customer on a
 * different axios major — or on a fetch-based client that mimics the
 * interceptor API — attaches without a type error, and this package's axios
 * version is not a constraint on theirs.
 *
 * ## Why it is the error interceptor
 *
 * axios' own contract, expressed in `validateStatus`, is that a non-2xx
 * response rejects, so a 401/403 arrives as an `AxiosError`. Resolving a
 * declined step-up would invert that contract: every caller's post-`await`
 * success path would run after the user clicked "Not now".
 */

import {
  type AbortView,
  type ChallengeContext,
  type UpgradeInterceptorOptions,
  type UpgradeInterceptorOptionsSource,
  handleChallenge,
  resolveInterceptorOptions,
  settleAxiosOutcome,
} from './core';
import { isUpgradeSdkError } from './errors';
import { hasUpgradeReplayedMarker, hasUpgradeTransactionMarker, markUpgradeReplayed } from './markers';
import { type ReplayHints, type UpgradeReplayInfo, policyPermits } from './replay';
import { type RequestSnapshot, createRequestSnapshot, headersToObject, swapAuthorization } from './snapshot';

/**
 * The only thing we require of a client: that it lets us add and remove a
 * response interceptor. Duck-typed deliberately — see the module comment.
 */
export type ResponseInterceptorHost = {
  interceptors: {
    response: {
      // biome-ignore lint/suspicious/noExplicitAny: structural mirror of axios' own looser signature; narrowing it here would reject real axios instances
      use(onFulfilled?: (value: any) => any, onRejected?: (error: any) => any): number;
      eject(id: number): void;
    };
  };
};

/** Re-issues a request from a config. Supplied by whoever owns the client. */
export type AxiosReissue = (config: AxiosConfigLike) => Promise<unknown>;

/** The subset of `AxiosRequestConfig` this adapter reads. */
export type AxiosConfigLike = {
  url?: string;
  baseURL?: string;
  method?: string;
  data?: unknown;
  headers?: unknown;
  /**
   * The caller's own signal, forwarded to the core untouched. Typed as the
   * core's `AbortView` so an `AbortSignal`'s listener pair types through: that
   * pair is what lets the core settle this caller at abort time while a proof
   * is still pending (REQ-C12). A plain `{ aborted }` object is still accepted,
   * and then the core reads the flag after the elevation as it always did.
   */
  signal?: AbortView;
};

/** The subset of `AxiosResponse` this adapter reads. */
type AxiosResponseLike = {
  status: number;
  headers?: unknown;
  data?: unknown;
  config?: AxiosConfigLike;
};

/** The subset of `AxiosError` this adapter reads. */
type AxiosErrorLike = {
  response?: AxiosResponseLike;
  config?: AxiosConfigLike;
};

const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null;

/**
 * Reads a header off an axios headers bag, in the callback shape the one parser
 * takes.
 *
 * axios hands back a plain object, an `AxiosHeaders` instance or (in node) an
 * array value per name. All three are flattened here, which is the whole reason
 * the parser takes a callback instead of a DOM `Headers`.
 */
const headerReader =
  (headers: unknown) =>
  (name: string): string | null | undefined => {
    if (!isRecord(headers)) {
      return undefined;
    }
    const direct = headers[name] ?? headers[name.toLowerCase()];
    const value =
      direct ??
      (typeof (headers as { get?: (n: string) => unknown }).get === 'function'
        ? (headers as { get: (n: string) => unknown }).get(name)
        : undefined);
    if (Array.isArray(value)) {
      return value.join(', ');
    }
    return typeof value === 'string' ? value : undefined;
  };

/**
 * The request's absolute URL, as far as the config states it.
 *
 * A relative `url` with no `baseURL` stays relative, which is what lets a SPA's
 * `backend: '/api'` declaration match: the scope predicate understands a path
 * prefix, and inventing an origin here would be the derived model the design
 * removed.
 */
const urlOf = (config: AxiosConfigLike | undefined): string => {
  const url = config?.url ?? '';
  const base = config?.baseURL;
  if (!base) {
    return url;
  }
  // axios' own `isAbsoluteURL` is `/^([a-z][a-z\d+\-.]*:)?\/\//i`, so it treats
  // a PROTOCOL-RELATIVE url as absolute and does not prepend `baseURL` to
  // `//evil.example/x`. Reading it as a path and joining it onto `baseURL` would
  // hand the scope predicate a same-origin-looking url for a request axios
  // actually sends off-origin. Same regex here, so the two cannot disagree.
  if (/^([a-z][a-z\d+\-.]*:)?\/\//i.test(url)) {
    return url;
  }
  return `${base.replace(/\/+$/, '')}/${url.replace(/^\/+/, '')}`;
};

const methodOf = (config: AxiosConfigLike | undefined): string => (config?.method ?? 'GET').toUpperCase();

/** How a config's body can be re-sent. axios serialises `data` on every send. */
const bodyKindOf = (data: unknown): UpgradeReplayInfo['bodyKind'] => {
  if (data === undefined || data === null) {
    return 'none';
  }
  // A node stream or a web stream is consumed by the first send.
  if (isRecord(data) && (typeof data.pipe === 'function' || typeof data.getReader === 'function')) {
    return 'one-shot';
  }
  return 'reusable';
};

/**
 * The config a replay is issued with: the original, re-pointed at the SNAPSHOT.
 *
 * url, method, headers and data all come from the frozen snapshot rather than
 * from the live config object, so a config the caller still holds — axios
 * instances are routinely built once and reused — cannot change where the
 * elevated credential goes or what it carries. The credential swap is applied
 * to the snapshot's header set by exact match: equality with the token we hold
 * is what proves the header was ours, and rewriting a header we do not own
 * would be a security bug.
 *
 * `baseURL` is cleared when the snapshot resolved to an absolute URL, because
 * the snapshot's `href` already includes it; leaving both would depend on
 * axios' `isAbsoluteURL` to not join them twice.
 */
const replayConfig = (config: AxiosConfigLike, snapshot: RequestSnapshot, hints?: ReplayHints): AxiosConfigLike => {
  const headers = headersToObject(swapAuthorization(snapshot.headers, hints?.authorizationSwap));
  const absolute = snapshot.dispatchUrl === snapshot.href && snapshot.resolved;
  return {
    ...config,
    ...(absolute ? { baseURL: undefined } : {}),
    url: snapshot.dispatchUrl,
    method: snapshot.method,
    headers,
    ...('body' in snapshot ? { data: snapshot.body } : {}),
  };
};

/**
 * Wraps an axios response as a `ChallengeContext`.
 *
 * The markers live on the request config: axios hands `error.config` back
 * unchanged, and a non-enumerable property would not survive `mergeConfig`'s
 * `Object.keys` walk (see `markers.ts`). Writing `markers.replayed` therefore
 * means stamping the config of the request we are about to re-issue, which is
 * what the `replay` thunk below does.
 */
const contextFor = (
  response: AxiosResponseLike | undefined,
  config: AxiosConfigLike | undefined,
  raw: unknown,
  reissue: AxiosReissue,
  options: UpgradeInterceptorOptions,
  /** The FIRST send's snapshot, threaded through every replayed context. */
  inherited?: RequestSnapshot,
): ChallengeContext => {
  const effective = config ?? response?.config;
  const bodyKind = bodyKindOf(effective?.data);
  // Taken once per intercepted request and inherited by the replayed context:
  // a second snapshot taken off the replay's own config would be a second
  // description of one request, which is the thing §13.4 revision 6 forbids.
  const snapshot =
    inherited ??
    createRequestSnapshot({
      url: urlOf(effective),
      method: methodOf(effective),
      headers: effective?.headers,
      bodyKind,
      body: effective?.data,
    });
  const info: UpgradeReplayInfo = { url: snapshot.href, method: snapshot.method, bodyKind };
  const permitted = bodyKind !== 'one-shot' && policyPermits(options.replay, info);

  return {
    status: response?.status ?? 0,
    getHeader: headerReader(response?.headers),
    // Pre-read by axios into `data`; nothing is consumed by reading it again,
    // and the core still decides whether reading it is in scope.
    readBody: async () => response?.data,
    request: snapshot,
    replay: async (hints?: ReplayHints) => {
      const next = markUpgradeReplayed(replayConfig(effective ?? {}, snapshot, hints));
      try {
        const replayed = (await reissue(next)) as AxiosResponseLike;
        return contextFor(replayed, replayed?.config ?? next, replayed, reissue, options, snapshot);
      } catch (e) {
        // axios REJECTS a non-2xx, so the replay's own 401 — the second
        // challenge, which is the normal AAL3/TOTP-only path — arrives here as
        // a rejection rather than as a response. Handing it to the core as an
        // exchange is the only way the core can classify it; letting it escape
        // sent a raw `AxiosError`, complete with `config` and `response`, over
        // the SDK's public edge where §13.3 requires `upgrade_insufficient`.
        //
        // No logic is added: this adapter still parses nothing and compares no
        // bar. It only translates axios' rejection convention into the one
        // exchange shape the core reads, and flags that the exchange was
        // delivered as a rejection so the settlement can honour the same
        // convention on the way back out.
        //
        // A rejection with no response is not an exchange — a replay that never
        // reached the server is the caller's error, not a step-up outcome — and
        // neither is a settled upgrade outcome, which is what re-entering this
        // same interceptor on the attached surfaces produces.
        const failure = (isRecord(e) ? e : {}) as AxiosErrorLike;
        if (!failure.response || typeof failure.response.status !== 'number' || isUpgradeSdkError(e)) {
          throw e;
        }
        const replayed = contextFor(failure.response, failure.config ?? next, e, reissue, options, snapshot);
        return { ...replayed, rejected: true };
      }
    },
    markers: {
      ...(hasUpgradeTransactionMarker(effective) ? { upgradeTransaction: true as const } : {}),
      ...(hasUpgradeReplayedMarker(effective) ? { replayed: true as const } : {}),
    },
    raw,
    replayable: permitted,
    replayUnsupportedReason:
      bodyKind === 'one-shot'
        ? 'a streaming request body is consumed by the first send'
        : 'the replay policy refused this request',
    signal: effective?.signal,
  };
};

/**
 * The rejection handler itself: an `AxiosError` in, a replayed response or a
 * tagged rejection out.
 *
 * Shared by `attachUpgradeAuth` (the customer's own instance) and by the SDK's
 * internal seam, so both surfaces settle from the same table.
 */
export const createAxiosUpgradeHandler =
  (source: UpgradeInterceptorOptionsSource, reissue: AxiosReissue) =>
  async (error: unknown): Promise<unknown> => {
    // Resolved PER CHALLENGE. A handler built at `enable()` time that captured
    // the RESOLVED options would freeze the interception scope at attach time,
    // which is how a module-scope client ended up pinned to `backend: []`.
    const options = resolveInterceptorOptions(source);
    const typed = (isRecord(error) ? error : {}) as AxiosErrorLike;
    const ctx = contextFor(typed.response, typed.config, typed.response, reissue, options);

    const outcome = await handleChallenge(ctx, options);
    const settlement = settleAxiosOutcome<unknown>(outcome, error);
    if (settlement.settle === 'reject') {
      throw settlement.error;
    }
    return settlement.value;
  };

/**
 * Attaches step-up handling to a client the developer already owns, MUTATING
 * it, and returns a disposer that ejects exactly the interceptor it added.
 *
 * It returns the disposer rather than the instance on purpose: it mutates, and
 * returning the instance would invite `const api = attachAuth(axios.create())`
 * and read as if it had built something. The disposer is also what a React
 * effect needs.
 *
 * `reissue` defaults to the host's own `request`, duck-typed, so the replay
 * goes back through the customer's interceptors, `baseURL` and adapter rather
 * than through some instance of ours.
 */
export const attachUpgradeAuth = (
  host: ResponseInterceptorHost,
  source: UpgradeInterceptorOptionsSource,
  reissue?: AxiosReissue,
): (() => void) => {
  const own = (host as unknown as { request?: (config: AxiosConfigLike) => Promise<unknown> }).request;
  const send: AxiosReissue =
    reissue ??
    (typeof own === 'function'
      ? (config) => own.call(host, config)
      : () => Promise.reject(new Error('Passflow: this client exposes no request() to replay through.')));

  const id = host.interceptors.response.use(undefined, createAxiosUpgradeHandler(source, send));
  let ejected = false;
  return () => {
    if (ejected) {
      return;
    }
    ejected = true;
    host.interceptors.response.eject(id);
  };
};
