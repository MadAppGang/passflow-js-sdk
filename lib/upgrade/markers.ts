/**
 * Per-request markers for the upgrade transaction.
 *
 * Two 401s look identical on the wire and mean opposite things. A protected
 * resource's 401 says "this session is not strong enough"; the elevation's own
 * `POST /auth/refresh` 401 says "that TOTP code was wrong, try again". Neither
 * carries RFC 9470 vocabulary on the commit path — `refreshErrorStatus` maps the
 * four recoverable upgrade errors to a bare 401 with no `WWW-Authenticate` and no
 * `upgrade_required` body — so the response alone cannot tell them apart from an
 * expired session.
 *
 * The evidence that CAN tell them apart is the request: we know we issued it.
 * Both rounds of the elevation (`POST /auth/upgrade/start` and the committing
 * `POST /auth/refresh`) carry a marker on their axios config, set at the call
 * site immediately before dispatch. The response interceptor reads it off
 * `error.config`, which axios hands back unchanged, and suppresses
 * `setSessionInvalid()` for that one request only. An unrelated background 401
 * arriving while a prompt is open is unmarked and invalidates exactly as before.
 *
 * A second marker records that a request has already been replayed after an
 * elevation, so an adapter that re-issues through the same interceptor cannot
 * elevate twice for one challenge.
 *
 * ## Why these are enumerable, against the design's "non-enumerable"
 *
 * The design asks for non-enumerable properties, reasoning that they must never
 * reach the wire. Non-enumerable does not survive the trip: `AxiosClient.send`
 * spreads the caller's config into a fresh object (`{ method, url, ...options }`)
 * and axios' own `mergeConfig` iterates `Object.keys`, so both drop a
 * non-enumerable property before the request is dispatched — verified against
 * `axios@1.13` with a stub adapter. An enumerable key reaches both the adapter
 * and `error.config`.
 *
 * The property the design actually wanted is preserved regardless: axios
 * serializes only `data` (and `params`/`headers`), never unknown config keys, so
 * a marker is never transmitted. The same mechanism already carries
 * `_retryCount` through the rate-limit retry path.
 */

/** Config key marking a request as one of the upgrade transaction's two rounds. */
export const UPGRADE_TRANSACTION_MARKER = '__passflowUpgradeTransaction';

/** Config key marking a request as the single post-elevation replay (FR3). */
export const UPGRADE_REPLAYED_MARKER = '__passflowUpgradeReplayed';

/** The markers as they appear on a request config. Both are absent unless set. */
export type UpgradeRequestMarkers = {
  /** Set by the upgrade transport on `prepare` and `commit`. */
  __passflowUpgradeTransaction?: true;
  /** Set by the replaying adapter before it re-issues the original request. */
  __passflowUpgradeReplayed?: true;
};

const readMarker = (config: unknown, key: string): boolean =>
  typeof config === 'object' && config !== null && (config as Record<string, unknown>)[key] === true;

/**
 * Returns a copy of `config` marked as part of the upgrade transaction.
 *
 * Copies rather than mutates: the caller may be reusing a config object, and a
 * marker that outlives its request would suppress invalidation for an unrelated
 * 401 — the exact over-broad behaviour the per-request rule replaces.
 */
export const markUpgradeTransaction = <T extends object>(config?: T): T & UpgradeRequestMarkers => ({
  ...((config ?? {}) as T),
  [UPGRADE_TRANSACTION_MARKER]: true,
});

/** Reports whether a request config carries the upgrade-transaction marker. */
export const hasUpgradeTransactionMarker = (config: unknown): boolean => readMarker(config, UPGRADE_TRANSACTION_MARKER);

/** Returns a copy of `config` marked as the one permitted post-elevation replay. */
export const markUpgradeReplayed = <T extends object>(config: T): T & UpgradeRequestMarkers => ({
  ...config,
  [UPGRADE_REPLAYED_MARKER]: true,
});

/** Reports whether a request config has already been replayed after an elevation. */
export const hasUpgradeReplayedMarker = (config: unknown): boolean => readMarker(config, UPGRADE_REPLAYED_MARKER);
