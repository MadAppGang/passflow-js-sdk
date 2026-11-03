/**
 * Cross-tab wire protocol (architecture §2.10, §6): message types, parsing and validation,
 * builders, and the lock and channel names for a storage prefix.
 *
 * Every message is a plain object `{ v?: 1, type, tabId, ...fields }`. The SDK sends `v: 1`;
 * messages without `v` (tabs running the portal wrapper) are accepted, other versions are
 * ignored. A tab ignores unknown types and malformed messages (parseMessage returns null), and its
 * own `tabId` (the coordinator's job). The legacy portal messages `rate-limited` and
 * `refresh-failed` are parsed but never sent.
 *
 * Refresh tokens are named by fingerprint (lineage.ts `fingerprint`); `iat`, `sid` and `sub` are
 * the refresh JWT's own claims.
 *
 * @module refresh/protocol
 */

import { AUTH_CHANNEL, PROTOCOL_VERSION, REFRESH_LOCK, REFRESH_TAKEOVER_LOCK } from './constants';

/** The tokens a `tokens-refreshed` carries: the sender's whole cached set. */
export interface WireTokens {
  access_token?: string;
  refresh_token?: string;
  id_token?: string;
  scopes?: string[];
}

/** The holder's retry schedule, shared with every tab so a handover continues it. */
export interface RetryInfo {
  /** Fingerprint of the token the holder sends; absent in cookie/BFF mode. */
  from?: string;
  kind: 'transient' | 'auth';
  /** Consecutive failed attempts so far (1-based). */
  attempt: number;
  /** Epoch ms of the next attempt. */
  nextAt: number;
  /** Set while a transient episode is open. */
  failingSince?: number;
  strikes: number;
}

/** A refresh token's lineage as end messages name it. */
export interface WireLineage {
  fp?: string;
  sub?: string;
  sid?: string;
  iat?: number;
}

export interface TokensRefreshedMessage {
  type: 'tokens-refreshed';
  tabId: string;
  tokens: WireTokens;
  /** Fingerprint of the token sent (or, when the sender adopted instead, of the token it held). */
  from: string;
  fromIat?: number;
  /** `from`'s own session: "" when it has no sid; absent from a tab on older code. */
  fromSid?: string;
  /** Fingerprint of `tokens.refresh_token`. */
  to: string;
  /** Epoch ms the request was sent; absent when the sender adopted. */
  sentAt?: number;
}

export interface SessionRefreshedMessage {
  type: 'session-refreshed';
  tabId: string;
  at: number;
  sub?: string;
}

export interface StillRefreshingMessage {
  type: 'still-refreshing';
  tabId: string;
  retry?: RetryInfo;
}

/** On the wire the RetryInfo fields are flat on the message; parsed, they sit under `retry`. */
export interface RetryScheduledMessage {
  type: 'retry-scheduled';
  tabId: string;
  message: string;
  retry: RetryInfo;
}

export interface TakeoverMessage {
  type: 'takeover';
  tabId: string;
}

export type LockWantedPurpose = 'commit' | 'logout';

export interface LockWantedMessage {
  type: 'lock-wanted';
  tabId: string;
  purpose: LockWantedPurpose;
}

export interface SessionEndedMessage extends WireLineage {
  type: 'session-ended';
  tabId: string;
}

export interface SignedOutMessage extends WireLineage {
  type: 'signed-out';
  tabId: string;
}

/** Legacy (portal wrapper holder): accepted, never sent. */
export interface RateLimitedMessage {
  type: 'rate-limited';
  tabId: string;
  until: number;
}

/** Legacy (portal wrapper holder): accepted, never sent. Treated as `retry-scheduled` with no `nextAt`. */
export interface RefreshFailedMessage {
  type: 'refresh-failed';
  tabId: string;
  message: string;
  from: string;
}

export type RefreshMessage =
  | TokensRefreshedMessage
  | SessionRefreshedMessage
  | StillRefreshingMessage
  | RetryScheduledMessage
  | TakeoverMessage
  | LockWantedMessage
  | SessionEndedMessage
  | SignedOutMessage
  | RateLimitedMessage
  | RefreshFailedMessage;

export type RefreshMessageType = RefreshMessage['type'];

type DistributiveOmit<T, K extends PropertyKey> = T extends unknown ? Omit<T, K> : never;

/** What this SDK sends: every message but the legacy ones, without `tabId` (stamped by buildMessage). */
export type OutgoingMessageBody = DistributiveOmit<Exclude<RefreshMessage, RateLimitedMessage | RefreshFailedMessage>, 'tabId'>;

/** Lock and channel names for a storage prefix. Empty prefix: the portal's names. */
export interface RefreshNames {
  lock: string;
  takeoverLock: string;
  channel: string;
}

/** With prefix `p`, `:p` is appended to each name, so apps with separate storage never coordinate. */
export function refreshNames(prefix: string | undefined): RefreshNames {
  const suffix = prefix ? `:${prefix}` : '';
  return {
    lock: `${REFRESH_LOCK}${suffix}`,
    takeoverLock: `${REFRESH_TAKEOVER_LOCK}${suffix}`,
    channel: `${AUTH_CHANNEL}${suffix}`,
  };
}

function optionalString(value: unknown): string | undefined {
  return typeof value === 'string' && value !== '' ? value : undefined;
}

function optionalNumber(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isFinite(value) ? value : undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

/** Copies the defined entries of `fields` onto `target`, so parsed messages carry no undefined keys. */
function withDefined<T extends object>(target: T, fields: Record<string, unknown>): T {
  for (const [key, value] of Object.entries(fields)) {
    if (value !== undefined) (target as Record<string, unknown>)[key] = value;
  }
  return target;
}

function parseTokens(value: unknown): WireTokens | null {
  if (!isRecord(value)) return null;
  const scopes = Array.isArray(value.scopes) ? value.scopes.filter((s): s is string => typeof s === 'string') : undefined;
  return withDefined<WireTokens>(
    {},
    {
      access_token: optionalString(value.access_token),
      refresh_token: optionalString(value.refresh_token),
      id_token: optionalString(value.id_token),
      scopes: Array.isArray(value.scopes) && scopes?.length === value.scopes.length ? scopes : undefined,
    },
  );
}

/** Validates a RetryInfo (a heartbeat's `retry`, or a retry-scheduled's flat fields). */
export function parseRetryInfo(value: unknown): RetryInfo | null {
  if (!isRecord(value)) return null;
  const { kind, attempt, nextAt, strikes } = value;
  if (kind !== 'transient' && kind !== 'auth') return null;
  if (typeof attempt !== 'number' || !Number.isInteger(attempt) || attempt < 1) return null;
  if (optionalNumber(nextAt) === undefined) return null;
  if (typeof strikes !== 'number' || !Number.isFinite(strikes) || strikes < 0) return null;
  return withDefined<RetryInfo>(
    { kind, attempt, nextAt: nextAt as number, strikes },
    { from: optionalString(value.from), failingSince: optionalNumber(value.failingSince) },
  );
}

function parseLineage(m: Record<string, unknown>): WireLineage {
  return withDefined<WireLineage>(
    {},
    { fp: optionalString(m.fp), sub: optionalString(m.sub), sid: optionalString(m.sid), iat: optionalNumber(m.iat) },
  );
}

/** Parses one channel message. Null for anything this tab must ignore. */
export function parseMessage(data: unknown): RefreshMessage | null {
  if (!isRecord(data)) return null;
  const m = data;
  if (m.v !== undefined && m.v !== PROTOCOL_VERSION) return null;
  const tabId = optionalString(m.tabId);
  if (!tabId) return null;
  switch (m.type) {
    case 'tokens-refreshed': {
      const tokens = parseTokens(m.tokens);
      const from = optionalString(m.from);
      const to = optionalString(m.to);
      if (!tokens || !from || !to) return null;
      return withDefined<TokensRefreshedMessage>(
        { type: m.type, tabId, tokens, from, to },
        {
          fromIat: optionalNumber(m.fromIat),
          fromSid: typeof m.fromSid === 'string' ? m.fromSid : undefined,
          sentAt: optionalNumber(m.sentAt),
        },
      );
    }
    case 'session-refreshed': {
      const at = optionalNumber(m.at);
      if (at === undefined) return null;
      return withDefined<SessionRefreshedMessage>({ type: m.type, tabId, at }, { sub: optionalString(m.sub) });
    }
    case 'still-refreshing': {
      const retry = m.retry === undefined ? null : parseRetryInfo(m.retry);
      return retry ? { type: m.type, tabId, retry } : { type: m.type, tabId };
    }
    case 'retry-scheduled': {
      const retry = parseRetryInfo(m);
      if (!retry) return null;
      return { type: m.type, tabId, message: typeof m.message === 'string' ? m.message : '', retry };
    }
    case 'takeover':
      return { type: m.type, tabId };
    case 'lock-wanted':
      return m.purpose === 'commit' || m.purpose === 'logout' ? { type: m.type, tabId, purpose: m.purpose } : null;
    case 'session-ended':
    case 'signed-out':
      return { type: m.type, tabId, ...parseLineage(m) };
    case 'rate-limited': {
      const until = optionalNumber(m.until);
      return until === undefined ? null : { type: m.type, tabId, until };
    }
    case 'refresh-failed': {
      const from = optionalString(m.from);
      return from ? { type: m.type, tabId, message: typeof m.message === 'string' ? m.message : '', from } : null;
    }
    default:
      return null;
  }
}

/** A message ready to post: `v` and `tabId` stamped, undefined fields dropped, RetryInfo flat. */
export function buildMessage(tabId: string, body: OutgoingMessageBody): Record<string, unknown> {
  const message: Record<string, unknown> = { v: PROTOCOL_VERSION, tabId };
  if (body.type === 'retry-scheduled') {
    const { retry, ...rest } = body;
    return withDefined(message, { ...rest, ...retry });
  }
  return withDefined(message, { ...body });
}
