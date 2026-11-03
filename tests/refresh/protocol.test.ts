// Architecture §2.10 / §6: wire format. Every message is { v?: 1, type, tabId, ...fields }. A tab
// ignores unknown types and malformed messages; messages without `v` (portal wrapper tabs) are
// accepted; the legacy `rate-limited` and `refresh-failed` are parsed but never sent.
import { describe, expect, it } from 'vitest';
import { AUTH_CHANNEL, PROTOCOL_VERSION, REFRESH_LOCK, REFRESH_TAKEOVER_LOCK } from '../../lib/refresh/constants';
import { buildMessage, parseMessage, parseRetryInfo, refreshNames } from '../../lib/refresh/protocol';

const tokens = { access_token: 'a', refresh_token: 'r', id_token: 'i', scopes: ['id', 'offline'] };
const retry = {
  from: 'abc',
  kind: 'transient',
  attempt: 2,
  nextAt: 1_700_000_004_000,
  failingSince: 1_700_000_000_000,
  strikes: 0,
};

describe('refreshNames', () => {
  it('should use the portal names when the storage prefix is empty', () => {
    expect(refreshNames('')).toEqual({ lock: REFRESH_LOCK, takeoverLock: REFRESH_TAKEOVER_LOCK, channel: AUTH_CHANNEL });
    expect(refreshNames(undefined)).toEqual(refreshNames(''));
    expect(refreshNames('')).toEqual({
      lock: 'passflow-refresh',
      takeoverLock: 'passflow-refresh-takeover',
      channel: 'passflow-auth',
    });
  });

  it('should append :prefix to every name, so apps with separate storage never coordinate', () => {
    expect(refreshNames('app1')).toEqual({
      lock: 'passflow-refresh:app1',
      takeoverLock: 'passflow-refresh-takeover:app1',
      channel: 'passflow-auth:app1',
    });
  });
});

describe('parseMessage', () => {
  it('should accept every SDK message type with v: 1', () => {
    const cases: Record<string, unknown>[] = [
      { type: 'tokens-refreshed', tokens, from: 'f', fromIat: 100, fromSid: 's1', to: 't', sentAt: 5 },
      { type: 'session-refreshed', at: 10, sub: 'user-1' },
      { type: 'still-refreshing' },
      { type: 'still-refreshing', retry },
      { type: 'retry-scheduled', message: '503', ...retry },
      { type: 'takeover' },
      { type: 'lock-wanted', purpose: 'commit' },
      { type: 'lock-wanted', purpose: 'logout' },
      { type: 'session-ended', fp: 'f', sub: 'user-1', sid: 's1', iat: 100 },
      { type: 'signed-out', fp: 'f', sub: 'user-1', sid: 's1', iat: 100 },
      { type: 'signed-out' },
    ];
    for (const body of cases) {
      const parsed = parseMessage({ v: 1, tabId: 'tab-a', ...body });
      expect(parsed, JSON.stringify(body)).not.toBeNull();
      expect(parsed?.type).toBe(body.type);
      expect(parsed?.tabId).toBe('tab-a');
    }
  });

  it('should accept the portal wrapper messages (no v), including the legacy rate-limited and refresh-failed', () => {
    expect(parseMessage({ type: 'tokens-refreshed', tabId: 'p', tokens, from: 'f', fromIat: 1, fromSid: '', to: 't' })).toEqual(
      {
        type: 'tokens-refreshed',
        tabId: 'p',
        tokens,
        from: 'f',
        fromIat: 1,
        fromSid: '',
        to: 't',
      },
    );
    expect(parseMessage({ type: 'rate-limited', tabId: 'p', until: 99 })).toEqual({
      type: 'rate-limited',
      tabId: 'p',
      until: 99,
    });
    expect(parseMessage({ type: 'refresh-failed', tabId: 'p', message: 'down', from: 'f' })).toEqual({
      type: 'refresh-failed',
      tabId: 'p',
      message: 'down',
      from: 'f',
    });
    expect(parseMessage({ type: 'refresh-failed', tabId: 'p', from: 'f' })).toMatchObject({ message: '' });
    expect(parseMessage({ type: 'still-refreshing', tabId: 'p' })).toEqual({ type: 'still-refreshing', tabId: 'p' });
  });

  it('should ignore an unknown version, an unknown type and anything that is no message', () => {
    expect(parseMessage({ v: 2, type: 'takeover', tabId: 't' })).toBeNull();
    expect(parseMessage({ v: '1', type: 'takeover', tabId: 't' })).toBeNull();
    expect(parseMessage({ type: 'nonsense', tabId: 't' })).toBeNull();
    expect(parseMessage({ type: 'takeover' })).toBeNull();
    expect(parseMessage({ type: 'takeover', tabId: 7 })).toBeNull();
    expect(parseMessage({ type: 'takeover', tabId: '' })).toBeNull();
    expect(parseMessage(null)).toBeNull();
    expect(parseMessage('takeover')).toBeNull();
    expect(parseMessage(undefined)).toBeNull();
  });

  it('should reject a malformed tokens-refreshed', () => {
    const base = { type: 'tokens-refreshed', tabId: 't', tokens, from: 'f', to: 't2' };
    expect(parseMessage(base)).not.toBeNull();
    expect(parseMessage({ ...base, tokens: null })).toBeNull();
    expect(parseMessage({ ...base, tokens: 'x' })).toBeNull();
    expect(parseMessage({ ...base, from: '' })).toBeNull();
    expect(parseMessage({ ...base, to: undefined })).toBeNull();
  });

  it('should keep only the known token fields of the right types, and drop bad optional fields', () => {
    const parsed = parseMessage({
      type: 'tokens-refreshed',
      tabId: 't',
      tokens: { access_token: 'a', refresh_token: 'r', id_token: 5, scopes: ['id', 3], extra: 'x' },
      from: 'f',
      fromIat: 'soon',
      fromSid: 7,
      to: 't2',
      sentAt: Number.NaN,
    });
    expect(parsed).toEqual({
      type: 'tokens-refreshed',
      tabId: 't',
      tokens: { access_token: 'a', refresh_token: 'r' },
      from: 'f',
      to: 't2',
    });
  });

  it('should keep fromSid "" (the sent token had no sid) apart from a missing fromSid (older code)', () => {
    const base = { type: 'tokens-refreshed', tabId: 't', tokens, from: 'f', to: 't2' };
    expect(parseMessage({ ...base, fromSid: '' })).toMatchObject({ fromSid: '' });
    expect(parseMessage(base)).not.toHaveProperty('fromSid');
  });

  it('should reject a malformed session-refreshed, lock-wanted, rate-limited and retry-scheduled', () => {
    expect(parseMessage({ type: 'session-refreshed', tabId: 't' })).toBeNull();
    expect(parseMessage({ type: 'session-refreshed', tabId: 't', at: Number.POSITIVE_INFINITY })).toBeNull();
    expect(parseMessage({ type: 'lock-wanted', tabId: 't' })).toBeNull();
    expect(parseMessage({ type: 'lock-wanted', tabId: 't', purpose: 'refresh' })).toBeNull();
    expect(parseMessage({ type: 'rate-limited', tabId: 't', until: 'later' })).toBeNull();
    expect(parseMessage({ type: 'refresh-failed', tabId: 't', message: 'x' })).toBeNull();
    expect(parseMessage({ type: 'retry-scheduled', tabId: 't', message: 'x' })).toBeNull();
    expect(parseMessage({ type: 'retry-scheduled', tabId: 't', message: 'x', ...retry, kind: 'blocked' })).toBeNull();
  });

  it('should keep a heartbeat whose retry is malformed, without the retry', () => {
    expect(parseMessage({ type: 'still-refreshing', tabId: 't', retry: { kind: 'transient' } })).toEqual({
      type: 'still-refreshing',
      tabId: 't',
    });
  });

  it('should read the retry-scheduled fields flat on the message', () => {
    expect(parseMessage({ v: 1, type: 'retry-scheduled', tabId: 't', message: 'Service Unavailable', ...retry })).toEqual({
      type: 'retry-scheduled',
      tabId: 't',
      message: 'Service Unavailable',
      retry,
    });
    expect(parseMessage({ type: 'retry-scheduled', tabId: 't', kind: 'auth', attempt: 1, nextAt: 5, strikes: 1 })).toEqual({
      type: 'retry-scheduled',
      tabId: 't',
      message: '',
      retry: { kind: 'auth', attempt: 1, nextAt: 5, strikes: 1 },
    });
  });

  it('should drop empty or mistyped end-message fields', () => {
    expect(parseMessage({ type: 'session-ended', tabId: 't', fp: '', sub: 5, sid: null, iat: 'x' })).toEqual({
      type: 'session-ended',
      tabId: 't',
    });
  });
});

describe('parseRetryInfo', () => {
  it('should require kind, a positive integer attempt, a finite nextAt and non-negative strikes', () => {
    expect(parseRetryInfo(retry)).toEqual(retry);
    expect(parseRetryInfo({ ...retry, attempt: 0 })).toBeNull();
    expect(parseRetryInfo({ ...retry, attempt: 1.5 })).toBeNull();
    expect(parseRetryInfo({ ...retry, nextAt: undefined })).toBeNull();
    expect(parseRetryInfo({ ...retry, strikes: -1 })).toBeNull();
    expect(parseRetryInfo({ ...retry, kind: 'blocked' })).toBeNull();
    expect(parseRetryInfo(null)).toBeNull();
    expect(parseRetryInfo({ ...retry, from: '', failingSince: 'x' })).toEqual({
      kind: 'transient',
      attempt: 2,
      nextAt: retry.nextAt,
      strikes: 0,
    });
  });
});

describe('buildMessage', () => {
  it('should stamp v and tabId, and round-trip through parseMessage', () => {
    const message = buildMessage('tab-a', {
      type: 'tokens-refreshed',
      tokens,
      from: 'f',
      fromIat: 100,
      fromSid: '',
      to: 't',
      sentAt: 7,
    });
    expect(message).toEqual({
      v: PROTOCOL_VERSION,
      tabId: 'tab-a',
      type: 'tokens-refreshed',
      tokens,
      from: 'f',
      fromIat: 100,
      fromSid: '',
      to: 't',
      sentAt: 7,
    });
    expect(parseMessage(message)).toEqual({ ...message, v: undefined, tokens });
  });

  it('should flatten retry-scheduled on the wire, as the portal reads it', () => {
    const message = buildMessage('tab-a', {
      type: 'retry-scheduled',
      message: 'down',
      retry: { kind: 'auth', attempt: 1, nextAt: 9, strikes: 1 },
    });
    expect(message).toEqual({
      v: 1,
      tabId: 'tab-a',
      type: 'retry-scheduled',
      message: 'down',
      kind: 'auth',
      attempt: 1,
      nextAt: 9,
      strikes: 1,
    });
    expect(parseMessage(message)).toEqual({
      type: 'retry-scheduled',
      tabId: 'tab-a',
      message: 'down',
      retry: { kind: 'auth', attempt: 1, nextAt: 9, strikes: 1 },
    });
  });

  it('should omit undefined optional fields', () => {
    expect(buildMessage('tab-a', { type: 'signed-out', fp: undefined, sub: 'user-1' })).toEqual({
      v: 1,
      tabId: 'tab-a',
      type: 'signed-out',
      sub: 'user-1',
    });
    expect(buildMessage('tab-a', { type: 'still-refreshing', retry: undefined })).toEqual({
      v: 1,
      tabId: 'tab-a',
      type: 'still-refreshing',
    });
  });
});
