# Token refresh

How `@passflow/core` refreshes tokens, from 0.21.0 on: one refresh per browser across tabs, a
compare-and-set save, failure classification, one shared retry schedule, and a fixed event
sequence per tab.

Every refresh in a `Passflow` instance goes through one refresh controller. Four callers use it:

| Caller | Trigger (`Error.source`) |
|---|---|
| `passflow.refreshToken()` | `refresh-token` |
| `passflow.getTokens(true)`, `session({ doRefresh: true })` | `session` |
| `passflow.getTokensWithRefresh()` | `token-check` |
| An SDK API call whose access token expires within 30 s (JSON mode) | `pre-request` |
| The step-up (upgrade) commit | `upgrade` |
| The scheduled retry, when no new caller asked | `retry` |
| The held-tab send (see "Held tab") | `held` |

## Options

```ts
new Passflow({
  // ...
  refreshCoordination: 'web-locks', // default
  refreshStrikes: 3,                // default
});
```

### `refreshCoordination`

`'web-locks' | 'none' | RefreshCoordinator`.

- **`'web-locks'`** (default). One tab refreshes under a Web Lock, the others adopt its result
  through a `BroadcastChannel`. It is used when all of these hold: the page is a browser page
  (`window` and `document` exist, `platform.getDeviceType() === 'web'`), the platform's storage is
  shared by every tab (the default web adapter's `localStorage`; the adapter says so through
  `storageSharedAcrossTabs`), `navigator.locks.request` is a function, and `BroadcastChannel`
  exists. Otherwise the instance falls back to `'none'` (see "Fallback").
- **`'none'`**. No cross-tab coordination. Single flight inside this instance, the
  compare-and-set save, and per-instance retries.
- **A `RefreshCoordinator` object**. The same protocol as `'web-locks'` over transports you supply
  (tests, Electron, custom hosts). It never falls back.

```ts
interface RefreshCoordinator {
  locks: RefreshLockManager;   // navigator.locks subset: request(name, { ifAvailable?, steal?, signal? }, cb)
  channel: RefreshChannel;     // BroadcastChannel subset; must not deliver a post to its sender
  tabId?: string;              // default: crypto.randomUUID()
  onStorageChange?: (listener: () => void) => () => void; // another tab wrote the token storage
  clock?: RefreshClock;        // { now(), setTimeout(fn, ms) => cancel, random?() }
}
```

One instance is one tab. Several instances that share one `platform.storage` and each have their
own coordinator behave as several tabs, which is how the SDK's own multi-tab tests run.

### `refreshStrikes`

Authentication failures of the refresh request (kind `auth` below), counted since the last
successful refresh or adoption, after which the session ends. Transient failures in between
neither add a strike nor reset the count: auth, 503, auth counts 2 strikes. Default 3. A
non-integer is floored. A value below 1, or one that is not a finite number, uses the default.

### `Passflow.dispose()`

Leaves the lock queue, cancels every refresh timer, removes the listeners, closes the channel, and
rejects pending refresh callers with `PassflowRefreshError` `error.refresh.disposed`. The SDK never
calls it by itself (not on `beforeunload`, not on `pagehide`): closing the document already
releases its locks and channels. Call it on SPA teardown and in tests. Do not use the instance
afterwards.

## Events

Two new events, and new fields on existing ones:

| Event | Payload |
|---|---|
| `RefreshStart` (`'refresh:start'`) | `{}`. This tab is about to send one refresh request. |
| `Refresh` (`'refresh'`) | `{ tokens, parsedTokens, source: 'refresh' \| 'upgrade' \| 'adopted' }` |
| `TokenCacheExpired` (`'token-cache-expired'`) | `{ isExpired: boolean }` |
| `RefreshFailing` (`'refresh:failing'`) | `{ since: number, nextRetryAt?: number, origin: 'this-tab' \| 'other-tab' }` |
| `RefreshRecovered` (`'refresh:recovered'`) | `{ since: number, origin: 'this-tab' \| 'other-tab' }` |
| `SessionExpired` (`'session:expired'`) | `{ reason: 'refresh_failed' \| 'successor_timeout' \| 'identity_changed', origin }` |
| `SignOut` (`'signout'`) | `{ origin: 'this-tab' \| 'other-tab', userId?: string }` |
| `SignIn` (`'signin'`) | `{ tokens, parsedTokens, origin?: 'other-tab', source?: 'federated-landing' }` (`source`: see [pkce-sign-in.md](pkce-sign-in.md)) |
| `Error` (`'error'`) | `ErrorPayload`, below |

- `Refresh.source`: `'refresh'` is this tab's own request, `'upgrade'` this tab's step-up commit,
  `'adopted'` tokens this tab did not request (another tab's broadcast, newer tokens found in
  storage, a superseded own request, a successor found after `error.token.blocked`).
- `RefreshFailing.since` is the epoch ms of the episode's first transient failure;
  `RefreshRecovered.since` repeats it. `nextRetryAt` is the epoch ms of the shared pending retry.
- `SessionExpired.reason` also keeps the legacy members `'token_invalid' | 'logged_out'` in its
  type. The SDK never emits them.
- `SignIn` with `origin: 'other-tab'` comes from an ended tab that finds a new session in storage
  (another tab signed in). A tab's own sign-in has no `origin`.

### `ErrorPayload`

```ts
interface ErrorPayload {
  message: string;
  code?: string | number;         // PassflowError id, e.g. 'error.http.503'
  details?: unknown;
  originalError?: unknown;
  operation?: PassflowOperation;  // always set by the SDK: 'refresh', 'upgrade.commit', 'sign-in', '2fa.verify', ...
  source?: RefreshTrigger;        // for 'refresh' and 'upgrade.commit'
  refresh?: {                     // for 'refresh'
    classification: 'transient' | 'blocked' | 'auth';
    willRetry: boolean;           // a retry is scheduled
    nextRetryAt?: number;         // epoch ms, when willRetry
    strikes: number;              // auth failures since the last success, this one included
    maxStrikes: number;           // resolved refreshStrikes
  };
}
```

**One `Error` per failure.** An error object is reported at most once per instance, by the
innermost reporter (it has the most specific `operation`). A wrapper that catches and rethrows the
same object reports nothing. So a failed `refreshToken()` gives one `Error{operation:'refresh'}`;
`getTokens(true)` and an SDK API call that fail because of that refresh add no second one.

A tab that waits for another tab's request reports no refresh `Error`: it learns of the failure
through `RefreshFailing` and through its callers' rejections. An SDK API call in such a tab that
rejects because its pre-request refresh failed is reported once, with that call's own operation
(for example `passkey.list`).

### Ordering guarantees (per tab)

1. Each `RefreshStart` is followed by exactly one outcome for that request: a `Refresh` (any
   source) or an `Error` (`operation` `refresh` or `upgrade.commit`), whichever comes first. A
   `Refresh{adopted}` after that `Error` (a successor found after `error.token.blocked`) is an
   unpaired adoption. A tab that sends nothing emits no `RefreshStart`.
2. `Refresh{adopted}` may arrive with no `RefreshStart` (waiting or idle tabs).
3. Every `Refresh` is followed at once by `TokenCacheExpired{ isExpired: false }`.
4. When `Refresh` is emitted, `getCachedTokens()` and `getParsedTokens()` already return the new
   tokens.
5. When `SignOut` or `SessionExpired` is emitted, the token cache is already cleared.
6. A failing episode emits `RefreshFailing` at most once per tab, and `RefreshRecovered` at most
   once, only after its `RefreshFailing`, and only on a successful refresh or adoption. An episode
   that ends in `SessionExpired` or `SignOut` emits no `RefreshRecovered`.
7. A tab emits at most one `SessionExpired` or `SignOut` per session. `logOut()` and `reset()`
   called after the session already ended still emit their one `SignOut{origin:'this-tab'}`.

### Which tab emits what

| Situation | Tab that sent the request | Other tabs of the same session |
|---|---|---|
| Success | `RefreshStart`, `Refresh{refresh}`, `TokenCacheExpired{false}`, then `RefreshRecovered{this-tab}` if failing | `Refresh{adopted}`, `TokenCacheExpired{false}`, then `RefreshRecovered{other-tab}` if failing |
| Answered, but storage already moved on (superseded) | `RefreshStart`, `Refresh{adopted}`, `TokenCacheExpired{false}` | nothing new |
| Transient failure | `RefreshStart`, `Error{refresh, transient, willRetry:true}`, `RefreshFailing{this-tab}` once per episode | `RefreshFailing{other-tab}` once per episode, idle tabs included |
| Auth failure, strikes left | `RefreshStart`, `Error{refresh, auth, willRetry:true}` | nothing |
| Auth failure, last strike | `RefreshStart`, `Error{refresh, auth, willRetry:false}`, `SessionExpired{refresh_failed, this-tab}` | `SessionExpired{refresh_failed, other-tab}` |
| `error.token.blocked` | `RefreshStart`, `Error{refresh, blocked, willRetry:false}`; later `Refresh{adopted}` (successor found) or `SessionExpired{successor_timeout, this-tab}` after 20 s | nothing |
| `logOut()` / `reset()` here | `SignOut{this-tab, userId}` | `SignOut{other-tab, userId}` in every tab of that user |
| Another user's tokens appear in storage | `SessionExpired{identity_changed, this-tab}`, then `SignIn{other-tab}` with the new user's tokens | (each tab that sees it does the same) |
| Shared storage emptied with no sign-out or end message within 2 s | `SignOut{other-tab}` | |

Example: a two-tab, 2-attempt outage that then recovers, as tab A (holder) and tab B (waiting) see
it:

```
A: RefreshStart, Error{transient, source:'refresh-token', nextRetryAt:1000}, RefreshFailing{since:0, nextRetryAt:1000, this-tab},
   RefreshStart, Error{transient, source:'retry', nextRetryAt:4000},
   RefreshStart, Refresh{refresh}, TokenCacheExpired{false}, RefreshRecovered{since:0, this-tab}
B: RefreshFailing{since:0, nextRetryAt:1000, other-tab}, Refresh{adopted}, TokenCacheExpired{false}, RefreshRecovered{since:0, other-tab}
```

## What each caller gets

While a retry is pending, or a successor is awaited after `error.token.blocked`, callers **join**
it: they send nothing and settle with that next attempt. Only the scheduled timer sends. The
upgrade commit is the one exception.

| Caller | Idle | Request in flight, or waiting for another tab | Retry pending | Session ended |
|---|---|---|---|---|
| `refreshToken()` | starts | waits for a request sent before its call, then sends its own (it wants tokens from a request sent at or after the call) | joins | rejects `error.refresh.session_ended` |
| `getTokens(true)` / `session()` | starts if the access token is expired | joins | joins | resolves `undefined` |
| `getTokensWithRefresh()` | starts if the access token is expired | joins | joins | resolves `undefined` |
| SDK API call (JSON mode, access token expires within 30 s) | starts | joins | access token not yet expired: sends now with the current bearer; expired: joins | sends with no refresh |
| Upgrade commit | sends the stored token under the lock | waits for the lock, at most 10 s, then `UpgradeCommitInterruptedError{reason:'lock-timeout'}` | a holder in backoff yields; sends at once | runs |

Resolution values:

- `refreshToken()` resolves with the tokens this tab now has (own or adopted).
- `getTokens(true)`, `session()` and `getTokensWithRefresh()` resolve with the cached tokens after
  the outcome: the kept tokens after a transient, blocked or auth-with-strikes-left failure.
  `undefined` only after the session ended. `getTokensWithRefresh()` never rejects.
- Rejections:
  - this tab's own request failed: the request's original error (a `PassflowError` for HTTP
    answers, the axios error for a network failure). The exception is `error.token.blocked`:
    the callers, including this tab's own `refreshToken()`, do not see the 400. They wait up to
    20 s for the successor, then resolve with the adopted tokens or reject with
    `error.refresh.successor_timeout`;
  - joined another tab's attempt that failed: `PassflowRefreshError` `error.refresh.unavailable`
    (status 503) for a transient failure, `error.refresh.auth_retry` (status 401) for an auth
    failure with strikes left, both with `nextRetryAt`;
  - the session ended while waiting: `error.refresh.session_ended`, `error.refresh.signed_out`,
    `error.refresh.successor_timeout` or `error.refresh.identity_changed` (status 401);
  - `dispose()`: `error.refresh.disposed`.
- An SDK API call whose pre-request refresh failed rejects with that refresh's error. Nothing is
  deleted.
- JSON mode with nothing stored: `refreshToken()` rejects `Error('No tokens found')` or
  `Error('No refresh token found')` as before.

`RefreshErrorId` is exported (`unavailable`, `authRetry`, `sessionEnded`, `signedOut`,
`successorTimeout`, `identityChanged`, `disposed`), and `PassflowRefreshError` extends
`PassflowError` with `nextRetryAt?` and `cause?`.

## Classification

The input is what the refresh request rejected with. **The error id decides first; the HTTP status
is only the fallback for ids not in the table.** The engine answers some dead sessions with 500
or 403, and `PassflowError` defaults a missing status to 500.

| # | Match (first wins) | Kind |
|---|---|---|
| 1 | id `error.token.blocked` | **blocked** |
| 2 | id in `REFRESH_AUTH_FAILURE_IDS`: `error.token.invalid.error`, `error.api.token.parse.error`, `error.api.user.blocked`, `error.2fa.required_by_app`, `error.validation.token.invalid.subject`, `error.not.found` (any status) | **auth** |
| 3 | status 429 | **transient** |
| 4 | no HTTP status (network error, timeout, CORS, abort, any non-HTTP throw) | **transient** |
| 5 | status ≥ 500 | **transient** |
| 6 | status 400-499 | **auth** |

`REFRESH_AUTH_FAILURE_IDS` is exported. A status outside 100-599 counts as no status; 1xx-3xx
count as transient.

Effects:

- **transient**: no strike, tokens kept, retry on the schedule below, no give-up.
- **auth**: one strike, retry on the schedule while `strikes < refreshStrikes`. At the last strike
  the session ends in every tab of that session (`SessionExpired{refresh_failed}`), and the
  stored tokens are deleted only if storage still holds the dead token or an older one of its
  session.
- **blocked**: the token was already used (nearly always by another tab of the same user) or the
  session was revoked; the engine uses one id for both. Never a strike, never deletes, never
  signs out, never broadcasts an end. The tab waits up to 20 s for a successor (another tab's
  broadcast, a storage event, the tab coming to the foreground, a storage poll every 1 s). With
  none it ends **this tab only** with `SessionExpired{successor_timeout}` and deletes nothing. So
  a revoked session ends tab by tab: each tab that needs a refresh sends once and ends 20 s later.

Overrides:

- **Upgrade commit**: never classified. Any failure rejects with the error unchanged, keeps the
  tokens, and adds no strike, no retry, no `RefreshFailing`, no `SessionExpired`.
- **Superseded**: when storage moved to a successor of the sent token (another tab, `setTokens`),
  any answer is a success. The caller resolves with the stored successor, `Refresh{adopted}`, no
  strike and no `Error`.
- **Held send** (below): blocked and auth answers neither strike nor end.

## Retry schedule

This is the exact schedule. One schedule exists per browser while coordinated, and per instance
in fallback.

After the n-th consecutive failed attempt (transient and auth failures both count), the next
attempt is due at:

```
nextAt = (time the failed answer arrived) + delay(n)

step(n)   = [1000, 3000, 10000, 30000, 60000][min(n, 5) - 1]       ms
jitter(n) = floor(step(n) × 0.2 × r),  r = clock.random() clamped to [0, 0.999]
delay(n)  = max(step(n) + jitter(n), retryAfterMs)
```

| Attempt that failed (n) | Step | Jitter range | Delay range (no Retry-After) |
|---|---|---|---|
| 1 | 1 000 ms | 0-199 ms | 1 000-1 199 ms |
| 2 | 3 000 ms | 0-599 ms | 3 000-3 599 ms |
| 3 | 10 000 ms | 0-1 998 ms | 10 000-11 998 ms |
| 4 | 30 000 ms | 0-5 994 ms | 30 000-35 994 ms |
| 5 and every later attempt | 60 000 ms | 0-11 988 ms | 60 000-71 988 ms |

With `r = 0` and instant failures, attempts go at **0, 1, 4, 14, 44, 104, 164 s**, then every
60 s. `r` comes from `RefreshClock.random` (default `Math.random`), so a custom clock with
`random: () => 0` makes the schedule exact.

**Retry-After.** It is read from every transient answer that has a status (429 and 5xx), in
delta-seconds or as an HTTP date, and clamped to [0, 600 s]. The delay is at least that wait. The
SDK's generic 429 retry never retries `/auth/refresh`, so the refresh controller is the only
place the wait is honoured. The holder broadcasts the wait, so every tab shares it, and waiting
tabs extend their takeover silence to `nextAt + 20 s`, so a long Retry-After causes no takeover.

**What resets it.** The attempt count and the strike count reset **only** on:

- a successful refresh, or an adoption of newer tokens (own request, another tab's broadcast,
  newer tokens found in storage, a successful upgrade commit in any tab);
- the end of the session (last strike, successor timeout, sign-out, identity change);
- a new session (`SignIn`, `Register`, `setTokens()`).

A transient failure never resets the strike count. A failed upgrade commit leaves `nextAt` as it
was. A tab that takes over the lock (the holder closed or went silent) continues the same
schedule from the broadcast `nextAt` and attempt count, and sends nothing before `nextAt`.

**What a holder does meanwhile.** The tab that holds the lock keeps it through the backoff and
heartbeats every 5 s with the schedule. Every caller in every tab joins the pending retry, so no
tab starts a cycle of its own during an outage. A holder in backoff with no request in flight
releases the lock at once to a `logOut()` or an upgrade commit in another tab.

## Cross-tab protocol (coordinated mode)

1. **One request per browser.** When several tabs need a refresh at once, one request is sent and
   every tab ends on the same tokens.
2. **Storage first.** A tab granted the lock reads storage before sending. If storage already
   holds newer tokens of the same user, it adopts them, broadcasts them and sends nothing.
3. **Stuck holder.** The holder heartbeats every 5 s. After 20 s of silence one waiter takes
   over: it takes the takeover lock, then steals the refresh lock. The old holder's late answer is
   not saved if storage moved on.
4. **Compare-and-set save.** An answer is saved only if storage still holds the token that was
   sent, for the same user, and storage was not emptied by a sign-out. Otherwise the answer is
   dropped and the tab adopts what storage holds, if it is newer and the same user's.
5. **Forward only.** No tab adopts or saves a refresh token older than the one it holds, by the
   token's `iat` within the same `sid`. A same-second token counts as newer only when the held one
   is known to be retired.
6. **Held tab.** When storage shows an older token of the tab's own session than the tab caches,
   for 20 s on the same cached token, the next trigger sends the stored token once. A failed held
   send never strikes or ends anything.
7. **Sign-out.** `logOut()` stops this tab's callers, takes the refresh lock (posting
   `lock-wanted`, waiting at most 5 s, so a request in flight lands first), re-reads storage,
   posts `signed-out` naming the newest token, calls the logout API with the newest refresh
   token, clears storage and the cache, and emits one `SignOut{this-tab}`. Every tab of that user
   emits `SignOut{other-tab}`. `reset()` does the same synchronously, with no API call and no lock.
8. **Emptied storage.** A tab that sees the shared storage emptied before any explaining message
   waits up to 2 s for `session-ended` or `signed-out`, then ends with `SignOut{other-tab}`.
9. **Identity change.** If storage holds another user's tokens, a tab clears its cache, emits
   `SessionExpired{identity_changed}`, deletes nothing, then emits `SignIn{other-tab}` with the new
   user's tokens.
10. **Revival.** An ended tab that sees a new session in storage (another `sid` or `sub`) caches it
    and emits `SignIn{other-tab}`. It never revives on the token that ended it.

### Wire names

With `keyStoragePrefix` empty: lock `passflow-refresh`, takeover lock `passflow-refresh-takeover`,
channel `passflow-auth`. With prefix `p`, `:p` is appended to each (`passflow-refresh:p`,
`passflow-refresh-takeover:p`, `passflow-auth:p`), so apps with separate storage never coordinate.

Messages are plain objects `{ v: 1, type, tabId, ...fields }`. Messages without `v` (the portal's
earlier wrapper) are accepted. A tab ignores its own `tabId`, unknown types and malformed messages.
`fp(token)` is cyrb53 of the token string as lowercase hex.

| `type` | Fields | Sent by |
|---|---|---|
| `tokens-refreshed` | `tokens {access_token, refresh_token, id_token?, scopes?}`, `from`, `fromIat?`, `fromSid`, `to`, `sentAt?` | a tab that saved or adopted tokens |
| `session-refreshed` | `at`, `sub?` | the cookie/BFF holder after a success |
| `still-refreshing` | `retry?: RetryInfo` | the holder, every 5 s |
| `retry-scheduled` | `RetryInfo` and `message` | the holder after each failed attempt that will retry |
| `takeover` | | the waiter taking over |
| `lock-wanted` | `purpose: 'commit' \| 'logout'` | a tab that needs the lock out of turn |
| `session-ended` | `fp?`, `sub?`, `sid?`, `iat?` | the tab whose last strike ended the session |
| `signed-out` | `fp?`, `sub?`, `sid?`, `iat?` | `logOut()` / `reset()` |
| `rate-limited` (accepted, never sent) | `until` | the portal's earlier wrapper |
| `refresh-failed` (accepted, never sent) | `message`, `from` | the portal's earlier wrapper |

`RetryInfo` is `{ from?, kind: 'transient' | 'auth', attempt, nextAt, failingSince?, strikes }`.

## Fallback

`'web-locks'` falls back to `'none'` when the conditions above are not met:

- On a browser page whose storage is shared by every tab but that lacks `navigator.locks` or
  `BroadcastChannel` (an insecure context, an old browser), the instance writes **exactly one**
  `console.warn`, starting with `[passflow]`, when it first starts a refresh (not at
  construction).
- Non-web platforms (a `PlatformAdapter` whose device type is not `'web'`), Node/SSR, a per-tab
  storage (sessionStorage, memory) and an explicit `'none'` fall back silently.

In fallback each instance refreshes on its own, with the same classification, schedule, strikes
and events (`origin` is `'this-tab'` except for storage-driven adoption, revival and sign-out).
The compare-and-set save still applies, so two tabs that refresh the same token at once never roll
storage back: the later answer is dropped and its tab adopts the stored pair. On the web, tabs
also adopt each other's newer stored tokens through the `storage` event and when they come to the
foreground.

## Cookie and BFF modes

No refresh token is readable in these modes, so the token checks (lineage, held tab, fingerprint
compare-and-set, emptied-storage judgement) do not apply. What applies: single flight, the lock,
`session-refreshed` adoption (other tabs re-read the id token from storage), the classification,
the schedule and the strikes, the blocked successor wait, logout under the lock, and the identity
check on the answer's id token `sub`.

- A transient failure no longer marks the session invalid. Only the end does (the last strike, or
  the successor timeout): then the session is marked invalid, the local id token and CSRF token
  are cleared, and `SessionExpired` follows.
- Cookie mode sends `AuthAPI.refreshToken('', scopes)`; the server reads the HttpOnly cookie.
- BFF mode (`tokenExchange.refreshUrl`) sends `POST refreshUrl` with `credentials: 'include'`. A
  non-OK answer becomes a `PassflowError` with the HTTP status and the body's `error.id` (or
  `error.http.<status>`), and is classified like any other answer. BFF without a `refreshUrl`
  refreshes in JSON mode, as before. An upgrade commit is refused in BFF mode before any request
  and before `RefreshStart`.
- Blocked in fallback (no channel): the successor is a change of the stored id token or CSRF token
  after the send; failing that, one retry 1 s after the blocked answer.

## Migrating from 0.20.1

0.21.0 is a minor bump that changes observable behaviour.

**Breaking changes**

1. A failed refresh no longer deletes the tokens or emits `SessionExpired`, except at a real end
   (the last auth strike, a successor timeout, an identity change). Network errors, timeouts, 429
   and 5xx keep the session and retry on the schedule.
2. `SignOut` is emitted **once** per sign-out, after the token cache is cleared, with
   `{ origin, userId }`. 0.20.1 emitted it twice on `logOut()` (once with the cache still set).
3. `Refresh` carries `source`. Tabs that did not send the request now get `Refresh{adopted}`
   with no `RefreshStart`; a reducer that counts `RefreshStart`/`Refresh` pairs must not go below
   zero.
4. `SessionExpired.reason` gains `'refresh_failed' | 'successor_timeout' | 'identity_changed'`,
   and `SessionExpired` gains `origin`. An exhaustive `switch` over `reason` needs the new cases.
5. One failure produces one `Error`. The second `Error` that `Passflow.refreshToken()` added
   (`"Failed to refresh token"`) and the duplicates from the 2FA wrappers are gone. `ErrorPayload`
   gains `operation` (always set), and `source` and `refresh` for refresh errors.
6. `getTokens(true)` and `session({ doRefresh: true })` resolve with the **kept** tokens after a
   transient failure. They used to resolve `undefined`, which apps read as "go to sign-in".
7. API clients built standalone (`new TenantAPI(...)` and the other classes exported from the
   API layer) no longer refresh before a request; they send the current bearer. Only the clients a
   `Passflow` instance owns run the pre-request refresh, through its controller.
8. `TokenCacheService.isRefreshing` is a read-only getter ("this instance has a refresh cycle":
   in flight, waiting, a retry or a successor pending). Assigning it is a type error.
9. `TokenCacheService.getTokensWithRefresh()` on a `TokenCacheService` that is not attached to a
   `Passflow` returns the cache and sends nothing. `tokenExpiredFlag` no longer gates a refresh:
   the 60 s check still sets it and emits `TokenCacheExpired{isExpired:true}`, and every `Refresh`
   clears it.
10. The pre-request refresh no longer deletes tokens when it fails, and no longer aborts its own
    request.
11. With the default configuration each browser instance opens a `BroadcastChannel` and uses Web
    Locks. Call `dispose()` on SPA teardown.
12. `SignIn` can arrive with `origin: 'other-tab'` (an ended tab reviving on a sign-in made in
    another tab).
13. (0.21.1) `subscribe()` may be called at any time. Each call still starts the expiry check.
    It no longer reloads the cache from storage when the cache already holds tokens, so a held
    tab keeps its newer pair. `TokenCacheExpired{isExpired:true}` fires once per expiry, not once
    per `subscribe()`.

**New**: `refreshCoordination`, `refreshStrikes`, `Passflow.dispose()`, the `RefreshFailing` and
`RefreshRecovered` events, `PassflowRefreshError`, `RefreshErrorId`, `REFRESH_AUTH_FAILURE_IDS`,
`UpgradeCommitInterruptedError`, and the types `RefreshCoordination`, `RefreshCoordinator`,
`RefreshLockManager`, `RefreshLockOptions`, `RefreshChannel`, `RefreshClock`, `RefreshTrigger`,
`RefreshFailureKind`, `RefreshErrorInfo`, `EventOrigin`, `SessionExpiredReason`,
`PassflowOperation`, `OperationErrorPayload`.

**What an app can delete.** A cross-tab refresh wrapper (Web Lock plus BroadcastChannel around
`refreshToken()`), a refresh retry loop, a "credential fence" before saving, a pre-request
refresh guard, and reducer code that ignored the second `Error` or the first `SignOut`. Keep only
the UI: show a notice on `RefreshFailing`, hide it on `RefreshRecovered`, and send the user to
sign-in on `SessionExpired` or `SignOut`.

**Interop during a rollout.** The lock names, channel name, message types and fingerprint match
the portal's earlier `cross-tab-refresh.ts`, so tabs on the old wrapper and tabs on 0.21.0 can
share one browser.
