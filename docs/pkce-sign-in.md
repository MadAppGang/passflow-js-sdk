# Passwordless and federated sign-in on PKCE apps

What a host app must handle when an app has PKCE on. The SDK reads the app's setting and sends the
proof key itself, so the calls you already make stay the same. Apps with PKCE off behave as before:
no match code, no stored proof key, and the same requests.

Two names below:

- **Tab A** is the tab that called `passwordlessSignIn`. It holds the proof key and is the only place
  the sign-in can finish.
- **Device B** is wherever the user opens the emailed link. It only approves or denies, and it never
  gets tokens.

## OTP typed in tab A

`passwordlessSignIn` and `passwordlessSignInComplete` work as they did. `passwordlessSignInComplete`
now redeems the server's code in the background and answers with a new token pair, or a `tfa_token`
when a second factor is owed.

Complete the sign-in in the tab that started it. A code entered in another tab reaches the server,
but its answer cannot be redeemed there: the call throws and the user starts again.

## Magic link: approve on any device

`passwordlessSignIn` answers with `match_code`, a 4-digit code. Tab A shows it and waits. On device
B, the user opens the link, reads what is being approved, and types that code.

```typescript
const { challenge_id } = await passflow.passwordlessSignIn({
  email: "user@example.com",
  challenge_type: "magic_link",
  redirect_url: "https://yourapp.com/auth/callback",
});

const pending = passflow.getPendingPasswordlessSignIn(challenge_id);
if (pending) {
  showCode(pending.matchCode); // "Open the link we sent on any device and enter this code"

  const controller = new AbortController();
  const result = await passflow.waitForPasswordlessSignIn(challenge_id, {
    signal: controller.signal,
  });
} else {
  // No approval step: PKCE off, an older server, or an unknown user. Show "check your email".
}
```

Do not put the `passwordlessSignIn` answer into a URL as it is: it holds `match_code`.

### Tab A: `getPendingPasswordlessSignIn(challengeId)`

Returns `{ matchCode, expiresAt }`, with `expiresAt` in epoch milliseconds. Returns `undefined` unless
this tab's stored sign-in names that challenge and holds a match code.

### Tab A: `waitForPasswordlessSignIn(challengeId, options?)`

Polls every 3 s until the challenge expires. Network errors, 429, 5xx and unreadable answers keep
polling, so a phone changing networks only makes the sign-in land late.

| Result `status` | What happened | What the host does |
|---|---|---|
| `signed-in` | Tokens are applied and `SignIn` was emitted. `tokens` holds the new token pair. | Continue into the app. |
| `second-factor-required` | `TwoFactorRequired` was emitted. | Ask for the factor in tab A. |
| `denied` | Device B denied, or too many wrong answers. | "This sign-in was denied. Start again." |
| `expired` | The challenge ran out before it was redeemed. | "This link expired. Start again." |
| `completed` | The row was already used. This never means a session exists. | "This sign-in was already used. Start again." |

The method rejects in two other cases:

- **Abort.** It rejects with `signal.reason`, emits no `Error` and keeps the stored sign-in, so a later
  call can wait again. Once the approval has been read, the exchange finishes regardless of the signal.
- **Failure.** It rejects with a plain error and emits one `Error` with operation `passwordless.wait`:
  a 4xx on the poll, a failed exchange, or a lost or replaced record. Show "Sign-in failed. Start again."

Run one wait at a time for a challenge. The SDK does not coordinate two waits.

### Device B: the link

The email link carries `challenge_id`, `otp` and `flow=approval`. When `flow` is `approval`, show an
approve screen and do not call `passwordlessSignInComplete`: the server refuses it for this row with
`error.auth.passwordless.approval.unavailable`, and nothing is spent. A link with no `flow` works as
it did.

### Device B: `getPasswordlessApproval(challengeId)`

Answers what to show. It takes no OTP, changes nothing on the server, and holds no identity and never
the match code, so a mail scanner opening the link has no effect.

```typescript
type PasswordlessApprovalInfo = {
  state: "pending" | "approved" | "denied" | "expired" | "completed";
  app_name: string;
  requested_at: string;
  expires_at: string;
  browser: string;
  os: string;
  location: { city: string; country: string } | null;
  attempts_left: number;
};
```

### Device B: `decidePasswordlessApproval(challengeId, otp, approve, matchCode?)`

Approving needs the OTP from the link and the code typed from tab A. Denying needs only the OTP. It
resolves with no value; tab A sees the outcome on its next poll.

| `PassflowError.id` | Meaning |
|---|---|
| `error.auth.passwordless.approval.invalid` | Unknown challenge or wrong OTP. Counted. |
| `error.auth.passwordless.approval.match.invalid` | Wrong match code. Counted. Re-read `attempts_left`. |
| `error.auth.passwordless.approval.attempts` | Five wrong answers. The sign-in is denied. |
| `error.auth.passwordless.approval.unavailable` | The app is inactive or PKCE is off, or the challenge has no approval step. |
| `error.otp.expired` | The link expired. |
| `error.otp.already.used` | Already decided (status 409). |
| `error.passwordless.approval` | No usable answer (status 0): a 429 with no error body. Try again later. |
| `error.service.unavailable` | Passflow could not be reached (status 0) or its gateway answered 502/503/504 itself. Try again in a moment. The same id replaces the call's own id on every passwordless and PKCE call. |

Failures of both device B calls emit one `Error` with operation `passwordless.approval`.

### Same browser

A second tab in the same browser is device B like any other. It shows the approve screen, the user
types the code, and tab A finishes. The second tab does not sign in by itself, so tell the user to
return to the tab that started sign-in.

### When tab A loses the record

Tab A keeps one record, in memory and `sessionStorage`. There is nothing to recover from when it is
gone: show "Start again".

| Event | Effect |
|---|---|
| Reload of tab A | The record survives; call `waitForPasswordlessSignIn` again. |
| New `passwordlessSignIn` in the tab, Resend included | Replaces the record. A wait on the old challenge rejects; wait on the new `challenge_id`. |
| `logOut()` in this tab | Deletes the record. A running wait rejects. |
| Tab closed, or a React Native relaunch (memory only) | Nobody can finish. The challenge expires. |
| Wrong OTP on `passwordlessSignInComplete` | The record stays, so the user can try again. |

## Federated sign-in

`federatedAuthWithRedirect` still returns `void`, but it now **navigates asynchronously**, because
the proof key takes a moment to compute. Do not run code after the call that assumes the page is
leaving, and listen for failures:

- A missing `appId` still throws synchronously.
- Any later failure emits `Error` with operation `federated.redirect`, and the page stays.

`federatedAuthWithPopup` finishes in the opening tab as before. If the browser blocks the popup, the
SDK falls back to a redirect, so a popup host's `redirect_url` page must also handle a landing.

### The landing

The server sends the browser back with `?code=&user_state=`. The tab that started the sign-in holds
the verifier for 10 minutes, and redeems the code on the landing:

- With `parseQueryParams: true` the constructor takes the landing; otherwise `handleTokensRedirect()`
  does. `handleTokensRedirect()` stays sync and returns `undefined` here.
- `code` and `user_state` leave the URL. Other parameters, such as `appid` and `redirectto`, stay.
- The exchange runs in the background. Subscribing right after construction still hears the outcome:

| Event | Meaning |
|---|---|
| `SignIn` with `source: 'federated-landing'` | This tab took the landing and exchanged its code. No other `SignIn` carries `source`. |
| `TwoFactorRequired` | A second factor is owed. Ask for it on this page. |
| `Error` with operation `federated.redirect` | The exchange failed. Show "Sign-in failed. Start again." There is no retry. |

A `?code=` this tab did not ask for changes nothing: with no stored verifier or an expired one, the URL
stays as it is, nothing is exchanged and no `SignIn` fires. Treat `source` as the signal for anything
you do after a landing, never the URL. Landing on another origin or in another tab has the same result.

### `deferFederatedLanding` and `completeFederatedLanding()`

A host that builds its `Passflow` instance during render may have that instance thrown away, as React
StrictMode does. Taking the landing there would spend the code on the discarded instance. Set
`deferFederatedLanding: true`, and run the landing from code that runs once the instance is kept:

```typescript
const passflow = new Passflow({ appId, parseQueryParams: true, deferFederatedLanding: true });

// Later, for example in an effect:
passflow.subscribe(subscriber, [PassflowEvent.SignIn, PassflowEvent.TwoFactorRequired, PassflowEvent.Error]);
const taken = passflow.completeFederatedLanding();
```

With the option on, neither the constructor nor `handleTokensRedirect()` takes a `?code=` landing, and
`completeFederatedLanding()` is the only thing that does. Token and `#tfa_token` landings keep their
path either way.

`completeFederatedLanding()` returns `true` when the exchange began, once per landing. On `false`, the
URL and the stored verifier are unchanged, so an instance that has its app id can still take the
landing. An instance with no `appId` yet always answers `false`.
