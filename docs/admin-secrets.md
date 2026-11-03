# Admin settings secrets

How the Passflow admin API treats secrets in app settings and in server settings, and the types
`@passflow/core` exports for them. The SDK has no admin API client: these types and helpers are
for admin UIs that call the admin routes themselves.

## App secrets (write-only)

Three app secrets are write-only. An answer never echoes the stored value.

| Secret (`AppSecretName`) | Where it lives | How answers show it |
|---|---|---|
| `debug_otp_code_for_registration` | `AppSettings` | Always an empty string. `AppSettings.debug_otp_code_set` is `true` when a code is stored. |
| `fcm_server_key` | Push settings in the app's `two_factor_settings` | Absent. |
| `webpush_vapid_private_key` | Push settings in the app's `two_factor_settings` | Absent. `webpush_vapid_public_key` is still returned. |

On write:

- A blank or absent value keeps the stored secret.
- A non-blank value replaces it.
- Sending a blank value never clears it. To clear one, call:

```http
DELETE /admin/apps/{id}/secrets/{name}
```

where `{name}` is one of `APP_SECRET_NAMES`:

```ts
import { APP_SECRET_NAMES, type AppSecretName } from '@passflow/core';

APP_SECRET_NAMES; // ['debug_otp_code_for_registration', 'fcm_server_key', 'webpush_vapid_private_key']
```

In `AppSettings`, `debug_otp_code_for_registration` is optional (`string | undefined`) and
`debug_otp_code_set` is an optional, read-only `boolean`. Code that read
`debug_otp_code_for_registration` as the stored code must use `debug_otp_code_set` instead.

## Server settings secrets (masked)

`GET /admin/settings` and `PUT /admin/settings` return secrets as masked values (`MaskedSecret`):

| Value | Masked form |
|---|---|
| Secrets | `mask://********` |
| Connection strings, dynamo/s3/ssm endpoints, plugin address/cmd, activity-logger endpoints, management_keys | `mask://********/<16 lowercase hex>` |

The hex suffix tells two masked values apart without revealing either.

On `PUT /admin/settings`:

| You send | Result |
|---|---|
| The masked value, unchanged | The stored value is kept. |
| A plain value | The stored value is replaced. |
| An empty string | The stored value is cleared. |
| A stale or edited masked value | HTTP 400, error id `error.server.update.settings.masked.value.unknown` |

So an admin UI can send back the whole settings object it read, changing only the fields the
user edited.

```ts
import {
  isMaskedSecret,
  MASKED_SECRET_PREFIX, // 'mask://'
  SETTINGS_MASKED_VALUE_UNKNOWN_ERROR_ID, // 'error.server.update.settings.masked.value.unknown'
} from '@passflow/core';

// Show "stored" for a masked value, but keep the value itself to send back unchanged.
const label = isMaskedSecret(value) ? 'stored' : value;
```

`isMaskedSecret(value)` is `true` for any string that starts with `mask://`. It does not check
that the server would accept the value. When a `PUT` fails with
`SETTINGS_MASKED_VALUE_UNKNOWN_ERROR_ID`, read the settings again and reapply the user's edits.
