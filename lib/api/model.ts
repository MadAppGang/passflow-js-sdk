import type {
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
} from '@simplewebauthn/browser';
import type { AxiosRequestConfig } from 'axios';

import type { PlatformAdapter } from '../platform';
import type { RefreshCoordination } from '../refresh/types';
import type { Tokens } from '../types';
import type { UpgradeAssertion, UpgradeFactor } from '../upgrade/factors';

export type RequestOptions<D> = {
  data?: D;
  config?: AxiosRequestConfig;
};

export enum RequestMethod {
  GET = 'get',
  POST = 'post',
  PUT = 'put',
  PATCH = 'patch',
  DELETE = 'delete',
}

export enum PassflowEndpointPaths {
  signin = '/auth/login',
  signup = '/auth/register',
  pkceExchange = '/auth/pkce_exchange',
  redirectCheck = '/auth/redirect/check',
  signInWithProvider = '/auth/federated/start/',
  passwordless = '/auth/passwordless/start',
  passwordlessComplete = '/auth/passwordless/complete',
  passwordlessStatus = '/auth/passwordless/status',
  passwordlessApprovalInfo = '/auth/passwordless/approval/info',
  passwordlessApprovalDecide = '/auth/passwordless/approval/decide',
  logout = '/user/logout',
  refresh = '/auth/refresh',
  validateSession = '/user/me',
  sendPasswordResetEmail = '/auth/password/reset',
  resetPassword = '/auth/password/change',
  appSettings = '/app/settings',
  passkeyRegisterStart = '/auth/passkey/register/start',
  passkeyRegisterComplete = '/auth/passkey/register/complete',
  passkeyAuthenticateStart = '/auth/passkey/authenticate/start',
  passkeyAuthenticateComplete = '/auth/passkey/authenticate/complete',
  passkeyValidate = '/auth/validate',
  settingsAll = '/settings',
  settingsPasswordPolicy = '/settings/password',
  settingsPasskey = '/settings/passkey',
  userPasskey = '/user/passkey',
  addUserPasskey = `${PassflowEndpointPaths.userPasskey}/add/start`,
  completeAddUserPasskey = `${PassflowEndpointPaths.userPasskey}/add/complete`,
  joinInvitation = '/user/tenant/join',
  tenantPath = '/user/tenant',
  invitationsPath = '/user/tenant/:tenantID/invitations',
  requestInvitation = '/user/invite',
  invitationDelete = '/user/invite/:invitationID',
  invitationResend = '/user/invite/:invitationID/resend',
  invitationGetLink = '/user/invite/:invitationID/link',
  twoFactor = '/user/2fa',
  twoFactorStatus = '/user/2fa/status',
  twoFactorSetupBegin = '/user/2fa/setup/begin',
  twoFactorSetupConfirm = '/user/2fa/setup/confirm',
  twoFactorVerify = '/auth/2fa/verify',
  twoFactorRecovery = '/auth/2fa/recovery',
  twoFactorRegenerateCodes = '/user/2fa/recovery-codes/regenerate',
  twoFactorSetupMagicLink = '/auth/2fa-setup', // :token param appended in API call
  // Enrolment while a sign-in waits on its second factor; all take the tfa_token as the bearer
  twoFactorEnrollment = '/auth/2fa/enrollment',
  twoFactorEnrollmentEmailLink = '/auth/2fa/enrollment/email-link',
  twoFactorEnrollmentBegin = '/auth/2fa/setup/begin',
  twoFactorEnrollmentConfirm = '/auth/2fa/setup/confirm',
  // v2 2FA endpoints
  TwoFactorMethodsAvailable = '/v2/user/2fa/methods/available',
  TwoFactorMethodsRegistered = '/v2/user/2fa/methods',
  TwoFactorSetupStart = '/v2/user/2fa/setup/start',
  TwoFactorSetupComplete = '/v2/user/2fa/setup/complete',
  TwoFactorMethodRemove = '/v2/user/2fa/methods/:id',
  TwoFactorChallenge = '/v2/auth/2fa/challenge',
  TwoFactorVerifyV2 = '/v2/auth/2fa/verify',
  TwoFactorAlternative = '/v2/auth/2fa/alternative',
  TwoFactorTrustedDevices = '/v2/user/2fa/trusted-devices',
  TwoFactorTrustedDeviceRevoke = '/v2/user/2fa/trusted-devices/:id',
  // CLI Auth endpoints
  cliAuthStatus = '/cli/auth/status/:sessionId',
  cliAuthComplete = '/cli/auth/complete',
  // Assurance upgrade (step-up) endpoints. The commit round reuses `refresh`.
  upgradeStart = '/auth/upgrade/start',
}

export enum PassflowAdminEndpointPaths {
  passkeyRegisterStart = '/admin/auth/passkey/register/start',
  passkeyRegisterComplete = '/admin/auth/passkey/register/complete',
  passkeyAuthenticateStart = '/admin/auth/passkey/authenticate/start',
  passkeyAuthenticateComplete = '/admin/auth/passkey/authenticate/complete',
  passkeyValidate = '/admin/auth/validate',
  logout = '/admin/auth/logout',
}

/**
 * BFF (Backend-for-Frontend) configuration for secure token storage.
 * When enabled, tokens are sent to the BFF server which stores them in httpOnly cookies.
 */
export type TokenExchangeConfig = {
  /**
   * Enable token exchange mode. When true, authorization code is sent to your server
   * for token exchange instead of being exchanged directly from the browser.
   */
  enabled: boolean;
  /**
   * URL to send authorization code for server-side token exchange.
   * Your server exchanges the code for tokens and stores them in httpOnly cookies.
   * @example '/api/auth/callback'
   */
  callbackUrl: string;
  /**
   * URL to call for token refresh. BFF reads refresh_token from httpOnly cookie
   * and returns new tokens (also stored in cookies).
   * @example '/api/auth/refresh'
   */
  refreshUrl?: string;
  /**
   * URL to call for logout. BFF clears httpOnly cookies.
   * @example '/api/auth/logout'
   */
  logoutUrl?: string;
  /**
   * URL to check authentication status (whether httpOnly cookies are valid).
   * @example '/api/auth/status'
   */
  statusUrl?: string;
};

/** @deprecated Use TokenExchangeConfig instead */
export type BFFConfig = TokenExchangeConfig;

export type PassflowConfig = {
  url?: string;
  appId?: string;
  scopes?: string[];
  createTenantForNewUser?: boolean;
  parseQueryParams?: boolean;
  /**
   * Leaves a federated `?code=` landing alone in the constructor and in `handleTokensRedirect`,
   * so that only `completeFederatedLanding()` takes it. For hosts that build the instance during
   * render and may discard it. Token and `#tfa_token` landings are not affected.
   */
  deferFederatedLanding?: boolean;
  keyStoragePrefix?: string;
  /**
   * Token exchange configuration for secure server-side token handling.
   * When enabled, authorization code is sent to your server which exchanges it
   * for tokens and stores them in httpOnly cookies. Tokens never touch the browser.
   */
  tokenExchange?: TokenExchangeConfig;
  /**
   * Platform adapter for cross-platform compatibility.
   * Defaults to WebAdapter (browser APIs) if not provided.
   * Pass a custom adapter to support React Native or other platforms.
   */
  platform?: PlatformAdapter;
  /**
   * Assurance upgrade (step-up) configuration. Construction-time only: the
   * prompt handler is deliberately NOT here, because it is a lifetime-scoped
   * resource that has to be torn down, which configuration cannot express.
   */
  upgrade?: PassflowUpgradeConfig;
  /**
   * How tabs of this origin coordinate token refresh.
   * - `'web-locks'` (default): a Web Lock plus a BroadcastChannel, on a browser page whose
   *   `platform.storage` is shared by every tab (the default web adapter's localStorage) and that
   *   has `navigator.locks` and `BroadcastChannel`. Elsewhere it falls back to `'none'`; on a
   *   browser page with shared storage the fallback writes one `[passflow]` warning, at the first
   *   refresh.
   * - `'none'`: no cross-tab coordination. Single flight within this instance, compare-and-set
   *   save, per-instance retries.
   * - a `RefreshCoordinator` object: the same protocol as `'web-locks'` over the transports
   *   you supply (tests, Electron, custom hosts). Never falls back.
   */
  refreshCoordination?: RefreshCoordination;
  /**
   * Authentication failures of `/auth/refresh` counted since the last successful refresh or
   * adoption, after which the session ends. Transient failures in between neither add a strike nor
   * reset the count. Default 3. A non-integer is floored; a value below 1 or not a finite number
   * uses the default.
   */
  refreshStrikes?: number;
};

export type PassflowUpgradeConfig = {
  /** Relying-party id forwarded verbatim to `POST /auth/upgrade/start` for passkey upgrades. */
  relyingPartyId?: string;
  /** Overrides the factor set offered during an upgrade. Defaults to what this SDK can complete. */
  factors?: readonly UpgradeFactor[];
};

/**
 * Passflow's own API, as an interception scope — "domain 1".
 *
 * A challenge arriving from here is handled with zero configuration, because
 * `url` is an input the SDK already takes and whatever it points at is
 * unambiguously ours.
 */
export type UpgradeDomain = {
  /** The API origin, e.g. `https://api.passflow.dev`. */
  origin: string;
  /** The path prefix when `url` carries one, normalised without a trailing slash. */
  pathPrefix?: string;
};

/**
 * Resolves domain 1 from `PassflowConfig.url`.
 *
 * `url` is OPTIONAL, and the absent case is specified rather than guessed: the
 * domain is EMPTY (`null`), and nothing throws. Throwing would break apps that
 * never enabled step-up, and substituting a default origin — `PASSFLOW_CLOUD_URL`,
 * the document origin, the origin the first 401 came from — would be the SDK
 * inferring a trust boundary it has no information about. An empty domain is not
 * silent: the first parseable challenge on an attached surface must raise a
 * diagnostic naming `url` as the fix.
 *
 * Note this deliberately does NOT mirror `AxiosClient`'s `url || PASSFLOW_CLOUD_URL`
 * fallback. That fallback decides where to send our own traffic; this decides
 * whose 401s may drive a security prompt, and the two questions do not share an
 * answer.
 */
export const resolveUpgradeDomain = (url?: string): UpgradeDomain | null => {
  if (!url) {
    return null;
  }
  try {
    const parsed = new URL(url);
    const prefix = parsed.pathname.replace(/\/+$/, '');
    return { origin: parsed.origin, pathPrefix: prefix === '' ? undefined : prefix };
  } catch {
    // A `url` the platform's own URL parser rejects cannot be matched against a
    // response URL either. Same treatment as absent: empty, and never a throw.
    return null;
  }
};

/** The raw `POST /auth/upgrade/start` body, snake_case exactly as the server sends it. */
export type UpgradeStartWire = {
  challenge_id: string;
  method: string;
  /** RFC 3339. The server enforces the TTL; the SDK carries this for display only. */
  expires_at: string;
  /** WebAuthn assertion options, present only for a passkey upgrade. */
  webauthn?: PublicKeyCredentialRequestOptionsJSON;
  /** Masked delivery target (`j***@x.com`), present only for email / SMS OTP. */
  code_sent_to?: string;
};

/**
 * The `upgrade` field of `POST /auth/refresh` — the commit round.
 *
 * The server types `assertion` as `json.RawMessage`, so a new factor can extend
 * the payload without a wire-format change.
 */
export type UpgradeRefreshField = {
  type: string;
  assertion: UpgradeAssertion;
};

export type PassflowAuthorizationResponse = Tokens & {
  /**
   * The authorization code a PKCE app answers with in place of tokens. The SDK
   * redeems it, so a response handed back to a caller never carries one.
   */
  code?: string;
  /** Where the server sends the user next; a password reset answers with its link's redirect. */
  redirect_url?: string;
  requires_2fa?: boolean;
  challenge_id?: string;
  tfa_token?: string;
  token_delivery?: 'json_body' | 'cookie' | 'mobile';
  cookies?: string[];
  csrf_token?: string;
  /** `true` when the server needs the email proven before this sign-in finishes. No tokens come with it. */
  email_verification_required?: boolean;
  /** Human-readable text from the server, e.g. "We sent a code to a***@example.com." */
  message?: string;
};

/**
 * A sign-up, sign-in or password change that waits for the email to be proven.
 * With `challenge_id`: a code was emailed, finish with `Passflow.verifyEmailCode`.
 * Without: the code budget is spent and a link was emailed instead.
 * `message` is what the server sent; a malformed answer may leave it out.
 */
export type PassflowEmailVerificationStep = {
  email_verification_required: true;
  message: string;
  challenge_id?: string;
};

/** The emailed code for a `PassflowEmailVerificationStep` that carried a `challenge_id`. */
export type PassflowEmailCodePayload = {
  challenge_id: string;
  otp: string;
};

/**
 * Whether an auth answer is an email verification step rather than a session. Only the
 * `email_verification_required` flag is checked, so an answer with the flag is never taken
 * for a session.
 */
export const isEmailVerificationStep = (response: unknown): response is PassflowEmailVerificationStep =>
  typeof response === 'object' &&
  response !== null &&
  (response as { email_verification_required?: unknown }).email_verification_required === true;

export type PassflowValidationResponse = Tokens & {
  redirect_url: string;
  requires_2fa?: boolean;
  challenge_id?: string;
  tfa_token?: string;
  /** PKCE app: the code to redeem with the verifier, in place of tokens. */
  code?: string;
};

export type PassflowSuccessResponse = {
  result: 'ok';
};

export type PassflowLogoutResponse = {
  status: 'ok';
};

export interface PassflowSessionValidationResponse {
  valid: boolean;
  user?: {
    id: string;
    email?: string;
    username?: string;
    [key: string]: unknown;
  };
  expires_at?: number;
}

export type PassflowResponseError = {
  error: {
    id: string;
    message: string;
    status: number;
    location: string;
    time: string;
  };
};

/** Id of the error a call rejects with when the Passflow API cannot be reached or its gateway answers 502, 503 or 504. */
export const SERVICE_UNAVAILABLE_ERROR_ID = 'error.service.unavailable';

/** Message of the {@link SERVICE_UNAVAILABLE_ERROR_ID} error. */
export const SERVICE_UNAVAILABLE_MESSAGE = 'Passflow is temporarily unavailable. Please try again in a moment.';

export class PassflowError extends Error {
  id: string;
  message: string;
  status: number;
  location: string;
  time: string;
  /** Declared here rather than inherited: `Error.cause` is ES2022 and this build targets ES2021 libs. */
  readonly cause?: unknown;

  constructor(error: PassflowResponseError['error'], options?: { cause?: unknown }) {
    super();
    this.id = error?.id ?? 'unknown';
    this.message = error?.message ?? error ?? 'Something went wrong';
    this.status = error?.status ?? 500;
    this.location = error?.location ?? 'unknown';
    this.time = error?.time ?? new Date().toISOString();
    if (options?.cause !== undefined) this.cause = options.cause;
  }
}

export type PassflowSignInPayload = {
  password: string;
  scopes?: string[];
  invite_token?: string;
  code_challenge?: string;
} & (
  | { email: string; phone?: never; username?: never }
  | { phone: string; email?: never; username?: never }
  | { username: string; email?: never; phone?: never }
);

export type PassflowSignInExtendedPayload = PassflowSignInPayload & {
  device: string;
  os: OS;
};

export type PassflowAddressPayload = {
  formatted?: string;
  street_address?: string;
  locality?: string;
  region?: string;
  postal_code?: string;
  country?: string;
};

export type PassflowUserPayload = {
  password: string;
  username?: string;
  email?: string;
  given_name?: string;
  family_name?: string;
  middle_name?: string;
  nickname?: string;
  preferred_username?: string;
  phone_number?: string;
  profile?: string;
  picture?: string;
  website?: string;
  gender?: string;
  birthday?: Date;
  timezone?: string;
  locale?: string;
  addresses?: PassflowAddressPayload;
} & ({ email: string } | { phone_number: string });

export type PassflowSignUpPayload = {
  user: PassflowUserPayload;
  scopes?: string[];
  create_tenant?: boolean;
  anonymous?: boolean;
  invite_token?: string;
  code_challenge?: string;
};

export type PassflowPasswordlessSignInPayload = {
  challenge_type: InternalStrategyChallenge;
  redirect_url: string;
  scopes?: string[];
  create_tenant?: boolean;
  invite_token?: string;
  code_challenge?: string;
} & ({ email: string; phone?: never } | { phone: string; email?: never });

export type PassflowPasswordlessResponse = {
  challenge_id: string;
  expires_at: Date | string;
  /** The code the user types on the approving device. Only on a row that can be approved from another device. */
  match_code?: string;
};

export type PassflowPasswordlessSignInExtendedPayload = PassflowPasswordlessSignInPayload & {
  device: string;
  os: OS;
};

export type PassflowPasswordlessSignInCompletePayload = {
  challenge_id: string;
  otp: string;
  device?: string;
  scopes?: string[];
  challenge_type?: InternalStrategyChallenge;
};

export type PassflowPasswordlessStatusPayload = {
  challenge_id: string;
  code_challenge: string;
};

export type PassflowPasswordlessStatusResponse =
  | { status: 'pending' | 'denied' | 'expired' | 'completed' }
  | { status: 'approved'; code: string };

export type PassflowPasswordlessApprovalInfoPayload = {
  challenge_id: string;
};

export type PassflowPasswordlessApprovalDecidePayload = {
  challenge_id: string;
  otp: string;
  approve: boolean;
  match_code?: string;
};

export type PassflowPasswordlessApprovalDecideResponse = {
  state: 'approved' | 'denied';
};

export type PasswordlessWaitResult =
  | { status: 'signed-in'; tokens: PassflowAuthorizationResponse }
  | { status: 'second-factor-required' | 'denied' | 'expired' | 'completed' };

export type PasswordlessApprovalInfo = {
  state: 'pending' | 'approved' | 'denied' | 'expired' | 'completed';
  app_name: string;
  requested_at: string;
  expires_at: string;
  browser: string;
  os: string;
  location: { city: string; country: string } | null;
  attempts_left: number;
};

export enum Providers {
  google = 'google',
  facebook = 'facebook',
}

export type FimStrategy = {
  fim_type: Providers;
};

export type InternalStrategyIdentity = 'id' | 'email' | 'phone' | 'username' | 'anonymous' | 'none';
export type InternalStrategyChallenge = 'password' | 'otp' | 'magic_link' | 'recovery_codes' | 'guardian' | 'none';
export type InternalStrategyTransport = 'email' | 'sms' | 'push' | 'socket' | 'authenticator' | 'none';

export type InternalStrategy = {
  identity: InternalStrategyIdentity;
  challenge: InternalStrategyChallenge;
  transport: InternalStrategyTransport;
};

export type OtherStrategy = Record<string, never>;

export type AuthTypeStrategy = 'internal' | 'passkey' | 'webauthn' | 'fim' | 'pkce' | 'anonymous';

export type AuthStrategies =
  | { type: Extract<AuthTypeStrategy, 'internal'>; strategy: InternalStrategy }
  | { type: Extract<AuthTypeStrategy, 'fim'>; strategy: FimStrategy }
  | {
      type: Exclude<AuthTypeStrategy, 'internal' | 'fim'>;
      strategy: OtherStrategy;
    };

export type AppType = 'web' | 'spa' | 'bff' | 'android' | 'ios' | 'desktop' | 'm2m' | 'other';

export type TokenDeliveryMethod = 'json_body' | 'cookie' | '';

export type AppSettings = {
  id: string;
  secret: string;
  active: boolean;
  name: string;
  description: string;
  offline: boolean;
  type: AppType;
  redirect_urls: string[] | null;
  origins: string[] | null;
  custom_email_templates: boolean;
  auth_strategies: AuthStrategies[];
  force_passwordless_login: boolean;
  pkce_enabled: boolean;
  custom_sms_messages: boolean;
  registration_allowed: boolean;
  invite_only_registration: boolean;
  passwordless_registration_allowed: boolean;
  anonymous_registration_allowed: boolean;
  create_tenant_on_registration: 'never' | 'always' | 'optional';
  fim_merge_by_email_allowed: boolean;
  debug_otp_code_allowed: boolean;
  /**
   * WRITE-ONLY. Every read and write answer returns it as an empty string; the stored code is
   * never echoed. On write, a blank or absent value keeps the stored code and a non-blank value
   * replaces it. The only way to clear it is
   * `DELETE /admin/apps/{id}/secrets/debug_otp_code_for_registration` (see `AppSecretName`).
   * Use `debug_otp_code_set` to tell whether a code is stored.
   */
  debug_otp_code_for_registration?: string;
  /** READ-ONLY. `true` when a `debug_otp_code_for_registration` is stored. Ignored on write. */
  debug_otp_code_set?: boolean;
  defaults: DefaultAppSettings;
  login_app_theme: LoginWebAppTheme;
  login_app_settings?: unknown;
  token_delivery_method?: TokenDeliveryMethod;
};

/**
 * A write-only app secret that the admin API clears by name with
 * `DELETE /admin/apps/{id}/secrets/{name}`. The SDK has no admin client, so this route is not
 * wrapped; the names are exported for admin UIs that call it themselves.
 *
 * - `debug_otp_code_for_registration`: an `AppSettings` field. Answers return it as an empty
 *   string; `AppSettings.debug_otp_code_set` tells whether one is stored.
 * - `fcm_server_key`, `webpush_vapid_private_key`: push settings in the app's
 *   `two_factor_settings`. Both are absent from every answer; `webpush_vapid_public_key` is
 *   still returned.
 *
 * On write, a blank or absent value keeps the stored secret and a non-blank value replaces it.
 * DELETE is the only way to clear one. See docs/admin-secrets.md.
 */
export type AppSecretName = 'debug_otp_code_for_registration' | 'fcm_server_key' | 'webpush_vapid_private_key';

/** Every `AppSecretName`, in the order the type lists them. */
export const APP_SECRET_NAMES: readonly AppSecretName[] = Object.freeze([
  'debug_otp_code_for_registration',
  'fcm_server_key',
  'webpush_vapid_private_key',
]);

/**
 * A secret in the server settings (`GET`/`PUT /admin/settings`) as the admin API returns it.
 *
 * - Secrets come back as `mask://********`.
 * - Connection strings, dynamo/s3/ssm endpoints, plugin address/cmd, activity-logger endpoints
 *   and management_keys come back as `mask://********` followed by `/` and 16 lowercase
 *   hex characters (e.g. a `/0123456789abcdef` suffix); the suffix tells values apart without
 *   revealing them. (Written in two parts because the full form would end this comment.)
 *
 * On `PUT`: echo the masked value unchanged to keep the stored one, send a plain value to
 * replace it, send an empty string to clear it. A stale or edited masked value fails with
 * HTTP 400 and id `SETTINGS_MASKED_VALUE_UNKNOWN_ERROR_ID`. See docs/admin-secrets.md.
 */
export type MaskedSecret = string;

/** The prefix every `MaskedSecret` starts with. */
export const MASKED_SECRET_PREFIX = 'mask://';

/**
 * Error id of the HTTP 400 that `PUT /admin/settings` returns for a masked value the server did
 * not issue for the stored one (stale or edited).
 */
export const SETTINGS_MASKED_VALUE_UNKNOWN_ERROR_ID = 'error.server.update.settings.masked.value.unknown';

/**
 * Whether a server settings value is a masked secret rather than a plain value: any string that
 * starts with `MASKED_SECRET_PREFIX`. It does not check that the server would accept it.
 */
export const isMaskedSecret = (value: unknown): value is MaskedSecret =>
  typeof value === 'string' && value.startsWith(MASKED_SECRET_PREFIX);

export type DefaultAppSettings = {
  app_id: string;
  redirect: string;
  scopes: string[];
  create_tenant_for_new_user: boolean;
};

export enum OS {
  web = 'web',
  ios = 'ios',
  android = 'android',
}

/**
 * Maps platform.getDeviceType() return values to the OS enum.
 * The OS enum values match the getDeviceType() strings exactly,
 * so this is a safe cast.
 */
export function getOSFromDeviceType(deviceType: 'web' | 'ios' | 'android'): OS {
  // OS enum values happen to match getDeviceType() string values exactly
  return deviceType as OS;
}

export type PassflowPasskeyRegisterStartPayload = {
  passkey_display_name?: string;
  passkey_username?: string;
  invite_token?: string;

  scopes: string[];
  create_tenant?: boolean;

  relying_party_id: string;
  redirect_url: string;
  code_challenge?: string;
};

export type PassflowPasskeyRegisterStartExtendedPayload = PassflowPasskeyRegisterStartPayload & {
  device: string;
  os: OS;
};

export type PassflowPasskeyStart = {
  challenge_id: string;
  publicKey: PublicKeyCredentialCreationOptionsJSON;
};

export type PassflowPasskeyCompleteMessageWithTokens = Tokens;

export type PassflowPasskeyPayload = {
  device: string;
  challenge_id: string;
};

export type PassflowPasskeyRegisterPayload = PassflowPasskeyPayload & {
  passkey_data: RegistrationResponseJSON;
};

export type PassflowPasskeyAuthenticatePayload = PassflowPasskeyPayload & {
  passkey_data: AuthenticationResponseJSON;
};

export type PassflowPasskeyAuthenticateStartPayload = {
  relying_party_id: string;
  scopes?: string[];
  user_id?: string;
  invite_token?: string;
  code_challenge?: string;
};

export type PassflowPasskeyAuthenticateStartExtendedPayload = PassflowPasskeyAuthenticateStartPayload & {
  device: string;
  os: OS;
};

export type PassflowFederatedAuthPayload = {
  provider: Providers;
  redirect_url: string;
  scopes?: string[];
  invite_token?: string;
  create_tenant?: boolean;
  code_challenge?: string;
  code_challenge_method?: 'S256';
};

export type PassflowFederatedAuthExtendedPayload = PassflowFederatedAuthPayload & {
  device?: string;
};

export type PassflowValidatePayload = {
  otp: string;
  device: string;
  challenge_id: string;
};

// SETTINGS
export type PassflowPasskeyProviderOption = 'none' | 'required' | 'preferred' | 'discouraged';

export type PassflowSettingsAll = {
  password_policy: PassflowPasswordPolicySettings;
  passkey_provider: PassflowPasskeySettings;
};

export type PassflowPasswordPolicySettings = {
  restrict_min_password_length: boolean;
  min_password_length: number;
  reject_compromised: boolean;
  enforce_password_strength: 'none' | 'weak' | 'average' | 'strong';
  require_lowercase: boolean;
  require_uppercase: boolean;
  require_number: boolean;
  require_symbol: boolean;
};

export type PassflowPasskeySettings = {
  // name: string;
  id: string;
  display_name: string;
  // id_field: 'email' | 'phone' | 'username';
  // validation: InternalStrategyChallenge;
  registration?: {
    user_verification: PassflowPasskeyProviderOption;
    authenticator_attachment: 'platform' | 'cross-platform' | 'any';
    discoverable_key: PassflowPasskeyProviderOption;
    attestation_metadata: PassflowPasskeyProviderOption;
    extensions: unknown;
  };
  authentication?: {
    user_verification: PassflowPasskeyProviderOption;
    attestation_metadata: PassflowPasskeyProviderOption;
    extensions: unknown;
  };
};

type PassflowCredentialFlags = {
  user_present: boolean;
  user_verified: boolean;
  backup_eligible: boolean;
  backup_state: boolean;
};

type PassflowEnrolmentAuthenticator = {
  aaguid: string;
  sign_count: number;
  clone_warning: boolean;
  attachment: 'platform' | 'cross-platform';
};

export type PassflowUserPasskey = {
  id: string;
  user_id: string;
  name: string;
  strategy: InternalStrategy;
  challenge_type: InternalStrategyChallenge;
  strategy_hash: string;
  enrolled_at: Date | string;
  enrollment_challenge_id: string;
  confirmed_at: Date | string;
  last_auth_at: Date | string;
  public_key: string;
  attestation_type: string;
  transport: string[];
  flags: PassflowCredentialFlags;
  authenticator: PassflowEnrolmentAuthenticator;
  archived: boolean;
  archived_at: Date | string;
  count?: number;
  enrolled_with_app_id?: string;
};

export type PassflowSendPasswordResetEmailPayload = {
  reset_page_url?: string;
  redirect_url?: string;
} & (
  | { email: string; phone?: never; username?: never }
  | { phone: string; email?: never; username?: never }
  | { username: string; email?: never; phone?: never }
);

export type PassflowInviteResponse = {
  link: string;
};

export type PassflowInvitePayload = {
  invite_token: string;
  scopes: string[];
};

export type PassflowUserWithRoles = {
  user_id: string;
  username: string;
  email: string;
  phone_number: string;
  tenant_id: string;
  group_id: string;
  role_id: string;
  preferred_username?: string;
  given_name?: string;
  family_name?: string;
  nickname?: string;
  picture?: string;
  roles: {
    [role_id: string]: string; // Maps role_id to role_name
  };
};

export type PassflowGroup = {
  id: string;
  name: string;
  default: boolean;
  updated_at: string;
  created_at: string;
};

export type PassflowRole = {
  id: string;
  tenant_id: string;
  name: string;
};

export type PassflowTenantResponse = {
  tenant_id: string;
  tenant_name: string;
  users_in_groups?: PassflowUserInGroup[];
  groups?: PassflowGroup[];
  roles?: PassflowRole[];
};

/**
 * Represents a user's membership in a group with their assigned roles
 */
export type PassflowUserInGroup = {
  user: {
    id: string;
    name?: string | null;
    email?: string | null;
    phone?: string | null;
  };
  group_id: string;
  roles?: {
    id: string;
  }[];
};

export type PassflowCreateTenantPayload = {
  name: string;
};

export type LoginWebAppTemplateType = 'default' | 'simple' | 'extendable';

export type LoginWebAppTemplateColorScheme = 'system' | 'light' | 'dark';

export type LoginWebAppStyle = {
  primary_color: string;
  text_color: string;
  secondary_text_color: string;
  background_color: string;
  card_color: string;
  input_background_color: string;
  input_border_color: string;
  button_text_color: string;
  divider_color: string;
  federated_button_background_color: string;
  federated_button_text_color: string;
  logo_url: string;
  passkey_button_background_color: string;
  passkey_button_text_color: string;
  background_image: string;
  custom_css: string;
};

export type LoginWebAppTheme = {
  template_type: LoginWebAppTemplateType;
  application_name: string;
  remove_passflow_logo: boolean;
  description: string;
  color_scheme: LoginWebAppTemplateColorScheme;
  light_style: LoginWebAppStyle;
  dark_style: LoginWebAppStyle;
};

export type PassflowCreateTokenResponse = PassflowTenantResponse;

// Helper function to create paths with parameters
export function pathWithParams(template: string, params: Record<string, string>): string {
  let result = template;
  Object.entries(params).forEach(([key, value]) => {
    result = result.replace(`:${key}`, value);
  });
  return result;
}

// Usage example:
// const invitationsUrl = pathWithParams(PassflowEndpointPaths.invitationsPath, { tenantID: '123' });

// ============================================
// Two-Factor Authentication Types
// ============================================

/**
 * Two-Factor authentication policy
 */
export enum TwoFactorPolicy {
  Disabled = 'disabled',
  Optional = 'optional',
  Required = 'required',
}

/**
 * Two-Factor error codes
 */
export type TwoFactorErrorCode =
  | 'INVALID_CODE'
  | 'CODE_EXPIRED'
  | 'TOO_MANY_ATTEMPTS'
  | 'SETUP_NOT_STARTED'
  | 'ALREADY_ENABLED'
  | 'NOT_ENABLED'
  | 'INVALID_RECOVERY_CODE'
  | 'NO_RECOVERY_CODES_REMAINING'
  | 'INVALID_CHALLENGE'
  | 'TIME_DRIFT_DETECTED';

// Request Types
export type TwoFactorConfirmRequest = {
  code: string;
};

export type TwoFactorVerifyRequest = {
  code: string;
  tfa_token: string;
  trust_device?: boolean;
};

export type TwoFactorRecoveryRequest = {
  recovery_code: string;
  tfa_token: string;
  trust_device?: boolean;
};

export type TwoFactorDisableRequest = {
  code: string;
};

export type TwoFactorRegenerateRequest = {
  code: string;
};

// Response Types
export type TwoFactorStatusResponse = {
  enabled: boolean;
  policy: TwoFactorPolicy;
  recovery_codes_remaining: number;
  totp_digits?: 6 | 8; // Optional for backward compatibility, defaults to 6 if not provided
};

export type TwoFactorSetupResponse = {
  secret: string;
  /** Base64-encoded PNG of the QR code. Empty when the server sent no image: use `qr_code_url`. */
  qr_code: string;
  /** The `otpauth://` URL the QR code holds. */
  qr_code_url?: string;
  totp_digits?: 6 | 8; // Optional for backward compatibility, defaults to 6 if not provided
};

export type TwoFactorConfirmResponse = {
  success: true;
  enabled?: boolean;
  recovery_codes: string[];
};

/**
 * What a sign-in waiting on its second factor can do next, decided by the server:
 * - `verify`: ask for a code; the user has a factor the app accepts.
 * - `email_link`: no factor yet and a validated email: send the setup link, then the user signs in again.
 * - `direct`: no factor and no validated email: enrol here, then finish with the code.
 * - `unavailable`: the app offers no way to enrol this user: contact the administrator.
 */
export type TwoFactorEnrollment = 'verify' | 'email_link' | 'direct' | 'unavailable';

/** GET /auth/2fa/enrollment */
export type TwoFactorEnrollmentResponse = {
  enrollment: TwoFactorEnrollment;
};

/** POST /auth/2fa/enrollment/email-link */
export type TwoFactorSetupLinkResponse = {
  email_sent: boolean;
};

export type TwoFactorVerifyResponse = Tokens & {
  success: true;
  /** On a PKCE app; `TwoFactorService` redeems it, so its callers never see one. */
  code?: string;
};

/**
 * Options for the call that completes a sign-in with its second factor.
 */
export type TwoFactorCompletionOptions = {
  /**
   * Ask the server to trust this device, so later sign-ins from it skip the
   * second factor where the app allows that. The server keeps the trust in
   * an HttpOnly cookie; nothing is stored by the SDK.
   */
  trustDevice?: boolean;
};

/**
 * A device the user trusted to stand in for their second factor on this app.
 */
export type TwoFactorTrustedDevice = {
  id: string;
  user_agent?: string;
  created_at: string;
  last_used_at?: string;
  expires_at: string;
  /** True for the device the request came from. */
  current: boolean;
};

/** GET /v2/user/2fa/trusted-devices */
export type TwoFactorTrustedDevicesResponse = {
  devices: TwoFactorTrustedDevice[];
};

export type TwoFactorRecoveryResponse = Tokens & {
  success: true;
  remaining_recovery_codes: number;
  /** On a PKCE app; `TwoFactorService` redeems it, so its callers never see one. */
  code?: string;
};

export type TwoFactorDisableResponse = {
  success: true;
};

export type TwoFactorRegenerateResponse = {
  success: true;
  recovery_codes: string[];
};

// ============================================
// Two-Factor Magic Link Setup Types
// ============================================

/**
 * Two-Factor magic link error codes
 */
export type TwoFactorSetupMagicLinkErrorCode =
  | 'INVALID_TOKEN'
  | 'EXPIRED_TOKEN'
  | 'REVOKED_TOKEN'
  | 'ALREADY_USED'
  | 'RATE_LIMITED'
  | 'SERVER_ERROR';

/**
 * Two-Factor magic link error details
 */
export type TwoFactorSetupMagicLinkError = {
  code: TwoFactorSetupMagicLinkErrorCode;
  message: string;
  retryAfter?: number; // Seconds until retry allowed (for RATE_LIMITED)
};

/**
 * Response from magic link validation endpoint
 * Backend returns scoped session token for 2FA setup operations
 */
export type TwoFactorSetupMagicLinkValidationResponse = {
  success: boolean;
  sessionToken?: string; // JWT with scope "2fa_setup"
  userId?: string; // Target user ID
  expiresIn?: number; // Session expiration in seconds (3600 = 1 hour)
  appId?: string | null; // Optional associated app ID
  error?: TwoFactorSetupMagicLinkError;
};

/**
 * Internal session state for magic link 2FA setup
 * Stored in memory only, not persisted across page reloads
 */
export type TwoFactorSetupMagicLinkSession = {
  sessionToken: string;
  userId: string;
  appId?: string | null;
  scope: '2fa_setup'; // Immutable scope
  timestamp: number;
  expiresAt: number;
};

// ============================================
// Two-Factor v2 Multi-Method Types
// ============================================

/**
 * Two-Factor method types
 */
export type TwoFactorMethod = 'totp' | 'email_otp' | 'sms_otp' | 'passkey' | 'push_fcm' | 'push_webpush' | 'recovery_codes';

/**
 * Challenge Request for v2 2FA flow
 */
export interface TwoFactorChallengeRequest {
  first_factor_method?: string;
  trust_device?: boolean;
}

/**
 * Challenge Response from v2 2FA flow
 */
export interface TwoFactorChallengeResponse {
  challenge_id: string;
  method: TwoFactorMethod;
  alternative_methods: TwoFactorMethod[];
  expires_at: string;
  code_sent_to?: string; // Masked email/phone for OTP
  webauthn_options?: unknown; // For passkey
}

/**
 * Verify Request for v2 2FA flow
 */
export interface TwoFactorVerifyRequestV2 {
  challenge_id: string;
  method: TwoFactorMethod;
  response: string; // OTP code or WebAuthn response
  trust_device?: boolean;
}

/**
 * Verify Response from v2 2FA flow
 */
export interface TwoFactorVerifyResponseV2 {
  success: boolean;
  access_token?: string;
  refresh_token?: string;
  /** On a PKCE app; `TwoFactorService` redeems it, so its callers never see one. */
  code?: string;
  device_trusted?: boolean;
}

/**
 * Registered Two-Factor Method
 */
export interface RegisteredTwoFactorMethod {
  id: string;
  method: TwoFactorMethod;
  name: string;
  created_at: string;
  last_used_at?: string;
}

/**
 * Alternative Method Request
 */
export interface TwoFactorAlternativeRequest {
  challenge_id: string;
  method: TwoFactorMethod;
}

// ============================================
// CLI Authentication Types
// ============================================

export interface CLIAuthStatusResponse {
  status: 'pending' | 'completed' | 'expired' | 'failed';
  expires_at?: string;
  challenge?: Record<string, unknown>; // WebAuthn challenge - raw PublicKeyCredentialRequestOptions
  access_token?: string;
  refresh_token?: string;
  user_id?: string;
  expires_in?: number;
  error?: string;
}

export interface CLIAuthCompleteRequest {
  session_id: string;
  access_token: string;
  refresh_token: string;
  user_id: string;
  expires_in: number;
}
