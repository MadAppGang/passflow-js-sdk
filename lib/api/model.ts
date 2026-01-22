import type {
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  RegistrationResponseJSON,
} from '@simplewebauthn/types';
import type { AxiosRequestConfig } from 'axios';

import type { Tokens } from '../types';

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
  signInWithProvider = '/auth/federated/start/',
  passwordless = '/auth/passwordless/start',
  passwordlessComplete = '/auth/passwordless/complete',
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
  // v2 2FA endpoints
  TwoFactorMethodsAvailable = '/v2/user/2fa/methods/available',
  TwoFactorMethodsRegistered = '/v2/user/2fa/methods',
  TwoFactorMethodSetupBegin = '/v2/user/2fa/methods/:method/setup/begin',
  TwoFactorMethodSetupConfirm = '/v2/user/2fa/methods/:method/setup/confirm',
  TwoFactorMethodRemove = '/v2/user/2fa/methods/:id',
  TwoFactorChallenge = '/v2/auth/2fa/challenge',
  TwoFactorVerifyV2 = '/v2/auth/2fa/verify',
  TwoFactorAlternative = '/v2/auth/2fa/alternative',
  TwoFactorTrustedDevices = '/v2/user/2fa/trusted-devices',
  TwoFactorTrustedDeviceRevoke = '/v2/user/2fa/trusted-devices/:id',
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
  keyStoragePrefix?: string;
  /**
   * Token exchange configuration for secure server-side token handling.
   * When enabled, authorization code is sent to your server which exchanges it
   * for tokens and stores them in httpOnly cookies. Tokens never touch the browser.
   */
  tokenExchange?: TokenExchangeConfig;
};

export type PassflowAuthorizationResponse = Tokens & {
  requires_2fa?: boolean;
  challenge_id?: string;
  tfa_token?: string;
  token_delivery?: 'json_body' | 'cookie' | 'mobile';
  cookies?: string[];
  csrf_token?: string;
};

export type PassflowValidationResponse = Tokens & {
  redirect_url: string;
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

export class PassflowError extends Error {
  id: string;
  message: string;
  status: number;
  location: string;
  time: string;

  constructor(error: PassflowResponseError['error']) {
    super();
    this.id = error?.id ?? 'unknown';
    this.message = error?.message ?? error ?? 'Something went wrong';
    this.status = error?.status ?? 500;
    this.location = error?.location ?? 'unknown';
    this.time = error?.time ?? new Date().toISOString();
  }
}

export type PassflowSignInPayload = {
  password: string;
  scopes?: string[];
  invite_token?: string;
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
};

export type PassflowPasswordlessSignInPayload = {
  challenge_type: InternalStrategyChallenge;
  redirect_url: string;
  scopes?: string[];
  create_tenant?: boolean;
  invite_token?: string;
} & ({ email: string; phone?: never } | { phone: string; email?: never });

export type PassflowPasswordlessResponse = {
  challenge_id: string;
  expires_at: Date | string;
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
  debug_otp_code_for_registration: string;
  defaults: DefaultAppSettings;
  login_app_theme: LoginWebAppTheme;
  login_app_settings?: unknown;
  token_delivery_method?: TokenDeliveryMethod;
};

export type DefaultAppSettings = {
  app_id: string;
  redirect: string;
  scopes: string[];
  create_tenant_for_new_user: boolean;
};

export enum OS {
  web = 'web',
}

export type PassflowPasskeyRegisterStartPayload = {
  passkey_display_name?: string;
  passkey_username?: string;
  invite_token?: string;

  scopes: string[];
  create_tenant?: boolean;

  relying_party_id: string;
  redirect_url: string;
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
};

export type TwoFactorRecoveryRequest = {
  recovery_code: string;
  tfa_token: string;
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
  qr_code: string;
  totp_digits?: 6 | 8; // Optional for backward compatibility, defaults to 6 if not provided
};

export type TwoFactorConfirmResponse = {
  success: true;
  recovery_codes: string[];
};

export type TwoFactorVerifyResponse = Tokens & {
  success: true;
};

export type TwoFactorRecoveryResponse = Tokens & {
  success: true;
  remaining_recovery_codes: number;
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
