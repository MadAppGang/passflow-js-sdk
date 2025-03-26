import {
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  RegistrationResponseJSON,
} from '@simplewebauthn/types';
import { AxiosRequestConfig } from 'axios';

import { Tokens } from '../types';

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
}

export enum PassflowAdminEndpointPaths {
  passkeyRegisterStart = '/admin/auth/passkey/register/start',
  passkeyRegisterComplete = '/admin/auth/passkey/register/complete',
  passkeyAuthenticateStart = '/admin/auth/passkey/authenticate/start',
  passkeyAuthenticateComplete = '/admin/auth/passkey/authenticate/complete',
  passkeyValidate = '/admin/auth/validate',
  logout = '/admin/auth/logout',
}

export type PassflowConfig = {
  url?: string;
  appId?: string;
  scopes?: string[];
  createTenantForNewUser?: boolean;
  parseQueryParams?: boolean;
  keyStoragePrefix?: string;
};

export type PassflowAuthorizationResponse = Tokens;

export type PassflowValidationResponse = Tokens & {
  redirect_url: string;
};

export type PassflowSuccessResponse = {
  result: 'ok';
};

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
  email?: string;
  phone?: string;
  username?: string;
} & ({ email: string } | { phone: string } | { username: string });

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
  invite?: string;
};

export type PassflowPasswordlessSignInPayload = {
  challenge_type: InternalStrategyChallenge;
  redirect_url: string;
  scopes?: string[];
  create_tenant?: boolean;
  email?: string;
  phone?: string;
} & ({ email: string } | { phone: string });

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
  | { type: Exclude<AuthTypeStrategy, 'internal' | 'fim'>; strategy: OtherStrategy };

export type AppType = 'web' | 'android' | 'ios' | 'desktop' | 'other';

export type AppSettings = {
  id: string;
  secret: string;
  active: boolean;
  name: string;
  description: string;
  offline: boolean;
  type: AppType;
  redirect_urls: string[];
  origins: string[];
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

  login_app_settings?: unknown;
};

export enum OS {
  web = 'web',
}

export type PassflowPasskeyRegisterStartPayload = {
  passkey_display_name?: string;
  passkey_username?: string;
  invite?: string;

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
};

export type PassflowPasskeyAuthenticateStartExtendedPayload = PassflowPasskeyAuthenticateStartPayload & {
  device: string;
  os: OS;
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
  email?: string;
  phone?: string;
  username?: string;
  reset_page_url?: string;
  redirect_url?: string;
} & ({ email: string } | { phone: string } | { username: string });

export type PassflowInviteResponse = {
  link: string;
};

export type PassflowInvitePayload = {
  invite: string;
  scopes: string[];
};

export type PassflowTenantResponse = {
  tenant_id: string;
  tenant_name: string;
  // add groups and tenants here
};

export type PassflowCreateTenantPayload = {
  name: string;
};

export type PassflowCreateTokenResponse = PassflowTenantResponse;
