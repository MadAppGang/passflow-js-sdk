import {
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  RegistrationResponseJSON,
} from '@simplewebauthn/types';
import { AxiosRequestConfig } from 'axios';

import { ChallengeType, Providers } from '../token-service';
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

export enum AoothEndpointPaths {
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
  addUserPasskey = `${AoothEndpointPaths.userPasskey}/add/start`,
  completeAddUserPasskey = `${AoothEndpointPaths.userPasskey}/add/complete`,
  joinInvitation = '/user/tenant/join',
}

export enum AoothAdminEndpointPaths {
  passkeyRegisterStart = '/admin/auth/passkey/register/start',
  passkeyRegisterComplete = '/admin/auth/passkey/register/complete',
  passkeyAuthenticateStart = '/admin/auth/passkey/authenticate/start',
  passkeyAuthenticateComplete = '/admin/auth/passkey/authenticate/complete',
  passkeyValidate = '/admin/auth/validate',
  loginInsecure = '/admin/auth/insecure_login',
  logout = '/admin/auth/logout',
}

export type AoothConfig = {
  url?: string;
  appId?: string;
  scopes?: string[];
  createTenantForNewUser?: boolean;
};

export type AoothAuthorizationResponse = Tokens;

export type AoothSuccessResponse = {
  result: 'ok';
};

export type AoothResponseError = {
  error: {
    id: string;
    message: string;
    status: number;
    location: string;
    time: string;
  };
};

export class AoothError extends Error {
  id: string;
  message: string;
  status: number;
  location: string;
  time: string;

  constructor(error: AoothResponseError['error']) {
    super();
    this.id = error?.id ?? 'unknown';
    this.message = error?.message ?? error ?? 'Something went wrong';
    this.status = error?.status ?? 500;
    this.location = error?.location ?? 'unknown';
    this.time = error?.time ?? new Date().toISOString();
  }
}

export type AoothSignInPayload = {
  password: string;
  scopes?: string[];
  email?: string;
  phone?: string;
  username?: string;
} & ({ email: string } | { phone: string } | { username: string });

export type AoothSignInExtendedPayload = AoothSignInPayload & {
  device: string;
  os: OS;
};

export type AoothAddressPayload = {
  formatted?: string;
  street_address?: string;
  locality?: string;
  region?: string;
  postal_code?: string;
  country?: string;
};

export type AoothUserPayload = {
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
  addresses?: AoothAddressPayload;
} & ({ email: string } | { phone_number: string });

export type AoothSignUpPayload = {
  user: AoothUserPayload;
  scopes?: string[];
  create_tenant?: boolean;
  anonymous?: boolean;
  invite?: string;
};

export type AoothPasswordlessSignInPayload = {
  scopes?: string[];
  challenge_type: ChallengeType;
  create_tenant?: boolean;
  email?: string;
  phone?: string;
} & ({ email: string } | { phone: string });

export type AoothPasswordlessSignInExtendedPayload = AoothPasswordlessSignInPayload & {
  device: string;
  os: OS;
};

export type AoothPasswordlessSignInCompletePayload = AoothPasswordlessSignInPayload & {
  otp: string;
};

export type FirstFactorFim = {
  fim_type: Providers;
};

export type FirstFactorInternal = {
  identity: string;
  challenge: string;
  transport: string;
};

export type AuthStrategies = {
  strategy: FirstFactorFim | FirstFactorInternal;
  type: string;
};

export type AppSettings = {
  id: string;
  secret: string;
  active: boolean;
  name: string;
  description: string;
  offline: boolean;
  type: string;
  redirect_urls: string[];
  login_app_settings: unknown;
  custom_email_templates: boolean;
  auth_strategies: AuthStrategies[];
  custom_sms_messages: unknown;
  registration_allowed: boolean;
  passwordless_registration_allowed: string | boolean;
  anonymous_registration_allowed: boolean;
  fim_merge_by_email_allowed: boolean;
  debug_otp_code_allowed: boolean;
  debug_otp_code_for_registration: string;
};

export enum OS {
  web = 'web',
}

export type AoothPasskeyRegisterStartPayload = {
  scopes: string[];
  relying_party_id: string;
  create_tenant?: boolean;
  phone?: string;
  email?: string;
  username?: string;
} & ({ email: string } | { phone: string } | { username: string });

export type AoothPasskeyRegisterStartExtendedPayload = AoothPasskeyRegisterStartPayload & {
  device: string;
  os: OS;
};

export type AoothPasskeyStart = {
  challenge_id: string;
  publicKey: PublicKeyCredentialCreationOptionsJSON;
};

export type AoothPasskeyRegisterCompleteMessage = {
  challenge_id: string;
  message: string;
};

export type AoothPasskeyPayload = {
  device: string;
  challenge_id: string;
};

export type AoothPasskeyRegisterPayload = AoothPasskeyPayload & {
  passkey_data: RegistrationResponseJSON;
};

export type AoothPasskeyAuthenticatePayload = AoothPasskeyPayload & {
  passkey_data: AuthenticationResponseJSON;
};

export type AoothPasskeyAuthenticateStartPayload = {
  scopes?: string[];
  relying_party_id: string;
  user_id?: string;
};

export type AoothPasskeyAuthenticateStartExtendedPayload = AoothPasskeyAuthenticateStartPayload & {
  device: string;
  os: OS;
};

export type AoothValidatePayload = {
  otp: string;
  device: string;
  challenge_id: string;
};

export type AoothInsecureLoginPayload = {
  email: string;
  password: string;
};

// SETTINGS
export type AoothPasskeyProviderOption = 'none' | 'required' | 'preferred' | 'discouraged';

export type AoothSettingsAll = {
  password_policy: AoothPasswordPolicySettings;
  passkey_provider: AoothPasskeySettings;
};

export type AoothPasswordPolicySettings = {
  restrict_min_password_length: boolean;
  min_password_length: number;
  reject_compromised: boolean;
  enforce_password_strength: 'none' | 'weak' | 'average' | 'strong';
  require_lowercase: boolean;
  require_uppercase: boolean;
  require_number: boolean;
  require_symbol: boolean;
};

export type AoothPasskeySettings = {
  name: string;
  display_name: string;
  id_field: 'email' | 'phone' | 'username';
  validation: ChallengeType;
  registration?: {
    user_verification: AoothPasskeyProviderOption;
    authenticator_attachment: 'platform' | 'cross-platform' | 'any';
    discoverable_key: AoothPasskeyProviderOption;
    attestation_metadata: AoothPasskeyProviderOption;
    extensions: unknown;
  };
  authentication?: {
    user_verification: AoothPasskeyProviderOption;
    attestation_metadata: AoothPasskeyProviderOption;
    extensions: unknown;
  };
};

type AoothCredentialFlags = {
  user_present: boolean;
  user_verified: boolean;
  backup_eligible: boolean;
  backup_state: boolean;
};

type AoothEnrolmentAuthenticator = {
  aaguid: string;
  sign_count: number;
  clone_warning: boolean;
  attachment: 'platform' | 'cross-platform';
};

export type AoothUserPasskey = {
  id: string;
  user_id: string;
  name: string;
  strategy: FirstFactorInternal;
  challenge_type: ChallengeType;
  strategy_hash: string;
  enrolled_at: Date | string;
  enrollment_challenge_id: string;
  confirmed_at: Date | string;
  last_used: Date | string;
  public_key: string;
  attestation_type: string;
  transport: string[];
  flags: AoothCredentialFlags;
  authenticator: AoothEnrolmentAuthenticator;
  archived: boolean;
  archived_at: Date | string;
  count?: number;
  enrolled_with_app_id?: string;
};

export type AoothSendPasswordResetEmailPayload = {
  email?: string;
  phone?: string;
  username?: string;
} & ({ email: string } | { phone: string } | { username: string });

export type AoothInviteResponse = {
  link: string;
};

export type AoothInvitePayload = {
  invite: string;
  scopes: string[];
};
