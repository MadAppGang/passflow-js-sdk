import { RawUserMembership, UserMembership } from './membership';

export type Token = {
  aud: string[];
  exp: number;
  iat: number;
  iss: string;
  jti: string;
  sub: string;
  type: string;
  email?: string;
  phonenumber?: string;
  passflow_tm?: RawUserMembership;
  payload?: unknown;
  membership?: UserMembership;
};

export type InvitationToken = Token & {
  email: string;
  inviter_id: string;
  inviter_name: string;
  redirect_url: string;
  tenant_name: string;
};

/**
 * Token types used in the Passflow SDK.
 *
 * Note: Some enum values intentionally differ from keys for API compatibility.
 * The values match what the Passflow API returns in token payloads.
 *
 * @example
 * // access_token key maps to 'access' value (API response format)
 * TokenType.access_token === 'access' // true
 */
export enum TokenType {
  /** ID token - contains user identity claims */
  id_token = 'id_token',
  /** Access token - for API authorization. Maps to 'access' in API responses */
  access_token = 'access',
  /** Refresh token - for obtaining new access tokens. Maps to 'refresh' in API responses */
  refresh_token = 'refresh',
  /** Invitation token - for accepting user invitations */
  invite_token = 'invite',
  /** Password reset token - for password reset flows */
  reset_token = 'reset',
  /** Web cookie token - for web-based session management */
  web_cookie = 'web-cookie',
  /** Management token - for administrative operations */
  management = 'management',
  /** Sign-in token - for authentication flows */
  signin = 'signin',
  /** Actor token - for impersonation and delegated access */
  actor = 'actor',
}
