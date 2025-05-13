import { RawUserMembership, UserMembership } from '../token-service/membership';

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

export enum TokenType {
  id_token = 'id_token',
  access_token = 'access',
  refresh_token = 'refresh',
  invite_token = 'invite',
  reset_token = 'reset',
  web_cookie = 'web-cookie',
  management = 'management',
  signin = 'signin',
  actor = 'actor',
}
