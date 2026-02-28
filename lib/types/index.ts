import { Token } from '../token';
import { SessionState, TokenDeliveryMode } from '../token/delivery-manager';

export type Tokens = {
  access_token?: string;
  id_token?: string;
  refresh_token?: string;
  scopes?: string[];
};

export type ParsedTokens = {
  access_token?: Token;
  id_token?: Token;
  refresh_token?: Token;
  scopes?: string[];
};

export type SessionParams = {
  createSession?: ({ tokens, parsedTokens }: { tokens?: Tokens; parsedTokens?: ParsedTokens }) => Promise<void>;
  expiredSession?: () => Promise<void>;
  doRefresh?: boolean;
};

// Token delivery mode and session state exports
export { TokenDeliveryMode, SessionState };
