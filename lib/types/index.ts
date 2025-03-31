import { PassflowError } from '../api';
import { Token } from '../token-service';

export type Tokens = {
  access_token: string;
  id_token?: string;
  refresh_token?: string;
  scopes?: string[];
};

export type ParsedTokens = {
  access_token: Token;
  id_token?: Token;
  refresh_token?: Token;
  scopes?: string[];
};

export type SessionParams = {
  createSession?: (tokens?: Tokens) => Promise<void>;
  expiredSession?: () => Promise<void>;
  refreshError?: (error: PassflowError) => Promise<void>;
  doRefresh?: boolean;
};
