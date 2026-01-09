/**
 * M2M (Machine-to-Machine) Authentication Types
 *
 * OAuth 2.0 Client Credentials Grant implementation for server-to-server
 * authentication without user involvement.
 */

/**
 * M2M Client configuration options
 */
export type M2MClientConfig = {
  /** Passflow server URL */
  url: string;

  /** M2M application client ID */
  clientId: string;

  /** M2M application client secret */
  clientSecret: string;

  /** Scopes to request (default: []) */
  scopes?: string[];

  /** Target audiences for the token */
  audience?: string[];

  /** Automatically refresh tokens before expiry (default: false) */
  autoRefresh?: boolean;

  /** Seconds before expiry to trigger refresh (default: 30) */
  refreshThreshold?: number;

  /** Request timeout in milliseconds (default: 10000) */
  timeout?: number;

  /** Number of retry attempts on failure (default: 3) */
  retries?: number;

  /** Delay between retries in milliseconds (default: 1000) */
  retryDelay?: number;

  /** Custom retry strategy */
  retryStrategy?: RetryStrategy;

  /** Custom token cache implementation */
  cache?: M2MTokenCache;

  /** Callback for token requests (for logging/metrics) */
  onTokenRequest?: (request: M2MTokenRequestInfo) => void;

  /** Callback for token responses (for logging/metrics) */
  onTokenResponse?: (response: M2MTokenResponse) => void;

  /** Callback for errors (for logging/metrics) */
  onError?: (error: M2MErrorResponse) => void;
};

/**
 * Token request options (can override defaults per-request)
 */
export type M2MTokenRequestOptions = {
  /** Override default scopes for this request */
  scopes?: string[];

  /** Override default audience for this request */
  audience?: string[];

  /** Force a new token request, ignoring cache */
  forceRefresh?: boolean;
};

/**
 * Token request info (for logging callbacks)
 */
export type M2MTokenRequestInfo = {
  /** Client ID being used */
  clientId: string;

  /** Scopes being requested */
  scopes: string[];

  /** Audiences being requested */
  audience: string[];

  /** Request timestamp */
  timestamp: string;
};

/**
 * OAuth 2.0 token response from the authorization server
 */
export type M2MTokenResponse = {
  /** The access token (JWT) */
  access_token: string;

  /** Token type (always "Bearer") */
  token_type: 'Bearer';

  /** Token lifetime in seconds */
  expires_in: number;

  /** Granted scopes (space-separated string) */
  scope?: string;

  /** Timestamp when token was issued (added by client) */
  issued_at?: number;
};

/**
 * OAuth 2.0 error response from the authorization server
 */
export type M2MErrorResponse = {
  /** OAuth 2.0 error code */
  error: M2MErrorCode;

  /** Human-readable error description */
  error_description?: string;

  /** URI with more information about the error */
  error_uri?: string;
};

/**
 * Parsed M2M JWT token claims
 */
export type M2MTokenClaims = {
  /** Issuer (Passflow server URL) */
  iss: string;

  /** Subject (client_id) */
  sub: string;

  /** Audience (target APIs) */
  aud: string | string[];

  /** Issued at timestamp (Unix epoch seconds) */
  iat: number;

  /** Expiration timestamp (Unix epoch seconds) */
  exp: number;

  /** JWT ID (unique token identifier) */
  jti?: string;

  /** Token type ("m2m") */
  type: 'm2m';

  /** Client ID */
  client_id: string;

  /** Tenant ID (for tenant-scoped M2M apps) */
  tenant_id?: string;

  /** Granted scopes */
  scopes: string[];
};

/**
 * M2M error codes (OAuth 2.0 compliant)
 */
export type M2MErrorCode =
  | 'invalid_request'
  | 'invalid_client'
  | 'invalid_grant'
  | 'invalid_scope'
  | 'unauthorized_client'
  | 'unsupported_grant_type'
  | 'rate_limit_exceeded'
  | 'server_error'
  | 'temporarily_unavailable';

/**
 * M2M error code enum for convenience
 */
export const M2MErrorCodes = {
  InvalidRequest: 'invalid_request' as const,
  InvalidClient: 'invalid_client' as const,
  InvalidGrant: 'invalid_grant' as const,
  InvalidScope: 'invalid_scope' as const,
  UnauthorizedClient: 'unauthorized_client' as const,
  UnsupportedGrantType: 'unsupported_grant_type' as const,
  RateLimitExceeded: 'rate_limit_exceeded' as const,
  ServerError: 'server_error' as const,
  TemporarilyUnavailable: 'temporarily_unavailable' as const,
};

/**
 * Custom token cache interface for external cache implementations
 */
export interface M2MTokenCache {
  /**
   * Get cached token by key
   * @param key Cache key (typically clientId)
   * @returns Cached token or null if not found/expired
   */
  get(key: string): Promise<M2MTokenResponse | null>;

  /**
   * Cache a token with TTL
   * @param key Cache key (typically clientId)
   * @param token Token to cache
   * @param ttl Time-to-live in seconds
   */
  set(key: string, token: M2MTokenResponse, ttl: number): Promise<void>;

  /**
   * Delete cached token
   * @param key Cache key (typically clientId)
   */
  delete(key: string): Promise<void>;
}

/**
 * Custom retry strategy interface
 */
export interface RetryStrategy {
  /**
   * Determine if the request should be retried
   * @param error The error that occurred
   * @param attempt Current attempt number (1-based)
   * @returns true if request should be retried
   */
  shouldRetry(error: { code: M2MErrorCode; status?: number }, attempt: number): boolean;

  /**
   * Get delay before next retry
   * @param attempt Current attempt number (1-based)
   * @returns Delay in milliseconds
   */
  getDelay(attempt: number): number;
}

/**
 * Internal token request payload sent to the authorization server
 */
export type M2MTokenRequestPayload = {
  grant_type: 'client_credentials';
  client_id: string;
  client_secret: string;
  scope?: string;
  audience?: string;
};

/**
 * Rate limit information from response headers
 */
export type M2MRateLimitInfo = {
  /** Maximum requests allowed in the window */
  limit: number;

  /** Remaining requests in the current window */
  remaining: number;

  /** Unix timestamp when the window resets */
  reset: number;
};

/**
 * Default configuration values
 */
export const M2M_DEFAULTS = {
  /** Default token endpoint path */
  TOKEN_ENDPOINT: '/oauth2/token',

  /** Default request timeout in milliseconds */
  TIMEOUT: 10000,

  /** Default number of retry attempts */
  RETRIES: 3,

  /** Default delay between retries in milliseconds */
  RETRY_DELAY: 1000,

  /** Default refresh threshold in seconds */
  REFRESH_THRESHOLD: 30,

  /** Content-Type for token requests */
  CONTENT_TYPE: 'application/x-www-form-urlencoded',
} as const;
