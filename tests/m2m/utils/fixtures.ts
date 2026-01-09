/**
 * Test fixtures for M2M Authentication tests
 */

import type { M2MClientConfig, M2MTokenClaims, M2MTokenResponse } from '../../../lib/m2m';

/**
 * Standard test constants
 */
export const TEST_URL = 'https://api.passflow.cloud';
export const TEST_CLIENT_ID = 'test-m2m-client-id';
export const TEST_CLIENT_SECRET = 'test-m2m-client-secret';
export const TEST_SCOPES = ['api:read', 'api:write'];
export const TEST_AUDIENCE = ['users-api', 'orders-api'];

/**
 * JWT Token Parts
 */
const JWT_HEADER = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9';

// Create a valid-looking JWT payload
const createJwtPayload = (claims: Record<string, unknown>) => {
  const payload = Buffer.from(JSON.stringify(claims)).toString('base64url');
  return payload;
};

const SIGNATURE = 'test_signature_mock';

// Future expiration (year 2099)
const FUTURE_EXP = 4102444800; // 2099-12-31
// Past expiration
const PAST_EXP = 1500000000; // 2017-07-14
// Current time for iat
const NOW_IAT = Math.floor(Date.now() / 1000);

/**
 * Create a valid JWT string with custom claims
 */
export function createValidJWT(claims?: Partial<M2MTokenClaims>): string {
  const defaultClaims: M2MTokenClaims = {
    iss: TEST_URL,
    sub: TEST_CLIENT_ID,
    aud: TEST_AUDIENCE,
    iat: NOW_IAT,
    exp: FUTURE_EXP,
    jti: 'test-jwt-id-123',
    type: 'm2m',
    client_id: TEST_CLIENT_ID,
    scopes: TEST_SCOPES,
    ...claims,
  };

  return `${JWT_HEADER}.${createJwtPayload(defaultClaims)}.${SIGNATURE}`;
}

/**
 * Create a mock M2MTokenResponse
 */
export function createMockToken(overrides?: Partial<M2MTokenResponse>): M2MTokenResponse {
  return {
    access_token: createValidJWT(),
    token_type: 'Bearer',
    expires_in: 3600,
    scope: TEST_SCOPES.join(' '),
    issued_at: NOW_IAT,
    ...overrides,
  };
}

/**
 * Create an expired token
 */
export function createExpiredToken(overrides?: Partial<M2MTokenResponse>): M2MTokenResponse {
  const expiredJwt = `${JWT_HEADER}.${createJwtPayload({
    iss: TEST_URL,
    sub: TEST_CLIENT_ID,
    aud: TEST_AUDIENCE,
    iat: PAST_EXP - 3600,
    exp: PAST_EXP,
    jti: 'expired-jwt-123',
    type: 'm2m',
    client_id: TEST_CLIENT_ID,
    scopes: TEST_SCOPES,
  })}.${SIGNATURE}`;

  return {
    access_token: expiredJwt,
    token_type: 'Bearer',
    expires_in: 3600,
    scope: TEST_SCOPES.join(' '),
    issued_at: PAST_EXP - 3600,
    ...overrides,
  };
}

/**
 * Create a mock M2MClientConfig
 */
export function createMockConfig(overrides?: Partial<M2MClientConfig>): M2MClientConfig {
  return {
    url: TEST_URL,
    clientId: TEST_CLIENT_ID,
    clientSecret: TEST_CLIENT_SECRET,
    scopes: TEST_SCOPES,
    audience: TEST_AUDIENCE,
    ...overrides,
  };
}

/**
 * Valid M2M JWT token (not expired)
 */
export const VALID_M2M_TOKEN = createValidJWT();

/**
 * Expired M2M JWT token
 */
export const EXPIRED_M2M_TOKEN = `${JWT_HEADER}.${createJwtPayload({
  iss: TEST_URL,
  sub: TEST_CLIENT_ID,
  aud: TEST_AUDIENCE,
  iat: PAST_EXP - 3600,
  exp: PAST_EXP,
  jti: 'expired-jwt-123',
  type: 'm2m',
  client_id: TEST_CLIENT_ID,
  scopes: TEST_SCOPES,
})}.${SIGNATURE}`;

/**
 * Invalid JWT formats for testing error handling
 */
export const INVALID_JWT_FORMAT = 'not.a.valid.jwt.token.with.extra.parts';
export const MALFORMED_JWT = 'eyJhbGci.incomplete';
export const EMPTY_JWT = '';
export const NON_JWT_STRING = 'this-is-not-a-jwt';

/**
 * Valid M2M token response
 */
export const VALID_TOKEN_RESPONSE: M2MTokenResponse = {
  access_token: VALID_M2M_TOKEN,
  token_type: 'Bearer',
  expires_in: 3600,
  scope: TEST_SCOPES.join(' '),
  issued_at: NOW_IAT,
};

/**
 * Expired M2M token response
 */
export const EXPIRED_TOKEN_RESPONSE: M2MTokenResponse = {
  access_token: EXPIRED_M2M_TOKEN,
  token_type: 'Bearer',
  expires_in: 3600,
  scope: TEST_SCOPES.join(' '),
  issued_at: PAST_EXP - 3600,
};

/**
 * Token response without scope
 */
export const TOKEN_RESPONSE_NO_SCOPE: M2MTokenResponse = {
  access_token: VALID_M2M_TOKEN,
  token_type: 'Bearer',
  expires_in: 3600,
  issued_at: NOW_IAT,
};

/**
 * Token response with different scopes
 */
export const TOKEN_RESPONSE_CUSTOM_SCOPES: M2MTokenResponse = {
  access_token: createValidJWT({ scopes: ['custom:read', 'custom:write'] }),
  token_type: 'Bearer',
  expires_in: 7200,
  scope: 'custom:read custom:write',
  issued_at: NOW_IAT,
};

/**
 * OAuth 2.0 Error Responses
 */
export const OAUTH_ERROR_INVALID_CLIENT = {
  error: 'invalid_client',
  error_description: 'Client authentication failed',
};

export const OAUTH_ERROR_INVALID_SCOPE = {
  error: 'invalid_scope',
  error_description: 'Requested scope is invalid',
};

export const OAUTH_ERROR_RATE_LIMIT = {
  error: 'rate_limit_exceeded',
  error_description: 'Too many requests',
};

export const OAUTH_ERROR_SERVER_ERROR = {
  error: 'server_error',
  error_description: 'The authorization server encountered an error',
};

export const OAUTH_ERROR_TEMPORARILY_UNAVAILABLE = {
  error: 'temporarily_unavailable',
  error_description: 'The server is temporarily unavailable',
};

/**
 * Parsed M2M token claims
 */
export const VALID_M2M_CLAIMS: M2MTokenClaims = {
  iss: TEST_URL,
  sub: TEST_CLIENT_ID,
  aud: TEST_AUDIENCE,
  iat: NOW_IAT,
  exp: FUTURE_EXP,
  jti: 'test-jwt-id-123',
  type: 'm2m',
  client_id: TEST_CLIENT_ID,
  scopes: TEST_SCOPES,
};

/**
 * Default M2M client config
 */
export const DEFAULT_M2M_CONFIG: M2MClientConfig = {
  url: TEST_URL,
  clientId: TEST_CLIENT_ID,
  clientSecret: TEST_CLIENT_SECRET,
};

/**
 * M2M config with all options
 */
export const FULL_M2M_CONFIG: M2MClientConfig = {
  url: TEST_URL,
  clientId: TEST_CLIENT_ID,
  clientSecret: TEST_CLIENT_SECRET,
  scopes: TEST_SCOPES,
  audience: TEST_AUDIENCE,
  autoRefresh: true,
  refreshThreshold: 60,
  timeout: 5000,
  retries: 5,
  retryDelay: 2000,
};

/**
 * Rate limit headers
 */
export const RATE_LIMIT_HEADERS = {
  'x-ratelimit-limit': '100',
  'x-ratelimit-remaining': '0',
  'x-ratelimit-reset': String(Math.floor(Date.now() / 1000) + 3600),
};
