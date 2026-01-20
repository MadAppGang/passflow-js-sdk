import type { PassflowAuthorizationResponse, PassflowLogoutResponse, PassflowSuccessResponse } from '../../lib/api';
import type { Token } from '../../lib/token';
import type { ParsedTokens, Tokens } from '../../lib/types';

/**
 * JWT Token Parts
 * These are base64url encoded, not real JWTs but properly formatted for testing
 */
const JWT_HEADER = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9';

// Create a valid-looking JWT payload (exp in year 2099)
const createJwtPayload = (claims: Record<string, unknown>) => {
  const payload = btoa(JSON.stringify(claims)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
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
 * Valid JWT Tokens
 */
export const VALID_ACCESS_TOKEN = `${JWT_HEADER}.${createJwtPayload({
  sub: 'user-123',
  aud: ['test-app'],
  exp: FUTURE_EXP,
  iat: NOW_IAT,
  iss: 'test-issuer',
  jti: 'access-token-123',
  type: 'access',
})}.${SIGNATURE}`;

export const VALID_REFRESH_TOKEN = `${JWT_HEADER}.${createJwtPayload({
  sub: 'user-123',
  aud: ['test-app'],
  exp: FUTURE_EXP,
  iat: NOW_IAT,
  iss: 'test-issuer',
  jti: 'refresh-token-123',
  type: 'refresh',
})}.${SIGNATURE}`;

export const VALID_ID_TOKEN = `${JWT_HEADER}.${createJwtPayload({
  sub: 'user-123',
  aud: ['test-app'],
  exp: FUTURE_EXP,
  iat: NOW_IAT,
  iss: 'test-issuer',
  jti: 'id-token-123',
  type: 'id',
  email: 'test@example.com',
  name: 'Test User',
})}.${SIGNATURE}`;

/**
 * Expired JWT Tokens
 */
export const EXPIRED_ACCESS_TOKEN = `${JWT_HEADER}.${createJwtPayload({
  sub: 'user-123',
  aud: ['test-app'],
  exp: PAST_EXP,
  iat: PAST_EXP - 3600,
  iss: 'test-issuer',
  jti: 'expired-access-123',
  type: 'access',
})}.${SIGNATURE}`;

export const EXPIRED_REFRESH_TOKEN = `${JWT_HEADER}.${createJwtPayload({
  sub: 'user-123',
  aud: ['test-app'],
  exp: PAST_EXP,
  iat: PAST_EXP - 3600,
  iss: 'test-issuer',
  jti: 'expired-refresh-123',
  type: 'refresh',
})}.${SIGNATURE}`;

/**
 * Invalid Tokens
 */
export const INVALID_JWT_FORMAT = 'not.a.valid.jwt.token.with.extra.parts';
export const MALFORMED_TOKEN = 'eyJhbGci.incomplete';
export const EMPTY_TOKEN = '';
export const NON_JWT_STRING = 'this-is-not-a-jwt';

/**
 * Token Objects
 */
export const VALID_TOKENS: Tokens = {
  access_token: VALID_ACCESS_TOKEN,
  refresh_token: VALID_REFRESH_TOKEN,
  id_token: VALID_ID_TOKEN,
  scopes: ['id', 'offline', 'email', 'openid'],
};

export const TOKENS_WITHOUT_REFRESH: Tokens = {
  access_token: VALID_ACCESS_TOKEN,
  id_token: VALID_ID_TOKEN,
  scopes: ['id', 'email'],
};

export const TOKENS_ONLY_ACCESS: Tokens = {
  access_token: VALID_ACCESS_TOKEN,
  scopes: ['id'],
};

export const EXPIRED_TOKENS: Tokens = {
  access_token: EXPIRED_ACCESS_TOKEN,
  refresh_token: VALID_REFRESH_TOKEN,
  id_token: VALID_ID_TOKEN,
  scopes: ['id', 'offline', 'email'],
};

export const FULLY_EXPIRED_TOKENS: Tokens = {
  access_token: EXPIRED_ACCESS_TOKEN,
  refresh_token: EXPIRED_REFRESH_TOKEN,
  scopes: ['id', 'offline'],
};

/**
 * Cookie Mode Tokens (only ID token available, access/refresh in HttpOnly cookies)
 */
export const COOKIE_MODE_TOKENS: Tokens = {
  id_token: VALID_ID_TOKEN,
  scopes: ['id', 'email', 'openid'],
};

/**
 * Parsed Token Objects
 */
export const VALID_PARSED_ACCESS_TOKEN: Token = {
  sub: 'user-123',
  aud: ['test-app'],
  exp: FUTURE_EXP,
  iat: NOW_IAT,
  iss: 'test-issuer',
  jti: 'access-token-123',
  type: 'access',
};

export const VALID_PARSED_REFRESH_TOKEN: Token = {
  sub: 'user-123',
  aud: ['test-app'],
  exp: FUTURE_EXP,
  iat: NOW_IAT,
  iss: 'test-issuer',
  jti: 'refresh-token-123',
  type: 'refresh',
};

export const VALID_PARSED_ID_TOKEN: Token = {
  sub: 'user-123',
  aud: ['test-app'],
  exp: FUTURE_EXP,
  iat: NOW_IAT,
  iss: 'test-issuer',
  jti: 'id-token-123',
  type: 'id',
  email: 'test@example.com',
};

export const VALID_PARSED_TOKENS: ParsedTokens = {
  access_token: VALID_PARSED_ACCESS_TOKEN,
  refresh_token: VALID_PARSED_REFRESH_TOKEN,
  id_token: VALID_PARSED_ID_TOKEN,
  scopes: ['id', 'offline', 'email', 'openid'],
};

/**
 * API Response Fixtures
 */
export const AUTH_RESPONSE: PassflowAuthorizationResponse = {
  access_token: VALID_ACCESS_TOKEN,
  refresh_token: VALID_REFRESH_TOKEN,
  id_token: VALID_ID_TOKEN,
  scopes: ['id', 'offline', 'email', 'openid'],
};

export const AUTH_RESPONSE_NO_REFRESH: PassflowAuthorizationResponse = {
  access_token: VALID_ACCESS_TOKEN,
  id_token: VALID_ID_TOKEN,
  scopes: ['id', 'email'],
};

export const LOGOUT_RESPONSE: PassflowLogoutResponse = {
  status: 'ok',
};

export const SUCCESS_RESPONSE: PassflowSuccessResponse = {
  result: 'ok',
};

/**
 * 2FA Fixtures
 */
export const TWO_FACTOR_STATUS_ENABLED = {
  enabled: true,
  method: 'totp' as const,
  recovery_codes_remaining: 5,
};

export const TWO_FACTOR_STATUS_DISABLED = {
  enabled: false,
};

export const TWO_FACTOR_SETUP_DATA = {
  secret: 'JBSWY3DPEHPK3PXP',
  qr_code: 'iVBORw0KGgo...', // Base64 QR code
  recovery_codes: ['ABCD-1234', 'EFGH-5678', 'IJKL-9012', 'MNOP-3456', 'QRST-7890'],
};

export const TWO_FACTOR_REQUIRED_RESPONSE = {
  challenge_id: 'challenge-123',
  email: 'test@example.com',
  two_factor_required: true,
};

export const TWO_FACTOR_VERIFY_SUCCESS = {
  ...AUTH_RESPONSE,
  recovery_codes_remaining: 5,
};

/**
 * User Fixtures
 */
export const TEST_USER = {
  id: 'user-123',
  email: 'test@example.com',
  name: 'Test User',
  phone: '+12345678901',
};

export const TEST_CREDENTIALS = {
  email: 'test@example.com',
  password: 'Password123!',
};

/**
 * Config Fixtures
 */
export const TEST_CONFIG = {
  url: 'https://api.passflow.cloud',
  appId: 'test-app-id',
  scopes: ['id', 'offline', 'email', 'openid'],
};

export const MINIMAL_CONFIG = {
  url: 'https://api.passflow.cloud',
  appId: 'test-app-id',
};

/**
 * Device Fixtures
 */
export const TEST_DEVICE_ID = 'device-123-abc-456';

/**
 * Tenant Fixtures
 */
export const TEST_TENANT = {
  id: 'tenant-123',
  name: 'Test Tenant',
  slug: 'test-tenant',
};

/**
 * Error Fixtures
 */
export const NETWORK_ERROR = new Error('Network error');
export const AUTH_ERROR = {
  code: 401,
  message: 'Unauthorized',
  details: { reason: 'Invalid credentials' },
};

export const PASSFLOW_ERROR = {
  code: 'invalid_credentials',
  message: 'The email or password is incorrect',
  status: 401,
};
