/**
 * M2M (Machine-to-Machine) Authentication Module
 *
 * OAuth 2.0 Client Credentials Grant implementation for server-to-server
 * authentication without user involvement.
 *
 * @example
 * ```typescript
 * import { M2MClient } from '@passflow/core';
 *
 * const m2m = new M2MClient({
 *   url: 'https://auth.yourapp.com',
 *   clientId: 'your-client-id',
 *   clientSecret: 'your-client-secret',
 *   scopes: ['users:read', 'orders:write'],
 * });
 *
 * const token = await m2m.getToken();
 * ```
 *
 * @packageDocumentation
 */

// Main client
export { M2MClient } from './client';

// Error classes
export { M2MConfigError, M2MError, M2MNetworkError, M2MTokenParseError } from './errors';

// Types
export type {
  M2MClientConfig,
  M2MErrorCode,
  M2MErrorResponse,
  M2MRateLimitInfo,
  M2MTokenCache,
  M2MTokenClaims,
  M2MTokenRequestInfo,
  M2MTokenRequestOptions,
  M2MTokenResponse,
  RetryStrategy,
} from './types';

// Constants
export { M2M_DEFAULTS, M2MErrorCodes } from './types';
