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
export { M2MError, M2MNetworkError, M2MTokenParseError, M2MConfigError } from './errors';

// Types
export type {
  M2MClientConfig,
  M2MTokenRequestOptions,
  M2MTokenRequestInfo,
  M2MTokenResponse,
  M2MErrorResponse,
  M2MTokenClaims,
  M2MErrorCode,
  M2MTokenCache,
  RetryStrategy,
  M2MRateLimitInfo,
} from './types';

// Constants
export { M2MErrorCodes, M2M_DEFAULTS } from './types';
