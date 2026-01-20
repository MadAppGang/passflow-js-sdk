// Re-export from API
export * from './api';

// Re-export constants
export * from './constants';
// Export Passflow class
export { Passflow } from './passflow';
// Export service interfaces for extensibility
export * from './services';
// Re-export events
export { type ErrorPayload, PassflowEvent, type PassflowEventPayload, type PassflowSubscriber } from './store';
// Re-export token utilities
export {
  type Group,
  type GroupMembership,
  type InvitationToken,
  isTokenExpired,
  parseToken,
  type RawUserMembership,
  type Tenant,
  type TenantMembership,
  type Token,
  TokenType,
  type UserMembership,
} from './token';
// Re-export types
export * from './types';
// Re-export validation utilities
export { isValidEmail, isValidJWTFormat, isValidPhoneNumber, isValidUsername, sanitizeErrorMessage } from './utils/validation';

// Re-export Two-Factor Authentication types (explicitly for clarity)
export type {
  TwoFactorConfirmRequest,
  TwoFactorConfirmResponse,
  TwoFactorDisableRequest,
  TwoFactorDisableResponse,
  TwoFactorErrorCode,
  TwoFactorPolicy,
  TwoFactorRecoveryRequest,
  TwoFactorRecoveryResponse,
  TwoFactorRegenerateRequest,
  TwoFactorRegenerateResponse,
  TwoFactorSetupMagicLinkError,
  TwoFactorSetupMagicLinkErrorCode,
  TwoFactorSetupMagicLinkSession,
  TwoFactorSetupMagicLinkValidationResponse,
  TwoFactorSetupResponse,
  TwoFactorStatusResponse,
  TwoFactorVerifyRequest,
  TwoFactorVerifyResponse,
} from './api/model';

// Re-export Two-Factor Authentication API client and service
export { TwoFactorApiClient } from './api/two-factor';
export { TwoFactorService } from './services/two-factor-service';

// Re-export M2M (Machine-to-Machine) Authentication module
export { M2MClient, M2MError, M2MNetworkError, M2MTokenParseError, M2MConfigError, M2MErrorCodes, M2M_DEFAULTS } from './m2m';
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
} from './m2m';

// Re-export Token Delivery and Session State (explicitly for clarity)
export { TokenDeliveryMode, SessionState } from './types';
