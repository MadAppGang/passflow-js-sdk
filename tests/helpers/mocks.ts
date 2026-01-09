import { type Mock, vi } from 'vitest';
import type { PassflowAuthorizationResponse, PassflowLogoutResponse, PassflowSuccessResponse } from '../../lib/api';

/**
 * Mock factory for AuthAPI
 */
export interface MockAuthApi {
  signIn: Mock;
  signUp: Mock;
  passwordlessSignIn: Mock;
  passwordlessSignInComplete: Mock;
  logOut: Mock;
  refreshToken: Mock;
  sendPasswordResetEmail: Mock;
  resetPassword: Mock;
  passkeyRegisterStart: Mock;
  passkeyRegisterComplete: Mock;
  passkeyAuthenticateStart: Mock;
  passkeyAuthenticateComplete: Mock;
}

export const createMockAuthApi = (overrides?: Partial<MockAuthApi>): MockAuthApi => ({
  signIn: vi.fn(),
  signUp: vi.fn(),
  passwordlessSignIn: vi.fn(),
  passwordlessSignInComplete: vi.fn(),
  logOut: vi.fn(),
  refreshToken: vi.fn(),
  sendPasswordResetEmail: vi.fn(),
  resetPassword: vi.fn(),
  passkeyRegisterStart: vi.fn(),
  passkeyRegisterComplete: vi.fn(),
  passkeyAuthenticateStart: vi.fn(),
  passkeyAuthenticateComplete: vi.fn(),
  ...overrides,
});

/**
 * Mock factory for DeviceService
 */
export interface MockDeviceService {
  getDeviceId: Mock;
}

export const createMockDeviceService = (deviceId = 'mock-device-id'): MockDeviceService => ({
  getDeviceId: vi.fn().mockReturnValue(deviceId),
});

/**
 * Mock factory for StorageManager
 */
export interface MockStorageManager {
  saveTokens: Mock;
  getTokens: Mock;
  getToken: Mock;
  deleteTokens: Mock;
  getDeviceId: Mock;
}

export const createMockStorageManager = (): MockStorageManager => ({
  saveTokens: vi.fn(),
  getTokens: vi.fn(),
  getToken: vi.fn(),
  deleteTokens: vi.fn(),
  getDeviceId: vi.fn().mockReturnValue('mock-device-id'),
});

/**
 * Mock factory for PassflowStore (subscribe store)
 */
export interface MockPassflowStore {
  notify: Mock;
  subscribe: Mock;
  unsubscribe: Mock;
}

export const createMockPassflowStore = (): MockPassflowStore => ({
  notify: vi.fn(),
  subscribe: vi.fn(),
  unsubscribe: vi.fn(),
});

/**
 * Mock factory for TokenCacheService
 */
export interface MockTokenCacheService {
  setTokensCache: Mock;
  getTokens: Mock;
  getParsedTokens: Mock;
  isExpired: Mock;
  getTokensWithRefresh: Mock;
  initialize: Mock;
  startTokenCheck: Mock;
  stopTokenCheck: Mock;
  destroy: Mock;
  refreshTokensCache: Mock;
  isRefreshing: boolean;
  tokenExpiredFlag: boolean;
}

export const createMockTokenCacheService = (overrides?: Partial<MockTokenCacheService>): MockTokenCacheService => ({
  setTokensCache: vi.fn(),
  getTokens: vi.fn(),
  getParsedTokens: vi.fn(),
  isExpired: vi.fn().mockReturnValue(false),
  getTokensWithRefresh: vi.fn(),
  initialize: vi.fn(),
  startTokenCheck: vi.fn(),
  stopTokenCheck: vi.fn(),
  destroy: vi.fn(),
  refreshTokensCache: vi.fn(),
  isRefreshing: false,
  tokenExpiredFlag: false,
  ...overrides,
});

/**
 * Mock factory for TenantAPI
 */
export interface MockTenantApi {
  createTenant: Mock;
  getTenantDetails: Mock;
  updateTenant: Mock;
  deleteTenant: Mock;
  joinInvitation: Mock;
  createGroup: Mock;
  createRoleForTenant: Mock;
  getUserTenantMembership: Mock;
}

export const createMockTenantApi = (): MockTenantApi => ({
  createTenant: vi.fn(),
  getTenantDetails: vi.fn(),
  updateTenant: vi.fn(),
  deleteTenant: vi.fn(),
  joinInvitation: vi.fn(),
  createGroup: vi.fn(),
  createRoleForTenant: vi.fn(),
  getUserTenantMembership: vi.fn(),
});

/**
 * Mock factory for UserAPI
 */
export interface MockUserApi {
  getUserPasskeys: Mock;
  renameUserPasskey: Mock;
  deleteUserPasskey: Mock;
  addUserPasskey: Mock;
}

export const createMockUserApi = (): MockUserApi => ({
  getUserPasskeys: vi.fn(),
  renameUserPasskey: vi.fn(),
  deleteUserPasskey: vi.fn(),
  addUserPasskey: vi.fn(),
});

/**
 * Mock factory for InvitationAPI
 */
export interface MockInvitationApi {
  requestInviteLink: Mock;
  getInvitations: Mock;
  deleteInvitation: Mock;
  resendInvitation: Mock;
  getInvitationLink: Mock;
}

export const createMockInvitationApi = (): MockInvitationApi => ({
  requestInviteLink: vi.fn(),
  getInvitations: vi.fn(),
  deleteInvitation: vi.fn(),
  resendInvitation: vi.fn(),
  getInvitationLink: vi.fn(),
});

/**
 * Mock factory for TwoFactorApiClient
 */
export interface MockTwoFactorApi {
  getStatus: Mock;
  beginSetup: Mock;
  confirmSetup: Mock;
  verify: Mock;
  useRecoveryCode: Mock;
  disable: Mock;
  regenerateRecoveryCodes: Mock;
}

export const createMockTwoFactorApi = (): MockTwoFactorApi => ({
  getStatus: vi.fn(),
  beginSetup: vi.fn(),
  confirmSetup: vi.fn(),
  verify: vi.fn(),
  useRecoveryCode: vi.fn(),
  disable: vi.fn(),
  regenerateRecoveryCodes: vi.fn(),
});

/**
 * Mock factory for AuthService
 */
export interface MockAuthService {
  signIn: Mock;
  signUp: Mock;
  passwordlessSignIn: Mock;
  passwordlessSignInComplete: Mock;
  logOut: Mock;
  getTokens: Mock;
  refreshToken: Mock;
  passkeyRegister: Mock;
  passkeyAuthenticate: Mock;
  sendPasswordResetEmail: Mock;
  resetPassword: Mock;
  federatedAuthWithPopup: Mock;
  federatedAuthWithRedirect: Mock;
}

export const createMockAuthService = (): MockAuthService => ({
  signIn: vi.fn(),
  signUp: vi.fn(),
  passwordlessSignIn: vi.fn(),
  passwordlessSignInComplete: vi.fn(),
  logOut: vi.fn(),
  getTokens: vi.fn(),
  refreshToken: vi.fn(),
  passkeyRegister: vi.fn(),
  passkeyAuthenticate: vi.fn(),
  sendPasswordResetEmail: vi.fn(),
  resetPassword: vi.fn(),
  federatedAuthWithPopup: vi.fn(),
  federatedAuthWithRedirect: vi.fn(),
});

/**
 * Mock factory for TwoFactorService
 */
export interface MockTwoFactorService {
  getTwoFactorStatus: Mock;
  beginTwoFactorSetup: Mock;
  confirmTwoFactorSetup: Mock;
  verifyTwoFactor: Mock;
  useTwoFactorRecoveryCode: Mock;
  disableTwoFactor: Mock;
  regenerateTwoFactorRecoveryCodes: Mock;
  isTwoFactorVerificationRequired: Mock;
  clearPartialAuthState: Mock;
}

export const createMockTwoFactorService = (): MockTwoFactorService => ({
  getTwoFactorStatus: vi.fn(),
  beginTwoFactorSetup: vi.fn(),
  confirmTwoFactorSetup: vi.fn(),
  verifyTwoFactor: vi.fn(),
  useTwoFactorRecoveryCode: vi.fn(),
  disableTwoFactor: vi.fn(),
  regenerateTwoFactorRecoveryCodes: vi.fn(),
  isTwoFactorVerificationRequired: vi.fn().mockReturnValue(false),
  clearPartialAuthState: vi.fn(),
});
