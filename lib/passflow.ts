import {
  AppAPI,
  type AppSettings,
  AuthAPI,
  InvitationAPI,
  type InvitationsPaginatedList,
  type InviteLinkResponse,
  type PassflowAuthorizationResponse,
  type PassflowConfig,
  PassflowError,
  PassflowFederatedAuthPayload,
  type PassflowPasskeyAuthenticateStartPayload,
  type PassflowPasskeyRegisterStartPayload,
  type PassflowPasskeySettings,
  type PassflowPasswordPolicySettings,
  type PassflowPasswordlessResponse,
  type PassflowPasswordlessSignInCompletePayload,
  type PassflowPasswordlessSignInPayload,
  type PassflowSendPasswordResetEmailPayload,
  type PassflowSettingsAll,
  type PassflowSignInPayload,
  type PassflowSignUpPayload,
  type PassflowSuccessResponse,
  type PassflowTenantResponse,
  type PassflowValidationResponse,
  type RequestInviteLinkPayload,
  SettingAPI,
  TenantAPI,
  UserAPI,
} from './api';
import { DEFAULT_SCOPES, PASSFLOW_CLOUD_URL, SDK_VERSION } from './constants';
import { DeviceService } from './device';
import { AuthService, InvitationService, TenantService, TokenCacheService, UserService } from './services';
import { StorageManager } from './storage';
import { type ErrorPayload, PassflowEvent, PassflowStore, type PassflowSubscriber } from './store';
import { type TokenType } from './token';

import type { ParsedTokens, SessionParams, Tokens } from './types';
import { isValidJWTFormat, sanitizeErrorMessage } from './utils/validation';

export class Passflow {
  /**
   * SDK version string.
   * Useful for debugging and reporting version-specific issues.
   * @example
   * ```typescript
   * console.log('Using Passflow SDK version:', Passflow.version);
   * ```
   */
  static readonly version: string = SDK_VERSION;

  // API clients
  private authApi: AuthAPI;
  private appApi: AppAPI;
  private userApi: UserAPI;
  private settingApi: SettingAPI;
  private tenantApi: TenantAPI;
  private invitationApi: InvitationAPI;

  // Configuration
  private scopes: string[];
  private createTenantForNewUser: boolean;
  private doRefreshTokens = false;

  // Services
  private deviceService: DeviceService;
  private storageManager: StorageManager;
  private subscribeStore: PassflowStore;
  private authService: AuthService;
  private userService: UserService;
  private tenantService: TenantService;
  private invitationService: InvitationService;
  private tokenCacheService: TokenCacheService;

  // Public services
  public tenant: TenantService;

  // Session callbacks
  private createSessionCallback?: ({ tokens, parsedTokens }: { tokens?: Tokens; parsedTokens?: ParsedTokens }) => Promise<void>;
  private expiredSessionCallback?: () => Promise<void>;

  // State
  error?: Error;
  origin = window.location.origin;
  url: string;
  appId?: string;

  constructor(config: PassflowConfig) {
    const { url, appId, scopes } = config;
    this.url = url || PASSFLOW_CLOUD_URL;
    this.appId = appId;

    // Initialize single StorageManager instance
    this.storageManager = new StorageManager({
      prefix: config.keyStoragePrefix ?? '',
    });

    // Initialize single DeviceService instance with shared StorageManager
    this.deviceService = new DeviceService(this.storageManager);

    // Initialize API clients with shared instances
    this.authApi = new AuthAPI(config, this.storageManager, this.deviceService);
    this.appApi = new AppAPI(config, this.storageManager, this.deviceService);
    this.userApi = new UserAPI(config, this.storageManager, this.deviceService);
    this.settingApi = new SettingAPI(config, this.storageManager, this.deviceService);
    this.tenantApi = new TenantAPI(config, this.storageManager, this.deviceService);
    this.invitationApi = new InvitationAPI(config, this.storageManager, this.deviceService);

    // Initialize PassflowStore
    this.subscribeStore = new PassflowStore();

    this.tokenCacheService = new TokenCacheService(this.storageManager, this.authApi, this.subscribeStore);

    this.scopes = scopes ?? DEFAULT_SCOPES;
    this.createTenantForNewUser = config.createTenantForNewUser ?? false;

    // Initialize domain services with dependencies
    this.authService = new AuthService(
      this.authApi,
      this.deviceService,
      this.storageManager,
      this.subscribeStore,
      this.tokenCacheService,
      this.scopes,
      this.createTenantForNewUser,
      this.origin,
      this.url,
      {
        createSession: this.createSessionCallback,
        expiredSession: this.expiredSessionCallback,
      },
      this.appId ?? '',
    );

    this.userService = new UserService(this.userApi, this.deviceService);

    this.tenantService = new TenantService(this.tenantApi, this.scopes);
    this.tenant = this.tenantService;

    this.invitationService = new InvitationService(this.invitationApi);

    // Check for tokens in query params if configured
    if (config.parseQueryParams) {
      this.checkAndSetTokens();
    }

    this.setTokensToCacheFromLocalStorage();
  }

  // Session management
  /**
   * Configure session callbacks and check current session status.
   *
   * **WARNING**: Calling this method multiple times will overwrite previously registered callbacks.
   * Only the most recent `createSession` and `expiredSession` callbacks will be active.
   *
   * @param params - Session configuration parameters
   * @param params.createSession - Callback invoked when a valid session exists or is created
   * @param params.expiredSession - Callback invoked when no valid session exists
   * @param params.doRefresh - Whether to automatically refresh expired tokens (default: false)
   * @returns Promise that resolves when session check is complete
   *
   * @example
   * ```typescript
   * await passflow.session({
   *   createSession: async ({ tokens, parsedTokens }) => {
   *     console.log('User is authenticated', parsedTokens?.access_token?.sub);
   *     // Initialize user session in your app
   *   },
   *   expiredSession: async () => {
   *     console.log('User session expired');
   *     // Redirect to login or show login modal
   *   },
   *   doRefresh: true // Automatically refresh tokens if expired
   * });
   * ```
   */
  session: ({ createSession, expiredSession, doRefresh }: SessionParams) => Promise<void> = async ({
    createSession,
    expiredSession,
    doRefresh = false,
  }) => {
    this.createSessionCallback = createSession;
    this.expiredSessionCallback = expiredSession;
    this.doRefreshTokens = doRefresh;

    await this.submitSessionCheck();
  };

  private async submitSessionCheck() {
    let tokens;
    let parsedTokens;
    try {
      tokens = await this.authService.getTokens(this.doRefreshTokens);
      parsedTokens = this.tokenCacheService.getParsedTokens();
    } catch (error) {
      const errorPayload: ErrorPayload = {
        message: error instanceof Error || error instanceof PassflowError ? error.message : 'Session check failed',
        originalError: error,
      };
      this.subscribeStore.notify(PassflowEvent.Error, errorPayload);
      tokens = undefined;
    }

    if (tokens && this.createSessionCallback) {
      await this.createSessionCallback({ tokens, parsedTokens });
    }

    if (!tokens && this.expiredSessionCallback) {
      await this.expiredSessionCallback();
    }
  }

  // Event subscription
  /**
   * Subscribe to Passflow authentication events.
   *
   * @param subscriber - Subscriber function that receives event type and payload
   * @param events - Optional array of specific events to listen for. If omitted, subscribes to all events.
   *
   * @example
   * ```typescript
   * // Subscribe to all events
   * passflow.subscribe((event, payload) => {
   *   console.log('Event:', event, payload);
   * });
   *
   * // Subscribe to specific events only
   * passflow.subscribe(
   *   (event, payload) => {
   *     if (event === PassflowEvent.SignIn) {
   *       console.log('User signed in', payload.tokens);
   *     }
   *   },
   *   [PassflowEvent.SignIn, PassflowEvent.SignOut]
   * );
   * ```
   */
  subscribe(subscriber: PassflowSubscriber, events?: PassflowEvent[]) {
    this.subscribeStore.subscribe(subscriber, events);

    // Initialize token cache service and token event listener
    this.tokenCacheService.initialize();
  }

  /**
   * Unsubscribe from Passflow authentication events.
   *
   * @param subscriber - The subscriber function to remove
   * @param events - Optional array of specific events to unsubscribe from. If omitted, unsubscribes from all events.
   *
   * @example
   * ```typescript
   * const subscriber = (event, payload) => console.log(event, payload);
   *
   * // Subscribe
   * passflow.subscribe(subscriber);
   *
   * // Later, unsubscribe
   * passflow.unsubscribe(subscriber);
   * ```
   */
  unsubscribe(subscriber: PassflowSubscriber, events?: PassflowEvent[]) {
    this.subscribeStore.unsubscribe(subscriber, events);
  }

  // Token handling
  /**
   * Handle OAuth redirect callback and extract tokens from URL query parameters.
   * This method should be called on the redirect page after authentication.
   *
   * @returns Tokens object if found in URL, undefined otherwise
   *
   * @example
   * ```typescript
   * // On your redirect page (e.g., /auth/callback)
   * const tokens = passflow.handleTokensRedirect();
   * if (tokens) {
   *   console.log('Authentication successful', tokens.access_token);
   *   // Tokens are automatically saved to storage
   * }
   * ```
   */
  handleTokensRedirect(): Tokens | undefined {
    return this.checkAndSetTokens();
  }

  private checkAndSetTokens(): Tokens | undefined {
    const urlParams = new URLSearchParams(window.location.search);
    const access_token = urlParams.get('access_token');
    const refresh_token = urlParams.get('refresh_token');
    const id_token = urlParams.get('id_token');
    const scopes: string[] = urlParams.get('scopes')?.split(',') ?? this.scopes;
    let tokens: Tokens | undefined = undefined;

    if (access_token) {
      // Validate JWT format for access_token
      if (!isValidJWTFormat(access_token)) {
        const errorPayload: ErrorPayload = {
          message: 'Invalid access token format received',
          code: 'INVALID_TOKEN_FORMAT',
        };
        this.subscribeStore.notify(PassflowEvent.Error, errorPayload);
        this.cleanupUrlParams();
        return undefined;
      }

      // Validate optional refresh_token if present
      if (refresh_token && !isValidJWTFormat(refresh_token)) {
        const errorPayload: ErrorPayload = {
          message: 'Invalid refresh token format received',
          code: 'INVALID_TOKEN_FORMAT',
        };
        this.subscribeStore.notify(PassflowEvent.Error, errorPayload);
        this.cleanupUrlParams();
        return undefined;
      }

      // Validate optional id_token if present
      if (id_token && !isValidJWTFormat(id_token)) {
        const errorPayload: ErrorPayload = {
          message: 'Invalid ID token format received',
          code: 'INVALID_TOKEN_FORMAT',
        };
        this.subscribeStore.notify(PassflowEvent.Error, errorPayload);
        this.cleanupUrlParams();
        return undefined;
      }

      tokens = {
        access_token,
        refresh_token: refresh_token ?? undefined,
        id_token: id_token ?? undefined,
        scopes,
      };
      this.storageManager.saveTokens(tokens);
      this.tokenCacheService.setTokensCache(tokens);
      this.subscribeStore.notify(PassflowEvent.SignIn, { tokens, parsedTokens: this.getParsedTokens() });
      this.submitSessionCheck();
      this.cleanupUrlParams();
      this.error = undefined;
      return tokens;
    } else {
      this.error = this.checkErrorsFromURL();
    }
    return undefined;
  }

  private checkErrorsFromURL(): Error | undefined {
    const urlParams = new URLSearchParams(window.location.search);
    const error = urlParams.get('error');
    if (error) {
      // Sanitize error message to prevent XSS
      const sanitized = sanitizeErrorMessage(error);
      return new Error(sanitized);
    }
    return undefined;
  }

  private cleanupUrlParams(): void {
    const urlParams = new URLSearchParams(window.location.search);

    // Remove sensitive token parameters
    urlParams.delete('access_token');
    urlParams.delete('refresh_token');
    urlParams.delete('id_token');
    urlParams.delete('client_challenge');

    // Use replaceState to fully clear from browser history
    if (urlParams.size > 0) {
      window.history.replaceState({}, document.title, `${window.location.pathname}?${urlParams.toString()}`);
    } else {
      window.history.replaceState({}, document.title, window.location.pathname);
    }
  }

  private setTokensToCacheFromLocalStorage(): void {
    const tokens = this.storageManager.getTokens();
    if (tokens) {
      this.tokenCacheService.setTokensCache(tokens);
    }
  }

  /**
   * Get cached tokens from memory without triggering a refresh.
   *
   * @returns Cached tokens or undefined if not cached
   *
   * @example
   * ```typescript
   * const tokens = passflow.getCachedTokens();
   * if (tokens) {
   *   console.log('Access token:', tokens.access_token);
   * }
   * ```
   */
  getCachedTokens() {
    return this.tokenCacheService.getTokens();
  }

  /**
   * Get cached tokens from memory and automatically refresh if expired.
   *
   * @returns Promise resolving to tokens or undefined
   *
   * @example
   * ```typescript
   * const tokens = await passflow.getTokensWithRefresh();
   * // Tokens are guaranteed to be valid or undefined
   * ```
   */
  getTokensWithRefresh() {
    return this.tokenCacheService.getTokensWithRefresh();
  }

  /**
   * Get parsed JWT tokens with decoded claims.
   *
   * @returns Parsed token objects with decoded payloads
   *
   * @example
   * ```typescript
   * const parsed = passflow.getParsedTokens();
   * if (parsed?.access_token) {
   *   console.log('User ID:', parsed.access_token.sub);
   *   console.log('Expires at:', new Date(parsed.access_token.exp * 1000));
   * }
   * ```
   */
  getParsedTokens() {
    return this.tokenCacheService.getParsedTokens();
  }

  /**
   * Check if the cached tokens are expired.
   *
   * @returns True if tokens are expired, false otherwise
   *
   * @example
   * ```typescript
   * if (passflow.areTokensExpired()) {
   *   await passflow.refreshToken();
   * }
   * ```
   */
  areTokensExpired() {
    return this.tokenCacheService.isExpired();
  }

  // Auth delegation methods
  /**
   * Check if the user is currently authenticated with valid tokens.
   *
   * @returns True if user has valid, non-expired tokens
   *
   * @example
   * ```typescript
   * if (passflow.isAuthenticated()) {
   *   console.log('User is logged in');
   * } else {
   *   console.log('User needs to sign in');
   * }
   * ```
   */
  isAuthenticated(): boolean {
    const tokens = this.storageManager.getTokens();
    if (!tokens || !tokens.access_token) return false;

    // Use cached parsed tokens instead of re-parsing
    const parsedTokens = this.tokenCacheService.getParsedTokens();
    if (!parsedTokens) return false;

    return this.authService.isAuthenticated(parsedTokens);
  }

  /**
   * Sign in a user with email/username and password.
   *
   * @param payload - Sign-in credentials and options
   * @param payload.email - User's email or username
   * @param payload.password - User's password
   * @param payload.scopes - Optional scopes to request (defaults to SDK scopes)
   * @returns Promise with authorization response containing tokens
   * @throws {PassflowError} If authentication fails
   *
   * @example
   * ```typescript
   * try {
   *   const response = await passflow.signIn({
   *     email: 'user@example.com',
   *     password: 'secure-password'
   *   });
   *   console.log('Signed in successfully', response.access_token);
   * } catch (error) {
   *   console.error('Sign in failed', error.message);
   * }
   * ```
   */
  async signIn(payload: PassflowSignInPayload): Promise<PassflowAuthorizationResponse> {
    const response = await this.authService.signIn(payload);

    return response;
  }

  /**
   * Register a new user account with email and password.
   *
   * @param payload - Registration details
   * @param payload.email - User's email address
   * @param payload.password - User's password
   * @param payload.username - Optional username
   * @param payload.scopes - Optional scopes to request
   * @returns Promise with authorization response containing tokens
   * @throws {PassflowError} If registration fails
   *
   * @example
   * ```typescript
   * try {
   *   const response = await passflow.signUp({
   *     email: 'newuser@example.com',
   *     password: 'secure-password',
   *     username: 'newuser'
   *   });
   *   console.log('Account created', response.access_token);
   * } catch (error) {
   *   console.error('Sign up failed', error.message);
   * }
   * ```
   */
  async signUp(payload: PassflowSignUpPayload): Promise<PassflowAuthorizationResponse> {
    const response = await this.authService.signUp(payload);

    return response;
  }

  /**
   * Initiate passwordless authentication by sending a magic link or OTP.
   *
   * @param payload - Passwordless sign-in configuration
   * @param payload.email - User's email address
   * @param payload.method - Delivery method ('email' or 'sms')
   * @returns Promise with response indicating if the code was sent
   * @throws {PassflowError} If request fails
   *
   * @example
   * ```typescript
   * // Send magic link via email
   * const response = await passflow.passwordlessSignIn({
   *   email: 'user@example.com',
   *   method: 'email'
   * });
   * console.log('Magic link sent:', response.success);
   * ```
   */
  passwordlessSignIn(payload: PassflowPasswordlessSignInPayload): Promise<PassflowPasswordlessResponse> {
    return this.authService.passwordlessSignIn(payload);
  }

  /**
   * Complete passwordless authentication by verifying the OTP or token.
   *
   * @param payload - Verification payload
   * @param payload.email - User's email address
   * @param payload.code - Verification code from email/SMS
   * @param payload.scopes - Optional scopes to request
   * @returns Promise with validation response containing tokens
   * @throws {PassflowError} If verification fails
   *
   * @example
   * ```typescript
   * try {
   *   const response = await passflow.passwordlessSignInComplete({
   *     email: 'user@example.com',
   *     code: '123456'
   *   });
   *   console.log('Passwordless sign-in complete', response.access_token);
   * } catch (error) {
   *   console.error('Invalid code', error.message);
   * }
   * ```
   */
  async passwordlessSignInComplete(payload: PassflowPasswordlessSignInCompletePayload): Promise<PassflowValidationResponse> {
    const response = await this.authService.passwordlessSignInComplete(payload);

    return response;
  }

  /**
   * Centralized error handler for all public methods.
   * Creates proper ErrorPayload, distinguishes PassflowError from generic Error,
   * notifies error event, and re-throws the error.
   *
   * @param error - The error to handle
   * @param context - Context description for the error
   * @throws The original error after handling
   */
  private handleError(error: unknown, context: string): never {
    const errorPayload: ErrorPayload = {
      message: error instanceof Error ? error.message : `${context} failed`,
      originalError: error,
      code: error instanceof PassflowError ? error.id : undefined,
    };
    this.subscribeStore.notify(PassflowEvent.Error, errorPayload);
    throw error;
  }

  /**
   * Sign out the current user and clear all tokens.
   *
   * @returns Promise that resolves when sign-out is complete
   * @throws {PassflowError} If sign-out request fails
   *
   * @example
   * ```typescript
   * try {
   *   await passflow.logOut();
   *   console.log('User signed out successfully');
   *   // Redirect to login page
   * } catch (error) {
   *   console.error('Sign out failed', error.message);
   * }
   * ```
   */
  async logOut(): Promise<void> {
    try {
      // Only clear tokens after successful logout API call
      await this.authService.logOut();
      this.storageManager.deleteTokens();
      this.tokenCacheService.setTokensCache(undefined);
      await this.submitSessionCheck();
      this.subscribeStore.notify(PassflowEvent.SignOut, {});
    } catch (error) {
      this.handleError(error, 'Log out');
    }
  }

  /**
   * Initiate federated authentication (OAuth) with a popup window.
   *
   * @param payload - Federated authentication configuration
   * @param payload.provider - OAuth provider (e.g., 'google', 'github', 'microsoft')
   * @param payload.scopes - Optional scopes to request
   *
   * @example
   * ```typescript
   * // Sign in with Google using a popup
   * passflow.federatedAuthWithPopup({
   *   provider: 'google'
   * });
   *
   * // Listen for the result via subscribe
   * passflow.subscribe((event, payload) => {
   *   if (event === PassflowEvent.SignIn) {
   *     console.log('OAuth sign-in successful', payload.tokens);
   *   }
   * });
   * ```
   */
  federatedAuthWithPopup(payload: PassflowFederatedAuthPayload): void {
    this.authService.federatedAuthWithPopup(payload);
  }

  /**
   * Initiate federated authentication (OAuth) with a full-page redirect.
   *
   * @param payload - Federated authentication configuration
   * @param payload.provider - OAuth provider (e.g., 'google', 'github', 'microsoft')
   * @param payload.scopes - Optional scopes to request
   * @param payload.redirectUrl - URL to redirect to after authentication
   *
   * @example
   * ```typescript
   * // Sign in with GitHub using redirect
   * passflow.federatedAuthWithRedirect({
   *   provider: 'github',
   *   redirectUrl: window.location.origin + '/auth/callback'
   * });
   * ```
   */
  federatedAuthWithRedirect(payload: PassflowFederatedAuthPayload): void {
    this.authService.federatedAuthWithRedirect(payload);
  }

  /**
   * Reset the SDK state by clearing all tokens and optionally throwing an error.
   *
   * @param error - Optional error message to throw after reset
   * @throws {Error} If error message is provided
   *
   * @example
   * ```typescript
   * // Clear tokens without error
   * passflow.reset();
   *
   * // Clear tokens and throw error
   * try {
   *   passflow.reset('Session expired');
   * } catch (error) {
   *   console.error('Reset error:', error.message);
   * }
   * ```
   */
  reset(error?: string) {
    this.storageManager.deleteTokens();
    this.tokenCacheService.setTokensCache(undefined);
    this.subscribeStore.notify(PassflowEvent.SignOut, {});
    if (error) {
      this.error = new Error(error);
      const errorPayload: ErrorPayload = {
        message: error,
        code: 'RESET_ERROR',
      };
      this.subscribeStore.notify(PassflowEvent.Error, errorPayload);
      throw this.error;
    }
  }

  /**
   * Refresh the access token using the refresh token.
   *
   * @returns Promise with new authorization response containing refreshed tokens
   * @throws {Error} If no refresh token is found
   * @throws {PassflowError} If refresh request fails
   *
   * @example
   * ```typescript
   * try {
   *   const response = await passflow.refreshToken();
   *   console.log('Token refreshed', response.access_token);
   * } catch (error) {
   *   console.error('Failed to refresh token', error.message);
   *   // Redirect to login
   * }
   * ```
   */
  async refreshToken(): Promise<PassflowAuthorizationResponse> {
    if (!this.tokenCacheService.parsedTokensCache?.refresh_token) {
      throw new Error('No refresh token found');
    }

    try {
      const response = await this.authService.refreshToken();

      return response;
    } catch (error) {
      if (error instanceof PassflowError) {
        throw error;
      } else {
        this.subscribeStore.notify(PassflowEvent.Error, {
          message: 'Failed to refresh token',
          originalError: error,
        });
        throw error;
      }
    }
  }

  /**
   * Send a password reset email to the user.
   *
   * @param payload - Password reset request
   * @param payload.email - User's email address
   * @returns Promise with success response
   * @throws {PassflowError} If request fails
   *
   * @example
   * ```typescript
   * try {
   *   await passflow.sendPasswordResetEmail({
   *     email: 'user@example.com'
   *   });
   *   console.log('Password reset email sent');
   * } catch (error) {
   *   console.error('Failed to send reset email', error.message);
   * }
   * ```
   */
  sendPasswordResetEmail(payload: PassflowSendPasswordResetEmailPayload): Promise<PassflowSuccessResponse> {
    return this.authService.sendPasswordResetEmail(payload);
  }

  /**
   * Reset password using a reset token (typically from URL after clicking email link).
   *
   * @param newPassword - The new password to set
   * @param scopes - Optional scopes to request after reset
   * @returns Promise with authorization response containing new tokens
   * @throws {PassflowError} If reset fails
   *
   * @example
   * ```typescript
   * // On password reset page (e.g., /reset-password?token=xyz)
   * try {
   *   const response = await passflow.resetPassword('new-secure-password');
   *   console.log('Password reset successful', response.access_token);
   * } catch (error) {
   *   console.error('Password reset failed', error.message);
   * }
   * ```
   */
  async resetPassword(newPassword: string, scopes?: string[]): Promise<PassflowAuthorizationResponse> {
    const response = await this.authService.resetPassword(newPassword, scopes);

    return response;
  }

  // App settings
  /**
   * Get application settings and configuration.
   *
   * @returns Promise with app settings including branding, features, and config
   * @throws {PassflowError} If request fails
   *
   * @example
   * ```typescript
   * const settings = await passflow.getAppSettings();
   * console.log('App name:', settings.name);
   * console.log('Passwordless enabled:', settings.passwordless_enabled);
   * ```
   */
  async getAppSettings(): Promise<AppSettings> {
    try {
      return await this.appApi.getAppSettings();
    } catch (error) {
      this.handleError(error, 'Get app settings');
    }
  }

  /**
   * Get all Passflow settings including password policy, passkey settings, etc.
   *
   * @returns Promise with all settings
   * @throws {PassflowError} If request fails
   *
   * @example
   * ```typescript
   * const settings = await passflow.getSettingsAll();
   * console.log('Password policy:', settings.password_policy);
   * console.log('Passkey settings:', settings.passkey);
   * ```
   */
  async getSettingsAll(): Promise<PassflowSettingsAll> {
    try {
      return await this.settingApi.getSettingsAll();
    } catch (error) {
      this.handleError(error, 'Get all settings');
    }
  }

  /**
   * Get password policy settings (min length, complexity requirements, etc.).
   *
   * @returns Promise with password policy configuration
   * @throws {PassflowError} If request fails
   *
   * @example
   * ```typescript
   * const policy = await passflow.getPasswordPolicySettings();
   * console.log('Min length:', policy.min_length);
   * console.log('Require uppercase:', policy.require_uppercase);
   * ```
   */
  async getPasswordPolicySettings(): Promise<PassflowPasswordPolicySettings> {
    try {
      return await this.settingApi.getPasswordPolicySettings();
    } catch (error) {
      this.handleError(error, 'Get password policy settings');
    }
  }

  /**
   * Get passkey (WebAuthn) configuration settings.
   *
   * @returns Promise with passkey settings
   * @throws {PassflowError} If request fails
   *
   * @example
   * ```typescript
   * const passkeySettings = await passflow.getPasskeySettings();
   * console.log('Passkeys enabled:', passkeySettings.enabled);
   * console.log('User verification:', passkeySettings.user_verification);
   * ```
   */
  async getPasskeySettings(): Promise<PassflowPasskeySettings> {
    try {
      return await this.settingApi.getPasskeySettings();
    } catch (error) {
      this.handleError(error, 'Get passkey settings');
    }
  }

  // Passkey methods
  /**
   * Register a new user with a passkey (WebAuthn).
   *
   * @param payload - Passkey registration configuration
   * @param payload.email - User's email address
   * @param payload.username - Optional username
   * @param payload.scopes - Optional scopes to request
   * @returns Promise with authorization response containing tokens
   * @throws {PassflowError} If passkey registration fails
   *
   * @example
   * ```typescript
   * try {
   *   const response = await passflow.passkeyRegister({
   *     email: 'user@example.com',
   *     username: 'myusername'
   *   });
   *   console.log('Passkey registered', response.access_token);
   * } catch (error) {
   *   console.error('Passkey registration failed', error.message);
   * }
   * ```
   */
  async passkeyRegister(payload: PassflowPasskeyRegisterStartPayload): Promise<PassflowAuthorizationResponse> {
    const response = await this.authService.passkeyRegister(payload);

    return response;
  }

  /**
   * Authenticate a user with a passkey (WebAuthn).
   *
   * @param payload - Passkey authentication configuration
   * @param payload.email - Optional user email to pre-fill
   * @param payload.scopes - Optional scopes to request
   * @returns Promise with authorization response containing tokens
   * @throws {PassflowError} If passkey authentication fails
   *
   * @example
   * ```typescript
   * try {
   *   // Let user select from available passkeys
   *   const response = await passflow.passkeyAuthenticate({});
   *   console.log('Passkey sign-in successful', response.access_token);
   * } catch (error) {
   *   console.error('Passkey authentication failed', error.message);
   * }
   * ```
   */
  async passkeyAuthenticate(payload: PassflowPasskeyAuthenticateStartPayload): Promise<PassflowAuthorizationResponse> {
    const response = await this.authService.passkeyAuthenticate(payload);

    return response;
  }

  // Token management
  /**
   * Manually set tokens (useful after custom authentication flows).
   * This will save tokens to storage, update cache, and trigger SignIn event.
   *
   * @param tokensData - Tokens object to set
   * @param tokensData.access_token - JWT access token
   * @param tokensData.refresh_token - Optional refresh token
   * @param tokensData.id_token - Optional ID token
   * @param tokensData.scopes - Token scopes
   *
   * @example
   * ```typescript
   * // Set tokens from a custom auth flow
   * passflow.setTokens({
   *   access_token: 'eyJhbGci...',
   *   refresh_token: 'eyJhbGci...',
   *   id_token: 'eyJhbGci...',
   *   scopes: ['id', 'offline', 'email']
   * });
   * ```
   */
  setTokens(tokensData: Tokens): void {
    this.storageManager.saveTokens(tokensData);
    this.tokenCacheService.setTokensCache(tokensData);
    this.subscribeStore.notify(PassflowEvent.SignIn, {
      tokens: tokensData,
      parsedTokens: this.tokenCacheService.getParsedTokens(),
    });
  }

  /**
   * Get current tokens from storage, optionally refreshing if expired.
   *
   * @param doRefresh - If true, automatically refresh expired tokens (default: false)
   * @returns Promise with tokens or undefined if not authenticated
   *
   * @example
   * ```typescript
   * // Get tokens without refresh
   * const tokens = await passflow.getTokens();
   *
   * // Get tokens and auto-refresh if expired
   * const freshTokens = await passflow.getTokens(true);
   * ```
   */
  async getTokens(doRefresh = false): Promise<Tokens | undefined> {
    return await this.authService.getTokens(doRefresh);
  }

  /**
   * Get a specific token from storage by type.
   *
   * @param tokenType - Type of token to retrieve ('access_token', 'refresh_token', 'id_token')
   * @returns Token string or undefined if not found
   *
   * @example
   * ```typescript
   * const accessToken = passflow.getToken('access_token');
   * if (accessToken) {
   *   // Use token for API calls
   *   fetch('/api/data', {
   *     headers: { Authorization: `Bearer ${accessToken}` }
   *   });
   * }
   * ```
   */
  getToken(tokenType: TokenType): string | undefined {
    return this.storageManager.getToken(tokenType);
  }

  // User passkey methods delegated to UserService
  /**
   * Get list of passkeys registered for the current user.
   *
   * @returns Promise with array of user's passkeys
   * @throws {PassflowError} If request fails
   *
   * @example
   * ```typescript
   * const passkeys = await passflow.getUserPasskeys();
   * passkeys.forEach(passkey => {
   *   console.log('Passkey:', passkey.name, passkey.id);
   * });
   * ```
   */
  async getUserPasskeys() {
    try {
      return await this.userService.getUserPasskeys();
    } catch (error) {
      this.handleError(error, 'Get user passkeys');
    }
  }

  /**
   * Rename a user's passkey to a friendly name.
   *
   * @param name - New friendly name for the passkey
   * @param passkeyId - ID of the passkey to rename
   * @returns Promise with success response
   * @throws {PassflowError} If request fails
   *
   * @example
   * ```typescript
   * await passflow.renameUserPasskey('My MacBook Pro', 'passkey-123');
   * console.log('Passkey renamed successfully');
   * ```
   */
  async renameUserPasskey(name: string, passkeyId: string): Promise<PassflowSuccessResponse> {
    try {
      return await this.userService.renameUserPasskey(name, passkeyId);
    } catch (error) {
      this.handleError(error, 'Rename user passkey');
    }
  }

  /**
   * Delete a passkey from the user's account.
   *
   * @param passkeyId - ID of the passkey to delete
   * @returns Promise with success response
   * @throws {PassflowError} If request fails
   *
   * @example
   * ```typescript
   * await passflow.deleteUserPasskey('passkey-123');
   * console.log('Passkey deleted successfully');
   * ```
   */
  async deleteUserPasskey(passkeyId: string): Promise<PassflowSuccessResponse> {
    try {
      return await this.userService.deleteUserPasskey(passkeyId);
    } catch (error) {
      this.handleError(error, 'Delete user passkey');
    }
  }

  /**
   * Add a new passkey to the current user's account (requires active session).
   *
   * @param options - Optional passkey configuration
   * @param options.relyingPartyId - Optional RP ID for the passkey
   * @param options.passkeyUsername - Optional username to associate with passkey
   * @param options.passkeyDisplayName - Optional display name for the passkey
   * @returns Promise that resolves when passkey is added
   * @throws {PassflowError} If request fails
   *
   * @example
   * ```typescript
   * // Add passkey with default settings
   * await passflow.addUserPasskey();
   *
   * // Add passkey with custom display name
   * await passflow.addUserPasskey({
   *   passkeyDisplayName: 'My iPhone'
   * });
   * ```
   */
  async addUserPasskey(options?: {
    relyingPartyId?: string;
    passkeyUsername?: string;
    passkeyDisplayName?: string;
  }): Promise<void> {
    try {
      return await this.userService.addUserPasskey(options);
    } catch (error) {
      this.handleError(error, 'Add user passkey');
    }
  }

  // Tenant methods delegated to TenantService
  /**
   * Join a tenant invitation
   * @param token The invitation token
   * @param scopes Optional scopes to request
   * @returns Promise with invite response
   */
  async joinInvitation(token: string, scopes?: string[]): Promise<PassflowAuthorizationResponse> {
    try {
      const response = await this.tenant.joinInvitation(token, scopes);
      response.scopes = scopes ?? this.scopes;
      this.storageManager.saveTokens(response);
      this.tokenCacheService.setTokensCache(response);
      return response;
    } catch (error) {
      this.handleError(error, 'Join invitation');
    }
  }

  /**
   * Create a new tenant
   * @param name The name of the tenant
   * @param refreshToken Whether to refresh the token after creating the tenant
   * @returns Promise with tenant response
   */
  async createTenant(name: string, refreshToken?: boolean): Promise<PassflowTenantResponse> {
    try {
      const response = await this.tenant.createTenant(name);
      if (refreshToken) {
        await this.refreshToken();
      }
      return response;
    } catch (error) {
      this.handleError(error, 'Create tenant');
    }
  }

  // Invitation methods delegated to InvitationService
  /**
   * Request an invitation link for a user to join a tenant.
   *
   * @param payload - Invitation request configuration
   * @param payload.email - Email address to send invitation to
   * @param payload.tenantID - Tenant ID for the invitation
   * @param payload.send_to_email - Whether to send email automatically (default: true)
   * @returns Promise with invitation link response
   * @throws {PassflowError} If request fails
   *
   * @example
   * ```typescript
   * const invitation = await passflow.requestInviteLink({
   *   email: 'newuser@example.com',
   *   tenantID: 'tenant-123',
   *   send_to_email: true
   * });
   * console.log('Invitation link:', invitation.link);
   * ```
   */
  async requestInviteLink(payload: RequestInviteLinkPayload): Promise<InviteLinkResponse> {
    try {
      // default is true
      if (payload.send_to_email === undefined) {
        payload.send_to_email = true;
      }
      return await this.invitationService.requestInviteLink(payload);
    } catch (error) {
      this.handleError(error, 'Request invite link');
    }
  }

  /**
   * Gets a list of active invitations
   * @param options Optional parameters for filtering and pagination
   * @returns Promise with paginated list of invitations
   */
  async getInvitations(options: {
    tenantID: string;
    groupID?: string;
    skip?: number | string;
    limit?: number | string;
  }): Promise<InvitationsPaginatedList> {
    try {
      return await this.invitationService.getInvitations(options);
    } catch (error) {
      this.handleError(error, 'Get invitations');
    }
  }

  /**
   * Delete an invitation by its token.
   *
   * @param token - Invitation token to delete
   * @returns Promise with success response
   * @throws {PassflowError} If request fails
   *
   * @example
   * ```typescript
   * await passflow.deleteInvitation('invitation-token-123');
   * console.log('Invitation deleted');
   * ```
   */
  async deleteInvitation(token: string): Promise<PassflowSuccessResponse> {
    try {
      return await this.invitationService.deleteInvitation(token);
    } catch (error) {
      this.handleError(error, 'Delete invitation');
    }
  }

  /**
   * Resend an invitation email.
   *
   * @param token - Invitation token to resend
   * @returns Promise with success response
   * @throws {PassflowError} If request fails
   *
   * @example
   * ```typescript
   * await passflow.resendInvitation('invitation-token-123');
   * console.log('Invitation email resent');
   * ```
   */
  async resendInvitation(token: string): Promise<PassflowSuccessResponse> {
    try {
      return await this.invitationService.resendInvitation(token);
    } catch (error) {
      this.handleError(error, 'Resend invitation');
    }
  }

  /**
   * Get invitation details and link by invitation ID.
   *
   * @param invitationID - Invitation ID to retrieve
   * @returns Promise with invitation link response
   * @throws {PassflowError} If request fails
   *
   * @example
   * ```typescript
   * const invitation = await passflow.getInvitationLink('invitation-123');
   * console.log('Invitation link:', invitation.link);
   * ```
   */
  async getInvitationLink(invitationID: string): Promise<InviteLinkResponse> {
    try {
      return await this.invitationService.getInvitationLink(invitationID);
    } catch (error) {
      this.handleError(error, 'Get invitation link');
    }
  }

  // Auth redirect helpers
  /**
   * Generate an authentication redirect URL for hosted login.
   *
   * @param options - Redirect URL configuration
   * @param options.url - Optional custom Passflow server URL
   * @param options.redirectUrl - URL to redirect to after authentication
   * @param options.scopes - Optional scopes to request
   * @param options.appId - Optional app ID to use
   * @returns Authentication redirect URL
   *
   * @example
   * ```typescript
   * const authUrl = passflow.authRedirectUrl({
   *   redirectUrl: window.location.origin + '/auth/callback',
   *   scopes: ['id', 'email', 'offline']
   * });
   * console.log('Auth URL:', authUrl);
   * // Use this URL for custom navigation logic
   * ```
   */
  authRedirectUrl(options: { url?: string; redirectUrl?: string; scopes?: string[]; appId?: string } = {}): string {
    return this.authService.authRedirectUrl(options);
  }

  /**
   * Redirect to the Passflow hosted login page.
   *
   * @param options - Redirect configuration
   * @param options.url - Optional custom Passflow server URL
   * @param options.redirectUrl - URL to redirect to after authentication
   * @param options.scopes - Optional scopes to request
   * @param options.appId - Optional app ID to use
   *
   * @example
   * ```typescript
   * // Redirect to hosted login page
   * passflow.authRedirect({
   *   redirectUrl: window.location.origin + '/auth/callback'
   * });
   * ```
   */
  authRedirect(options: { url?: string; redirectUrl?: string; scopes?: string[]; appId?: string } = {}): void {
    this.authService.authRedirect(options);
  }
}
