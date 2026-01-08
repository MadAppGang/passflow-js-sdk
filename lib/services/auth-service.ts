import { startAuthentication, startRegistration } from '@simplewebauthn/browser';
import axios from 'axios';
import {
  AuthAPI,
  OS,
  PassflowAuthorizationResponse,
  PassflowError,
  PassflowFederatedAuthExtendedPayload,
  PassflowFederatedAuthPayload,
  PassflowPasskeyAuthenticateStartPayload,
  PassflowPasskeyRegisterStartPayload,
  PassflowPasswordlessResponse,
  PassflowPasswordlessSignInCompletePayload,
  PassflowPasswordlessSignInPayload,
  PassflowSendPasswordResetEmailPayload,
  PassflowSignInPayload,
  PassflowSignUpPayload,
  PassflowSuccessResponse,
  PassflowValidationResponse,
} from '../api';
import { POPUP_HEIGHT, POPUP_POLL_INTERVAL_MS, POPUP_TIMEOUT_MS, POPUP_WIDTH } from '../constants';
import { DeviceService } from '../device';
import { StorageManager } from '../storage';
import { ErrorPayload, PassflowEvent, PassflowStore } from '../store';
import { TokenType, isTokenExpired, parseToken } from '../token';
import { ParsedTokens, Tokens } from '../types';
import { isValidEmail, isValidPhoneNumber, isValidUsername } from '../utils/validation';
import { TokenCacheService } from './token-cache-service';

/**
 * Service for handling authentication related functionality
 */
export class AuthService {
  constructor(
    private authApi: AuthAPI,
    private deviceService: DeviceService,
    private storageManager: StorageManager,
    private subscribeStore: PassflowStore,
    private tokenCacheService: TokenCacheService,
    private scopes: string[],
    private createTenantForNewUser: boolean,
    private origin: string,
    private url: string,
    private sessionCallbacks: {
      createSession?: ({ tokens, parsedTokens }: { tokens?: Tokens; parsedTokens?: ParsedTokens }) => Promise<void>;
      expiredSession?: () => Promise<void>;
    },
    private appId?: string,
  ) {}

  async signIn(payload: PassflowSignInPayload): Promise<PassflowAuthorizationResponse> {
    // Validate input before API call
    if ('email' in payload && payload.email) {
      if (!isValidEmail(payload.email)) {
        const error = new Error('Invalid email format');
        const errorPayload: ErrorPayload = {
          message: 'Invalid email format',
          originalError: error,
          code: 'VALIDATION_ERROR',
        };
        this.subscribeStore.notify(PassflowEvent.Error, errorPayload);
        throw error;
      }
    }

    if ('username' in payload && payload.username) {
      if (!isValidUsername(payload.username)) {
        const error = new Error(
          'Invalid username format. Username must be 3-30 characters and contain only letters, numbers, underscores, and hyphens',
        );
        const errorPayload: ErrorPayload = {
          message:
            'Invalid username format. Username must be 3-30 characters and contain only letters, numbers, underscores, and hyphens',
          originalError: error,
          code: 'VALIDATION_ERROR',
        };
        this.subscribeStore.notify(PassflowEvent.Error, errorPayload);
        throw error;
      }
    }

    if ('phone' in payload && payload.phone) {
      if (!isValidPhoneNumber(payload.phone)) {
        const error = new Error('Invalid phone number format. Phone must be in E.164 format (e.g., +12345678901)');
        const errorPayload: ErrorPayload = {
          message: 'Invalid phone number format. Phone must be in E.164 format (e.g., +12345678901)',
          originalError: error,
          code: 'VALIDATION_ERROR',
        };
        this.subscribeStore.notify(PassflowEvent.Error, errorPayload);
        throw error;
      }
    }

    this.subscribeStore.notify(PassflowEvent.SignInStart, { email: payload.email });
    const deviceId = this.deviceService.getDeviceId();
    const os = OS.web;
    payload.scopes = payload.scopes ?? this.scopes;

    try {
      const response = await this.authApi.signIn(payload, deviceId, os);
      response.scopes = payload.scopes;
      this.storageManager.saveTokens(response);
      this.tokenCacheService.setTokensCache(response);
      this.subscribeStore.notify(PassflowEvent.SignIn, {
        tokens: response,
        parsedTokens: this.tokenCacheService.getParsedTokens(),
      });
      await this.submitSessionCheck();
      return response;
    } catch (error) {
      const errorPayload: ErrorPayload = {
        message: error instanceof Error ? error.message : 'Sign in failed',
        originalError: error,
        code: error instanceof PassflowError ? error.id : undefined,
      };
      this.subscribeStore.notify(PassflowEvent.Error, errorPayload);
      throw error;
    }
  }

  async signUp(payload: PassflowSignUpPayload): Promise<PassflowAuthorizationResponse> {
    // Validate user input before API call
    if (payload.user.email && !isValidEmail(payload.user.email)) {
      const error = new Error('Invalid email format');
      const errorPayload: ErrorPayload = {
        message: 'Invalid email format',
        originalError: error,
        code: 'VALIDATION_ERROR',
      };
      this.subscribeStore.notify(PassflowEvent.Error, errorPayload);
      throw error;
    }

    if (payload.user.phone_number && !isValidPhoneNumber(payload.user.phone_number)) {
      const error = new Error('Invalid phone number format. Phone must be in E.164 format (e.g., +12345678901)');
      const errorPayload: ErrorPayload = {
        message: 'Invalid phone number format. Phone must be in E.164 format (e.g., +12345678901)',
        originalError: error,
        code: 'VALIDATION_ERROR',
      };
      this.subscribeStore.notify(PassflowEvent.Error, errorPayload);
      throw error;
    }

    this.subscribeStore.notify(PassflowEvent.RegisterStart, { email: payload.user.email });
    payload.scopes = payload.scopes ?? this.scopes;
    payload.create_tenant = this.createTenantForNewUser;

    try {
      const response = await this.authApi.signUp(payload);
      response.scopes = payload.scopes;
      this.storageManager.saveTokens(response);
      this.tokenCacheService.setTokensCache(response);
      this.subscribeStore.notify(PassflowEvent.Register, {
        tokens: response,
        parsedTokens: this.tokenCacheService.getParsedTokens(),
      });
      await this.submitSessionCheck();
      return response;
    } catch (error) {
      const errorPayload: ErrorPayload = {
        message: error instanceof Error ? error.message : 'Sign up failed',
        originalError: error,
        code: error instanceof PassflowError ? error.id : undefined,
      };
      this.subscribeStore.notify(PassflowEvent.Error, errorPayload);
      throw error;
    }
  }

  async passwordlessSignIn(payload: PassflowPasswordlessSignInPayload): Promise<PassflowPasswordlessResponse> {
    // Validate input before API call
    if (payload.email && !isValidEmail(payload.email)) {
      const error = new Error('Invalid email format');
      const errorPayload: ErrorPayload = {
        message: 'Invalid email format',
        originalError: error,
        code: 'VALIDATION_ERROR',
      };
      this.subscribeStore.notify(PassflowEvent.Error, errorPayload);
      throw error;
    }

    if (payload.phone && !isValidPhoneNumber(payload.phone)) {
      const error = new Error('Invalid phone number format. Phone must be in E.164 format (e.g., +12345678901)');
      const errorPayload: ErrorPayload = {
        message: 'Invalid phone number format. Phone must be in E.164 format (e.g., +12345678901)',
        originalError: error,
        code: 'VALIDATION_ERROR',
      };
      this.subscribeStore.notify(PassflowEvent.Error, errorPayload);
      throw error;
    }

    this.subscribeStore.notify(PassflowEvent.SignInStart, { email: payload.email });
    payload.scopes = payload.scopes ?? this.scopes;
    const deviceId = this.deviceService.getDeviceId();
    const os = OS.web;

    try {
      const response = await this.authApi.passwordlessSignIn(payload, deviceId, os);
      // Don't emit SignIn event yet since this is just the first step (magic link sent)
      // We'll emit SignIn when passwordlessSignInComplete is called
      return response;
    } catch (error) {
      const errorPayload: ErrorPayload = {
        message: error instanceof Error ? error.message : 'Failed to send passwordless sign-in link',
        originalError: error,
        code: error instanceof PassflowError ? error.id : undefined,
      };
      this.subscribeStore.notify(PassflowEvent.Error, errorPayload);
      throw error;
    }
  }

  async passwordlessSignInComplete(payload: PassflowPasswordlessSignInCompletePayload): Promise<PassflowValidationResponse> {
    this.subscribeStore.notify(PassflowEvent.SignInStart, {});
    payload.scopes = payload.scopes ?? this.scopes;
    payload.device = this.deviceService.getDeviceId();

    try {
      const response = await this.authApi.passwordlessSignInComplete(payload);
      response.scopes = payload.scopes;
      this.storageManager.saveTokens(response);
      this.tokenCacheService.setTokensCache(response);
      this.subscribeStore.notify(PassflowEvent.SignIn, {
        tokens: response,
        parsedTokens: this.tokenCacheService.getParsedTokens(),
      });
      await this.submitSessionCheck();
      return response;
    } catch (error) {
      const errorPayload: ErrorPayload = {
        message: error instanceof Error ? error.message : 'Passwordless sign in failed',
        originalError: error,
        code: error instanceof PassflowError ? error.id : undefined,
      };
      this.subscribeStore.notify(PassflowEvent.Error, errorPayload);
      throw error;
    }
  }

  async logOut() {
    const refreshToken = this.storageManager.getToken(TokenType.refresh_token);
    const deviceId = this.storageManager.getDeviceId();

    const response = await this.authApi.logOut(deviceId, refreshToken, !this.appId);
    if (response.status !== 'ok') {
      throw new Error('Logout failed');
    }
    this.storageManager.deleteTokens();
    this.subscribeStore.notify(PassflowEvent.SignOut, {});
  }

  async refreshToken(): Promise<PassflowAuthorizationResponse> {
    this.subscribeStore.notify(PassflowEvent.RefreshStart, {});
    const tokens = this.storageManager.getTokens();
    if (!tokens) {
      const error = new Error('No tokens found');
      const errorPayload: ErrorPayload = {
        message: 'No tokens found',
        originalError: error,
      };
      this.subscribeStore.notify(PassflowEvent.Error, errorPayload);
      throw error;
    } else if (!tokens?.refresh_token) {
      const error = new Error('No refresh token found');
      const errorPayload: ErrorPayload = {
        message: 'No refresh token found',
        originalError: error,
      };
      this.subscribeStore.notify(PassflowEvent.Error, errorPayload);
      throw error;
    }

    const oldScopes = tokens?.scopes ?? this.scopes;
    try {
      const response = await this.authApi.refreshToken(tokens?.refresh_token ?? '', oldScopes, tokens?.access_token);
      response.scopes = oldScopes;
      this.storageManager.saveTokens(response);
      this.tokenCacheService.setTokensCache(response);
      this.subscribeStore.notify(PassflowEvent.Refresh, {
        tokens: response,
        parsedTokens: this.tokenCacheService.getParsedTokens(),
      });
      this.subscribeStore.notify(PassflowEvent.TokenCacheExpired, { isExpired: false });
      this.tokenCacheService.isRefreshing = false;
      this.tokenCacheService.tokenExpiredFlag = false;
      this.tokenCacheService.startTokenCheck();
      return response;
    } catch (error) {
      const errorPayload: ErrorPayload = {
        message: error instanceof Error ? error.message : 'Token refresh failed',
        originalError: error,
        code: error instanceof PassflowError ? error.id : undefined,
        details:
          axios.isAxiosError(error) && error.response
            ? {
                status: error.response.status,
                data: error.response.data,
              }
            : undefined,
      };
      this.subscribeStore.notify(PassflowEvent.Error, errorPayload);

      if (error instanceof PassflowError) {
        throw error;
      } else if (axios.isAxiosError(error) && error.response && error.response?.status >= 400 && error.response?.status < 500) {
        throw new Error(`Getting unknown error message from server with code:${error.response.status}`);
      } else {
        throw error;
      }
    }
  }

  async sendPasswordResetEmail(payload: PassflowSendPasswordResetEmailPayload): Promise<PassflowSuccessResponse> {
    try {
      return await this.authApi.sendPasswordResetEmail(payload);
    } catch (error) {
      const errorPayload: ErrorPayload = {
        message: error instanceof Error ? error.message : 'Failed to send password reset email',
        originalError: error,
        code: error instanceof PassflowError ? error.id : undefined,
      };
      this.subscribeStore.notify(PassflowEvent.Error, errorPayload);
      throw error;
    }
  }

  async resetPassword(newPassword: string, scopes?: string[]): Promise<PassflowAuthorizationResponse> {
    this.subscribeStore.notify(PassflowEvent.SignInStart, {});
    const urlParams = new URLSearchParams(window.location.search);
    const resetToken = urlParams.get('token') ?? undefined;
    const sscopes = scopes ?? this.scopes;

    try {
      const response = await this.authApi.resetPassword(newPassword, sscopes, resetToken);
      response.scopes = sscopes;
      this.storageManager.saveTokens(response);
      this.tokenCacheService.setTokensCache(response);
      this.subscribeStore.notify(PassflowEvent.SignIn, {
        tokens: response,
        parsedTokens: this.tokenCacheService.getParsedTokens(),
      });
      await this.submitSessionCheck();
      return response;
    } catch (error) {
      const errorPayload: ErrorPayload = {
        message: error instanceof Error ? error.message : 'Password reset failed',
        originalError: error,
        code: error instanceof PassflowError ? error.id : undefined,
      };
      this.subscribeStore.notify(PassflowEvent.Error, errorPayload);
      throw error;
    }
  }

  async passkeyRegister(payload: PassflowPasskeyRegisterStartPayload): Promise<PassflowAuthorizationResponse> {
    this.subscribeStore.notify(PassflowEvent.RegisterStart, {});
    const deviceId = this.deviceService.getDeviceId();
    const os = OS.web;
    payload.scopes = payload.scopes ?? this.scopes;
    payload.create_tenant = this.createTenantForNewUser;

    try {
      const { challenge_id, publicKey } = await this.authApi.passkeyRegisterStart(payload, deviceId, os, !this.appId);
      // user handle should be base64 encoded for simplewebauthn lib we are using
      publicKey.user.id = btoa(publicKey.user.id);
      const webauthn = await startRegistration({
        optionsJSON: publicKey,
      });

      const responseRegisterComplete = await this.authApi.passkeyRegisterComplete(
        webauthn,
        deviceId,
        challenge_id,
        !this.appId,
      );
      responseRegisterComplete.scopes = payload.scopes;
      this.storageManager.saveTokens(responseRegisterComplete);
      this.tokenCacheService.setTokensCache(responseRegisterComplete);
      this.subscribeStore.notify(PassflowEvent.Register, {
        tokens: responseRegisterComplete,
        parsedTokens: this.tokenCacheService.getParsedTokens(),
      });
      await this.submitSessionCheck();
      return responseRegisterComplete;
    } catch (error) {
      const errorPayload: ErrorPayload = {
        message: error instanceof Error ? error.message : 'Passkey registration failed',
        originalError: error,
        code: error instanceof PassflowError ? error.id : undefined,
      };
      this.subscribeStore.notify(PassflowEvent.Error, errorPayload);
      throw error;
    }
  }

  async passkeyAuthenticate(payload: PassflowPasskeyAuthenticateStartPayload): Promise<PassflowAuthorizationResponse> {
    this.subscribeStore.notify(PassflowEvent.SignInStart, {});
    const deviceId = this.deviceService.getDeviceId();
    const os = OS.web;
    payload.scopes = payload.scopes ?? this.scopes;

    try {
      const { challenge_id, publicKey } = await this.authApi.passkeyAuthenticateStart(payload, deviceId, os, !this.appId);
      const webauthn = await startAuthentication({
        optionsJSON: publicKey,
      });

      const responseAuthenticateComplete = await this.authApi.passkeyAuthenticateComplete(
        webauthn,
        deviceId,
        challenge_id,
        !this.appId,
      );

      if ('access_token' in responseAuthenticateComplete) {
        responseAuthenticateComplete.scopes = payload.scopes;
        this.storageManager.saveTokens(responseAuthenticateComplete);
        this.tokenCacheService.setTokensCache(responseAuthenticateComplete);
        this.subscribeStore.notify(PassflowEvent.SignIn, {
          tokens: responseAuthenticateComplete,
          parsedTokens: this.tokenCacheService.getParsedTokens(),
        });
        await this.submitSessionCheck();
      }

      return responseAuthenticateComplete;
    } catch (error) {
      const errorPayload: ErrorPayload = {
        message: error instanceof Error ? error.message : 'Passkey authentication failed',
        originalError: error,
        code: error instanceof PassflowError ? error.id : undefined,
      };
      this.subscribeStore.notify(PassflowEvent.Error, errorPayload);
      throw error;
    }
  }

  createFederatedAuthUrl(payload: PassflowFederatedAuthExtendedPayload): string {
    const passflowPathWithProvider = `/auth/federated/start/${payload.provider}`;

    if (!this.appId) throw new Error('AppId is required for federated auth');
    const sscopes = payload.scopes ?? this.scopes;

    const params: Record<string, string> = {
      scopes: sscopes.join(' '),
      redirect_url: payload.redirect_url ?? this.origin,
      appId: this.appId,
      ...(payload.invite_token ? { invite_token: payload.invite_token } : {}),
      ...(payload.create_tenant ? { create_tenant: payload.create_tenant.toString() } : {}),
      ...(payload.device ? { device: payload.device } : {}),
    };

    const url = new URL(passflowPathWithProvider, this.url);
    const queryParams = new URLSearchParams(params);
    url.search = queryParams.toString();

    return url.toString();
  }

  federatedAuthWithPopup(payload: PassflowFederatedAuthPayload): void {
    this.subscribeStore.notify(PassflowEvent.SignInStart, { provider: payload.provider });
    const sscopes = payload.scopes ?? this.scopes;
    const deviceId = this.deviceService.getDeviceId();
    const passflowURL = this.createFederatedAuthUrl({ ...payload, scopes: sscopes, device: deviceId });

    const popupWindow = window.open(passflowURL, '_blank', `width=${POPUP_WIDTH},height=${POPUP_HEIGHT}`);

    if (!popupWindow) {
      this.federatedAuthWithRedirect(payload);
      return;
    }

    const startTime = Date.now();

    const checkInterval = setInterval(() => {
      // Check if popup was closed by user
      if (popupWindow.closed) {
        clearInterval(checkInterval);
        const errorPayload: ErrorPayload = {
          message: 'Authentication popup was closed',
          code: 'POPUP_CLOSED',
        };
        this.subscribeStore.notify(PassflowEvent.Error, errorPayload);
        return;
      }

      // Check for timeout
      if (Date.now() - startTime > POPUP_TIMEOUT_MS) {
        clearInterval(checkInterval);
        popupWindow.close();
        const errorPayload: ErrorPayload = {
          message: 'Authentication popup timed out',
          code: 'POPUP_TIMEOUT',
        };
        this.subscribeStore.notify(PassflowEvent.Error, errorPayload);
        return;
      }

      // Try to check popup URL (may throw cross-origin error)
      try {
        if (popupWindow.location.href.startsWith(this.origin)) {
          const urlParams = new URLSearchParams(popupWindow.location.search);
          const access_token = urlParams.get('access_token') || '';
          const refresh_token = urlParams.get('refresh_token') || '';
          const id_token = urlParams.get('id_token') || '';

          const tokensData = {
            access_token,
            refresh_token: refresh_token || undefined,
            id_token: id_token || undefined,
            scopes: sscopes,
          };

          this.storageManager.saveTokens(tokensData);
          this.tokenCacheService.setTokensCache(tokensData);
          this.subscribeStore.notify(PassflowEvent.SignIn, {
            tokens: tokensData,
            parsedTokens: this.tokenCacheService.getParsedTokens(),
          });

          clearInterval(checkInterval);
          popupWindow.close();
          window.location.href = `${this.origin}`;
        }
      } catch (_error) {
        // Expected cross-origin error - popup still on auth provider domain
        // Continue polling
      }
    }, POPUP_POLL_INTERVAL_MS);
  }

  federatedAuthWithRedirect(payload: PassflowFederatedAuthPayload): void {
    this.subscribeStore.notify(PassflowEvent.SignInStart, { provider: payload.provider });
    const sscopes = payload.scopes ?? this.scopes;
    const deviceId = this.deviceService.getDeviceId();
    const passflowURL = this.createFederatedAuthUrl({ ...payload, scopes: sscopes, device: deviceId });
    window.location.href = passflowURL;
  }

  // Helper methods for authentication UI redirect
  authRedirectUrl(options: { url?: string; redirectUrl?: string; scopes?: string[]; appId?: string } = {}): string {
    try {
      const { url, redirectUrl, scopes, appId } = options ?? {};
      const externalUrl = new URL(url ?? this.url);
      // add web to the pathname if it's not there
      externalUrl.pathname = (externalUrl.pathname.endsWith('/') ? externalUrl.pathname : externalUrl.pathname + '/') + 'web';
      const sscopes = scopes ?? this.scopes;
      const params: Record<string, string> = {
        appId: appId ?? this.appId ?? '',
        redirectto: redirectUrl ?? window.location.href,
        scopes: sscopes.join(','),
      };

      const queryParams = new URLSearchParams(params);
      externalUrl.search = queryParams.toString();
      return externalUrl.toString();
    } catch (error) {
      const errorPayload: ErrorPayload = {
        message: error instanceof Error ? error.message : 'Failed to create auth redirect URL',
        originalError: error,
      };
      this.subscribeStore.notify(PassflowEvent.Error, errorPayload);
      throw error;
    }
  }

  authRedirect(options: { url?: string; redirectUrl?: string; scopes?: string[]; appId?: string } = {}): void {
    try {
      window.location.href = this.authRedirectUrl(options);
    } catch (error) {
      const errorPayload: ErrorPayload = {
        message: error instanceof Error ? error.message : 'Failed to redirect to auth page',
        originalError: error,
      };
      this.subscribeStore.notify(PassflowEvent.Error, errorPayload);
      throw error;
    }
  }

  /**
   * Check if user is authenticated
   */
  isAuthenticated(parsedTokens: ParsedTokens): boolean {
    try {
      if (!parsedTokens) return false;

      return (
        !isTokenExpired(parsedTokens.access_token) ||
        (!!parsedTokens.refresh_token && !isTokenExpired(parsedTokens.refresh_token))
      );
    } catch (error) {
      const errorPayload: ErrorPayload = {
        message: error instanceof Error ? error.message : 'Failed to check authentication status',
        originalError: error,
      };
      this.subscribeStore.notify(PassflowEvent.Error, errorPayload);
      return false;
    }
  }

  /**
   * Handle session check and callbacks
   */
  async submitSessionCheck(doRefresh = false): Promise<Tokens | undefined> {
    let tokens;
    let parsedTokens;
    try {
      tokens = await this.getTokens(doRefresh);
      parsedTokens = this.tokenCacheService.getParsedTokens();
    } catch (error) {
      const errorPayload: ErrorPayload = {
        message: error instanceof Error || error instanceof PassflowError ? error.message : 'Session check failed',
        originalError: error,
      };
      this.subscribeStore.notify(PassflowEvent.Error, errorPayload);
      tokens = undefined;
    }

    if (tokens && this.sessionCallbacks.createSession) {
      await this.sessionCallbacks.createSession({ tokens, parsedTokens });
    }

    if (!tokens && this.sessionCallbacks.expiredSession) {
      await this.sessionCallbacks.expiredSession();
    }

    return tokens;
  }

  /**
   * Get tokens and refresh if needed
   */
  async getTokens(doRefresh: boolean): Promise<Tokens | undefined> {
    try {
      const tokens = this.storageManager.getTokens();
      // we have no token in storage
      if (!tokens || !tokens.access_token) return undefined;

      const access = parseToken(tokens.access_token);

      if (isTokenExpired(access)) {
        // we have expired token and we need to refresh it or throw error if it's not possible
        if (doRefresh) return await this.refreshToken();

        // we need return undefined here, because we have expired token and we no need to refresh it
        return undefined;
      } else {
        return tokens;
      }
    } catch (error) {
      const errorPayload: ErrorPayload = {
        message: error instanceof Error ? error.message : 'Failed to get tokens',
        originalError: error,
      };
      this.subscribeStore.notify(PassflowEvent.Error, errorPayload);
      return undefined;
    }
  }
}
