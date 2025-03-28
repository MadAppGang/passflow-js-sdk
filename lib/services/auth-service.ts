import { startAuthentication, startRegistration } from '@simplewebauthn/browser';
import axios from 'axios';
import {
  AuthAPI,
  OS,
  PassflowAuthorizationResponse,
  PassflowError,
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
  Providers,
} from '../api';
import { DeviceService } from '../device-service';
import { StorageManager } from '../storage-manager';
import { PassflowEvent, PassflowStore } from '../store';
import { TokenType, isTokenExpired, parseToken } from '../token-service';
import { ParsedTokens, Tokens } from '../types';

/**
 * Service for handling authentication related functionality
 */
export class AuthService {
  constructor(
    private authApi: AuthAPI,
    private deviceService: DeviceService,
    private storageManager: StorageManager,
    private subscribeStore: PassflowStore,
    private scopes: string[],
    private createTenantForNewUser: boolean,
    private origin: string,
    private url: string,
    private sessionCallbacks: {
      createSession?: (tokens?: Tokens) => void;
      expiredSession?: () => void;
    },
    private appId?: string,
  ) {}

  async signIn(payload: PassflowSignInPayload): Promise<PassflowAuthorizationResponse> {
    const deviceId = this.deviceService.getDeviceId();
    const os = OS.web;
    payload.scopes = payload.scopes ?? this.scopes;
    const response = await this.authApi.signIn(payload, deviceId, os);
    response.scopes = payload.scopes;
    this.storageManager.saveTokens(response);
    this.subscribeStore.notify(null, PassflowEvent.SignIn);
    await this.submitSessionCheck();
    return response;
  }

  async signUp(payload: PassflowSignUpPayload): Promise<PassflowAuthorizationResponse> {
    payload.scopes = payload.scopes ?? this.scopes;
    payload.create_tenant = this.createTenantForNewUser;
    const response = await this.authApi.signUp(payload);
    response.scopes = payload.scopes;
    this.storageManager.saveTokens(response);
    this.subscribeStore.notify(null, PassflowEvent.Register);
    await this.submitSessionCheck();
    return response;
  }

  passwordlessSignIn(payload: PassflowPasswordlessSignInPayload): Promise<PassflowPasswordlessResponse> {
    payload.scopes = payload.scopes ?? this.scopes;
    const deviceId = this.deviceService.getDeviceId();
    const os = OS.web;
    return this.authApi.passwordlessSignIn(payload, deviceId, os);
  }

  async passwordlessSignInComplete(payload: PassflowPasswordlessSignInCompletePayload): Promise<PassflowValidationResponse> {
    payload.scopes = payload.scopes ?? this.scopes;
    payload.device = this.deviceService.getDeviceId();
    const response = await this.authApi.passwordlessSignInComplete(payload);
    response.scopes = payload.scopes;
    this.storageManager.saveTokens(response);
    this.subscribeStore.notify(null, PassflowEvent.SignIn);
    await this.submitSessionCheck();
    return response;
  }

  async logOut() {
    const refreshToken = this.storageManager.getToken(TokenType.refresh_token);
    const deviceId = this.storageManager.getDeviceId();

    try {
      const status = await this.authApi.logOut(deviceId, refreshToken, !this.appId);
      if (status.result !== 'ok') {
        this.subscribeStore.notify(null, PassflowEvent.Error);
      }
    } catch (error) {
      // biome-ignore lint/suspicious/noConsole: <explanation>
      console.error(error);
      this.subscribeStore.notify(null, PassflowEvent.Error);
    }

    this.storageManager.deleteTokens();
    this.subscribeStore.notify(null, PassflowEvent.SignOut);
    await this.submitSessionCheck();
  }

  async refreshToken(): Promise<PassflowAuthorizationResponse> {
    const tokens = this.storageManager.getTokens();
    if (!tokens) {
      throw new Error('No tokens found');
    } else if (!tokens?.refresh_token) {
      throw new Error('No refresh token found');
    }

    const oldScopes = tokens?.scopes ?? this.scopes;
    try {
      const response = await this.authApi.refreshToken(tokens?.refresh_token ?? '', oldScopes, tokens?.access_token);
      response.scopes = oldScopes;
      this.storageManager.saveTokens(response);
      this.subscribeStore.notify(null, PassflowEvent.Refresh);
      return response;
    } catch (error) {
      if (error instanceof PassflowError) {
        throw error;
      } else if (axios.isAxiosError(error) && error.response && error.response?.status >= 400 && error.response?.status < 500) {
        throw new Error(`Getting unknown error message from server with code:${error.response.status}`);
      } else {
        this.subscribeStore.notify(null, PassflowEvent.Error);
        throw error;
      }
    }
  }

  sendPasswordResetEmail(payload: PassflowSendPasswordResetEmailPayload): Promise<PassflowSuccessResponse> {
    return this.authApi.sendPasswordResetEmail(payload);
  }

  async resetPassword(newPassword: string, scopes?: string[]): Promise<PassflowAuthorizationResponse> {
    const urlParams = new URLSearchParams(window.location.search);
    const resetToken = urlParams.get('token') ?? undefined;
    const sscopes = scopes ?? this.scopes;

    const response = await this.authApi.resetPassword(newPassword, sscopes, resetToken);
    response.scopes = sscopes;
    this.storageManager.saveTokens(response);
    this.subscribeStore.notify(null, PassflowEvent.SignIn);
    await this.submitSessionCheck();
    return response;
  }

  async passkeyRegister(payload: PassflowPasskeyRegisterStartPayload): Promise<PassflowAuthorizationResponse> {
    const deviceId = this.deviceService.getDeviceId();
    const os = OS.web;
    payload.scopes = payload.scopes ?? this.scopes;
    payload.create_tenant = this.createTenantForNewUser;
    const { challenge_id, publicKey } = await this.authApi.passkeyRegisterStart(payload, deviceId, os, !this.appId);
    // user handle should be base64 encoded for simplewebauthn lib we are using
    publicKey.user.id = btoa(publicKey.user.id);
    const webauthn = await startRegistration({
      optionsJSON: publicKey,
    });

    const responseRegisterComplete = await this.authApi.passkeyRegisterComplete(webauthn, deviceId, challenge_id, !this.appId);
    responseRegisterComplete.scopes = payload.scopes;
    this.storageManager.saveTokens(responseRegisterComplete);
    this.subscribeStore.notify(null, PassflowEvent.Register);
    await this.submitSessionCheck();
    return responseRegisterComplete;
  }

  async passkeyAuthenticate(payload: PassflowPasskeyAuthenticateStartPayload): Promise<PassflowAuthorizationResponse> {
    const deviceId = this.deviceService.getDeviceId();
    const os = OS.web;
    payload.scopes = payload.scopes ?? this.scopes;
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
      this.subscribeStore.notify(null, PassflowEvent.SignIn);
      await this.submitSessionCheck();
    }

    return responseAuthenticateComplete;
  }

  createFederatedAuthUrl(provider: Providers, redirect_url: string, scopes?: string[]): string {
    const passflowPathWithProvider = `/api/auth/provider/${provider}`;

    if (!this.appId) throw new Error('AppId is required for federated auth');
    const sscopes = scopes ?? this.scopes;

    const params: Record<string, string> = {
      scopes: sscopes.join(' '),
      redirect_url: redirect_url ?? this.origin,
      appId: this.appId,
    };

    const url = new URL(passflowPathWithProvider, this.url);
    const queryParams = new URLSearchParams(params);
    url.search = queryParams.toString();

    return url.toString();
  }

  federatedAuthWithPopup(provider: Providers, redirect_url: string, scopes?: string[]): void {
    const sscopes = scopes ?? this.scopes;
    const passflowURL = this.createFederatedAuthUrl(provider, redirect_url, sscopes);

    const popupWindow = window.open(passflowURL, '_blank', 'width=500,height=500');

    if (!popupWindow) {
      this.federatedAuthWithRedirect(provider, redirect_url, sscopes);
    } else {
      const checkInterval = setInterval(() => {
        if (popupWindow.location.href.startsWith(this.origin)) {
          const urlParams = new URLSearchParams(popupWindow.location.search);
          const access_token = urlParams.get('access_token') || '';
          const refresh_token = urlParams.get('refresh_token') || '';
          const id_token = urlParams.get('id_token') || '';

          const tokensData = {
            access_token,
            refresh_token,
            id_token,
            scopes: sscopes,
          };
          this.storageManager.saveTokens(tokensData);
          this.subscribeStore.notify(null, PassflowEvent.SignIn);
          window.location.href = `${this.origin}`;
          clearInterval(checkInterval);
          popupWindow.close();
        }
      }, 100);
    }
  }

  federatedAuthWithRedirect(provider: Providers, redirect_url: string, scopes?: string[]): void {
    const sscopes = scopes ?? this.scopes;
    const passflowURL = this.createFederatedAuthUrl(provider, redirect_url, sscopes);
    window.location.href = passflowURL;
  }

  // Helper methods for authentication UI redirect
  authRedirectUrl(
    options: {
      url?: string;
      redirectUrl?: string;
      scopes?: string[];
      appId?: string;
    } = {},
  ): string {
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
  }

  authRedirect(
    options: {
      url?: string;
      redirectUrl?: string;
      scopes?: string[];
      appId?: string;
    } = {},
  ): void {
    window.location.href = this.authRedirectUrl(options);
  }

  /**
   * Check if user is authenticated
   */
  isAuthenticated(parsedTokens: ParsedTokens): boolean {
    if (!parsedTokens) return false;

    return (
      !isTokenExpired(parsedTokens.access_token) ||
      (!!parsedTokens.refresh_token && !isTokenExpired(parsedTokens.refresh_token))
    );
  }

  /**
   * Handle session check and callbacks
   */
  async submitSessionCheck(doRefresh = false): Promise<Tokens | undefined> {
    const tokens = await this.getTokens(doRefresh);

    if (tokens && this.sessionCallbacks.createSession) {
      this.sessionCallbacks.createSession(tokens);
    }

    if (!tokens && this.sessionCallbacks.expiredSession) {
      this.sessionCallbacks.expiredSession();
    }

    return tokens;
  }

  /**
   * Get tokens and refresh if needed
   */
  async getTokens(doRefresh: boolean): Promise<Tokens | undefined> {
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
  }
}
