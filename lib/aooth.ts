/* eslint-disable complexity */
import { startAuthentication, startRegistration } from '@simplewebauthn/browser';

import {
  AoothAuthorizationResponse,
  AoothConfig,
  AoothEndpointPaths,
  AoothError,
  AoothInsecureLoginPayload,
  AoothInviteResponse,
  AoothPasskeyAuthenticateStartPayload,
  AoothPasskeyRegisterCompleteMessage,
  AoothPasskeyRegisterStartPayload,
  AoothPasskeySettings,
  AoothPasswordPolicySettings,
  AoothPasswordlessSignInCompletePayload,
  AoothPasswordlessSignInPayload,
  AoothSendPasswordResetEmailPayload,
  AoothSettingsAll,
  AoothSignInPayload,
  AoothSignUpPayload,
  AoothSuccessResponse,
  AoothTenantResponse,
  AoothUserPasskey,
  AppAPI,
  AppSettings,
  AuthAPI,
  OS,
  SettingAPI,
  TenantAPI,
  UserAPI,
} from './api';
import { AOOTH_CLOUD_URL, DEFAULT_SCOPES } from './constants';
import { DeviceService } from './device-service';
import { StorageManager } from './storage-manager';
import { AoothEvent, AoothStore, AoothSubscriber } from './store';
import { Providers, TokenService, TokenType, isTokenExpired, parseToken } from './token-service';
import { ParsedTokens, Tokens } from './types';
import axios from 'axios';

export class Aooth {
  private authApi: AuthAPI;
  private appApi: AppAPI;
  private userApi: UserAPI;
  private settingApi: SettingAPI;
  private tenantAPI: TenantAPI;
  private scopes: string[];
  private createTenantForNewUser: boolean;
  private subscribeStore: AoothStore;

  deviceService: DeviceService;
  storageManager: StorageManager;
  tokenService: TokenService;
  tokensCache: Tokens | undefined;
  parsedTokensCache: ParsedTokens | undefined;

  origin = window.location.origin;
  url: string;
  appId?: string;

  constructor(config: AoothConfig) {
    const { url, appId, scopes } = config;
    this.url = url || AOOTH_CLOUD_URL;
    this.appId = appId;

    this.authApi = new AuthAPI(config);
    this.appApi = new AppAPI(config);
    this.userApi = new UserAPI(config);
    this.settingApi = new SettingAPI(config);
    this.tenantAPI = new TenantAPI(config);
    this.storageManager = new StorageManager();
    this.tokenService = new TokenService();
    this.deviceService = new DeviceService();
    this.scopes = scopes ?? DEFAULT_SCOPES;
    this.createTenantForNewUser = config.createTenantForNewUser ?? false;
    this.subscribeStore = new AoothStore();

    this.checkAndSetTokens();
  }

  // subscribe to authentication events, empty 't' means all event types
  subscribe(s: AoothSubscriber, t?: AoothEvent[]) {
    this.subscribeStore.subscribe(s, t);
  }

  // unsubscribe from  authentication events, empty 't' means all event
  unsubscribe(s: AoothSubscriber, t?: AoothEvent[]) {
    this.subscribeStore.unsubscribe(s, t);
  }

  // handleTokensRedirect - handles tokens from URL params
  handleTokensRedirect(): Tokens | undefined {
    //TODO: check challenge ID for PCKE
    //if we have PCKE - we have to run post request and exchange PCKE challenge for tokens with Post request
    //instead of getting token from URL
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
      tokens = {
        access_token,
        refresh_token: refresh_token ?? undefined,
        id_token: id_token ?? undefined,
        scopes,
      };
      this.storageManager.saveTokens(tokens);
      this.setTokensCache(tokens);
      this.subscribeStore.notify(this, AoothEvent.SignIn);
    }

    urlParams.delete('access_token');
    urlParams.delete('refresh_token');
    urlParams.delete('id_token');
    urlParams.delete('client_challenge');
    urlParams.delete('scopes');

    if (urlParams.size > 0)
      window.history.replaceState({}, document.title, `${window.location.pathname}?${urlParams.toString()}`);
    else window.history.replaceState({}, document.title, window.location.pathname);

    return tokens;
  }

  private createFederatedAuthUrl(provider: Providers, redirect_url: string, scopes?: string[]): string {
    const aoothPathWithProvider = `${AoothEndpointPaths.signInWithProvider}${provider}`;

    if (!this.appId) throw new Error('AppId is required for federated auth');
    const sscopes = scopes ?? this.scopes;

    const params: Record<string, string> = {
      scopes: sscopes.join(' '),
      redirect_url: redirect_url ?? this.origin,
      appId: this.appId,
    };

    const url = new URL(aoothPathWithProvider, this.url);
    const queryParams = new URLSearchParams(params);
    url.search = queryParams.toString();

    return url.toString();
  }

  generateExternalAoothUrl(url: string, scopes?: string[]): string {
    const externalUrl = new URL(url);

    const sscopes = scopes ?? this.scopes;
    const params: Record<string, string> = {
      appId: this.appId ?? '',
      redirectto: this.origin,
      scopes: sscopes.join(','),
    };

    const queryParams = new URLSearchParams(params);
    externalUrl.search = queryParams.toString();

    return externalUrl.toString();
  }

  authCloudRedirect(cloudAoothUrl: string, scopes?: string[]): void {
    window.location.href = this.generateExternalAoothUrl(cloudAoothUrl, scopes);
  }

  async getTokens(doRefresh: boolean): Promise<Tokens | undefined> {
    const tokens = this.storageManager.getTokens();
    // we have not token in storage
    if (!tokens || !tokens.access_token) return undefined;

    const access = parseToken(tokens.access_token);

    if (isTokenExpired(access) && doRefresh) {
      return this.refreshToken();
    } else {
      this.setTokensCache(tokens);
      return tokens;
    }
  }

  setTokensCache(tokens: Tokens | undefined): void {
    this.tokensCache = tokens;
    if (tokens) {
      this.parsedTokensCache = {
        access_token: parseToken(tokens.access_token),
        id_token: tokens.id_token ? parseToken(tokens.id_token) : undefined,
        refresh_token: tokens.refresh_token ? parseToken(tokens.refresh_token) : undefined,
        scopes: tokens.scopes,
      };
    } else {
      this.parsedTokensCache = undefined;
    }
  }

  getTokensCache(): Tokens | undefined {
    return this.tokensCache;
  }

  getParsedTokenCache(): ParsedTokens | undefined {
    return this.parsedTokensCache;
  }

  async signIn(payload: AoothSignInPayload): Promise<AoothAuthorizationResponse> {
    const deviceId = this.deviceService.getDeviceId();
    const os = OS.web;
    payload.scopes = payload.scopes ?? this.scopes;
    const response = await this.authApi.signIn(payload, deviceId, os);
    response.scopes = payload.scopes;
    this.storageManager.saveTokens(response);
    this.setTokensCache(response);
    this.subscribeStore.notify(this, AoothEvent.SignIn);
    return response;
  }

  async signUp(payload: AoothSignUpPayload): Promise<AoothAuthorizationResponse> {
    payload.scopes = payload.scopes ?? this.scopes;
    payload.create_tenant = this.createTenantForNewUser;
    const response = await this.authApi.signUp(payload);
    response.scopes = payload.scopes;
    this.storageManager.saveTokens(response);
    this.setTokensCache(response);
    this.subscribeStore.notify(this, AoothEvent.Register);
    return response;
  }

  async passwordlessSignIn(payload: AoothPasswordlessSignInPayload): Promise<AoothSuccessResponse> {
    payload.scopes = payload.scopes ?? this.scopes;
    const deviceId = this.deviceService.getDeviceId();
    const os = OS.web;
    return this.authApi.passwordlessSignIn(payload, deviceId, os);
  }

  async passwordlessSignInComplete(payload: AoothPasswordlessSignInCompletePayload): Promise<AoothAuthorizationResponse> {
    payload.scopes = payload.scopes ?? this.scopes;
    const response = await this.authApi.passwordlessSignInComplete(payload);
    response.scopes = payload.scopes;
    this.storageManager.saveTokens(response);
    this.setTokensCache(response);
    this.subscribeStore.notify(this, AoothEvent.SignIn);
    return response;
  }

  async logOut(): Promise<AoothSuccessResponse> {
    const refreshToken = this.storageManager.getToken(TokenType.refresh_token);
    const deviceId = this.storageManager.getDeviceId();

    const status = await this.authApi.logOut(deviceId, refreshToken, !this.appId);
    //event if we have signout error, we could not keep forcefully user authenticated
    if (status.result !== 'ok') {
      this.subscribeStore.notify(this, AoothEvent.Error);
    }
    // handle error here?
    this.storageManager.deleteTokens();
    this.setTokensCache(undefined);
    this.subscribeStore.notify(this, AoothEvent.SignOut);
    return status;
  }

  federatedAuthWithPopup(provider: Providers, redirect_url: string, scopes?: string[]): void {
    const sscopes = scopes ?? this.scopes;
    const aoothURL = this.createFederatedAuthUrl(provider, redirect_url, sscopes);

    const popupWindow = window.open(aoothURL, '_blank', 'width=500,height=500');

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
            sscopes,
          };
          this.storageManager.saveTokens(tokensData);
          this.setTokensCache(tokensData);
          this.subscribeStore.notify(this, AoothEvent.SignIn);
          window.location.href = `${this.origin}`;
          clearInterval(checkInterval);
          popupWindow.close();
        }
      }, 100);
    }
  }

  federatedAuthWithRedirect(provider: Providers, redirect_url: string, scopes?: string[]): void {
    const sscopes = scopes ?? this.scopes;
    const aoothURL = this.createFederatedAuthUrl(provider, redirect_url, sscopes);
    window.location.href = aoothURL;
  }

  reset(error?: string) {
    this.storageManager.deleteTokens();
    this.setTokensCache(undefined);
    this.subscribeStore.notify(this, AoothEvent.SignOut);
    if (error) {
      this.subscribeStore.notify(this, AoothEvent.Error);
      throw new Error(error);
    }
  }

  async refreshToken(): Promise<AoothAuthorizationResponse> {
    const tokens = this.storageManager.getTokens();
    if (!tokens) {
      this.reset('No tokens found'); //throws
    } else if (!tokens?.refresh_token) {
      this.reset('No refresh token found'); //throws
    }

    const oldScopes = tokens?.scopes ?? this.scopes;
    try {
      const response = await this.authApi.refreshToken(tokens?.refresh_token ?? '', oldScopes, tokens?.access_token);
      response.scopes = oldScopes;
      this.storageManager.saveTokens(response);
      this.setTokensCache(response);
      this.subscribeStore.notify(this, AoothEvent.Refresh);
      return response;
    } catch (error) {
      if (error instanceof AoothError) {
        this.reset(error.message);
      } else if (axios.isAxiosError(error) && error.response && error.response?.status >= 400 && error.response?.status < 500) {
        this.reset(`Getting unknown error message from server with code:${error.response.status}`);
      } else {
        // this error means we have some network or other error
        // we don't need to reset state
        // let's just notify subscribers and rethrow the error
        this.subscribeStore.notify(this, AoothEvent.Error);
        throw error;
      }
    }
    // we should not be there ....
    throw new Error('Unexpected behavior');
  }

  async sendPasswordResetEmail(payload: AoothSendPasswordResetEmailPayload): Promise<AoothSuccessResponse> {
    return this.authApi.sendPasswordResetEmail(payload);
  }

  async resetPassword(newPassword: string, scopes?: string[]): Promise<AoothAuthorizationResponse> {
    const urlParams = new URLSearchParams(window.location.search);
    const resetToken = urlParams.get('token') ?? undefined;
    const sscopes = scopes ?? this.scopes;

    const response = await this.authApi.resetPassword(newPassword, sscopes, resetToken);
    response.scopes = sscopes;
    this.storageManager.saveTokens(response);
    this.setTokensCache(response);
    this.subscribeStore.notify(this, AoothEvent.SignIn);
    return response;
  }

  async getAppSettings(): Promise<AppSettings> {
    return this.appApi.getAppSettings();
  }

  async getSettingsAll(): Promise<AoothSettingsAll> {
    return this.settingApi.getSettingsAll();
  }

  async getPasswordPolicySettings(): Promise<AoothPasswordPolicySettings> {
    return this.settingApi.getPasswordPolicySettings();
  }

  async getPasskeySettings(): Promise<AoothPasskeySettings> {
    return this.settingApi.getPasskeySettings();
  }

  async passkeyRegister(
    payload: AoothPasskeyRegisterStartPayload,
  ): Promise<AoothAuthorizationResponse | AoothPasskeyRegisterCompleteMessage> {
    const deviceId = this.deviceService.getDeviceId();
    const os = OS.web;
    payload.scopes = payload.scopes ?? this.scopes;
    payload.create_tenant = this.createTenantForNewUser;
    const { challenge_id, publicKey } = await this.authApi.passkeyRegisterStart(payload, deviceId, os, !this.appId);

    const webauthn = await startRegistration(publicKey);

    const responseRegisterComplete = await this.authApi.passkeyRegisterComplete(webauthn, deviceId, challenge_id, !this.appId);

    if ('access_token' in responseRegisterComplete) {
      responseRegisterComplete.scopes = payload.scopes;
      this.storageManager.saveTokens(responseRegisterComplete);
      this.setTokensCache(responseRegisterComplete);
      this.subscribeStore.notify(this, AoothEvent.Register);
    }

    return responseRegisterComplete;
  }

  async passkeyAuthenticate(payload: AoothPasskeyAuthenticateStartPayload): Promise<AoothAuthorizationResponse> {
    const deviceId = this.deviceService.getDeviceId();
    const os = OS.web;
    payload.scopes = payload.scopes ?? this.scopes;

    const { challenge_id, publicKey } = await this.authApi.passkeyAuthenticateStart(payload, deviceId, os, !this.appId);

    const webauthn = await startAuthentication(publicKey);

    const responseAuthenticateComplete = await this.authApi.passkeyAuthenticateComplete(
      webauthn,
      deviceId,
      challenge_id,
      !this.appId,
    );

    if ('access_token' in responseAuthenticateComplete) {
      responseAuthenticateComplete.scopes = payload.scopes;
      this.storageManager.saveTokens(responseAuthenticateComplete);
      this.setTokensCache(responseAuthenticateComplete);
      this.subscribeStore.notify(this, AoothEvent.SignIn);
    }

    return responseAuthenticateComplete;
  }

  // TODO: Question, why do we need validate passkey with otp?
  // TODO: and if we need, how to get scopes here?
  async passkeyValidate(otp: string, challengeId: string): Promise<AoothAuthorizationResponse> {
    const deviceId = this.deviceService.getDeviceId();

    const responseValidate = await this.authApi.passkeyValidate(otp, deviceId, challengeId, !this.appId);

    if ('access_token' in responseValidate) {
      this.storageManager.saveTokens(responseValidate);
      this.setTokensCache(responseValidate);
    }

    return responseValidate;
  }

  async loginInsecure(payload: AoothInsecureLoginPayload): Promise<AoothAuthorizationResponse> {
    const response = await this.authApi.loginInsecure(payload);
    this.storageManager.saveTokens(response);
    this.setTokensCache(response);
    this.subscribeStore.notify(this, AoothEvent.SignIn);
    return response;
  }

  async getUserPasskeys(): Promise<AoothUserPasskey> {
    return this.userApi.getUserPasskeys();
  }

  async renameUserPasskey(name: string, passkeyId: string): Promise<AoothSuccessResponse> {
    return this.userApi.renameUserPasskey(name, passkeyId);
  }

  async deleteUserPasskey(passkeyId: string): Promise<AoothSuccessResponse> {
    return this.userApi.deleteUserPasskey(passkeyId);
  }

  async createUserPasskey(
    relyingPartyId: string,
    scopes: string[] = this.scopes,
  ): Promise<AoothAuthorizationResponse | AoothPasskeyRegisterCompleteMessage> {
    const deviceId = this.deviceService.getDeviceId();
    const os = OS.web;

    const { challenge_id, publicKey } = await this.userApi.createUserPasskeyStart(
      relyingPartyId,
      deviceId,
      os,
      this.createTenantForNewUser,
      scopes,
    );

    const webauthn = await startRegistration(publicKey);

    const responseCreateComplete = await this.userApi.createUserPasskeyComplete(webauthn, deviceId, challenge_id);

    if ('access_token' in responseCreateComplete) {
      responseCreateComplete.scopes = scopes;
      this.storageManager.saveTokens(responseCreateComplete);
      this.setTokensCache(responseCreateComplete);
      this.subscribeStore.notify(this, AoothEvent.Register);
    }

    return responseCreateComplete;
  }

  async joinInvitation(token: string, scopes?: string[]): Promise<AoothInviteResponse> {
    const sscopes = scopes ?? this.scopes;
    return this.tenantAPI.joinInvitation(token, sscopes);
  }

  async createTenant(name: string, refreshToken?: boolean): Promise<AoothTenantResponse> {
    const tenant = this.tenantAPI.createTenant(name);
    if (refreshToken) {
      await this.refreshToken();
    }
    return tenant;
  }
}
