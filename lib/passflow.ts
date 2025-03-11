/* eslint-disable complexity */
import { startAuthentication, startRegistration } from '@simplewebauthn/browser';
import axios from 'axios';

import {
  AppAPI,
  type AppSettings,
  AuthAPI,
  OS,
  type PassflowAuthorizationResponse,
  type PassflowConfig,
  PassflowEndpointPaths,
  PassflowError,
  type PassflowInviteResponse,
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
  type Providers,
  SettingAPI,
  TenantAPI,
  UserAPI,
} from './api';
import { DEFAULT_SCOPES, PASSFLOW_CLOUD_URL } from './constants';
import { DeviceService } from './device-service';
import { StorageManager } from './storage-manager';
import { PassflowEvent, PassflowStore, type PassflowSubscriber } from './store';
import { TokenService, TokenType, isTokenExpired, parseToken } from './token-service';

import type { ParsedTokens, SessionParams, Tokens } from './types';

export class Passflow {
  private authApi: AuthAPI;
  private appApi: AppAPI;
  private userApi: UserAPI;
  private settingApi: SettingAPI;
  private tenantAPI: TenantAPI;
  private scopes: string[];
  private createTenantForNewUser: boolean;
  private subscribeStore: PassflowStore;

  private doRefreshTokens = false;
  private createSessionCallback?: (tokens?: Tokens) => void;
  private expiredSessionCallback?: () => void;

  session: ({ createSession, expiredSession, doRefresh }: SessionParams) => void = async ({
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
    const tokens = await this.getTokens(this.doRefreshTokens);

    if (tokens && this.createSessionCallback) {
      this.createSessionCallback(this.tokensCache);
    }

    if (!tokens && this.expiredSessionCallback) {
      this.expiredSessionCallback();
    }
  }

  deviceService: DeviceService;
  storageManager: StorageManager;
  tokenService: TokenService;
  tokensCache: Tokens | undefined;
  parsedTokensCache: ParsedTokens | undefined;

  origin = window.location.origin;
  url: string;
  appId?: string;

  constructor(config: PassflowConfig) {
    const { url, appId, scopes } = config;
    this.url = url || PASSFLOW_CLOUD_URL;
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
    this.subscribeStore = new PassflowStore();

    // if parseQueryParams is true, we will check for tokens in the query params
    if (config.parseQueryParams) {
      this.checkAndSetTokens();
    } 
    this.setTokensToCacheFromLocalStorage();    
  }

  // subscribe to authentication events, empty 't' means all event types
  subscribe(s: PassflowSubscriber, t?: PassflowEvent[]) {
    this.subscribeStore.subscribe(s, t);
  }

  // unsubscribe from  authentication events, empty 't' means all event
  unsubscribe(s: PassflowSubscriber, t?: PassflowEvent[]) {
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
      this.subscribeStore.notify(this, PassflowEvent.SignIn);
      this.submitSessionCheck();
    }

    urlParams.delete('access_token');
    urlParams.delete('refresh_token');
    urlParams.delete('id_token');
    urlParams.delete('client_challenge');

    if (urlParams.size > 0) {
      window.history.replaceState({}, document.title, `${window.location.pathname}?${urlParams.toString()}`);
    } else {
      window.history.replaceState({}, document.title, window.location.pathname);
    }

    return tokens;
  }

  private setTokensToCacheFromLocalStorage(): void {
    const tokens = this.storageManager.getTokens();
    if (tokens) {
      this.setTokensCache(tokens);
    }
  }

  private createFederatedAuthUrl(provider: Providers, redirect_url: string, scopes?: string[]): string {
    const passflowPathWithProvider = `${PassflowEndpointPaths.signInWithProvider}${provider}`;

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

  generateExternalPassflowUrl(url: string, scopes?: string[]): string {
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

  authCloudRedirect(cloudPassflowUrl: string, scopes?: string[]): void {
    window.location.href = this.generateExternalPassflowUrl(cloudPassflowUrl, scopes);
  }

  getTokens(doRefresh: boolean): Promise<Tokens | undefined> {
    const tokens = this.storageManager.getTokens();
    // we have not token in storage
    if (!tokens || !tokens.access_token) return Promise.resolve(undefined);

    const access = parseToken(tokens.access_token);

    if (isTokenExpired(access)) {
      // we have expired token and we need to refresh it or throw error if it's not possible
      if (doRefresh) return this.refreshToken();

      // we need return undefined here, because we have expired token and we no need to refresh it
      return Promise.resolve(undefined);
    } else {
      this.setTokensCache(tokens);
      return Promise.resolve(tokens);
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

  async signIn(payload: PassflowSignInPayload): Promise<PassflowAuthorizationResponse> {
    const deviceId = this.deviceService.getDeviceId();
    const os = OS.web;
    payload.scopes = payload.scopes ?? this.scopes;
    const response = await this.authApi.signIn(payload, deviceId, os);
    response.scopes = payload.scopes;
    this.storageManager.saveTokens(response);
    this.setTokensCache(response);
    this.subscribeStore.notify(this, PassflowEvent.SignIn);
    await this.submitSessionCheck();
    return response;
  }

  async signUp(payload: PassflowSignUpPayload): Promise<PassflowAuthorizationResponse> {
    payload.scopes = payload.scopes ?? this.scopes;
    payload.create_tenant = this.createTenantForNewUser;
    const response = await this.authApi.signUp(payload);
    response.scopes = payload.scopes;
    this.storageManager.saveTokens(response);
    this.setTokensCache(response);
    this.subscribeStore.notify(this, PassflowEvent.Register);
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
    this.setTokensCache(response);
    this.subscribeStore.notify(this, PassflowEvent.SignIn);
    await this.submitSessionCheck();
    return response;
  }

  async logOut(): Promise<PassflowSuccessResponse> {
    const refreshToken = this.storageManager.getToken(TokenType.refresh_token);
    const deviceId = this.storageManager.getDeviceId();

    const status = await this.authApi.logOut(deviceId, refreshToken, !this.appId);
    //event if we have signout error, we could not keep forcefully user authenticated
    if (status.result !== 'ok') {
      this.subscribeStore.notify(this, PassflowEvent.Error);
    }
    // handle error here?
    this.storageManager.deleteTokens();
    this.setTokensCache(undefined);
    this.subscribeStore.notify(this, PassflowEvent.SignOut);
    await this.submitSessionCheck();
    return status;
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
            sscopes,
          };
          this.storageManager.saveTokens(tokensData);
          this.setTokensCache(tokensData);
          this.subscribeStore.notify(this, PassflowEvent.SignIn);
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

  reset(error?: string) {
    this.storageManager.deleteTokens();
    this.setTokensCache(undefined);
    this.subscribeStore.notify(this, PassflowEvent.SignOut);
    if (error) {
      this.subscribeStore.notify(this, PassflowEvent.Error);
      throw new Error(error);
    }
  }

  async refreshToken(): Promise<PassflowAuthorizationResponse> {
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
      this.subscribeStore.notify(this, PassflowEvent.Refresh);
      return response;
    } catch (error) {
      if (error instanceof PassflowError) {
        this.reset(error.message);
      } else if (axios.isAxiosError(error) && error.response && error.response?.status >= 400 && error.response?.status < 500) {
        this.reset(`Getting unknown error message from server with code:${error.response.status}`);
      } else {
        // this error means we have some network or other error
        // we don't need to reset state
        // let's just notify subscribers and rethrow the error
        this.subscribeStore.notify(this, PassflowEvent.Error);
        throw error;
      }
    }
    // we should not be there ....
    throw new Error('Unexpected behavior');
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
    this.setTokensCache(response);
    this.subscribeStore.notify(this, PassflowEvent.SignIn);
    await this.submitSessionCheck();
    return response;
  }

  getAppSettings(): Promise<AppSettings> {
    return this.appApi.getAppSettings();
  }

  getSettingsAll(): Promise<PassflowSettingsAll> {
    return this.settingApi.getSettingsAll();
  }

  getPasswordPolicySettings(): Promise<PassflowPasswordPolicySettings> {
    return this.settingApi.getPasswordPolicySettings();
  }

  getPasskeySettings(): Promise<PassflowPasskeySettings> {
    return this.settingApi.getPasskeySettings();
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
    this.setTokensCache(responseRegisterComplete);
    this.subscribeStore.notify(this, PassflowEvent.Register);
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
      this.setTokensCache(responseAuthenticateComplete);
      this.subscribeStore.notify(this, PassflowEvent.SignIn);
      await this.submitSessionCheck();
    }

    return responseAuthenticateComplete;
  }

  async setTokens(tokens: Tokens): Promise<Tokens> {
    this.storageManager.saveTokens(tokens);
    this.setTokensCache(tokens);
    this.subscribeStore.notify(this, PassflowEvent.SignIn);
    await this.submitSessionCheck();
    return tokens;
  }

  getUserPasskeys() {
    return this.userApi.getUserPasskeys();
  }

  renameUserPasskey(name: string, passkeyId: string): Promise<PassflowSuccessResponse> {
    return this.userApi.renameUserPasskey(name, passkeyId);
  }

  deleteUserPasskey(passkeyId: string): Promise<PassflowSuccessResponse> {
    return this.userApi.deleteUserPasskey(passkeyId);
  }

  async addUserPasskey({
    relyingPartyId,
    passkeyUsername,
    passkeyDisplayName,
  }: { relyingPartyId?: string; passkeyUsername?: string; passkeyDisplayName?: string } = {}): Promise<void> {
    const deviceId = this.deviceService.getDeviceId();
    const os = OS.web;
    const { challenge_id, publicKey } = await this.userApi.addUserPasskeyStart({
      relyingPartyId: relyingPartyId || window?.location?.hostname,
      deviceId,
      os,
      passkeyDisplayName,
      passkeyUsername,
    });
    // user handle should be base64 encoded for simplewebauthn lib we are using
    publicKey.user.id = btoa(publicKey.user.id); 
    const webauthn = await startRegistration({ optionsJSON: publicKey });
    return await this.userApi.addUserPasskeyComplete(webauthn, deviceId, challenge_id);
  }

  joinInvitation(token: string, scopes?: string[]): Promise<PassflowInviteResponse> {
    const sscopes = scopes ?? this.scopes;
    return this.tenantAPI.joinInvitation(token, sscopes);
  }

  async createTenant(name: string, refreshToken?: boolean): Promise<PassflowTenantResponse> {
    const tenant = this.tenantAPI.createTenant(name);
    if (refreshToken) {
      await this.refreshToken();
    }
    return tenant;
  }
}
