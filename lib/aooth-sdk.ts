import { startAuthentication, startRegistration } from '@simplewebauthn/browser';

import {
  AoothAuthorizationResponse,
  AoothConfig,
  AoothEndpointPaths,
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
import { Providers, TokenService, TokenType } from './token-service';
import { Tokens } from './types';

export class Aooth {
  private authApi: AuthAPI;
  private appApi: AppAPI;
  private userApi: UserAPI;
  private settingApi: SettingAPI;
  private tenantAPI: TenantAPI;
  deviceService: DeviceService;
  storageManager: StorageManager;
  tokenService: TokenService;

  origin = window.location.origin;
  url: string;
  appId?: string;

  constructor(config: AoothConfig) {
    const { url, appId } = config;
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

    this.checkAndSetTokens();
  }

  private checkAndSetTokens(): void {
    const urlParams = new URLSearchParams(window.location.search);
    const access_token = urlParams.get('access_token');
    const refresh_token = urlParams.get('refresh_token');
    const id_token = urlParams.get('id_token');

    this.tokenService.saveTokens(access_token ?? '', refresh_token, id_token);
    if (urlParams.size > 0)
      window.history.replaceState({}, document.title, `${window.location.pathname}?${urlParams.toString()}`);
    else window.history.replaceState({}, document.title, window.location.pathname);

    urlParams.delete('access_token');
    urlParams.delete('refresh_token');
    urlParams.delete('id_token');
    urlParams.delete('client_challenge');
  }

  private createFederatedAuthUrl(provider: Providers, redirect_url: string, scopes: string[]): string {
    const aoothPathWithProvider = `${AoothEndpointPaths.signInWithProvider}${provider}`;

    if (!this.appId) throw new Error('AppId is required for federated auth');

    const params: Record<string, string> = {
      scopes: scopes.join(' '),
      redirect_url: redirect_url ?? this.origin,
      appId: this.appId,
    };

    const url = new URL(aoothPathWithProvider, this.url);
    const queryParams = new URLSearchParams(params);
    url.search = queryParams.toString();

    return url.toString();
  }

  generateExternalAoothUrl(url: string): string {
    const externalUrl = new URL(url);

    const params: Record<string, string> = {
      appId: this.appId ?? '',
      redirectto: this.origin,
    };

    const queryParams = new URLSearchParams(params);
    externalUrl.search = queryParams.toString();

    return externalUrl.toString();
  }

  authCloudRedirect(cloudAoothUrl: string): void {
    window.location.href = this.generateExternalAoothUrl(cloudAoothUrl);
  }

  async getTokens(): Promise<Tokens | null> {
    const tokens = this.storageManager.getTokens();
    // we have not token in storage
    if (!tokens || !tokens.access_token) return null;

    const access = this.tokenService.parseToken(tokens.access_token);
    if (!access) return null;

    if (this.tokenService.isTokenExpired(access)) {
      const scopes = tokens.scopes ?? DEFAULT_SCOPES;
      return this.refreshToken(scopes);
    } else {
      return tokens;
    }
  }

  async signIn(payload: AoothSignInPayload): Promise<AoothAuthorizationResponse> {
    const deviceId = this.deviceService.getDeviceId();
    const os = OS.web;
    const response = await this.authApi.signIn(payload, deviceId, os);
    response.scopes = payload.scopes;
    this.storageManager.saveTokens(response);
    return response;
  }

  async signUp(payload: AoothSignUpPayload): Promise<AoothAuthorizationResponse> {
    const response = await this.authApi.signUp(payload);
    response.scopes = payload.scopes;
    this.storageManager.saveTokens(response);
    return response;
  }

  async passwordlessSignIn(payload: AoothPasswordlessSignInPayload): Promise<AoothSuccessResponse> {
    const deviceId = this.deviceService.getDeviceId();
    const os = OS.web;
    return this.authApi.passwordlessSignIn(payload, deviceId, os);
  }

  async passwordlessSignInComplete(payload: AoothPasswordlessSignInCompletePayload): Promise<AoothAuthorizationResponse> {
    const response = await this.authApi.passwordlessSignInComplete(payload);
    response.scopes = payload.scopes;
    this.storageManager.saveTokens(response);
    return response;
  }

  async logOut(): Promise<AoothSuccessResponse> {
    const refreshToken = this.storageManager.getToken(TokenType.refresh_token);
    const deviceId = this.storageManager.getDeviceId();

    const status = await this.authApi.logOut(deviceId, refreshToken, !this.appId);
    if (status.result === 'ok') this.storageManager.deleteTokens();
    return status;
  }

  federatedAuthWithPopup(provider: Providers, redirect_url: string, scopes: string[]): void {
    const aoothURL = this.createFederatedAuthUrl(provider, redirect_url, scopes);

    const popupWindow = window.open(aoothURL, '_blank', 'width=500,height=500');

    if (!popupWindow) {
      this.federatedAuthWithRedirect(provider, redirect_url, scopes);
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
            scopes,
          };
          this.storageManager.saveTokens(tokensData);
          window.location.href = `${this.origin}`;

          clearInterval(checkInterval);
          popupWindow.close();
        }
      }, 100);
    }
  }

  federatedAuthWithRedirect(provider: Providers, redirect_url: string, scopes: string[]): void {
    const aoothURL = this.createFederatedAuthUrl(provider, redirect_url, scopes);
    window.location.href = aoothURL;
  }

  async refreshToken(scopes: string[]): Promise<AoothAuthorizationResponse> {
    const accessToken = this.storageManager.getToken(TokenType.access_token);
    const refreshToken = this.storageManager.getToken(TokenType.refresh_token);

    const response = await this.authApi.refreshToken(accessToken, refreshToken, scopes);
    response.scopes = scopes;
    this.storageManager.saveTokens(response);
    return response;
  }

  async sendPasswordResetEmail(payload: AoothSendPasswordResetEmailPayload): Promise<AoothSuccessResponse> {
    return this.authApi.sendPasswordResetEmail(payload);
  }

  async resetPassword(newPassword: string, scopes: string[]): Promise<AoothAuthorizationResponse> {
    const urlParams = new URLSearchParams(window.location.search);
    const resetToken = urlParams.get('token');

    const response = await this.authApi.resetPassword(resetToken, newPassword, scopes);
    response.scopes = scopes;
    this.storageManager.saveTokens(response);

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

    const { challenge_id, publicKey } = await this.authApi.passkeyRegisterStart(payload, deviceId, os, !this.appId);

    const webauthn = await startRegistration(publicKey);

    const responseRegisterComplete = await this.authApi.passkeyRegisterComplete(webauthn, deviceId, challenge_id, !this.appId);

    if ('access_token' in responseRegisterComplete) {
      responseRegisterComplete.scopes = payload.scopes;
      this.storageManager.saveTokens(responseRegisterComplete);
    }

    return responseRegisterComplete;
  }

  async passkeyAuthenticate(payload: AoothPasskeyAuthenticateStartPayload): Promise<AoothAuthorizationResponse> {
    const deviceId = this.deviceService.getDeviceId();
    const os = OS.web;

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
    }

    return responseValidate;
  }

  async loginInsecure(payload: AoothInsecureLoginPayload): Promise<AoothAuthorizationResponse> {
    const response = await this.authApi.loginInsecure(payload);
    this.storageManager.saveTokens(response);

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

  //TODO: Add scopes here
  async createUserPasskey(
    relyingPartyId: string,
    scopes: string[] = DEFAULT_SCOPES,
    createTenant: boolean = false,
  ): Promise<AoothAuthorizationResponse | AoothPasskeyRegisterCompleteMessage> {
    const deviceId = this.deviceService.getDeviceId();
    const os = OS.web;

    const { challenge_id, publicKey } = await this.userApi.createUserPasskeyStart(
      relyingPartyId,
      deviceId,
      os,
      createTenant,
      scopes,
    );

    const webauthn = await startRegistration(publicKey);

    const responseCreateComplete = await this.userApi.createUserPasskeyComplete(webauthn, deviceId, challenge_id);

    if ('access_token' in responseCreateComplete) {
      responseCreateComplete.scopes = scopes;
      this.storageManager.saveTokens(responseCreateComplete);
    }

    return responseCreateComplete;
  }

  async joinInvitation(token: string, scopes: string[] = DEFAULT_SCOPES): Promise<AoothInviteResponse> {
    return this.tenantAPI.joinInvitation(token, scopes);
  }

  getTokenByType(tokenType: TokenType): string | null {
    return this.storageManager.getToken(tokenType);
  }
}
