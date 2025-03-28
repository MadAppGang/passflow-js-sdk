/* eslint-disable complexity */
import axios from 'axios';

import {
  AppAPI,
  type AppSettings,
  AuthAPI,
  type Invitation,
  InvitationAPI,
  type InviteLinkResponse,
  type PassflowAuthorizationResponse,
  type PassflowConfig,
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
  type RequestInviteLinkPayload,
  SettingAPI,
  TenantAPI,
  UserAPI,
} from './api';
import { DEFAULT_SCOPES, PASSFLOW_CLOUD_URL } from './constants';
import { DeviceService } from './device-service';
import { AuthService, InvitationService, TenantService, UserService } from './services';
import { StorageManager } from './storage-manager';
import { PassflowEvent, PassflowStore, type PassflowSubscriber } from './store';
import { parseToken } from './token-service';

import type { ParsedTokens, SessionParams, Tokens } from './types';

export class Passflow {
  // API clients
  private authApi: AuthAPI;
  private appApi: AppAPI;
  private userApi: UserAPI;
  private settingApi: SettingAPI;
  private tenantAPI: TenantAPI;
  private invitationAPI: InvitationAPI;

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

  // Session callbacks
  private createSessionCallback?: (tokens?: Tokens) => void;
  private expiredSessionCallback?: () => void;

  // State
  tokensCache: Tokens | undefined;
  parsedTokensCache: ParsedTokens | undefined;
  error?: Error;
  origin = window.location.origin;
  url: string;
  appId?: string;

  constructor(config: PassflowConfig) {
    const { url, appId, scopes } = config;
    this.url = url || PASSFLOW_CLOUD_URL;
    this.appId = appId;

    // Initialize API clients
    this.authApi = new AuthAPI(config);
    this.appApi = new AppAPI(config);
    this.userApi = new UserAPI(config);
    this.settingApi = new SettingAPI(config);
    this.tenantAPI = new TenantAPI(config);
    this.invitationAPI = new InvitationAPI(config);

    // Initialize services
    this.storageManager = new StorageManager({ prefix: config.keyStoragePrefix ?? '' });
    this.deviceService = new DeviceService();
    this.subscribeStore = new PassflowStore();

    this.scopes = scopes ?? DEFAULT_SCOPES;
    this.createTenantForNewUser = config.createTenantForNewUser ?? false;

    // Initialize domain services with dependencies
    this.authService = new AuthService(
      this.authApi,
      this.deviceService,
      this.storageManager,
      this.subscribeStore,
      this.scopes,
      this.createTenantForNewUser,
      this.origin,
      this.url,
      { createSession: this.createSessionCallback, expiredSession: this.expiredSessionCallback },
      this.appId ?? '',
    );

    this.userService = new UserService(this.userApi, this.deviceService);

    this.tenantService = new TenantService(this.tenantAPI, this.scopes);

    this.invitationService = new InvitationService(this.invitationAPI);

    // Check for tokens in query params if configured
    if (config.parseQueryParams) {
      this.checkAndSetTokens();
    }
    this.setTokensToCacheFromLocalStorage();
  }

  // Session management
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
    const tokens = await this.authService.getTokens(this.doRefreshTokens);

    if (tokens && this.createSessionCallback) {
      this.createSessionCallback(this.tokensCache);
    }

    if (!tokens && this.expiredSessionCallback) {
      this.expiredSessionCallback();
    }
  }

  // Event subscription
  subscribe(s: PassflowSubscriber, t?: PassflowEvent[]) {
    this.subscribeStore.subscribe(s, t);
  }

  unsubscribe(s: PassflowSubscriber, t?: PassflowEvent[]) {
    this.subscribeStore.unsubscribe(s, t);
  }

  // Token handling
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
      tokens = {
        access_token,
        refresh_token: refresh_token ?? undefined,
        id_token: id_token ?? undefined,
        scopes,
      };
      this.storageManager.saveTokens(tokens);
      this.setTokensCache(tokens);
      this.subscribeStore.notify(null, PassflowEvent.SignIn);
      this.submitSessionCheck();

      urlParams.delete('access_token');
      urlParams.delete('refresh_token');
      urlParams.delete('id_token');
      urlParams.delete('client_challenge');

      if (urlParams.size > 0) {
        window.history.replaceState({}, document.title, `${window.location.pathname}?${urlParams.toString()}`);
      } else {
        window.history.replaceState({}, document.title, window.location.pathname);
      }
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
      return new Error(error);
    }
    return undefined;
  }

  private setTokensToCacheFromLocalStorage(): void {
    const tokens = this.storageManager.getTokens();
    if (tokens) {
      this.setTokensCache(tokens);
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

  // Auth delegation methods
  isAuthenticated(): boolean {
    return this.parsedTokensCache ? this.authService.isAuthenticated(this.parsedTokensCache) : false;
  }

  async signIn(payload: PassflowSignInPayload): Promise<PassflowAuthorizationResponse> {
    const response = await this.authService.signIn(payload);
    this.setTokensCache(response);
    return response;
  }

  async signUp(payload: PassflowSignUpPayload): Promise<PassflowAuthorizationResponse> {
    const response = await this.authService.signUp(payload);
    this.setTokensCache(response);
    return response;
  }

  passwordlessSignIn(payload: PassflowPasswordlessSignInPayload): Promise<PassflowPasswordlessResponse> {
    return this.authService.passwordlessSignIn(payload);
  }

  async passwordlessSignInComplete(payload: PassflowPasswordlessSignInCompletePayload): Promise<PassflowValidationResponse> {
    const response = await this.authService.passwordlessSignInComplete(payload);
    this.setTokensCache(response);
    return response;
  }

  async logOut(): Promise<void> {
    await this.authService.logOut();
    this.setTokensCache(undefined);
  }

  federatedAuthWithPopup(provider: Providers, redirect_url: string, scopes?: string[]): void {
    this.authService.federatedAuthWithPopup(provider, redirect_url, scopes);
  }

  federatedAuthWithRedirect(provider: Providers, redirect_url: string, scopes?: string[]): void {
    this.authService.federatedAuthWithRedirect(provider, redirect_url, scopes);
  }

  reset(error?: string) {
    this.storageManager.deleteTokens();
    this.setTokensCache(undefined);
    this.subscribeStore.notify(null, PassflowEvent.SignOut);
    if (error) {
      this.error = new Error(error);
      this.subscribeStore.notify(null, PassflowEvent.Error);
      throw this.error;
    }
  }

  async refreshToken(): Promise<PassflowAuthorizationResponse> {
    try {
      const response = await this.authService.refreshToken();
      this.setTokensCache(response);
      return response;
    } catch (error) {
      if (error instanceof PassflowError) {
        this.reset(error.message);
      } else if (axios.isAxiosError(error) && error.response && error.response?.status >= 400 && error.response?.status < 500) {
        this.reset(`Getting unknown error message from server with code:${error.response.status}`);
      } else {
        this.error = error as Error;
        this.subscribeStore.notify(null, PassflowEvent.Error);
        throw error;
      }
      throw new Error('Unexpected behavior');
    }
  }

  sendPasswordResetEmail(payload: PassflowSendPasswordResetEmailPayload): Promise<PassflowSuccessResponse> {
    return this.authService.sendPasswordResetEmail(payload);
  }

  async resetPassword(newPassword: string, scopes?: string[]): Promise<PassflowAuthorizationResponse> {
    const response = await this.authService.resetPassword(newPassword, scopes);
    this.setTokensCache(response);
    return response;
  }

  // App settings
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

  // Passkey methods
  async passkeyRegister(payload: PassflowPasskeyRegisterStartPayload): Promise<PassflowAuthorizationResponse> {
    const response = await this.authService.passkeyRegister(payload);
    this.setTokensCache(response);
    return response;
  }

  async passkeyAuthenticate(payload: PassflowPasskeyAuthenticateStartPayload): Promise<PassflowAuthorizationResponse> {
    const response = await this.authService.passkeyAuthenticate(payload);
    if ('access_token' in response) {
      this.setTokensCache(response);
    }
    return response;
  }

  // Token management
  async setTokens(tokens: Tokens): Promise<Tokens> {
    this.storageManager.saveTokens(tokens);
    this.setTokensCache(tokens);
    this.error = undefined;
    this.subscribeStore.notify(null, PassflowEvent.SignIn);
    await this.submitSessionCheck();
    return tokens;
  }

  // Add getTokens method
  async getTokens(doRefresh = false): Promise<Tokens | undefined> {
    return await this.authService.getTokens(doRefresh);
  }

  // User passkey methods delegated to UserService
  getUserPasskeys() {
    return this.userService.getUserPasskeys();
  }

  renameUserPasskey(name: string, passkeyId: string): Promise<PassflowSuccessResponse> {
    return this.userService.renameUserPasskey(name, passkeyId);
  }

  deleteUserPasskey(passkeyId: string): Promise<PassflowSuccessResponse> {
    return this.userService.deleteUserPasskey(passkeyId);
  }

  addUserPasskey(options?: { relyingPartyId?: string; passkeyUsername?: string; passkeyDisplayName?: string }): Promise<void> {
    return this.userService.addUserPasskey(options);
  }

  // Tenant methods delegated to TenantService
  joinInvitation(token: string, scopes?: string[]): Promise<PassflowInviteResponse> {
    return this.tenantService.joinInvitation(token, scopes);
  }

  async createTenant(name: string, refreshToken?: boolean): Promise<PassflowTenantResponse> {
    const tenant = await this.tenantService.createTenant(name);
    if (refreshToken) {
      await this.refreshToken();
    }
    return tenant;
  }

  // Invitation methods delegated to InvitationService
  async requestInviteLink(payload: RequestInviteLinkPayload): Promise<InviteLinkResponse> {
    return await this.invitationService.requestInviteLink(payload);
  }

  /**
   * Gets a list of active invitations
   * @param options Optional parameters for filtering and pagination
   * @returns Promise with array of invitations
   */
  async getInvitations(options?: {
    tenant_id?: string;
    group_id?: string;
    skip?: number | string;
    limit?: number | string;
  }): Promise<Invitation[]> {
    return await this.invitationService.getInvitations(options);
  }

  async deleteInvitation(token: string): Promise<PassflowSuccessResponse> {
    return await this.invitationService.deleteInvitation(token);
  }

  // Auth redirect helpers
  authRedirectUrl(options: { url?: string; redirectUrl?: string; scopes?: string[]; appId?: string } = {}): string {
    return this.authService.authRedirectUrl(options);
  }

  authRedirect(options: { url?: string; redirectUrl?: string; scopes?: string[]; appId?: string } = {}): void {
    this.authService.authRedirect(options);
  }
}
