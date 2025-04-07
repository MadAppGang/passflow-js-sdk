import {
	AppAPI,
	type AppSettings,
	AuthAPI,
	type Invitation,
	InvitationAPI,
	type InvitationsResponse,
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
} from "./api";
import { DEFAULT_SCOPES, PASSFLOW_CLOUD_URL } from "./constants";
import { DeviceService } from "./device-service";
import {
	AuthService,
	InvitationService,
	TenantService,
	UserService,
} from "./services";
import { StorageManager } from "./storage-manager";
import {
	type ErrorPayload,
	PassflowEvent,
	PassflowStore,
	type PassflowSubscriber,
} from "./store";
import { type TokenType, parseToken } from "./token-service";

import type { ParsedTokens, SessionParams, Tokens } from "./types";

/**
 * @public
 * Result interface for invitation list requests containing both invitations array and pagination info
 */
export interface InvitationsResult {
	invitations: Invitation[];
	nextPageSkip: string;
}

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
	private createSessionCallback?: (tokens?: Tokens) => Promise<void>;
	private expiredSessionCallback?: () => Promise<void>;

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
		this.storageManager = new StorageManager({
			prefix: config.keyStoragePrefix ?? "",
		});
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
			{
				createSession: this.createSessionCallback,
				expiredSession: this.expiredSessionCallback,
			},
			this.appId ?? "",
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
	session: ({
		createSession,
		expiredSession,
		doRefresh,
	}: SessionParams) => Promise<void> = async ({
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
		try {
			tokens = await this.authService.getTokens(this.doRefreshTokens);
		} catch (error) {
			const errorPayload: ErrorPayload = {
				message:
					error instanceof Error || error instanceof PassflowError
						? error.message
						: "Session check failed",
				originalError: error,
			};
			this.subscribeStore.notify(PassflowEvent.Error, errorPayload);
			tokens = undefined;
		}

		if (tokens && this.createSessionCallback) {
			await this.createSessionCallback(tokens);
		}

		if (!tokens && this.expiredSessionCallback) {
			await this.expiredSessionCallback();
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
		const access_token = urlParams.get("access_token");
		const refresh_token = urlParams.get("refresh_token");
		const id_token = urlParams.get("id_token");
		const scopes: string[] = urlParams.get("scopes")?.split(",") ?? this.scopes;
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
			this.subscribeStore.notify(PassflowEvent.SignIn, { tokens });
			this.submitSessionCheck();

			urlParams.delete("access_token");
			urlParams.delete("refresh_token");
			urlParams.delete("id_token");
			urlParams.delete("client_challenge");

			if (urlParams.size > 0) {
				window.history.replaceState(
					{},
					document.title,
					`${window.location.pathname}?${urlParams.toString()}`,
				);
			} else {
				window.history.replaceState(
					{},
					document.title,
					window.location.pathname,
				);
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
		const error = urlParams.get("error");
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
				refresh_token: tokens.refresh_token
					? parseToken(tokens.refresh_token)
					: undefined,
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
		const tokens = this.storageManager.getTokens();
		if (!tokens || !tokens.access_token) return false;

		const parsedTokens = {
			access_token: parseToken(tokens.access_token),
			refresh_token: tokens.refresh_token
				? parseToken(tokens.refresh_token)
				: undefined,
		};

		return this.authService.isAuthenticated(parsedTokens);
	}

	async signIn(
		payload: PassflowSignInPayload,
	): Promise<PassflowAuthorizationResponse> {
		const response = await this.authService.signIn(payload);
		this.setTokensCache(response);
		return response;
	}

	async signUp(
		payload: PassflowSignUpPayload,
	): Promise<PassflowAuthorizationResponse> {
		const response = await this.authService.signUp(payload);
		this.setTokensCache(response);
		return response;
	}

	passwordlessSignIn(
		payload: PassflowPasswordlessSignInPayload,
	): Promise<PassflowPasswordlessResponse> {
		return this.authService.passwordlessSignIn(payload);
	}

	async passwordlessSignInComplete(
		payload: PassflowPasswordlessSignInCompletePayload,
	): Promise<PassflowValidationResponse> {
		const response = await this.authService.passwordlessSignInComplete(payload);
		this.setTokensCache(response);
		return response;
	}

	async logOut(): Promise<void> {
		try {
			await this.authService.logOut();
			this.storageManager.deleteTokens();
			await this.submitSessionCheck();
		} catch (error) {
			const errorPayload: ErrorPayload = {
				message: error instanceof Error ? error.message : "Failed to log out",
				originalError: error,
			};
			this.subscribeStore.notify(PassflowEvent.Error, errorPayload);
		}
		this.setTokensCache(undefined);
		this.subscribeStore.notify(PassflowEvent.SignOut, {});
	}

	federatedAuthWithPopup(
		provider: Providers,
		redirect_url: string,
		scopes?: string[],
	): void {
		this.authService.federatedAuthWithPopup(provider, redirect_url, scopes);
	}

	federatedAuthWithRedirect(
		provider: Providers,
		redirect_url: string,
		scopes?: string[],
	): void {
		this.authService.federatedAuthWithRedirect(provider, redirect_url, scopes);
	}

	reset(error?: string) {
		this.storageManager.deleteTokens();
		this.setTokensCache(undefined);
		this.subscribeStore.notify(PassflowEvent.SignOut, {});
		if (error) {
			this.error = new Error(error);
			const errorPayload: ErrorPayload = {
				message: error,
				code: "RESET_ERROR",
			};
			this.subscribeStore.notify(PassflowEvent.Error, errorPayload);
			throw this.error;
		}
	}

	async refreshToken(): Promise<PassflowAuthorizationResponse> {
		if (!this.parsedTokensCache?.refresh_token) {
			throw new Error("No refresh token found");
		}

		try {
			const response = await this.authService.refreshToken();
			this.setTokensCache(response);
			return response;
		} catch (error) {
			if (error instanceof PassflowError) {
				throw error;
			} else {
				this.subscribeStore.notify(PassflowEvent.Error, {
					message: "Failed to refresh token",
					originalError: error,
				});
				throw error;
			}
		}
	}

	sendPasswordResetEmail(
		payload: PassflowSendPasswordResetEmailPayload,
	): Promise<PassflowSuccessResponse> {
		return this.authService.sendPasswordResetEmail(payload);
	}

	async resetPassword(
		newPassword: string,
		scopes?: string[],
	): Promise<PassflowAuthorizationResponse> {
		const response = await this.authService.resetPassword(newPassword, scopes);
		this.setTokensCache(response);
		return response;
	}

	// App settings
	async getAppSettings(): Promise<AppSettings> {
		try {
			return await this.appApi.getAppSettings();
		} catch (error) {
			const errorPayload: ErrorPayload = {
				message:
					error instanceof Error ? error.message : "Failed to get app settings",
				originalError: error,
			};
			this.subscribeStore.notify(PassflowEvent.Error, errorPayload);
			throw error;
		}
	}

	async getSettingsAll(): Promise<PassflowSettingsAll> {
		try {
			return await this.settingApi.getSettingsAll();
		} catch (error) {
			const errorPayload: ErrorPayload = {
				message:
					error instanceof Error ? error.message : "Failed to get all settings",
				originalError: error,
			};
			this.subscribeStore.notify(PassflowEvent.Error, errorPayload);
			throw error;
		}
	}

	async getPasswordPolicySettings(): Promise<PassflowPasswordPolicySettings> {
		try {
			return await this.settingApi.getPasswordPolicySettings();
		} catch (error) {
			const errorPayload: ErrorPayload = {
				message:
					error instanceof Error
						? error.message
						: "Failed to get password policy settings",
				originalError: error,
			};
			this.subscribeStore.notify(PassflowEvent.Error, errorPayload);
			throw error;
		}
	}

	async getPasskeySettings(): Promise<PassflowPasskeySettings> {
		try {
			return await this.settingApi.getPasskeySettings();
		} catch (error) {
			const errorPayload: ErrorPayload = {
				message:
					error instanceof Error
						? error.message
						: "Failed to get passkey settings",
				originalError: error,
			};
			this.subscribeStore.notify(PassflowEvent.Error, errorPayload);
			throw error;
		}
	}

	// Passkey methods
	async passkeyRegister(
		payload: PassflowPasskeyRegisterStartPayload,
	): Promise<PassflowAuthorizationResponse> {
		const response = await this.authService.passkeyRegister(payload);
		this.setTokensCache(response);
		return response;
	}

	async passkeyAuthenticate(
		payload: PassflowPasskeyAuthenticateStartPayload,
	): Promise<PassflowAuthorizationResponse> {
		const response = await this.authService.passkeyAuthenticate(payload);
		if ("access_token" in response) {
			this.setTokensCache(response);
		}
		return response;
	}

	// Token management
	setTokens(tokensData: Tokens): void {
		this.storageManager.saveTokens(tokensData);
		this.setTokensCache(tokensData);
		this.subscribeStore.notify(PassflowEvent.SignIn, { tokens: tokensData });
	}

	// Add getTokens method
	async getTokens(doRefresh = false): Promise<Tokens | undefined> {
		return await this.authService.getTokens(doRefresh);
	}

	// Get token from storage by key
	getToken(tokenType: TokenType): string | undefined {
		return this.storageManager.getToken(tokenType);
	}

	// User passkey methods delegated to UserService
	async getUserPasskeys() {
		try {
			return await this.userService.getUserPasskeys();
		} catch (error) {
			const errorPayload: ErrorPayload = {
				message:
					error instanceof Error
						? error.message
						: "Failed to get user passkeys",
				originalError: error,
			};
			this.subscribeStore.notify(PassflowEvent.Error, errorPayload);
			throw error;
		}
	}

	async renameUserPasskey(
		name: string,
		passkeyId: string,
	): Promise<PassflowSuccessResponse> {
		try {
			return await this.userService.renameUserPasskey(name, passkeyId);
		} catch (error) {
			const errorPayload: ErrorPayload = {
				message:
					error instanceof Error
						? error.message
						: "Failed to rename user passkey",
				originalError: error,
			};
			this.subscribeStore.notify(PassflowEvent.Error, errorPayload);
			throw error;
		}
	}

	async deleteUserPasskey(passkeyId: string): Promise<PassflowSuccessResponse> {
		try {
			return await this.userService.deleteUserPasskey(passkeyId);
		} catch (error) {
			const errorPayload: ErrorPayload = {
				message:
					error instanceof Error
						? error.message
						: "Failed to delete user passkey",
				originalError: error,
			};
			this.subscribeStore.notify(PassflowEvent.Error, errorPayload);
			throw error;
		}
	}

	async addUserPasskey(options?: {
		relyingPartyId?: string;
		passkeyUsername?: string;
		passkeyDisplayName?: string;
	}): Promise<void> {
		try {
			return await this.userService.addUserPasskey(options);
		} catch (error) {
			const errorPayload: ErrorPayload = {
				message:
					error instanceof Error ? error.message : "Failed to add user passkey",
				originalError: error,
			};
			this.subscribeStore.notify(PassflowEvent.Error, errorPayload);
			throw error;
		}
	}

	// Tenant methods delegated to TenantService
	async joinInvitation(
		token: string,
		scopes?: string[],
	): Promise<PassflowInviteResponse> {
		try {
			return await this.tenantService.joinInvitation(token, scopes);
		} catch (error) {
			const errorPayload: ErrorPayload = {
				message:
					error instanceof Error ? error.message : "Failed to join invitation",
				originalError: error,
			};
			this.subscribeStore.notify(PassflowEvent.Error, errorPayload);
			throw error;
		}
	}

	async createTenant(
		name: string,
		refreshToken?: boolean,
	): Promise<PassflowTenantResponse> {
		try {
			const tenant = await this.tenantService.createTenant(name);
			if (refreshToken) {
				await this.refreshToken();
			}
			return tenant;
		} catch (error) {
			const errorPayload: ErrorPayload = {
				message:
					error instanceof Error ? error.message : "Failed to create tenant",
				originalError: error,
			};
			this.subscribeStore.notify(PassflowEvent.Error, errorPayload);
			throw error;
		}
	}

	// Invitation methods delegated to InvitationService
	async requestInviteLink(
		payload: RequestInviteLinkPayload,
	): Promise<InviteLinkResponse> {
		try {
			return await this.invitationService.requestInviteLink(payload);
		} catch (error) {
			const errorPayload: ErrorPayload = {
				message:
					error instanceof Error
						? error.message
						: "Failed to request invite link",
				originalError: error,
			};
			this.subscribeStore.notify(PassflowEvent.Error, errorPayload);
			throw error;
		}
	}

	/**
	 * Gets a list of active invitations
	 * @param options Optional parameters for filtering and pagination
	 * @returns Promise with invitations response containing array of invitations and pagination info
	 */
	async getInvitations(options: {
		tenantID: string;
		groupID?: string;
		skip?: number | string;
		limit?: number | string;
	}): Promise<InvitationsResult> {
		try {
			const response = await this.invitationService.getInvitations(options);
			return {
				invitations: response.invites,
				nextPageSkip: response.next_page_skip,
			};
		} catch (error) {
			const errorPayload: ErrorPayload = {
				message:
					error instanceof Error ? error.message : "Failed to get invitations",
				originalError: error,
			};
			this.subscribeStore.notify(PassflowEvent.Error, errorPayload);
			throw error;
		}
	}

	async deleteInvitation(token: string): Promise<PassflowSuccessResponse> {
		try {
			return await this.invitationService.deleteInvitation(token);
		} catch (error) {
			const errorPayload: ErrorPayload = {
				message:
					error instanceof Error
						? error.message
						: "Failed to delete invitation",
				originalError: error,
			};
			this.subscribeStore.notify(PassflowEvent.Error, errorPayload);
			throw error;
		}
	}

	// Auth redirect helpers
	authRedirectUrl(
		options: {
			url?: string;
			redirectUrl?: string;
			scopes?: string[];
			appId?: string;
		} = {},
	): string {
		return this.authService.authRedirectUrl(options);
	}

	authRedirect(
		options: {
			url?: string;
			redirectUrl?: string;
			scopes?: string[];
			appId?: string;
		} = {},
	): void {
		this.authService.authRedirect(options);
	}
}
