import type { AxiosRequestConfig } from 'axios';
import { DeviceService } from '../device';
import { StorageManager } from '../storage';

import { AxiosClient, withOwnBearer } from './axios-client';
import {
  PassflowConfig,
  PassflowEndpointPaths,
  PassflowError,
  pathWithParams,
  RegisteredTwoFactorMethod,
  TwoFactorAlternativeRequest,
  TwoFactorChallengeRequest,
  TwoFactorChallengeResponse,
  TwoFactorConfirmRequest,
  TwoFactorConfirmResponse,
  TwoFactorDisableRequest,
  TwoFactorDisableResponse,
  TwoFactorEnrollment,
  TwoFactorEnrollmentResponse,
  TwoFactorMethod,
  TwoFactorRecoveryRequest,
  TwoFactorRecoveryResponse,
  TwoFactorRegenerateRequest,
  TwoFactorRegenerateResponse,
  TwoFactorSetupLinkResponse,
  TwoFactorSetupMagicLinkErrorCode,
  TwoFactorSetupMagicLinkValidationResponse,
  TwoFactorSetupResponse,
  TwoFactorStatusResponse,
  TwoFactorTrustedDevice,
  TwoFactorTrustedDevicesResponse,
  TwoFactorVerifyRequest,
  TwoFactorVerifyRequestV2,
  TwoFactorVerifyResponse,
  TwoFactorVerifyResponseV2,
} from './model';

/** The 2FA token as the Bearer credential, or no config when there is none. */
const bearer = (tfaToken?: string): AxiosRequestConfig =>
  tfaToken ? { headers: { Authorization: `Bearer ${tfaToken}` } } : {};

/**
 * Request config for the calls that end a sign-in with its second factor.
 *
 * They go with credentials so that a `trust_device` answer can set the
 * HttpOnly trusted-device cookie on a cross-origin response, and so the
 * browser sends the one it already holds.
 */
const credentialed = (tfaToken?: string): AxiosRequestConfig => ({
  withCredentials: true,
  ...bearer(tfaToken),
});

/** The setup answer as the server sends it; `qr_code` is what the SDK's callers read. */
type TwoFactorSetupWireResponse = Omit<TwoFactorSetupResponse, 'qr_code'> & {
  qr_code?: string;
  qr_code_image?: string;
};

// The server's image is a whole `data:` URI; `qr_code` is documented as the bare base64.
const toSetupResponse = ({ qr_code_image, qr_code, ...rest }: TwoFactorSetupWireResponse): TwoFactorSetupResponse => ({
  ...rest,
  qr_code: (qr_code ?? qr_code_image ?? '').replace(/^data:image\/png;base64,/, ''),
});

/** Setup link refusals the HTTP status alone cannot tell apart. */
const SETUP_LINK_ERROR_CODES: Record<string, TwoFactorSetupMagicLinkErrorCode> = {
  'error.2fa.setup.token.expired': 'EXPIRED_TOKEN',
  'error.2fa.setup.token.revoked': 'REVOKED_TOKEN',
  'error.2fa.setup.token.already_used': 'ALREADY_USED',
  'error.2fa.setup.token.rate.limit.exceeded': 'RATE_LIMITED',
};

/** Backend response format (snake_case) for magic link validation */
interface TwoFactorSetupMagicLinkBackendResponse {
  valid?: boolean;
  session_token?: string;
  user_id?: string;
  expires_in?: number;
  app_id?: string | null;
}

/**
 * API client for Two-Factor Authentication operations
 */
export class TwoFactorApiClient {
  protected axiosClient: AxiosClient;

  constructor(config: PassflowConfig, storageManager?: StorageManager, deviceService?: DeviceService) {
    this.axiosClient = new AxiosClient(config, storageManager, deviceService);
  }

  setAppId(appId: string): void {
    this.axiosClient.setAppId(appId);
  }

  /**
   * Get current 2FA enrollment status
   * GET /user/2fa/status
   *
   * `setupSessionToken` is a setup link's session; without it the stored session is used.
   */
  getStatus(setupSessionToken?: string): Promise<TwoFactorStatusResponse> {
    return this.axiosClient.get<TwoFactorStatusResponse>(
      PassflowEndpointPaths.twoFactorStatus,
      withOwnBearer(setupSessionToken),
    );
  }

  /**
   * Begin 2FA setup process
   * POST /user/2fa/setup/begin
   * Returns secret and QR code for authenticator app
   *
   * `setupSessionToken` is a setup link's session; without it the stored session is used.
   */
  async beginSetup(setupSessionToken?: string): Promise<TwoFactorSetupResponse> {
    return toSetupResponse(
      await this.axiosClient.post<TwoFactorSetupWireResponse, {}>(
        PassflowEndpointPaths.twoFactorSetupBegin,
        {},
        withOwnBearer(setupSessionToken),
      ),
    );
  }

  /**
   * Confirm 2FA setup with TOTP code
   * POST /user/2fa/setup/confirm
   * Returns recovery codes on success
   *
   * `setupSessionToken` is a setup link's session; without it the stored session is used.
   */
  confirmSetup(payload: TwoFactorConfirmRequest, setupSessionToken?: string): Promise<TwoFactorConfirmResponse> {
    return this.axiosClient.post<TwoFactorConfirmResponse, TwoFactorConfirmRequest>(
      PassflowEndpointPaths.twoFactorSetupConfirm,
      payload,
      withOwnBearer(setupSessionToken),
    );
  }

  /**
   * What a sign-in waiting on its second factor can do next
   * GET /auth/2fa/enrollment
   */
  async getEnrollment(tfaToken: string): Promise<TwoFactorEnrollment> {
    const response = await this.axiosClient.get<TwoFactorEnrollmentResponse>(
      PassflowEndpointPaths.twoFactorEnrollment,
      withOwnBearer(tfaToken),
    );
    return response.enrollment;
  }

  /**
   * Email the user a link to set up 2FA
   * POST /auth/2fa/enrollment/email-link
   */
  sendSetupLink(tfaToken: string): Promise<TwoFactorSetupLinkResponse> {
    return this.axiosClient.post<TwoFactorSetupLinkResponse, undefined>(
      PassflowEndpointPaths.twoFactorEnrollmentEmailLink,
      undefined,
      withOwnBearer(tfaToken),
    );
  }

  /**
   * Begin 2FA setup on the sign-in itself, for a user with no validated email
   * POST /auth/2fa/setup/begin
   */
  async beginEnrollment(tfaToken: string): Promise<TwoFactorSetupResponse> {
    return toSetupResponse(
      await this.axiosClient.post<TwoFactorSetupWireResponse, undefined>(
        PassflowEndpointPaths.twoFactorEnrollmentBegin,
        undefined,
        withOwnBearer(tfaToken),
      ),
    );
  }

  /**
   * Confirm 2FA setup on the sign-in itself; `verify` with the same code then finishes it
   * POST /auth/2fa/setup/confirm
   */
  confirmEnrollment(tfaToken: string, payload: TwoFactorConfirmRequest): Promise<TwoFactorConfirmResponse> {
    return this.axiosClient.post<TwoFactorConfirmResponse, TwoFactorConfirmRequest>(
      PassflowEndpointPaths.twoFactorEnrollmentConfirm,
      payload,
      withOwnBearer(tfaToken),
    );
  }

  /**
   * Verify TOTP code during login
   * POST /auth/2fa/verify
   * Uses tfa_token as Bearer token for authentication
   */
  verify(payload: TwoFactorVerifyRequest): Promise<TwoFactorVerifyResponse> {
    const { tfa_token, code, trust_device } = payload;
    // `trust_device` is sent only when asked for, so a plain verify stays the
    // body it always was.
    return this.axiosClient.post<TwoFactorVerifyResponse, { code: string; trust_device?: true }>(
      PassflowEndpointPaths.twoFactorVerify,
      { code, ...(trust_device ? { trust_device: true as const } : {}) },
      credentialed(tfa_token),
    );
  }

  /**
   * Use recovery code for authentication
   * POST /auth/2fa/recovery
   * Uses tfa_token as Bearer token for authentication
   */
  useRecoveryCode(payload: TwoFactorRecoveryRequest): Promise<TwoFactorRecoveryResponse> {
    const { tfa_token, recovery_code, trust_device } = payload;
    return this.axiosClient.post<TwoFactorRecoveryResponse, { recovery_code: string; trust_device?: true }>(
      PassflowEndpointPaths.twoFactorRecovery,
      { recovery_code, ...(trust_device ? { trust_device: true as const } : {}) },
      credentialed(tfa_token),
    );
  }

  /**
   * Disable 2FA (requires TOTP verification)
   * DELETE /user/2fa
   */
  disable(payload: TwoFactorDisableRequest): Promise<TwoFactorDisableResponse> {
    return this.axiosClient.delete<TwoFactorDisableResponse>(PassflowEndpointPaths.twoFactor, { data: payload });
  }

  /**
   * Regenerate recovery codes
   * POST /user/2fa/recovery-codes/regenerate
   */
  regenerateRecoveryCodes(payload: TwoFactorRegenerateRequest): Promise<TwoFactorRegenerateResponse> {
    return this.axiosClient.post<TwoFactorRegenerateResponse, TwoFactorRegenerateRequest>(
      PassflowEndpointPaths.twoFactorRegenerateCodes,
      payload,
    );
  }

  /**
   * Validate magic link token for 2FA setup
   * GET /auth/2fa-setup/:token
   *
   * This endpoint validates an admin-generated magic link token
   * and returns a scoped session (scope: "2fa_setup") that can ONLY
   * be used for completing 2FA setup operations.
   *
   * This method never throws - it always returns a TwoFactorSetupMagicLinkValidationResponse
   * with either success=true and session data, or success=false and error details.
   *
   * @param token - Magic link token from URL parameter
   * @returns Validation response with scoped session token or error
   */
  validateTwoFactorSetupMagicLink(token: string): Promise<TwoFactorSetupMagicLinkValidationResponse> {
    // Construct endpoint with token as path parameter
    const endpoint = `${PassflowEndpointPaths.twoFactorSetupMagicLink}/${token}`;

    // No authentication required - token validation IS the authentication
    return this.axiosClient
      .get<TwoFactorSetupMagicLinkValidationResponse>(endpoint, {
        // Override default auth headers (this is a public endpoint)
        transformRequest: [
          (data, headers) => {
            if (headers) {
              delete headers.Authorization;
            }
            return data;
          },
        ],
      })
      .then((response) => {
        // Transform snake_case backend response to camelCase
        const backendResponse = response as unknown as TwoFactorSetupMagicLinkBackendResponse;
        if (backendResponse.valid === false) {
          return {
            success: false,
            error: { code: 'INVALID_TOKEN' as const, message: this.getDefaultErrorMessage(400) },
          };
        }
        return {
          success: true,
          sessionToken: backendResponse.session_token,
          userId: backendResponse.user_id,
          expiresIn: backendResponse.expires_in,
          appId: backendResponse.app_id,
        };
      })
      .catch((error) => {
        // Map all errors to structured TwoFactorSetupMagicLinkValidationResponse
        // This ensures consumers always get consistent error format
        // A server refusal arrives as a PassflowError from the client's error interceptor.
        if (error instanceof PassflowError) {
          return {
            success: false,
            error: {
              code: SETUP_LINK_ERROR_CODES[error.id] ?? this.mapStatusToErrorCode(error.status),
              message: error.message || this.getDefaultErrorMessage(error.status),
            },
          };
        }

        // A 429 keeps its raw axios shape after the client's retries.
        if (error.response) {
          const status = error.response.status;
          const data = error.response.data || {};

          // Parse Retry-After header for rate limiting
          const retryAfter = error.response.headers?.['retry-after']
            ? parseInt(error.response.headers['retry-after'], 10)
            : undefined;

          return {
            success: false,
            error: {
              code: data.error || this.mapStatusToErrorCode(status),
              message: data.message || this.getDefaultErrorMessage(status),
              retryAfter,
            },
          };
        }

        // Network error or other unexpected error
        return {
          success: false,
          error: {
            code: 'SERVER_ERROR' as const,
            message: error instanceof Error ? error.message : 'Unable to connect to the server. Please check your connection.',
          },
        };
      });
  }

  /**
   * Map HTTP status code to magic link error code
   */
  private mapStatusToErrorCode(status: number): TwoFactorSetupMagicLinkErrorCode {
    switch (status) {
      case 400:
        return 'INVALID_TOKEN';
      case 404:
        return 'REVOKED_TOKEN';
      case 410:
        return 'EXPIRED_TOKEN';
      case 429:
        return 'RATE_LIMITED';
      default:
        return 'SERVER_ERROR';
    }
  }

  /**
   * Get default error message for HTTP status code
   */
  private getDefaultErrorMessage(status: number): string {
    switch (status) {
      case 400:
        return 'The provided magic link is invalid or malformed.';
      case 404:
        return 'This magic link has been revoked or does not exist.';
      case 410:
        return 'This magic link has expired. Please request a new one from your administrator.';
      case 429:
        return 'Too many validation attempts. Please try again later.';
      default:
        return 'An error occurred while validating the magic link.';
    }
  }

  // ============================================
  // v2 Multi-Method 2FA API Methods
  // ============================================

  /**
   * Get available 2FA methods for current user
   * GET /v2/user/2fa/methods/available
   */
  getAvailableMethods(): Promise<TwoFactorMethod[]> {
    return this.axiosClient.get<TwoFactorMethod[]>(PassflowEndpointPaths.TwoFactorMethodsAvailable);
  }

  /**
   * Get registered 2FA methods for current user
   * GET /v2/user/2fa/methods
   */
  getRegisteredMethods(): Promise<RegisteredTwoFactorMethod[]> {
    return this.axiosClient.get<RegisteredTwoFactorMethod[]>(PassflowEndpointPaths.TwoFactorMethodsRegistered);
  }

  /**
   * Start 2FA method setup.
   * POST /v2/user/2fa/setup/start
   *
   * The method travels in the body: at this point it is a parameter of the
   * request, not the identity of an enrolled resource.
   */
  startMethodSetup(method: TwoFactorMethod, payload?: Record<string, unknown>): Promise<unknown> {
    return this.axiosClient.post<unknown, Record<string, unknown>>(PassflowEndpointPaths.TwoFactorSetupStart, {
      ...payload,
      method,
    });
  }

  /**
   * Complete 2FA method setup.
   * POST /v2/user/2fa/setup/complete
   */
  completeMethodSetup(method: TwoFactorMethod, payload: Record<string, unknown>): Promise<unknown> {
    return this.axiosClient.post<unknown, Record<string, unknown>>(PassflowEndpointPaths.TwoFactorSetupComplete, {
      ...payload,
      method,
    });
  }

  /**
   * Remove registered 2FA method
   * DELETE /v2/user/2fa/methods/:id
   */
  removeMethod(methodId: string): Promise<void> {
    const endpoint = pathWithParams(PassflowEndpointPaths.TwoFactorMethodRemove, { id: methodId });
    return this.axiosClient.delete<void>(endpoint);
  }

  /**
   * Request 2FA challenge during login
   * POST /v2/auth/2fa/challenge
   * `tfaToken`, when given, goes as the Bearer token the route is gated on.
   */
  requestChallenge(payload: TwoFactorChallengeRequest, tfaToken?: string): Promise<TwoFactorChallengeResponse> {
    return this.axiosClient.post<TwoFactorChallengeResponse, TwoFactorChallengeRequest>(
      PassflowEndpointPaths.TwoFactorChallenge,
      payload,
      bearer(tfaToken),
    );
  }

  /**
   * Verify 2FA challenge (v2)
   * POST /v2/auth/2fa/verify (the server's verify-challenge)
   *
   * `tfaToken` is the 2FA token the first factor returned; the route is gated
   * on it, so it goes as the Bearer token when given.
   */
  verifyV2(payload: TwoFactorVerifyRequestV2, tfaToken?: string): Promise<TwoFactorVerifyResponseV2> {
    const { trust_device, ...rest } = payload;
    return this.axiosClient.post<TwoFactorVerifyResponseV2, TwoFactorVerifyRequestV2>(
      PassflowEndpointPaths.TwoFactorVerifyV2,
      { ...rest, ...(trust_device ? { trust_device: true } : {}) },
      credentialed(tfaToken),
    );
  }

  /**
   * Switch to alternative 2FA method during challenge
   * POST /v2/auth/2fa/alternative
   * `tfaToken`, when given, goes as the Bearer token the route is gated on.
   */
  switchToAlternative(payload: TwoFactorAlternativeRequest, tfaToken?: string): Promise<TwoFactorChallengeResponse> {
    return this.axiosClient.post<TwoFactorChallengeResponse, TwoFactorAlternativeRequest>(
      PassflowEndpointPaths.TwoFactorAlternative,
      payload,
      bearer(tfaToken),
    );
  }

  /**
   * List the devices the user trusted on this app
   * GET /v2/user/2fa/trusted-devices
   *
   * Sent with credentials so the server sees this device's trust cookie and
   * can mark it `current`.
   */
  async getTrustedDevices(): Promise<TwoFactorTrustedDevice[]> {
    const response = await this.axiosClient.get<TwoFactorTrustedDevicesResponse>(
      PassflowEndpointPaths.TwoFactorTrustedDevices,
      { withCredentials: true },
    );
    return response?.devices ?? [];
  }

  /**
   * Revoke trusted device
   * DELETE /v2/user/2fa/trusted-devices/:id
   * The server answers 404 when the user has no such device.
   */
  revokeTrustedDevice(deviceId: string): Promise<void> {
    const endpoint = pathWithParams(PassflowEndpointPaths.TwoFactorTrustedDeviceRevoke, { id: deviceId });
    return this.axiosClient.delete<void>(endpoint);
  }
}
