import { DeviceService } from '../device';
import { StorageManager } from '../storage';

import { AxiosClient } from './axios-client';
import {
  PassflowConfig,
  PassflowEndpointPaths,
  TwoFactorConfirmRequest,
  TwoFactorConfirmResponse,
  TwoFactorDisableRequest,
  TwoFactorDisableResponse,
  TwoFactorRecoveryRequest,
  TwoFactorRecoveryResponse,
  TwoFactorRegenerateRequest,
  TwoFactorRegenerateResponse,
  TwoFactorSetupMagicLinkErrorCode,
  TwoFactorSetupMagicLinkValidationResponse,
  TwoFactorSetupResponse,
  TwoFactorStatusResponse,
  TwoFactorVerifyRequest,
  TwoFactorVerifyResponse,
} from './model';

/** Backend response format (snake_case) for magic link validation */
interface TwoFactorSetupMagicLinkBackendResponse {
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
   */
  getStatus(): Promise<TwoFactorStatusResponse> {
    return this.axiosClient.get<TwoFactorStatusResponse>(PassflowEndpointPaths.twoFactorStatus);
  }

  /**
   * Begin 2FA setup process
   * POST /user/2fa/setup/begin
   * Returns secret and QR code for authenticator app
   */
  beginSetup(): Promise<TwoFactorSetupResponse> {
    return this.axiosClient.post<TwoFactorSetupResponse, {}>(PassflowEndpointPaths.twoFactorSetupBegin, {});
  }

  /**
   * Confirm 2FA setup with TOTP code
   * POST /user/2fa/setup/confirm
   * Returns recovery codes on success
   */
  confirmSetup(payload: TwoFactorConfirmRequest): Promise<TwoFactorConfirmResponse> {
    return this.axiosClient.post<TwoFactorConfirmResponse, TwoFactorConfirmRequest>(
      PassflowEndpointPaths.twoFactorSetupConfirm,
      payload,
    );
  }

  /**
   * Verify TOTP code during login
   * POST /auth/2fa/verify
   * Uses tfa_token as Bearer token for authentication
   */
  verify(payload: TwoFactorVerifyRequest): Promise<TwoFactorVerifyResponse> {
    const { tfa_token, code } = payload;
    return this.axiosClient.post<TwoFactorVerifyResponse, { code: string }>(
      PassflowEndpointPaths.twoFactorVerify,
      { code },
      {
        headers: {
          Authorization: `Bearer ${tfa_token}`,
        },
      },
    );
  }

  /**
   * Use recovery code for authentication
   * POST /auth/2fa/recovery
   * Uses tfa_token as Bearer token for authentication
   */
  useRecoveryCode(payload: TwoFactorRecoveryRequest): Promise<TwoFactorRecoveryResponse> {
    const { tfa_token, recovery_code } = payload;
    return this.axiosClient.post<TwoFactorRecoveryResponse, { recovery_code: string }>(
      PassflowEndpointPaths.twoFactorRecovery,
      { recovery_code },
      {
        headers: {
          Authorization: `Bearer ${tfa_token}`,
        },
      },
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
}
