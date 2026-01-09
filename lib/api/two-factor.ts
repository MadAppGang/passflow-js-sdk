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
  TwoFactorSetupResponse,
  TwoFactorStatusResponse,
  TwoFactorVerifyRequest,
  TwoFactorVerifyResponse,
} from './model';

/**
 * API client for Two-Factor Authentication operations
 */
export class TwoFactorApiClient {
  protected axiosClient: AxiosClient;

  constructor(config: PassflowConfig, storageManager?: StorageManager, deviceService?: DeviceService) {
    this.axiosClient = new AxiosClient(config, storageManager, deviceService);
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
   * POST /user/2fa/verify
   */
  verify(payload: TwoFactorVerifyRequest): Promise<TwoFactorVerifyResponse> {
    return this.axiosClient.post<TwoFactorVerifyResponse, TwoFactorVerifyRequest>(
      PassflowEndpointPaths.twoFactorVerify,
      payload,
    );
  }

  /**
   * Use recovery code for authentication
   * POST /user/2fa/recovery
   */
  useRecoveryCode(payload: TwoFactorRecoveryRequest): Promise<TwoFactorRecoveryResponse> {
    return this.axiosClient.post<TwoFactorRecoveryResponse, TwoFactorRecoveryRequest>(
      PassflowEndpointPaths.twoFactorRecovery,
      payload,
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
}
