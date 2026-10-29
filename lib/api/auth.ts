import { AuthenticationResponseJSON, RegistrationResponseJSON } from '@simplewebauthn/types';
import type { AxiosRequestConfig } from 'axios';
import { APP_ID_HEADER_KEY, AUTHORIZATION_HEADER_KEY } from '../constants';

import { DeviceService } from '../device';
import { StorageManager } from '../storage';
import { markUpgradeTransaction } from '../upgrade/markers';

import { AxiosClient } from './axios-client';
import {
  OS,
  PassflowAdminEndpointPaths,
  PassflowAuthorizationResponse,
  PassflowConfig,
  PassflowEndpointPaths,
  PassflowLogoutResponse,
  PassflowPasskeyAuthenticatePayload,
  PassflowPasskeyAuthenticateStartExtendedPayload,
  PassflowPasskeyAuthenticateStartPayload,
  PassflowPasskeyRegisterPayload,
  PassflowPasskeyRegisterStartExtendedPayload,
  PassflowPasskeyRegisterStartPayload,
  PassflowPasskeyStart,
  PassflowPasswordlessResponse,
  PassflowPasswordlessSignInCompletePayload,
  PassflowPasswordlessSignInExtendedPayload,
  PassflowPasswordlessSignInPayload,
  PassflowSendPasswordResetEmailPayload,
  PassflowSessionValidationResponse,
  PassflowSignInExtendedPayload,
  PassflowSignInPayload,
  PassflowSignUpPayload,
  PassflowSuccessResponse,
  PassflowValidatePayload,
  PassflowValidationResponse,
  UpgradeRefreshField,
} from './model';

/**
 * Request config for the calls that end a sign-in.
 *
 * They go with credentials so the browser sends the trusted-device cookie
 * (`passflow_trusted_device_<appID>`) the server reads to skip the second
 * factor, and so a cross-origin response can set it. Only the per-request
 * flag: the Authorization and CSRF handling stay as the interceptor has them.
 */
const SIGN_IN_REQUEST_CONFIG: AxiosRequestConfig = { withCredentials: true };

export class AuthAPI {
  protected axiosClient: AxiosClient;

  constructor(config: PassflowConfig, storageManager?: StorageManager, deviceService?: DeviceService) {
    this.axiosClient = new AxiosClient(config, storageManager, deviceService);
  }

  setAppId(appId: string): void {
    this.axiosClient.setAppId(appId);
  }

  /**
   * Refreshes the session, optionally committing an assurance upgrade.
   *
   * `upgrade` carries `{type, assertion}` — the proof the user just produced.
   * The server scores the new `acr` from the durable session record plus the
   * verified factor and rotates the tokens, so this one endpoint is both the
   * refresh and the elevation.
   *
   * When `upgrade` is present the request is MARKED as part of the upgrade
   * transaction. The server answers a wrong code, a spent challenge, a foreign
   * session and an exhausted budget with a bare 401 carrying no RFC 9470
   * vocabulary, which is indistinguishable from an expired session on the
   * response alone; the marker is what tells the response interceptor not to
   * invalidate the session over a mistyped digit.
   */
  refreshToken(
    refreshToken: string,
    scopes: string[],
    accessToken?: string,
    upgrade?: UpgradeRefreshField,
  ): Promise<PassflowAuthorizationResponse> {
    const payload = {
      access: accessToken,
      scopes,
      // Omitted entirely rather than sent as `null` when absent: the server
      // decodes non-strictly and an explicit null would be a value, not a gap.
      ...(upgrade ? { upgrade } : {}),
    };

    const config: AxiosRequestConfig = {
      headers: {
        [AUTHORIZATION_HEADER_KEY]: `Bearer ${refreshToken}`,
      },
    };

    return this.axiosClient.post<PassflowAuthorizationResponse, typeof payload>(
      PassflowEndpointPaths.refresh,
      payload,
      upgrade ? markUpgradeTransaction(config) : config,
    );
  }

  signIn(payload: PassflowSignInPayload, deviceId: string, os: OS): Promise<PassflowAuthorizationResponse> {
    const defaultPayload: PassflowSignInExtendedPayload = {
      ...payload,
      device: deviceId,
      os,
    };
    return this.axiosClient.post<PassflowAuthorizationResponse, PassflowSignInExtendedPayload>(
      PassflowEndpointPaths.signin,
      defaultPayload,
      SIGN_IN_REQUEST_CONFIG,
    );
  }

  signUp(payload: PassflowSignUpPayload): Promise<PassflowAuthorizationResponse> {
    const { create_tenant, anonymous } = payload;
    const defaultPayload: PassflowSignUpPayload = {
      ...payload,
      create_tenant: create_tenant ?? false,
      anonymous: anonymous ?? false,
    };
    return this.axiosClient.post<PassflowAuthorizationResponse, PassflowSignUpPayload>(
      PassflowEndpointPaths.signup,
      defaultPayload,
      SIGN_IN_REQUEST_CONFIG,
    );
  }

  passwordlessSignIn(
    payload: PassflowPasswordlessSignInPayload,
    deviceId: string,
    os: OS,
  ): Promise<PassflowPasswordlessResponse> {
    const { create_tenant } = payload;
    const defaultPayload: PassflowPasswordlessSignInExtendedPayload = {
      ...payload,
      create_tenant: create_tenant ?? false,
      device: deviceId,
      os,
    };
    return this.axiosClient.post<PassflowPasswordlessResponse, PassflowPasswordlessSignInExtendedPayload>(
      PassflowEndpointPaths.passwordless,
      defaultPayload,
    );
  }

  passwordlessSignInComplete(payload: PassflowPasswordlessSignInCompletePayload): Promise<PassflowValidationResponse> {
    return this.axiosClient.post<PassflowValidationResponse, PassflowPasswordlessSignInCompletePayload>(
      PassflowEndpointPaths.passwordlessComplete,
      payload,
      SIGN_IN_REQUEST_CONFIG,
    );
  }

  logOut(deviceId?: string, refreshToken?: string, isAdmin = false): Promise<PassflowLogoutResponse> {
    const payload = !isAdmin ? { refresh_token: refreshToken, device: deviceId } : undefined;
    const endpoint = isAdmin ? PassflowAdminEndpointPaths.logout : PassflowEndpointPaths.logout;

    return this.axiosClient.post<PassflowLogoutResponse, typeof payload>(endpoint, payload);
  }

  validateSession(): Promise<PassflowSessionValidationResponse> {
    return this.axiosClient.get<PassflowSessionValidationResponse>(PassflowEndpointPaths.validateSession);
  }

  sendPasswordResetEmail(payload: PassflowSendPasswordResetEmailPayload): Promise<PassflowSuccessResponse> {
    return this.axiosClient.post<PassflowSuccessResponse, typeof payload>(
      PassflowEndpointPaths.sendPasswordResetEmail,
      payload,
    );
  }

  resetPassword(newPassword: string, scopes: string[], resetToken?: string): Promise<PassflowAuthorizationResponse> {
    const payload = {
      password: newPassword,
      scopes,
    };

    return this.axiosClient.post<PassflowAuthorizationResponse, typeof payload>(PassflowEndpointPaths.resetPassword, payload, {
      headers: {
        [AUTHORIZATION_HEADER_KEY]: `Bearer ${resetToken}`,
        [APP_ID_HEADER_KEY]: undefined,
      },
    });
  }

  passkeyRegisterStart(
    payload: PassflowPasskeyRegisterStartPayload,
    deviceId: string,
    os: OS,
    isAdmin = false,
  ): Promise<PassflowPasskeyStart> {
    const { create_tenant } = payload;
    const defaultPayload: PassflowPasskeyRegisterStartExtendedPayload = {
      ...payload,
      create_tenant: create_tenant ?? false,
      device: deviceId,
      os,
    };

    const endpoint = isAdmin ? PassflowAdminEndpointPaths.passkeyRegisterStart : PassflowEndpointPaths.passkeyRegisterStart;

    return this.axiosClient.post<PassflowPasskeyStart, PassflowPasskeyRegisterStartExtendedPayload>(endpoint, defaultPayload);
  }

  passkeyRegisterComplete(
    passkeyData: RegistrationResponseJSON,
    deviceId: string,
    challengeId: string,
    isAdmin = false,
  ): Promise<PassflowAuthorizationResponse> {
    const payload: PassflowPasskeyRegisterPayload = {
      challenge_id: challengeId,
      device: deviceId,
      passkey_data: passkeyData,
    };

    const endpoint = isAdmin
      ? PassflowAdminEndpointPaths.passkeyRegisterComplete
      : PassflowEndpointPaths.passkeyRegisterComplete;

    return this.axiosClient.post<PassflowAuthorizationResponse, PassflowPasskeyRegisterPayload>(
      endpoint,
      payload,
      SIGN_IN_REQUEST_CONFIG,
    );
  }

  passkeyAuthenticateStart(
    payload: PassflowPasskeyAuthenticateStartPayload,
    deviceId: string,
    os: OS,
    isAdmin = false,
  ): Promise<PassflowPasskeyStart> {
    const defaultPayload: PassflowPasskeyAuthenticateStartExtendedPayload = {
      ...payload,
      user_id: payload.user_id ?? '',
      device: deviceId,
      os,
    };

    const endpoint = isAdmin
      ? PassflowAdminEndpointPaths.passkeyAuthenticateStart
      : PassflowEndpointPaths.passkeyAuthenticateStart;

    return this.axiosClient.post<PassflowPasskeyStart, PassflowPasskeyAuthenticateStartExtendedPayload>(
      endpoint,
      defaultPayload,
    );
  }

  passkeyAuthenticateComplete(
    passkeyData: AuthenticationResponseJSON,
    deviceId: string,
    challengeId: string,
    isAdmin = false,
  ): Promise<PassflowAuthorizationResponse> {
    const payload: PassflowPasskeyAuthenticatePayload = {
      challenge_id: challengeId,
      device: deviceId,
      passkey_data: passkeyData,
    };

    const endpoint = isAdmin
      ? PassflowAdminEndpointPaths.passkeyAuthenticateComplete
      : PassflowEndpointPaths.passkeyAuthenticateComplete;

    return this.axiosClient.post<PassflowAuthorizationResponse, PassflowPasskeyAuthenticatePayload>(
      endpoint,
      payload,
      SIGN_IN_REQUEST_CONFIG,
    );
  }

  passkeyValidate(
    otp: string,
    deviceId: string,
    challengeId: string,
    isAdmin = false,
    appId?: string,
  ): Promise<PassflowValidationResponse> {
    const payload: PassflowValidatePayload = {
      otp,
      device: deviceId,
      challenge_id: challengeId,
    };

    let endpoint: PassflowEndpointPaths.passkeyValidate | PassflowAdminEndpointPaths.passkeyValidate =
      PassflowEndpointPaths.passkeyValidate;
    if (!appId && isAdmin) {
      endpoint = PassflowAdminEndpointPaths.passkeyValidate;
    }

    const headers = appId ? { [APP_ID_HEADER_KEY]: appId } : {};

    return this.axiosClient.post<PassflowValidationResponse, PassflowValidatePayload>(endpoint, payload, { headers });
  }
}
