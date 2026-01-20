import { AuthenticationResponseJSON, RegistrationResponseJSON } from '@simplewebauthn/types';
import { APP_ID_HEADER_KEY, AUTHORIZATION_HEADER_KEY } from '../constants';

import { DeviceService } from '../device';
import { StorageManager } from '../storage';

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
} from './model';

export class AuthAPI {
  protected axiosClient: AxiosClient;

  constructor(config: PassflowConfig, storageManager?: StorageManager, deviceService?: DeviceService) {
    this.axiosClient = new AxiosClient(config, storageManager, deviceService);
  }

  setAppId(appId: string): void {
    this.axiosClient.setAppId(appId);
  }

  refreshToken(refreshToken: string, scopes: string[], accessToken?: string): Promise<PassflowAuthorizationResponse> {
    const payload = {
      access: accessToken,
      scopes,
    };

    return this.axiosClient.post<PassflowAuthorizationResponse, typeof payload>(PassflowEndpointPaths.refresh, payload, {
      headers: {
        [AUTHORIZATION_HEADER_KEY]: `Bearer ${refreshToken}`,
      },
    });
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

    return this.axiosClient.post<PassflowAuthorizationResponse, PassflowPasskeyRegisterPayload>(endpoint, payload);
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

    return this.axiosClient.post<PassflowAuthorizationResponse, PassflowPasskeyAuthenticatePayload>(endpoint, payload);
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
