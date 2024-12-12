import { APP_ID_HEADER_KEY, AUTHORIZATION_HEADER_KEY } from 'lib/constants';

import { AuthenticationResponseJSON, RegistrationResponseJSON } from '@simplewebauthn/types';

import { StorageManager } from '../storage-manager';

import { AxiosClient } from './axios-client';
import {
  OS,
  PassflowAdminEndpointPaths,
  PassflowAuthorizationResponse,
  PassflowConfig,
  PassflowEndpointPaths,
  PassflowInsecureLoginPayload,
  PassflowPasskeyAuthenticatePayload,
  PassflowPasskeyAuthenticateStartExtendedPayload,
  PassflowPasskeyAuthenticateStartPayload,
  PassflowPasskeyCompleteMessage,
  PassflowPasskeyCompleteMessageWithTokens,
  PassflowPasskeyRegisterPayload,
  PassflowPasskeyRegisterStartExtendedPayload,
  PassflowPasskeyRegisterStartPayload,
  PassflowPasskeyStart,
  PassflowPasswordlessResponse,
  PassflowPasswordlessSignInCompletePayload,
  PassflowPasswordlessSignInExtendedPayload,
  PassflowPasswordlessSignInPayload,
  PassflowSendPasswordResetEmailPayload,
  PassflowSignInExtendedPayload,
  PassflowSignInPayload,
  PassflowSignUpPayload,
  PassflowSuccessResponse,
  PassflowValidatePayload,
  PassflowValidationResponse,
} from './model';

export class AuthAPI {
  protected axiosClient: AxiosClient;
  protected storageManager = new StorageManager();

  constructor(config: PassflowConfig) {
    this.axiosClient = new AxiosClient(config);
  }

  async refreshToken(refreshToken: string, scopes: string[], accessToken?: string): Promise<PassflowAuthorizationResponse> {
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

  async signIn(payload: PassflowSignInPayload, deviceId: string, os: OS): Promise<PassflowAuthorizationResponse> {
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

  async signUp(payload: PassflowSignUpPayload): Promise<PassflowAuthorizationResponse> {
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

  async passwordlessSignIn(
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

  async passwordlessSignInComplete(payload: PassflowPasswordlessSignInCompletePayload): Promise<PassflowValidationResponse> {
    return this.axiosClient.post<PassflowValidationResponse, PassflowPasswordlessSignInCompletePayload>(
      PassflowEndpointPaths.passwordlessComplete,
      payload,
    );
  }

  async logOut(deviceId?: string, refreshToken?: string, isAdmin = false): Promise<PassflowSuccessResponse> {
    const payload = !isAdmin ? { refresh_token: refreshToken, device: deviceId } : undefined;
    const endpoint = isAdmin ? PassflowAdminEndpointPaths.logout : PassflowEndpointPaths.logout;

    return this.axiosClient.post<PassflowSuccessResponse, typeof payload>(endpoint, payload);
  }

  async sendPasswordResetEmail(payload: PassflowSendPasswordResetEmailPayload): Promise<PassflowSuccessResponse> {
    return this.axiosClient.post<PassflowSuccessResponse, typeof payload>(
      PassflowEndpointPaths.sendPasswordResetEmail,
      payload,
    );
  }

  async resetPassword(newPassword: string, scopes: string[], resetToken?: string): Promise<PassflowAuthorizationResponse> {
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

  async passkeyRegisterStart(
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

  async passkeyRegisterComplete(
    passkeyData: RegistrationResponseJSON,
    deviceId: string,
    challengeId: string,
    isAdmin = false,
  ): Promise<PassflowAuthorizationResponse | PassflowPasskeyCompleteMessageWithTokens | PassflowPasskeyCompleteMessage> {
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

  async passkeyAuthenticateStart(
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

  async passkeyAuthenticateComplete(
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

  async passkeyValidate(
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

  async loginInsecure(payload: PassflowInsecureLoginPayload): Promise<PassflowAuthorizationResponse> {
    return this.axiosClient.post<PassflowAuthorizationResponse, PassflowInsecureLoginPayload>(
      PassflowAdminEndpointPaths.loginInsecure,
      payload,
    );
  }
}
