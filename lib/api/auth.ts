import { AuthenticationResponseJSON, RegistrationResponseJSON } from '@simplewebauthn/types';
import { AUTHORIZATION_HEADER_KEY } from 'lib/constants';

import { StorageManager } from '../storage-manager';

import { AxiosClient } from './axios-client';
import {
  AoothAdminEndpointPaths,
  AoothAuthorizationResponse,
  AoothConfig,
  AoothEndpointPaths,
  AoothInsecureLoginPayload,
  AoothPasskeyAuthenticatePayload,
  AoothPasskeyAuthenticateStartExtendedPayload,
  AoothPasskeyAuthenticateStartPayload,
  AoothPasskeyRegisterCompleteMessage,
  AoothPasskeyRegisterPayload,
  AoothPasskeyRegisterStartExtendedPayload,
  AoothPasskeyRegisterStartPayload,
  AoothPasskeyStart,
  AoothPasswordlessSignInCompletePayload,
  AoothPasswordlessSignInExtendedPayload,
  AoothPasswordlessSignInPayload,
  AoothSendPasswordResetEmailPayload,
  AoothSignInExtendedPayload,
  AoothSignInPayload,
  AoothSignUpPayload,
  AoothSuccessResponse,
  AoothValidatePayload,
  OS,
} from './model';

export class AuthAPI {
  protected axiosClient: AxiosClient;
  protected storageManager = new StorageManager();

  constructor(config: AoothConfig) {
    this.axiosClient = new AxiosClient(config);
  }

  async refreshToken(
    accessToken: string | null,
    refreshToken: string | null,
    scopes: string[],
  ): Promise<AoothAuthorizationResponse> {
    const payload = {
      access: accessToken,
      scopes,
    };

    return this.axiosClient.post<AoothAuthorizationResponse, typeof payload>(AoothEndpointPaths.refresh, payload, {
      headers: {
        [AUTHORIZATION_HEADER_KEY]: `Bearer ${refreshToken}`,
      },
    });
  }

  async signIn(payload: AoothSignInPayload, deviceId: string, os: OS): Promise<AoothAuthorizationResponse> {
    const defaultPayload: AoothSignInExtendedPayload = {
      ...payload,
      device: deviceId,
      os,
    };
    return this.axiosClient.post<AoothAuthorizationResponse, AoothSignInExtendedPayload>(
      AoothEndpointPaths.signin,
      defaultPayload,
    );
  }

  async signUp(payload: AoothSignUpPayload): Promise<AoothAuthorizationResponse> {
    const { create_tenant, anonymous } = payload;
    const defaultPayload: AoothSignUpPayload = {
      ...payload,
      create_tenant: create_tenant ?? false,
      anonymous: anonymous ?? false,
    };
    return this.axiosClient.post<AoothAuthorizationResponse, AoothSignUpPayload>(AoothEndpointPaths.signup, defaultPayload);
  }

  async passwordlessSignIn(payload: AoothPasswordlessSignInPayload, deviceId: string, os: OS): Promise<AoothSuccessResponse> {
    const { create_tenant } = payload;
    const defaultPayload: AoothPasswordlessSignInExtendedPayload = {
      ...payload,
      create_tenant: create_tenant ?? false,
      device: deviceId,
      os,
    };
    return this.axiosClient.post<AoothSuccessResponse, AoothPasswordlessSignInExtendedPayload>(
      AoothEndpointPaths.passwordless,
      defaultPayload,
    );
  }

  async passwordlessSignInComplete(payload: AoothPasswordlessSignInCompletePayload): Promise<AoothAuthorizationResponse> {
    return this.axiosClient.post<AoothAuthorizationResponse, AoothPasswordlessSignInCompletePayload>(
      AoothEndpointPaths.passwordlessComplete,
      payload,
    );
  }

  async logOut(deviceId: string | null, refreshToken?: string | null, isAdmin = false): Promise<AoothSuccessResponse> {
    const payload = !isAdmin ? { refresh_token: refreshToken, device: deviceId } : null;
    const endpoint = isAdmin ? AoothAdminEndpointPaths.logout : AoothEndpointPaths.logout;

    return this.axiosClient.post<AoothSuccessResponse, typeof payload>(endpoint, payload);
  }

  async sendPasswordResetEmail(payload: AoothSendPasswordResetEmailPayload): Promise<AoothSuccessResponse> {
    return this.axiosClient.post<AoothSuccessResponse, typeof payload>(AoothEndpointPaths.sendPasswordResetEmail, payload);
  }

  async resetPassword(resetToken: string | null, newPassword: string, scopes: string[]): Promise<AoothAuthorizationResponse> {
    const payload = {
      password: newPassword,
      scopes,
    };

    return this.axiosClient.post<AoothAuthorizationResponse, typeof payload>(AoothEndpointPaths.resetPassword, payload, {
      headers: {
        [AUTHORIZATION_HEADER_KEY]: `Bearer ${resetToken}`,
      },
    });
  }

  async passkeyRegisterStart(
    payload: AoothPasskeyRegisterStartPayload,
    deviceId: string,
    os: OS,
    isAdmin = false,
  ): Promise<AoothPasskeyStart> {
    const { create_tenant } = payload;
    const defaultPayload: AoothPasskeyRegisterStartExtendedPayload = {
      ...payload,
      create_tenant: create_tenant ?? false,
      device: deviceId,
      os,
    };

    const endpoint = isAdmin ? AoothAdminEndpointPaths.passkeyRegisterStart : AoothEndpointPaths.passkeyRegisterStart;

    return this.axiosClient.post<AoothPasskeyStart, AoothPasskeyRegisterStartExtendedPayload>(endpoint, defaultPayload);
  }

  async passkeyRegisterComplete(
    passkeyData: RegistrationResponseJSON,
    deviceId: string,
    challengeId: string,
    isAdmin = false,
  ): Promise<AoothAuthorizationResponse | AoothPasskeyRegisterCompleteMessage> {
    const payload: AoothPasskeyRegisterPayload = {
      challenge_id: challengeId,
      device: deviceId,
      passkey_data: passkeyData,
    };

    const endpoint = isAdmin ? AoothAdminEndpointPaths.passkeyRegisterComplete : AoothEndpointPaths.passkeyRegisterComplete;

    return this.axiosClient.post<AoothAuthorizationResponse, AoothPasskeyRegisterPayload>(endpoint, payload);
  }

  async passkeyAuthenticateStart(
    payload: AoothPasskeyAuthenticateStartPayload,
    deviceId: string,
    os: OS,
    isAdmin = false,
  ): Promise<AoothPasskeyStart> {
    const defaultPayload: AoothPasskeyAuthenticateStartExtendedPayload = {
      ...payload,
      user_id: payload.user_id ?? '',
      device: deviceId,
      os,
    };

    const endpoint = isAdmin ? AoothAdminEndpointPaths.passkeyAuthenticateStart : AoothEndpointPaths.passkeyAuthenticateStart;

    return this.axiosClient.post<AoothPasskeyStart, AoothPasskeyAuthenticateStartExtendedPayload>(endpoint, defaultPayload);
  }

  async passkeyAuthenticateComplete(
    passkeyData: AuthenticationResponseJSON,
    deviceId: string,
    challengeId: string,
    isAdmin = false,
  ): Promise<AoothAuthorizationResponse> {
    const payload: AoothPasskeyAuthenticatePayload = {
      challenge_id: challengeId,
      device: deviceId,
      passkey_data: passkeyData,
    };

    const endpoint = isAdmin
      ? AoothAdminEndpointPaths.passkeyAuthenticateComplete
      : AoothEndpointPaths.passkeyAuthenticateComplete;

    return this.axiosClient.post<AoothAuthorizationResponse, AoothPasskeyAuthenticatePayload>(endpoint, payload);
  }

  async passkeyValidate(
    otp: string,
    deviceId: string,
    challengeId: string,
    isAdmin = false,
  ): Promise<AoothAuthorizationResponse> {
    const payload: AoothValidatePayload = {
      otp,
      device: deviceId,
      challenge_id: challengeId,
    };

    const endpoint = isAdmin ? AoothAdminEndpointPaths.passkeyValidate : AoothEndpointPaths.passkeyValidate;

    return this.axiosClient.post<AoothAuthorizationResponse, AoothValidatePayload>(endpoint, payload);
  }

  async loginInsecure(payload: AoothInsecureLoginPayload): Promise<AoothAuthorizationResponse> {
    return this.axiosClient.post<AoothAuthorizationResponse, AoothInsecureLoginPayload>(
      AoothAdminEndpointPaths.loginInsecure,
      payload,
    );
  }
}
