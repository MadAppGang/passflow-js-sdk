import type { AuthenticationResponseJSON, RegistrationResponseJSON } from '@simplewebauthn/browser';
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
  PassflowEmailCodePayload,
  PassflowEndpointPaths,
  PassflowError,
  PassflowLogoutResponse,
  PassflowPasskeyAuthenticatePayload,
  PassflowPasskeyAuthenticateStartExtendedPayload,
  PassflowPasskeyAuthenticateStartPayload,
  PassflowPasskeyRegisterPayload,
  PassflowPasskeyRegisterStartExtendedPayload,
  PassflowPasskeyRegisterStartPayload,
  PassflowPasskeyStart,
  PassflowPasswordlessApprovalDecidePayload,
  PassflowPasswordlessApprovalDecideResponse,
  PassflowPasswordlessApprovalInfoPayload,
  PassflowPasswordlessResponse,
  PassflowPasswordlessSignInCompletePayload,
  PassflowPasswordlessSignInExtendedPayload,
  PassflowPasswordlessSignInPayload,
  PassflowPasswordlessStatusPayload,
  PassflowPasswordlessStatusResponse,
  PassflowResponseError,
  PassflowSendPasswordResetEmailPayload,
  PassflowSessionValidationResponse,
  PassflowSignInExtendedPayload,
  PassflowSignInPayload,
  PassflowSignUpPayload,
  PassflowSuccessResponse,
  PassflowValidatePayload,
  PassflowValidationResponse,
  PasswordlessApprovalInfo,
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

/** One status poll may take this long, so a stalled request cannot hold up the next one. */
const PASSWORDLESS_STATUS_TIMEOUT_MS = 15000;

const SIGN_IN_FAILED_MESSAGE = 'Sign-in failed. Start again.';
const TRY_AGAIN_LATER_MESSAGE = 'Something went wrong. Try again later.';

/**
 * The plain error of a failed call whose body holds a secret. The rejections the axios client
 * passes on raw (a POST 429, a cancel, a timeout) hold that body in `config.data`, so only the
 * fields the server wrote are read here: never axios `config`, `request` or the original error.
 * A network failure already arrives as a `PassflowError` whose cause carries no config.
 */
const toPlainError = (error: unknown, path: PassflowEndpointPaths, id: string, message: string): PassflowError => {
  if (error instanceof PassflowError) return error;
  const body = (error as { response?: { data?: Partial<PassflowResponseError> } } | undefined)?.response?.data?.error;
  return new PassflowError({
    id: typeof body?.id === 'string' ? body.id : id,
    message: typeof body?.message === 'string' ? body.message : message,
    status: typeof body?.status === 'number' ? body.status : 0,
    location: path,
    time: new Date().toISOString(),
  });
};

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

  /**
   * Redeems the code a PKCE sign-in answered with for the tokens it stands for.
   *
   * Every exchange goes through here, so this is the one place that keeps the code and the
   * verifier out of its errors: it rejects only with a `PassflowError`.
   */
  async pkceExchange(code: string, verifier: string): Promise<PassflowAuthorizationResponse> {
    try {
      return await this.axiosClient.post<PassflowAuthorizationResponse, { authz_code: string; verifier: string }>(
        PassflowEndpointPaths.pkceExchange,
        { authz_code: code, verifier },
        SIGN_IN_REQUEST_CONFIG,
      );
    } catch (error) {
      throw toPlainError(error, PassflowEndpointPaths.pkceExchange, 'error.pkce.exchange', SIGN_IN_FAILED_MESSAGE);
    }
  }

  /** Rejects only with a `PassflowError`, because its body can hold the poll secret. */
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
    try {
      return await this.axiosClient.post<PassflowPasswordlessResponse, PassflowPasswordlessSignInExtendedPayload>(
        PassflowEndpointPaths.passwordless,
        defaultPayload,
      );
    } catch (error) {
      throw toPlainError(error, PassflowEndpointPaths.passwordless, 'error.passwordless.start', TRY_AGAIN_LATER_MESSAGE);
    }
  }

  /** Rejects only with a `PassflowError`, because its body holds the OTP. */
  async passwordlessSignInComplete(payload: PassflowPasswordlessSignInCompletePayload): Promise<PassflowValidationResponse> {
    try {
      return await this.axiosClient.post<PassflowValidationResponse, PassflowPasswordlessSignInCompletePayload>(
        PassflowEndpointPaths.passwordlessComplete,
        payload,
        SIGN_IN_REQUEST_CONFIG,
      );
    } catch (error) {
      throw toPlainError(
        error,
        PassflowEndpointPaths.passwordlessComplete,
        'error.passwordless.complete',
        TRY_AGAIN_LATER_MESSAGE,
      );
    }
  }

  /**
   * Polls a magic-link sign-in waiting for approval from another device. Sent with credentials:
   * the trusted-device cookie is read when an approved row answers with its code. It rejects only
   * with a `PassflowError`, because its body holds the poll secret.
   */
  async passwordlessStatus(
    payload: PassflowPasswordlessStatusPayload,
    options?: { signal?: AbortSignal },
  ): Promise<PassflowPasswordlessStatusResponse> {
    try {
      return await this.axiosClient.post<PassflowPasswordlessStatusResponse, PassflowPasswordlessStatusPayload>(
        PassflowEndpointPaths.passwordlessStatus,
        payload,
        { ...SIGN_IN_REQUEST_CONFIG, timeout: PASSWORDLESS_STATUS_TIMEOUT_MS, signal: options?.signal },
      );
    } catch (error) {
      throw toPlainError(error, PassflowEndpointPaths.passwordlessStatus, 'error.passwordless.status', SIGN_IN_FAILED_MESSAGE);
    }
  }

  /** Asks the server whether this app may redirect to `url`, and for the address to use. */
  async checkRedirectUrl(url: string): Promise<string> {
    try {
      const answer = await this.axiosClient.post<{ redirect_url: string }, { redirect_url: string }>(
        PassflowEndpointPaths.redirectCheck,
        { redirect_url: url },
      );
      return answer.redirect_url;
    } catch (error) {
      throw toPlainError(error, PassflowEndpointPaths.redirectCheck, 'error.redirect.check', TRY_AGAIN_LATER_MESSAGE);
    }
  }

  /** Reads what the approving device shows. It changes nothing on the server. */
  async passwordlessApprovalInfo(payload: PassflowPasswordlessApprovalInfoPayload): Promise<PasswordlessApprovalInfo> {
    try {
      return await this.axiosClient.post<PasswordlessApprovalInfo, PassflowPasswordlessApprovalInfoPayload>(
        PassflowEndpointPaths.passwordlessApprovalInfo,
        payload,
      );
    } catch (error) {
      throw toPlainError(
        error,
        PassflowEndpointPaths.passwordlessApprovalInfo,
        'error.passwordless.approval',
        TRY_AGAIN_LATER_MESSAGE,
      );
    }
  }

  /**
   * Approves or denies a waiting sign-in from the device that opened the link. It rejects only with
   * a `PassflowError`, because its body holds the OTP and the match code.
   */
  async passwordlessApprovalDecide(
    payload: PassflowPasswordlessApprovalDecidePayload,
  ): Promise<PassflowPasswordlessApprovalDecideResponse> {
    try {
      return await this.axiosClient.post<PassflowPasswordlessApprovalDecideResponse, PassflowPasswordlessApprovalDecidePayload>(
        PassflowEndpointPaths.passwordlessApprovalDecide,
        payload,
      );
    } catch (error) {
      throw toPlainError(
        error,
        PassflowEndpointPaths.passwordlessApprovalDecide,
        'error.passwordless.approval',
        TRY_AGAIN_LATER_MESSAGE,
      );
    }
  }

  /**
   * Proves an emailed code for a sign-up, sign-in or password change that answered with
   * `email_verification_required`. Only `{challenge_id, otp}` is sent: the server reads the
   * device from the `X-Passflow-DeviceId` header. Sent with credentials, as every call that
   * ends a sign-in is.
   */
  validateEmailCode(payload: PassflowEmailCodePayload): Promise<PassflowAuthorizationResponse> {
    return this.axiosClient.post<PassflowAuthorizationResponse, PassflowEmailCodePayload>(
      PassflowEndpointPaths.passkeyValidate,
      { challenge_id: payload.challenge_id, otp: payload.otp },
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

  resetPassword(
    newPassword: string,
    scopes: string[],
    resetToken?: string,
    codeChallenge?: string,
  ): Promise<PassflowAuthorizationResponse> {
    const payload = {
      password: newPassword,
      scopes,
      ...(codeChallenge ? { code_challenge: codeChallenge } : {}),
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
