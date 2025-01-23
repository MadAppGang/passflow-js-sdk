import {
  AuthAPI,
  OS,
  PassflowConfig,
  PassflowEndpointPaths,
  PassflowPasswordlessSignInCompletePayload,
  PassflowPasswordlessSignInPayload,
  PassflowSignInPayload,
  PassflowSignUpPayload,
} from 'lib/api';
import { AxiosClient } from 'lib/api/axios-client';
import { vi } from 'vitest';

const mockResponse = {
  id_token: 'id_token.test.example',
  access_token: 'access_token.test.example',
  refresh_token: 'refresh_token.test.example',
};

const mockSignInOnlyAccessTokenResponse = {
  access_token: 'access_token.test.example',
};

const mockSuccessResponse = {
  result: 'ok',
};

const mockSignInErrorNotFoundResponse = {
  error: {
    id: 'error.user.not_found',
    message: 'User not found.',
    status: 401,
    location: '/go/src/github.com/madappgang/aooth/web/api/login.go:41',
    time: '1970-01-01T00:00:00.000Z',
  },
};

const mockSignInErrorIncorrectPasOrUsernameResponse = {
  error: {
    id: 'error.api.request.incorrect_login_or_password',
    message: 'Invalid Username or Password!',
    status: 401,
    location: '/go/src/github.com/madappgang/aooth/web/api/login.go:47',
    time: '1970-01-01T00:00:00.000Z',
  },
};

const mockSignUpErrorTakenResponse = {
  error: {
    id: 'error.api.email.taken',
    message: 'Email is taken. Try to choose another one.',
    status: 500,
    location: '/go/src/github.com/madappgang/aooth/web/api/registration.go:99',
    time: '1970-01-01T00:00:00.000Z',
  },
};

const mockResetPasswordBlockTokenResponse = {
  error: {
    id: 'error.token.blocked',
    message: 'The token is blocked and not valid any more.',
    status: 400,
    location: '/Users/jack/mag/aooth/web/middleware/token.go:69',
    time: '1970-01-01T00:00:00.000Z',
  },
};

const payload = {
  email: 'test@test.com',
  password: 'testPassword1!',
};

const deviceId = 'deviceId';
const os = OS.web;

describe('AuthAPI', () => {
  let authApi: AuthAPI;

  beforeEach(() => {
    const mockConfig: PassflowConfig = {
      appId: 'test-app-id',
      url: 'https://test-base-url.com',
    };

    authApi = new AuthAPI(mockConfig);
  });

  describe('signIn', () => {
    it('Should sign in with scopes', async () => {
      const payloadWithScopes: PassflowSignInPayload = { ...payload, scopes: ['id', 'profile', 'offline', 'oidc'] };
      const axiosClientGetMock = vi.spyOn(AxiosClient.prototype, 'post').mockResolvedValue(mockResponse);
      const signInResponse = await authApi.signIn(payloadWithScopes, deviceId, os);

      expect(axiosClientGetMock).toHaveBeenCalledWith(PassflowEndpointPaths.signin, {
        ...payloadWithScopes,
        device: deviceId,
        os,
      });
      expect(signInResponse).toEqual(mockResponse);
    });

    it('Should sign in with empty array scopes', async () => {
      const payloadWithEmptyScopes: PassflowSignInPayload = { ...payload, scopes: [] };
      const axiosClientGetMock = vi.spyOn(AxiosClient.prototype, 'post').mockResolvedValue(mockSignInOnlyAccessTokenResponse);
      const signInResponse = await authApi.signIn(payloadWithEmptyScopes, deviceId, os);

      expect(axiosClientGetMock).toHaveBeenCalledWith(PassflowEndpointPaths.signin, {
        ...payloadWithEmptyScopes,
        device: deviceId,
        os,
      });
      expect(signInResponse).toEqual(mockSignInOnlyAccessTokenResponse);
    });

    it('Should sign in with wrong payload (email, phone, username)', async () => {
      const payloadWithWrongData: PassflowSignInPayload = {
        ...payload,
        email: 'wrong@mail.com',
        phone: '+33333333333',
        username: 'wrongUsername',
        scopes: ['id', 'profile', 'offline', 'oidc'],
      };
      const axiosClientGetMock = vi.spyOn(AxiosClient.prototype, 'post').mockResolvedValue(mockSignInErrorNotFoundResponse);
      const signInResponse = await authApi.signIn(payloadWithWrongData, deviceId, os);

      expect(axiosClientGetMock).toHaveBeenCalledWith(PassflowEndpointPaths.signin, {
        ...payloadWithWrongData,
        device: deviceId,
        os,
      });
      expect(signInResponse).toEqual(mockSignInErrorNotFoundResponse);
    });

    it('Should sign in with wrong password', async () => {
      const payloadWithWrongData: PassflowSignInPayload = {
        ...payload,
        password: 'wrongPassword',
        scopes: ['id', 'profile', 'offline', 'oidc'],
      };
      const axiosClientGetMock = vi
        .spyOn(AxiosClient.prototype, 'post')
        .mockResolvedValue(mockSignInErrorIncorrectPasOrUsernameResponse);
      const signInResponse = await authApi.signIn(payloadWithWrongData, deviceId, os);

      expect(axiosClientGetMock).toHaveBeenCalledWith(PassflowEndpointPaths.signin, {
        ...payloadWithWrongData,
        device: deviceId,
        os,
      });
      expect(signInResponse).toEqual(mockSignInErrorIncorrectPasOrUsernameResponse);
    });
  });

  describe('signUp', () => {
    it('Should sign up with scopes', async () => {
      const payloadWithScopes: PassflowSignUpPayload = {
        user: { ...payload },
        scopes: ['id', 'profile', 'offline', 'oidc'],
        create_tenant: false,
        anonymous: false,
      };
      const axiosClientGetMock = vi.spyOn(AxiosClient.prototype, 'post').mockResolvedValue(mockResponse);
      const signUpResponse = await authApi.signUp(payloadWithScopes);

      expect(axiosClientGetMock).toHaveBeenCalledWith(PassflowEndpointPaths.signup, payloadWithScopes);
      expect(signUpResponse).toEqual(mockResponse);
    });

    it('Should sign up with empty array scopes', async () => {
      const payloadWithEmptyScopes: PassflowSignUpPayload = {
        user: { ...payload },
        scopes: [],
        create_tenant: false,
        anonymous: false,
      };
      const axiosClientGetMock = vi.spyOn(AxiosClient.prototype, 'post').mockResolvedValue(mockSignInOnlyAccessTokenResponse);
      const signUpResponse = await authApi.signUp(payloadWithEmptyScopes);

      expect(axiosClientGetMock).toHaveBeenCalledWith(PassflowEndpointPaths.signup, payloadWithEmptyScopes);
      expect(signUpResponse).toEqual(mockSignInOnlyAccessTokenResponse);
    });

    it('Should sign up with identity (email, phone, username) is taken', async () => {
      const payloadWithTakenData: PassflowSignUpPayload = {
        user: {
          ...payload,
          email: 'taken@email.com',
          username: 'takenUsername',
        },
        scopes: ['id', 'profile', 'offline', 'oidc'],
        create_tenant: false,
        anonymous: false,
      };
      const axiosClientGetMock = vi.spyOn(AxiosClient.prototype, 'post').mockResolvedValue(mockSignUpErrorTakenResponse);
      const signUpResponse = await authApi.signUp(payloadWithTakenData);

      expect(axiosClientGetMock).toHaveBeenCalledWith(PassflowEndpointPaths.signup, payloadWithTakenData);
      expect(signUpResponse).toEqual(mockSignUpErrorTakenResponse);
    });
  });

  describe('passwordlessSignIn - Start', () => {
    it('Should passwordless with scopes, email, magic_link', async () => {
      const payloadWithScopes: PassflowPasswordlessSignInPayload = {
        email: payload.email,
        challenge_type: 'magic_link',
        scopes: ['id', 'profile', 'offline', 'oidc'],
        create_tenant: true,
        redirect_url: 'https://test-redirect-url.com',
      };
      const axiosClientGetMock = vi.spyOn(AxiosClient.prototype, 'post').mockResolvedValue(mockSuccessResponse);
      const passwordlessStartResponse = await authApi.passwordlessSignIn(payloadWithScopes, deviceId, os);

      expect(axiosClientGetMock).toHaveBeenCalledWith(PassflowEndpointPaths.passwordless, {
        ...payloadWithScopes,
        device: deviceId,
        os,
      });
      expect(passwordlessStartResponse).toEqual(mockSuccessResponse);
    });

    it('Should sign up with empty array scopes and phone, otp', async () => {
      const payloadWithEmptyScopes: PassflowPasswordlessSignInPayload = {
        phone: '+33333333333',
        challenge_type: 'otp',
        scopes: [],
        create_tenant: true,
        redirect_url: 'https://test-redirect-url.com',
      };
      const axiosClientGetMock = vi.spyOn(AxiosClient.prototype, 'post').mockResolvedValue(mockSuccessResponse);
      const passwordlessStartResponse = await authApi.passwordlessSignIn(payloadWithEmptyScopes, deviceId, os);

      expect(axiosClientGetMock).toHaveBeenCalledWith(PassflowEndpointPaths.passwordless, {
        ...payloadWithEmptyScopes,
        device: deviceId,
        os,
      });
      expect(passwordlessStartResponse).toEqual(mockSuccessResponse);
    });

    it('Should passwordless with identity (email, phone, username) is taken', async () => {
      const payloadWithTakenData: PassflowPasswordlessSignInPayload = {
        email: payload.email,
        challenge_type: 'magic_link',
        scopes: ['id', 'profile', 'offline', 'oidc'],
        create_tenant: true,
        redirect_url: 'https://test-redirect-url.com',
      };
      const axiosClientGetMock = vi.spyOn(AxiosClient.prototype, 'post').mockResolvedValue(mockSignUpErrorTakenResponse);
      const signInResponse = await authApi.passwordlessSignIn(payloadWithTakenData, deviceId, os);

      expect(axiosClientGetMock).toHaveBeenCalledWith(PassflowEndpointPaths.passwordless, {
        ...payloadWithTakenData,
        device: deviceId,
        os,
      });
      expect(signInResponse).toEqual(mockSignUpErrorTakenResponse);
    });
  });

  describe('passwordlessSignIn - Complete', () => {
    it('Should passwordless with scopes and otp', async () => {
      const payloadWithScopes: PassflowPasswordlessSignInCompletePayload = {
        challenge_id: 'challengeId',
        otp: '1234',
        challenge_type: 'magic_link',
        scopes: ['id', 'profile', 'offline', 'oidc'],
        device: deviceId,
      };
      const axiosClientGetMock = vi.spyOn(AxiosClient.prototype, 'post').mockResolvedValue(mockResponse);
      const passwordlessCompleteResponse = await authApi.passwordlessSignInComplete(payloadWithScopes);

      expect(axiosClientGetMock).toHaveBeenCalledWith(PassflowEndpointPaths.passwordlessComplete, payloadWithScopes);
      expect(passwordlessCompleteResponse).toEqual(mockResponse);
    });

    it('Should sign up with empty array scopes and otp', async () => {
      const payloadWithEmptyScopes: PassflowPasswordlessSignInCompletePayload = {
        challenge_id: 'challengeId',
        challenge_type: 'otp',
        otp: '1234',
        scopes: [],
        device: deviceId,
      };
      const axiosClientGetMock = vi.spyOn(AxiosClient.prototype, 'post').mockResolvedValue(mockSignInOnlyAccessTokenResponse);
      const passwordlessCompleteResponse = await authApi.passwordlessSignInComplete(payloadWithEmptyScopes);

      expect(axiosClientGetMock).toHaveBeenCalledWith(PassflowEndpointPaths.passwordlessComplete, payloadWithEmptyScopes);
      expect(passwordlessCompleteResponse).toEqual(mockSignInOnlyAccessTokenResponse);
    });
  });

  describe('logOut', () => {
    it('Should logout', async () => {
      const refreshToken = 'refreshToken.test.example';
      const axiosClientGetMock = vi.spyOn(AxiosClient.prototype, 'post').mockResolvedValue(mockSuccessResponse);
      const logoutResponse = await authApi.logOut(deviceId, refreshToken);
      expect(axiosClientGetMock).toHaveBeenCalledWith(PassflowEndpointPaths.logout, {
        device: deviceId,
        refresh_token: refreshToken,
      });
      expect(logoutResponse).toEqual(mockSuccessResponse);
    });
  });

  describe('refreshToken', () => {
    it('Should refresh token', async () => {
      const accessToken = 'accessToken.test.example';
      const refreshToken = 'refreshToken.test.example';
      const scopes = ['id', 'profile', 'offline', 'oidc'];
      const axiosClientGetMock = vi.spyOn(AxiosClient.prototype, 'post').mockResolvedValue(mockResponse);
      const refreshTokenResponse = await authApi.refreshToken(refreshToken, scopes, accessToken);

      expect(axiosClientGetMock).toHaveBeenCalledWith(
        PassflowEndpointPaths.refresh,
        { access: accessToken, scopes },
        { headers: { Authorization: `Bearer ${refreshToken}` } },
      );
      expect(refreshTokenResponse).toEqual(mockResponse);
    });
  });

  describe('sendPasswordResetEmail', () => {
    it('Should request to reset password', async () => {
      const sendPasswordResetPayload = { email: 'test@example.com' };
      const axiosClientGetMock = vi.spyOn(AxiosClient.prototype, 'post').mockResolvedValue(mockSuccessResponse);
      const sendPasswordResetEmailResponse = await authApi.sendPasswordResetEmail(sendPasswordResetPayload);

      expect(axiosClientGetMock).toHaveBeenCalledWith(PassflowEndpointPaths.sendPasswordResetEmail, sendPasswordResetPayload);
      expect(sendPasswordResetEmailResponse).toEqual(mockSuccessResponse);
    });
  });

  describe('resetPassword', () => {
    const newPassword = 'newPassword';
    const resetToken = 'resetToken.test.example';
    const scopes = ['id', 'profile', 'offline', 'oidc'];

    it('Should reset/change password', async () => {
      const axiosClientGetMock = vi.spyOn(AxiosClient.prototype, 'post').mockResolvedValue(mockResponse);
      const resetPasswordResponse = await authApi.resetPassword(newPassword, scopes, resetToken);

      expect(axiosClientGetMock).toHaveBeenCalledWith(
        PassflowEndpointPaths.resetPassword,
        { password: newPassword, scopes },
        { headers: { Authorization: `Bearer ${resetToken}` } },
      );
      expect(resetPasswordResponse).toEqual(mockResponse);
    });

    it('Should block token', async () => {
      const axiosClientGetMock = vi.spyOn(AxiosClient.prototype, 'post').mockResolvedValue(mockResetPasswordBlockTokenResponse);
      const resetPasswordResponse = await authApi.resetPassword(newPassword, scopes, 'blockedToken');

      expect(axiosClientGetMock).toHaveBeenCalledWith(
        PassflowEndpointPaths.resetPassword,
        { password: newPassword, scopes },
        { headers: { Authorization: `Bearer ${resetToken}` } },
      );
      expect(resetPasswordResponse).toEqual(mockResetPasswordBlockTokenResponse);
    });
  });
});
