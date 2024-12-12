import { RegistrationResponseJSON } from '@simplewebauthn/types';

import { AxiosClient } from './axios-client';
import {
  OS,
  PassflowAuthorizationResponse,
  PassflowConfig,
  PassflowEndpointPaths,
  PassflowPasskeyCompleteMessage,
  PassflowPasskeyRegisterPayload,
  PassflowPasskeyStart,
  PassflowSuccessResponse,
  PassflowUserPasskey,
} from './model';

export class UserAPI {
  protected axiosClient: AxiosClient;

  constructor(config: PassflowConfig) {
    this.axiosClient = new AxiosClient(config);
  }

  async getUserPasskeys(): Promise<PassflowUserPasskey> {
    return this.axiosClient.get<PassflowUserPasskey>(PassflowEndpointPaths.userPasskey);
  }

  async renameUserPasskey(name: string, passkeyId: string): Promise<PassflowSuccessResponse> {
    return this.axiosClient.patch<PassflowSuccessResponse, { name: string }>(
      `${PassflowEndpointPaths.userPasskey}/${passkeyId}`,
      {
        name,
      },
    );
  }

  async deleteUserPasskey(passkeyId: string): Promise<PassflowSuccessResponse> {
    return this.axiosClient.delete<PassflowSuccessResponse>(`${PassflowEndpointPaths.userPasskey}/${passkeyId}`);
  }

  async createUserPasskeyStart(
    relyingPartyId: string,
    deviceId: string,
    os: OS,
    createTenant: boolean,
    scopes: string[],
  ): Promise<PassflowPasskeyStart> {
    const payload = {
      relying_party_id: relyingPartyId,
      deviceId,
      os,
      createTenant,
      scopes,
      challenge_type: 'passkey',
      intention: 'register',
    };

    return this.axiosClient.post<PassflowPasskeyStart, typeof payload>(PassflowEndpointPaths.addUserPasskey, payload);
  }

  async createUserPasskeyComplete(
    passkeyData: RegistrationResponseJSON,
    deviceId: string,
    challengeId: string,
  ): Promise<PassflowAuthorizationResponse | PassflowPasskeyCompleteMessage> {
    const payload: PassflowPasskeyRegisterPayload = {
      challenge_id: challengeId,
      device: deviceId,
      passkey_data: passkeyData,
    };

    return this.axiosClient.post<PassflowAuthorizationResponse, PassflowPasskeyRegisterPayload>(
      PassflowEndpointPaths.completeAddUserPasskey,
      payload,
    );
  }
}
