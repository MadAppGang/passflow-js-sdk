import { RegistrationResponseJSON } from '@simplewebauthn/types';

import { AxiosClient } from './axios-client';
import {
  AoothAuthorizationResponse,
  AoothConfig,
  AoothEndpointPaths,
  AoothPasskeyCompleteMessage,
  AoothPasskeyRegisterPayload,
  AoothPasskeyStart,
  AoothSuccessResponse,
  AoothUserPasskey,
  OS,
} from './model';

export class UserAPI {
  protected axiosClient: AxiosClient;

  constructor(config: AoothConfig) {
    this.axiosClient = new AxiosClient(config);
  }

  async getUserPasskeys(): Promise<AoothUserPasskey> {
    return this.axiosClient.get<AoothUserPasskey>(AoothEndpointPaths.userPasskey);
  }

  async renameUserPasskey(name: string, passkeyId: string): Promise<AoothSuccessResponse> {
    return this.axiosClient.patch<AoothSuccessResponse, { name: string }>(`${AoothEndpointPaths.userPasskey}/${passkeyId}`, {
      name,
    });
  }

  async deleteUserPasskey(passkeyId: string): Promise<AoothSuccessResponse> {
    return this.axiosClient.delete<AoothSuccessResponse>(`${AoothEndpointPaths.userPasskey}/${passkeyId}`);
  }

  async createUserPasskeyStart(
    relyingPartyId: string,
    deviceId: string,
    os: OS,
    createTenant: boolean,
    scopes: string[],
  ): Promise<AoothPasskeyStart> {
    const payload = {
      relying_party_id: relyingPartyId,
      deviceId,
      os,
      createTenant,
      scopes,
      challenge_type: 'passkey',
      intention: 'register',
    };

    return this.axiosClient.post<AoothPasskeyStart, typeof payload>(AoothEndpointPaths.addUserPasskey, payload);
  }

  async createUserPasskeyComplete(
    passkeyData: RegistrationResponseJSON,
    deviceId: string,
    challengeId: string,
  ): Promise<AoothAuthorizationResponse | AoothPasskeyCompleteMessage> {
    const payload: AoothPasskeyRegisterPayload = {
      challenge_id: challengeId,
      device: deviceId,
      passkey_data: passkeyData,
    };

    return this.axiosClient.post<AoothAuthorizationResponse, AoothPasskeyRegisterPayload>(
      AoothEndpointPaths.completeAddUserPasskey,
      payload,
    );
  }
}
