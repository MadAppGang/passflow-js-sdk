import { RegistrationResponseJSON } from '@simplewebauthn/types';

import { AxiosClient } from './axios-client';
import {
  OS,
  PassflowConfig,
  PassflowEndpointPaths,
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

  getUserPasskeys() {
    return this.axiosClient.get<PassflowUserPasskey[]>(PassflowEndpointPaths.userPasskey);
  }

  renameUserPasskey(name: string, passkeyId: string): Promise<PassflowSuccessResponse> {
    return this.axiosClient.patch<PassflowSuccessResponse, { name: string }>(
      `${PassflowEndpointPaths.userPasskey}/${passkeyId}`,
      {
        name,
      },
    );
  }

  deleteUserPasskey(passkeyId: string): Promise<PassflowSuccessResponse> {
    return this.axiosClient.delete<PassflowSuccessResponse>(`${PassflowEndpointPaths.userPasskey}/${passkeyId}`);
  }

  addUserPasskeyStart({
    relyingPartyId,
    deviceId,
    os,
    passkeyDisplayName,
    passkeyUsername,
  }: {
    relyingPartyId: string;
    deviceId: string;
    os: OS;
    passkeyDisplayName?: string;
    passkeyUsername?: string;
  }): Promise<PassflowPasskeyStart> {
    const payload = {
      passkey_display_name: passkeyDisplayName,
      passkey_username: passkeyUsername,
      relying_party_id: relyingPartyId,
      deviceId,
      os,
    };

    return this.axiosClient.post<PassflowPasskeyStart, typeof payload>(PassflowEndpointPaths.addUserPasskey, payload);
  }

  addUserPasskeyComplete(passkeyData: RegistrationResponseJSON, deviceId: string, challengeId: string): Promise<void> {
    return this.axiosClient.post<void, PassflowPasskeyRegisterPayload>(PassflowEndpointPaths.completeAddUserPasskey, {
      challenge_id: challengeId,
      device: deviceId,
      passkey_data: passkeyData,
    });
  }
}
