import { AxiosClient } from './axios-client';
import { AoothConfig, AoothEndpointPaths, AoothInvitePayload, AoothInviteResponse } from './model';

export class TenantAPI {
  protected axiosClient: AxiosClient;

  constructor(config: AoothConfig) {
    this.axiosClient = new AxiosClient(config);
  }

  async joinInvitation(token: string, scopes: string[]): Promise<AoothInviteResponse> {
    const payload = {
      invite: token,
      scopes,
    };

    return this.axiosClient.post<AoothInviteResponse, AoothInvitePayload>(AoothEndpointPaths.joinInvitation, payload);
  }
}
