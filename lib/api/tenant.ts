import { AxiosClient } from './axios-client';
import {
  AoothConfig,
  AoothCreateTenantPayload,
  AoothEndpointPaths,
  AoothInvitePayload,
  AoothInviteResponse,
  AoothTenantResponse,
} from './model';

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

  async createTenant(name: string): Promise<AoothTenantResponse> {
    const payload = {
      name,
    };
    return this.axiosClient.post<AoothTenantResponse, AoothCreateTenantPayload>(AoothEndpointPaths.tenantPath, payload);
  }
}
