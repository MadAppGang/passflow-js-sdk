import { AxiosClient } from './axios-client';
import {
  PassflowConfig,
  PassflowCreateTenantPayload,
  PassflowEndpointPaths,
  PassflowInvitePayload,
  PassflowInviteResponse,
  PassflowTenantResponse,
} from './model';

export class TenantAPI {
  protected axiosClient: AxiosClient;

  constructor(config: PassflowConfig) {
    this.axiosClient = new AxiosClient(config);
  }

  joinInvitation(token: string, scopes: string[]): Promise<PassflowInviteResponse> {
    const payload = {
      invite: token,
      scopes,
    };

    return this.axiosClient.post<PassflowInviteResponse, PassflowInvitePayload>(PassflowEndpointPaths.joinInvitation, payload);
  }

  createTenant(name: string): Promise<PassflowTenantResponse> {
    const payload = {
      name,
    };
    return this.axiosClient.post<PassflowTenantResponse, PassflowCreateTenantPayload>(
      PassflowEndpointPaths.tenantPath,
      payload,
    );
  }
}
