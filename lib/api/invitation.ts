import { AxiosClient } from './axios-client';
import { type PassflowConfig, type PassflowSuccessResponse, PassflowEndpointPaths, pathWithParams } from './model';
import { TenantAPI } from './tenant';

export interface RequestInviteLinkPayload {
  email?: string;
  tenant?: string;
  group?: string;
  role?: string;
  callback?: string;
  send_to_email?: boolean;
  data?: Record<string, unknown>;
}

export interface InviteLinkResponse {
  link: string;
  token: string;
}

export interface Invitation {
  id: string;
  token: string;
  email?: string;
  tenant?: string;
  group?: string;
  role?: string;
  status: string;
  created_at: string;
  expires_at: string;
}

export class InvitationAPI {
  protected axiosClient: AxiosClient;

  constructor(config: PassflowConfig) {
    this.axiosClient = new AxiosClient(config);
  }

  /**
   * Requests an invitation link that can be used to invite users
   * @param payload Request invitation payload
   * @returns Promise with invitation link and token
   */
  requestInviteLink(payload: RequestInviteLinkPayload): Promise<InviteLinkResponse> {
    return this.axiosClient.post<InviteLinkResponse, RequestInviteLinkPayload>('/api/invitation/request', payload);
  }

  /**
   * Gets a list of active invitations
   * @param options Optional parameters for filtering and pagination
   * @returns Promise with array of invitations
   */
  getInvitations(options: {
    tenantID: string;
    groupID?: string;
    skip?: number | string;
    limit?: number | string;
  }): Promise<Invitation[]> {
    const params: Record<string, string> = {};

    if (options.groupID) params['group_id'] = options.groupID.toString();
    if (options.skip !== undefined) params['skip'] = options.skip.toString();
    if (options.limit !== undefined) params['limit'] = options.limit.toString();

    const path = pathWithParams(PassflowEndpointPaths.invitationsPath, { tenantID: options.tenantID });

    return this.axiosClient.get<Invitation[]>(path, { params });
  }

  /**
   * Deletes an invitation by token
   * @param token The invitation token to delete
   * @returns Promise with success response
   */
  deleteInvitation(token: string): Promise<PassflowSuccessResponse> {
    const path = pathWithParams(PassflowEndpointPaths.invitationDelete, { token });
    return this.axiosClient.delete<PassflowSuccessResponse>(path);
  }
}
