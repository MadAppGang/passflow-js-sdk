import { AxiosClient } from './axios-client';
import { type PassflowConfig, type PassflowSuccessResponse, PassflowEndpointPaths, pathWithParams } from './model';

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
  archived?: boolean;
  inviter_id?: string;
  email?: string;
  tenant?: string;
  group?: string;
  role?: string;
  created_at: string;
  created_by?: string;
  expires_at: string;
}

export interface InvitationsResponse {
  invites: Invitation[];
  next_page_skip: string;
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
    return this.axiosClient.post<InviteLinkResponse, RequestInviteLinkPayload>(PassflowEndpointPaths.inviteUserPath, payload);
  }

  /**
   * Gets a list of active invitations
   * @param options Optional parameters for filtering and pagination
   * @returns Promise with array of invitations and next page skip token
   */
  getInvitations(options: {
    tenantID: string;
    groupID?: string;
    skip?: number | string;
    limit?: number | string;
  }): Promise<InvitationsResponse> {
    const params: Record<string, string> = {};

    if (options.groupID) params.group_id = options.groupID.toString();
    if (options.skip !== undefined) params.skip = options.skip.toString();
    if (options.limit !== undefined) params.limit = options.limit.toString();

    const path = pathWithParams(PassflowEndpointPaths.invitationsPath, { tenantID: options.tenantID });

    return this.axiosClient.get<InvitationsResponse>(path, { params });
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
