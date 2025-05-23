import { AxiosClient } from './axios-client';
import { type PassflowConfig, PassflowEndpointPaths, type PassflowSuccessResponse, pathWithParams } from './model';

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
  token?: string;
}

export interface Invitation {
  id: string;
  archived?: boolean;
  app_id: string;
  inviter_id: string;
  inviter_name: string;
  token: string;
  email?: string;
  role?: string;
  tenant?: string;
  tenant_name?: string;
  group?: string;
  created_by?: string;
  created_at: string;
  expires_at: string;
  callback?: string;
  data?: Record<string, unknown>;
}

// Internal API response type
interface InvitationsAPIResponse {
  invites: Invitation[];
  next_page_skip?: string;
}

// Public interface for external use
export interface InvitationsPaginatedList {
  invites: Invitation[];
  nextPageSkip?: string;
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
    return this.axiosClient.post<InviteLinkResponse, RequestInviteLinkPayload>(
      PassflowEndpointPaths.requestInvitation,
      payload,
    );
  }

  /**
   * Gets a list of active invitations
   * @param options Optional parameters for filtering and pagination
   * @returns Promise with paginated list of invitations
   */
  getInvitations(options: {
    tenantID: string;
    groupID?: string;
    skip?: number | string;
    limit?: number | string;
  }): Promise<InvitationsPaginatedList> {
    const params: Record<string, string> = {};

    if (options.groupID) params.group_id = options.groupID.toString();
    if (options.skip !== undefined) params.skip = options.skip.toString();
    if (options.limit !== undefined) params.limit = options.limit.toString();

    const path = pathWithParams(PassflowEndpointPaths.invitationsPath, {
      tenantID: options.tenantID,
    });

    return this.axiosClient.get<InvitationsAPIResponse>(path, { params }).then((response) => ({
      invites: response.invites,
      nextPageSkip: response.next_page_skip,
    }));
  }

  /**
   * Deletes an invitation by token
   * @param invitationID The invitation ID to delete
   * @returns Promise with success response
   */
  deleteInvitation(invitationID: string): Promise<PassflowSuccessResponse> {
    const path = pathWithParams(PassflowEndpointPaths.invitationDelete, {
      invitationID,
    });
    return this.axiosClient.delete<PassflowSuccessResponse>(path);
  }

  /**
   * Resend an invitation by token
   * @param invitationID The invitation ID to resend
   * @returns Promise with success response
   */
  resendInvitation(invitationID: string): Promise<PassflowSuccessResponse> {
    const path = pathWithParams(PassflowEndpointPaths.invitationResend, {
      invitationID,
    });
    return this.axiosClient.post<PassflowSuccessResponse, unknown>(path, {});
  }

  /**
   * Get a link to an invitation by id
   * @param invitationID The invitation ID to get link
   * @returns Promise with the link
   */
  getInvitationLink(invitationID: string): Promise<InviteLinkResponse> {
    const path = pathWithParams(PassflowEndpointPaths.invitationGetLink, {
      invitationID,
    });
    return this.axiosClient.get<InviteLinkResponse>(path);
  }
}
