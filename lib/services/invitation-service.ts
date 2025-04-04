import {
  Invitation,
  InvitationAPI,
  InviteLinkResponse,
  InvitationsResponse,
  PassflowSuccessResponse,
  RequestInviteLinkPayload,
} from '../api';

/**
 * Service for managing invitations
 */
export class InvitationService {
  constructor(private invitationAPI: InvitationAPI) {}

  /**
   * Requests an invitation link that can be used to invite users
   * @param payload Request invitation payload
   * @returns Promise with invitation link and token
   */
  requestInviteLink(payload: RequestInviteLinkPayload): Promise<InviteLinkResponse> {
    return this.invitationAPI.requestInviteLink(payload);
  }

  /**
   * Gets a list of active invitations
   * @param options Optional parameters for filtering and pagination
   * @returns Promise with invitations response containing array of invitations and pagination info
   */
  getInvitations(options: {
    tenantID: string;
    groupID?: string;
    skip?: number | string;
    limit?: number | string;
  }): Promise<InvitationsResponse> {
    return this.invitationAPI.getInvitations({
      tenantID: options.tenantID,
      groupID: options.groupID,
      skip: options.skip,
      limit: options.limit,
    });
  }

  /**
   * Deletes an invitation by token
   * @param token The invitation token to delete
   * @returns Promise with success response
   */
  deleteInvitation(token: string): Promise<PassflowSuccessResponse> {
    return this.invitationAPI.deleteInvitation(token);
  }
}
