import type {
  InvitationAPI,
  InvitationsPaginatedList,
  InviteLinkResponse,
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
   * @returns Promise with paginated list of invitations
   */
  getInvitations(options: {
    tenantID: string;
    groupID?: string;
    skip?: number | string;
    limit?: number | string;
  }): Promise<InvitationsPaginatedList> {
    return this.invitationAPI.getInvitations(options);
  }

  /**
   * Deletes an invitation by token
   * @param token The invitation token to delete
   * @returns Promise with success response
   */
  deleteInvitation(token: string): Promise<PassflowSuccessResponse> {
    return this.invitationAPI.deleteInvitation(token);
  }

  /**
   * Resends an invitation by token
   * @param token The invitation token to resend
   * @returns Promise with success response
   */
  resendInvitation(token: string): Promise<PassflowSuccessResponse> {
    return this.invitationAPI.resendInvitation(token);
  }

  /**
   * Gets a link to an invitation by id
   * @param invitationID The invitation ID to get link
   * @returns Promise with the link
   */
  getInvitationLink(invitationID: string): Promise<InviteLinkResponse> {
    return this.invitationAPI.getInvitationLink(invitationID);
  }
}
