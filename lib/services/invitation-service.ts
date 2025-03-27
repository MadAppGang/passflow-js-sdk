import {
  InvitationAPI,
  RequestInviteLinkPayload,
  InviteLinkResponse,
  Invitation,
  PassflowSuccessResponse,
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
   * @returns Promise with array of invitations
   */
  getInvitations(): Promise<Invitation[]> {
    return this.invitationAPI.getInvitations();
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
