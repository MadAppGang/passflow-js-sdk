import { AxiosClient } from './axios-client';
import { PassflowConfig, PassflowSuccessResponse } from './model';

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
   * @returns Promise with array of invitations
   */
  getInvitations(): Promise<Invitation[]> {
    return this.axiosClient.get<Invitation[]>('/api/invitation/list');
  }

  /**
   * Deletes an invitation by token
   * @param token The invitation token to delete
   * @returns Promise with success response
   */
  deleteInvitation(token: string): Promise<PassflowSuccessResponse> {
    return this.axiosClient.delete<PassflowSuccessResponse>(`/api/invitation/${token}`);
  }
}
