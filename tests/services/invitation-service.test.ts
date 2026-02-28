import { Mock, beforeEach, describe, expect, test, vi } from 'vitest';
import {
  Invitation,
  InvitationAPI,
  InvitationsPaginatedList,
  InviteLinkResponse,
  PassflowSuccessResponse,
  RequestInviteLinkPayload,
} from '../../lib/api';
import { InvitationService } from '../../lib/services/invitation-service';

// Mock dependencies
vi.mock('../../lib/api/invitation');

describe('InvitationService', () => {
  // Setup for all tests
  let invitationService: InvitationService;
  let mockInvitationApi: {
    requestInviteLink: Mock;
    getInvitations: Mock;
    deleteInvitation: Mock;
    resendInvitation: Mock;
    getInvitationLink: Mock;
  };

  const mockInvitationToken = 'invitation-token-123';

  const mockRequestPayload: RequestInviteLinkPayload = {
    email: 'user@example.com',
    role: 'member',
    send_to_email: true,
  };

  const mockInviteLinkResponse: InviteLinkResponse = {
    link: 'https://example.com/invite/token123',
    token: 'token123',
  };

  const mockInvitations: Invitation[] = [
    {
      id: 'invitation-1',
      token: 'token-1',
      email: 'user1@example.com',
      archived: false,
      app_id: 'app-1',
      inviter_id: 'inviter-1',
      inviter_name: 'Inviter 1',
      created_by: 'creator-1',
      created_at: '2023-01-01',
      expires_at: '2023-02-01',
    },
    {
      id: 'invitation-2',
      token: 'token-2',
      email: 'user2@example.com',
      archived: false,
      app_id: 'app-2',
      inviter_id: 'inviter-2',
      inviter_name: 'Inviter 2',
      created_by: 'creator-2',
      created_at: '2023-01-02',
      expires_at: '2023-02-02',
    },
  ];

  const mockInvitationsResponse: InvitationsPaginatedList = {
    invites: mockInvitations,
    nextPageSkip: '2',
  };

  const mockSuccessResponse: PassflowSuccessResponse = {
    result: 'ok',
  };

  beforeEach(() => {
    // Reset mocks
    vi.resetAllMocks();

    // Create mock instances
    mockInvitationApi = {
      requestInviteLink: vi.fn().mockResolvedValue(mockInviteLinkResponse),
      getInvitations: vi.fn().mockResolvedValue(mockInvitationsResponse),
      deleteInvitation: vi.fn().mockResolvedValue(mockSuccessResponse),
      resendInvitation: vi.fn().mockResolvedValue(mockSuccessResponse),
      getInvitationLink: vi.fn().mockResolvedValue(mockInviteLinkResponse),
    };

    // Create InvitationService instance
    invitationService = new InvitationService(mockInvitationApi as unknown as InvitationAPI);
  });

  describe('requestInviteLink', () => {
    test('should call InvitationAPI requestInviteLink with correct parameters', async () => {
      await invitationService.requestInviteLink(mockRequestPayload);

      expect(mockInvitationApi.requestInviteLink).toHaveBeenCalledWith(mockRequestPayload);
    });

    test('should return invite link response', async () => {
      const response = await invitationService.requestInviteLink(mockRequestPayload);

      expect(response).toEqual(mockInviteLinkResponse);
    });
  });

  describe('getInvitations', () => {
    test('should call InvitationAPI getInvitations', async () => {
      const response = await invitationService.getInvitations({ tenantID: 'tenant-1' });

      expect(mockInvitationApi.getInvitations).toHaveBeenCalledWith({
        tenantID: 'tenant-1',
        groupID: undefined,
        skip: undefined,
        limit: undefined,
      });
      expect(response).toEqual(mockInvitationsResponse);
    });
  });

  describe('deleteInvitation', () => {
    test('should call InvitationAPI deleteInvitation with correct parameters', async () => {
      await invitationService.deleteInvitation(mockInvitationToken);

      expect(mockInvitationApi.deleteInvitation).toHaveBeenCalledWith(mockInvitationToken);
    });

    test('should return success response', async () => {
      const response = await invitationService.deleteInvitation(mockInvitationToken);

      expect(response).toEqual(mockSuccessResponse);
    });
  });
});
