import { describe, test, expect, beforeEach, vi } from 'vitest';
import { InvitationService } from '../../lib/services/invitation-service';
import { 
  InvitationAPI,
  RequestInviteLinkPayload,
  InviteLinkResponse, 
  Invitation,
  PassflowSuccessResponse
} from '../../lib/api';

// Mock dependencies
vi.mock('../../lib/api/invitation');

describe('InvitationService', () => {
  // Setup for all tests
  let invitationService: InvitationService;
  let mockInvitationApi: any;
  
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
      status: 'pending',
      created_at: '2023-01-01',
      expires_at: '2023-02-01',
    },
    {
      id: 'invitation-2',
      token: 'token-2',
      email: 'user2@example.com',
      status: 'pending',
      created_at: '2023-01-02',
      expires_at: '2023-02-02',
    },
  ];
  
  const mockSuccessResponse: PassflowSuccessResponse = {
    result: 'ok'
  };

  beforeEach(() => {
    // Reset mocks
    vi.resetAllMocks();
    
    // Create mock instances
    mockInvitationApi = {
      requestInviteLink: vi.fn().mockResolvedValue(mockInviteLinkResponse),
      getInvitations: vi.fn().mockResolvedValue(mockInvitations),
      deleteInvitation: vi.fn().mockResolvedValue(mockSuccessResponse),
    };
    
    // Create InvitationService instance
    invitationService = new InvitationService(
      mockInvitationApi as InvitationAPI
    );
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
      const invitations = await invitationService.getInvitations();
      
      expect(mockInvitationApi.getInvitations).toHaveBeenCalled();
      expect(invitations).toEqual(mockInvitations);
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