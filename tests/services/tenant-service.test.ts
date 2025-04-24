import { Mock, beforeEach, describe, expect, test, vi } from 'vitest';
import { TenantAPI } from '../../lib/api';
import { TenantService } from '../../lib/services/tenant-service';

// Mock dependencies
vi.mock('../../lib/api/tenant');

describe('TenantService', () => {
  // Setup for all tests
  let tenantService: TenantService;
  let mockTenantApi: {
    // Original methods
    joinInvitation: Mock;
    createTenant: Mock;
    
    // 1. Tenant Management
    getTenantDetails: Mock;
    updateTenant: Mock;
    deleteTenant: Mock;
    getUserTenantMembership: Mock;
    
    // 2. Group Management
    createGroup: Mock;
    getGroupInfo: Mock;
    updateGroup: Mock;
    deleteGroup: Mock;
    addUserToGroup: Mock;
    removeUserRolesFromGroup: Mock;
    changeUserRoles: Mock;
    deleteUserFromGroup: Mock;
    
    // 3. Role Management
    getRolesForTenant: Mock;
    createRoleForTenant: Mock;
    updateRole: Mock;
    deleteRole: Mock;
    
    // 4. User Management in Tenants
    deleteUserFromTenant: Mock;
    
    // 5. Invitation Management
    getGroupInvitations: Mock;
    getTenantInvitations: Mock;
    invalidateInviteById: Mock;
    invalidateInviteByEmail: Mock;
  };

  const mockScopes = ['profile', 'email'];
  const mockTenantName = 'Test Organization';
  const mockInvitationToken = 'invitation-token-123';
  const mockTenantId = 'tenant-123';
  const mockGroupId = 'group-123';
  const mockUserId = 'user-123';
  const mockRoleId = 'role-123';
  const mockRoleName = 'Admin';
  const mockGroupName = 'Engineering';
  const mockEmail = 'test@example.com';
  const mockInviteId = 'invite-123';

  const mockTenantResponse = {
    name: mockTenantName,
    id: mockTenantId,
  };

  const mockInviteResponse = {
    access_token: 'access-token-123',
    refresh_token: 'refresh-token-123',
    id_token: 'id-token-123',
  };

  const mockStatusResponse = {
    status: 'success',
  };

  const mockGroupResponse = {
    id: mockGroupId,
    name: mockGroupName,
    updated_at: '2023-01-01T00:00:00Z',
    created_at: '2023-01-01T00:00:00Z',
  };

  const mockRoleResponse = {
    id: mockRoleId,
    tenant_id: mockTenantId,
    name: mockRoleName,
  };

  const mockUserTenantMembershipResponse = {
    [mockTenantId]: {
      tenant_id: mockTenantId,
      tenant_name: mockTenantName,
      groups: {
        [mockGroupId]: [mockRoleId],
      },
      group_names: {
        [mockGroupId]: mockGroupName,
      },
    },
  };

  const mockInvitationsResponse = {
    invites: [
      {
        id: mockInviteId,
        archived: false,
        app_id: 'app-123',
        inviter_id: 'inviter-123',
        inviter_name: 'Inviter Name',
        token: 'token-123',
        email: mockEmail,
        role: mockRoleName,
        tenant: mockTenantId,
        tenant_name: mockTenantName,
        group: mockGroupId,
        created_by: 'creator-123',
        created_at: '2023-01-01T00:00:00Z',
        expires_at: '2023-02-01T00:00:00Z',
      },
    ],
    next_page_skip: '10',
  };

  beforeEach(() => {
    // Reset mocks
    vi.resetAllMocks();

    // Create mock instances
    mockTenantApi = {
      // Original methods
      joinInvitation: vi.fn().mockResolvedValue(mockInviteResponse),
      createTenant: vi.fn().mockResolvedValue(mockTenantResponse),
      
      // 1. Tenant Management
      getTenantDetails: vi.fn().mockResolvedValue(mockTenantResponse),
      updateTenant: vi.fn().mockResolvedValue(mockStatusResponse),
      deleteTenant: vi.fn().mockResolvedValue(mockStatusResponse),
      getUserTenantMembership: vi.fn().mockResolvedValue(mockUserTenantMembershipResponse),
      
      // 2. Group Management
      createGroup: vi.fn().mockResolvedValue(mockGroupResponse),
      getGroupInfo: vi.fn().mockResolvedValue(mockGroupResponse),
      updateGroup: vi.fn().mockResolvedValue(mockGroupResponse),
      deleteGroup: vi.fn().mockResolvedValue(mockStatusResponse),
      addUserToGroup: vi.fn().mockResolvedValue(mockStatusResponse),
      removeUserRolesFromGroup: vi.fn().mockResolvedValue(mockStatusResponse),
      changeUserRoles: vi.fn().mockResolvedValue(mockStatusResponse),
      deleteUserFromGroup: vi.fn().mockResolvedValue(mockStatusResponse),
      
      // 3. Role Management
      getRolesForTenant: vi.fn().mockResolvedValue([mockRoleResponse]),
      createRoleForTenant: vi.fn().mockResolvedValue(mockRoleResponse),
      updateRole: vi.fn().mockResolvedValue(mockRoleResponse),
      deleteRole: vi.fn().mockResolvedValue(mockStatusResponse),
      
      // 4. User Management in Tenants
      deleteUserFromTenant: vi.fn().mockResolvedValue(mockStatusResponse),
      
      // 5. Invitation Management
      getGroupInvitations: vi.fn().mockResolvedValue(mockInvitationsResponse),
      getTenantInvitations: vi.fn().mockResolvedValue(mockInvitationsResponse),
      invalidateInviteById: vi.fn().mockResolvedValue({}),
      invalidateInviteByEmail: vi.fn().mockResolvedValue({}),
    };

    // Create TenantService instance
    tenantService = new TenantService(mockTenantApi as unknown as TenantAPI, mockScopes);
  });

  describe('joinInvitation', () => {
    test('should call TenantAPI joinInvitation with correct parameters', async () => {
      await tenantService.joinInvitation(mockInvitationToken);

      expect(mockTenantApi.joinInvitation).toHaveBeenCalledWith(mockInvitationToken, mockScopes);
    });

    test('should use provided scopes if specified', async () => {
      const customScopes = ['custom:scope', 'another:scope'];

      await tenantService.joinInvitation(mockInvitationToken, customScopes);

      expect(mockTenantApi.joinInvitation).toHaveBeenCalledWith(mockInvitationToken, customScopes);
    });

    test('should return invite response', async () => {
      const response = await tenantService.joinInvitation(mockInvitationToken);

      expect(response).toEqual(mockInviteResponse);
    });
  });

  describe('createTenant', () => {
    test('should call TenantAPI createTenant with correct parameters', async () => {
      await tenantService.createTenant(mockTenantName);

      expect(mockTenantApi.createTenant).toHaveBeenCalledWith(mockTenantName);
    });

    test('should return tenant response', async () => {
      const response = await tenantService.createTenant(mockTenantName);

      expect(response).toEqual(mockTenantResponse);
    });
  });

  // 1. Tenant Management Tests
  describe('getTenantDetails', () => {
    test('should call TenantAPI getTenantDetails with correct parameters', async () => {
      await tenantService.getTenantDetails(mockTenantId);

      expect(mockTenantApi.getTenantDetails).toHaveBeenCalledWith(mockTenantId);
    });

    test('should return tenant response', async () => {
      const response = await tenantService.getTenantDetails(mockTenantId);

      expect(response).toEqual(mockTenantResponse);
    });
  });

  describe('updateTenant', () => {
    test('should call TenantAPI updateTenant with correct parameters', async () => {
      await tenantService.updateTenant(mockTenantId, mockTenantName);

      expect(mockTenantApi.updateTenant).toHaveBeenCalledWith(mockTenantId, mockTenantName);
    });

    test('should return status response', async () => {
      const response = await tenantService.updateTenant(mockTenantId, mockTenantName);

      expect(response).toEqual(mockStatusResponse);
    });
  });

  describe('getUserTenantMembership', () => {
    test('should call TenantAPI getUserTenantMembership', async () => {
      await tenantService.getUserTenantMembership();

      expect(mockTenantApi.getUserTenantMembership).toHaveBeenCalled();
    });

    test('should return user tenant membership response', async () => {
      const response = await tenantService.getUserTenantMembership();

      expect(response).toEqual(mockUserTenantMembershipResponse);
    });
  });

  // 2. Group Management Tests
  describe('createGroup', () => {
    test('should call TenantAPI createGroup with correct parameters', async () => {
      await tenantService.createGroup(mockTenantId, mockGroupName);

      expect(mockTenantApi.createGroup).toHaveBeenCalledWith(mockTenantId, mockGroupName);
    });

    test('should return group response', async () => {
      const response = await tenantService.createGroup(mockTenantId, mockGroupName);

      expect(response).toEqual(mockGroupResponse);
    });
  });

  describe('updateGroup', () => {
    test('should call TenantAPI updateGroup with correct parameters', async () => {
      await tenantService.updateGroup(mockTenantId, mockGroupId, mockGroupName);

      expect(mockTenantApi.updateGroup).toHaveBeenCalledWith(mockTenantId, mockGroupId, mockGroupName);
    });

    test('should return group response', async () => {
      const response = await tenantService.updateGroup(mockTenantId, mockGroupId, mockGroupName);

      expect(response).toEqual(mockGroupResponse);
    });
  });

  describe('addUserToGroup', () => {
    test('should call TenantAPI addUserToGroup with correct parameters', async () => {
      await tenantService.addUserToGroup(mockTenantId, mockGroupId, mockUserId, mockRoleName);

      expect(mockTenantApi.addUserToGroup).toHaveBeenCalledWith(mockTenantId, mockGroupId, mockUserId, mockRoleName);
    });

    test('should return status response', async () => {
      const response = await tenantService.addUserToGroup(mockTenantId, mockGroupId, mockUserId, mockRoleName);

      expect(response).toEqual(mockStatusResponse);
    });
  });

  // 3. Role Management Tests
  describe('getRolesForTenant', () => {
    test('should call TenantAPI getRolesForTenant with correct parameters', async () => {
      await tenantService.getRolesForTenant(mockTenantId);

      expect(mockTenantApi.getRolesForTenant).toHaveBeenCalledWith(mockTenantId);
    });

    test('should return roles response', async () => {
      const response = await tenantService.getRolesForTenant(mockTenantId);

      expect(response).toEqual([mockRoleResponse]);
    });
  });

  describe('createRoleForTenant', () => {
    test('should call TenantAPI createRoleForTenant with correct parameters', async () => {
      await tenantService.createRoleForTenant(mockTenantId, mockRoleName);

      expect(mockTenantApi.createRoleForTenant).toHaveBeenCalledWith(mockTenantId, mockRoleName);
    });

    test('should return role response', async () => {
      const response = await tenantService.createRoleForTenant(mockTenantId, mockRoleName);

      expect(response).toEqual(mockRoleResponse);
    });
  });

  // 4. User Management in Tenants Tests
  describe('deleteUserFromTenant', () => {
    test('should call TenantAPI deleteUserFromTenant with correct parameters', async () => {
      await tenantService.deleteUserFromTenant(mockTenantId, mockUserId);

      expect(mockTenantApi.deleteUserFromTenant).toHaveBeenCalledWith(mockTenantId, mockUserId);
    });

    test('should return status response', async () => {
      const response = await tenantService.deleteUserFromTenant(mockTenantId, mockUserId);

      expect(response).toEqual(mockStatusResponse);
    });
  });

  // 5. Invitation Management Tests
  describe('getTenantInvitations', () => {
    const mockLimit = 10;
    const mockSkip = 0;

    test('should call TenantAPI getTenantInvitations with correct parameters', async () => {
      await tenantService.getTenantInvitations(mockTenantId, mockLimit, mockSkip);

      expect(mockTenantApi.getTenantInvitations).toHaveBeenCalledWith(mockTenantId, mockLimit, mockSkip);
    });

    test('should return invitations response', async () => {
      const response = await tenantService.getTenantInvitations(mockTenantId, mockLimit, mockSkip);

      expect(response).toEqual(mockInvitationsResponse);
    });
  });

  describe('invalidateInviteById', () => {
    test('should call TenantAPI invalidateInviteById with correct parameters', async () => {
      await tenantService.invalidateInviteById(mockTenantId, mockGroupId, mockInviteId);

      expect(mockTenantApi.invalidateInviteById).toHaveBeenCalledWith(mockTenantId, mockGroupId, mockInviteId);
    });

    test('should return empty record', async () => {
      const response = await tenantService.invalidateInviteById(mockTenantId, mockGroupId, mockInviteId);

      expect(response).toEqual({});
    });
  });
});
