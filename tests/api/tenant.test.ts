import { beforeEach, describe, expect, test, vi } from 'vitest';
import axios from 'axios';
import { TenantAPI } from '../../lib/api/tenant';
import { PassflowEndpointPaths } from '../../lib/api/model';

// Mock axios
vi.mock('axios', () => {
  return {
    default: {
      create: vi.fn(() => ({
        request: vi.fn(),
        interceptors: {
          request: { use: vi.fn() },
          response: { use: vi.fn() }
        }
      }))
    }
  };
});

describe('TenantAPI', () => {
  // Setup for all tests
  let tenantApi: TenantAPI;
  let mockAxiosInstance: {
    request: ReturnType<typeof vi.fn>;
    interceptors: {
      request: { use: ReturnType<typeof vi.fn> };
      response: { use: ReturnType<typeof vi.fn> };
    };
  };

  // Test data
  const mockConfig = { url: 'https://api.example.com', appId: 'test-app-id' };
  const mockTenantId = 'tenant-123';
  const mockGroupId = 'group-123';
  const mockUserId = 'user-123';
  const mockRoleId = 'role-123';
  const mockInviteId = 'invite-123';
  const mockEmail = 'test@example.com';
  
  // Mock responses
  const mockTenantResponse = {
    tenant_id: mockTenantId,
    tenant_name: 'Test Tenant'
  };
  
  const mockStatusResponse = {
    status: 'success'
  };
  
  const mockGroupResponse = {
    id: mockGroupId,
    name: 'Test Group',
    updated_at: '2023-01-01T00:00:00Z',
    created_at: '2023-01-01T00:00:00Z'
  };
  
  const mockRoleResponse = {
    id: mockRoleId,
    tenant_id: mockTenantId,
    name: 'Admin'
  };
  
  const mockUserTenantMembershipResponse = {
    [mockTenantId]: {
      tenant_id: mockTenantId,
      tenant_name: 'Test Tenant',
      groups: {
        [mockGroupId]: [mockRoleId]
      },
      group_names: {
        [mockGroupId]: 'Test Group'
      }
    }
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
        role: 'Admin',
        tenant: mockTenantId,
        tenant_name: 'Test Tenant',
        group: mockGroupId,
        created_by: 'creator-123',
        created_at: '2023-01-01T00:00:00Z',
        expires_at: '2023-02-01T00:00:00Z'
      }
    ],
    next_page_skip: '10'
  };

  beforeEach(() => {
    vi.resetAllMocks();
    
    // Create TenantAPI instance
    tenantApi = new TenantAPI(mockConfig);
    
    // Get the axios instance created inside TenantAPI
    mockAxiosInstance = (axios.create as ReturnType<typeof vi.fn>).mock.results[0].value;
    
    // Setup default mock response
    mockAxiosInstance.request.mockImplementation((config: {
      method?: string;
      url: string;
      data?: unknown;
      params?: Record<string, unknown>;
    }) => {
      // Default response
      let responseData = {};
      
      // Tenant Management
      if (config.url === `${PassflowEndpointPaths.tenantPath}/${mockTenantId}`) {
        if (config.method === 'get') {
          responseData = mockTenantResponse;
        } else if (config.method === 'put') {
          responseData = mockStatusResponse;
        } else if (config.method === 'delete') {
          responseData = mockStatusResponse;
        }
      }
      // User Tenant Membership
      else if (config.url === PassflowEndpointPaths.tenantPath && config.method === 'get') {
        responseData = mockUserTenantMembershipResponse;
      }
      // Group Management
      else if (config.url === `${PassflowEndpointPaths.tenantPath}/${mockTenantId}/group` && config.method === 'post') {
        responseData = mockGroupResponse;
      }
      else if (config.url === `${PassflowEndpointPaths.tenantPath}/${mockTenantId}/group/${mockGroupId}`) {
        if (config.method === 'get') {
          responseData = mockGroupResponse;
        } else if (config.method === 'put') {
          responseData = mockGroupResponse;
        } else if (config.method === 'delete') {
          responseData = mockStatusResponse;
        }
      }
      else if (config.url === `${PassflowEndpointPaths.tenantPath}/${mockTenantId}/group/${mockGroupId}/add` && config.method === 'post') {
        responseData = mockStatusResponse;
      }
      else if (config.url === `${PassflowEndpointPaths.tenantPath}/${mockTenantId}/group/${mockGroupId}/remove_roles` && config.method === 'post') {
        responseData = mockStatusResponse;
      }
      else if (config.url === `${PassflowEndpointPaths.tenantPath}/${mockTenantId}/group/${mockGroupId}/change` && config.method === 'post') {
        responseData = mockStatusResponse;
      }
      else if (config.url === `${PassflowEndpointPaths.tenantPath}/${mockTenantId}/group/${mockGroupId}/${mockUserId}` && config.method === 'delete') {
        responseData = mockStatusResponse;
      }
      // Role Management
      else if (config.url === `${PassflowEndpointPaths.tenantPath}/${mockTenantId}/role`) {
        if (config.method === 'get') {
          responseData = [mockRoleResponse];
        } else if (config.method === 'post') {
          responseData = mockRoleResponse;
        }
      }
      else if (config.url === `${PassflowEndpointPaths.tenantPath}/${mockTenantId}/role/${mockRoleId}`) {
        if (config.method === 'put') {
          responseData = mockRoleResponse;
        } else if (config.method === 'delete') {
          responseData = mockStatusResponse;
        }
      }
      // User Management in Tenants
      else if (config.url === `${PassflowEndpointPaths.tenantPath}/${mockTenantId}/user/${mockUserId}` && config.method === 'delete') {
        responseData = mockStatusResponse;
      }
      // Invitation Management
      else if (config.url === `${PassflowEndpointPaths.tenantPath}/${mockTenantId}/group/${mockGroupId}/invitations` && config.method === 'get') {
        responseData = mockInvitationsResponse;
      }
      else if (config.url === `${PassflowEndpointPaths.tenantPath}/${mockTenantId}/invitations` && config.method === 'get') {
        responseData = mockInvitationsResponse;
      }
      else if (config.url === `${PassflowEndpointPaths.tenantPath}/${mockTenantId}/group/${mockGroupId}/invite/${mockInviteId}` && config.method === 'delete') {
        responseData = {};
      }
      else if (config.url === `${PassflowEndpointPaths.tenantPath}/${mockTenantId}/group/${mockGroupId}/invite/email/${mockEmail}` && config.method === 'delete') {
        responseData = {};
      }
      
      return { data: responseData };
    });
  });

  // 1. Tenant Management Tests
  describe('Tenant Management', () => {
    test('getTenantDetails should call axios with correct parameters', async () => {
      const result = await tenantApi.getTenantDetails(mockTenantId);
      
      expect(mockAxiosInstance.request).toHaveBeenCalledWith({
        method: 'get',
        url: `${PassflowEndpointPaths.tenantPath}/${mockTenantId}`
      });
      expect(result).toEqual(mockTenantResponse);
    });
    
    test('updateTenant should call axios with correct parameters', async () => {
      const newName = 'Updated Tenant Name';
      const result = await tenantApi.updateTenant(mockTenantId, newName);
      
      expect(mockAxiosInstance.request).toHaveBeenCalledWith({
        method: 'put',
        url: `${PassflowEndpointPaths.tenantPath}/${mockTenantId}`,
        data: { name: newName }
      });
      expect(result).toEqual(mockStatusResponse);
    });
    
    test('deleteTenant should call axios with correct parameters', async () => {
      const result = await tenantApi.deleteTenant(mockTenantId);
      
      expect(mockAxiosInstance.request).toHaveBeenCalledWith({
        method: 'delete',
        url: `${PassflowEndpointPaths.tenantPath}/${mockTenantId}`
      });
      expect(result).toEqual(mockStatusResponse);
    });
    
    test('getUserTenantMembership should call axios with correct parameters', async () => {
      const result = await tenantApi.getUserTenantMembership();
      
      expect(mockAxiosInstance.request).toHaveBeenCalledWith({
        method: 'get',
        url: PassflowEndpointPaths.tenantPath
      });
      expect(result).toEqual(mockUserTenantMembershipResponse);
    });
  });

  // 2. Group Management Tests
  describe('Group Management', () => {
    test('createGroup should call axios with correct parameters', async () => {
      const groupName = 'New Group';
      const result = await tenantApi.createGroup(mockTenantId, groupName);
      
      expect(mockAxiosInstance.request).toHaveBeenCalledWith({
        method: 'post',
        url: `${PassflowEndpointPaths.tenantPath}/${mockTenantId}/group`,
        data: { name: groupName }
      });
      expect(result).toEqual(mockGroupResponse);
    });
    
    test('getGroupInfo should call axios with correct parameters', async () => {
      const result = await tenantApi.getGroupInfo(mockTenantId, mockGroupId);
      
      expect(mockAxiosInstance.request).toHaveBeenCalledWith({
        method: 'get',
        url: `${PassflowEndpointPaths.tenantPath}/${mockTenantId}/group/${mockGroupId}`
      });
      expect(result).toEqual(mockGroupResponse);
    });
    
    test('updateGroup should call axios with correct parameters', async () => {
      const newName = 'Updated Group Name';
      const result = await tenantApi.updateGroup(mockTenantId, mockGroupId, newName);
      
      expect(mockAxiosInstance.request).toHaveBeenCalledWith({
        method: 'put',
        url: `${PassflowEndpointPaths.tenantPath}/${mockTenantId}/group/${mockGroupId}`,
        data: { name: newName }
      });
      expect(result).toEqual(mockGroupResponse);
    });
    
    test('deleteGroup should call axios with correct parameters', async () => {
      const result = await tenantApi.deleteGroup(mockTenantId, mockGroupId);
      
      expect(mockAxiosInstance.request).toHaveBeenCalledWith({
        method: 'delete',
        url: `${PassflowEndpointPaths.tenantPath}/${mockTenantId}/group/${mockGroupId}`
      });
      expect(result).toEqual(mockStatusResponse);
    });
    
    test('addUserToGroup should call axios with correct parameters', async () => {
      const role = 'Admin';
      const result = await tenantApi.addUserToGroup(mockTenantId, mockGroupId, mockUserId, role);
      
      expect(mockAxiosInstance.request).toHaveBeenCalledWith({
        method: 'post',
        url: `${PassflowEndpointPaths.tenantPath}/${mockTenantId}/group/${mockGroupId}/add`,
        data: { user_id: mockUserId, role }
      });
      expect(result).toEqual(mockStatusResponse);
    });
    
    test('removeUserRolesFromGroup should call axios with correct parameters', async () => {
      const roles = ['Admin', 'Editor'];
      const result = await tenantApi.removeUserRolesFromGroup(mockTenantId, mockGroupId, mockUserId, roles);
      
      expect(mockAxiosInstance.request).toHaveBeenCalledWith({
        method: 'post',
        url: `${PassflowEndpointPaths.tenantPath}/${mockTenantId}/group/${mockGroupId}/remove_roles`,
        data: { user_id: mockUserId, roles }
      });
      expect(result).toEqual(mockStatusResponse);
    });
    
    test('changeUserRoles should call axios with correct parameters', async () => {
      const roles = ['Editor', 'Viewer'];
      const result = await tenantApi.changeUserRoles(mockTenantId, mockGroupId, mockUserId, roles);
      
      expect(mockAxiosInstance.request).toHaveBeenCalledWith({
        method: 'post',
        url: `${PassflowEndpointPaths.tenantPath}/${mockTenantId}/group/${mockGroupId}/change`,
        data: { user_id: mockUserId, roles }
      });
      expect(result).toEqual(mockStatusResponse);
    });
    
    test('deleteUserFromGroup should call axios with correct parameters', async () => {
      const result = await tenantApi.deleteUserFromGroup(mockTenantId, mockGroupId, mockUserId);
      
      expect(mockAxiosInstance.request).toHaveBeenCalledWith({
        method: 'delete',
        url: `${PassflowEndpointPaths.tenantPath}/${mockTenantId}/group/${mockGroupId}/${mockUserId}`
      });
      expect(result).toEqual(mockStatusResponse);
    });
  });

  // 3. Role Management Tests
  describe('Role Management', () => {
    test('getRolesForTenant should call axios with correct parameters', async () => {
      const result = await tenantApi.getRolesForTenant(mockTenantId);
      
      expect(mockAxiosInstance.request).toHaveBeenCalledWith({
        method: 'get',
        url: `${PassflowEndpointPaths.tenantPath}/${mockTenantId}/role`
      });
      expect(result).toEqual([mockRoleResponse]);
    });
    
    test('createRoleForTenant should call axios with correct parameters', async () => {
      const roleName = 'New Role';
      const result = await tenantApi.createRoleForTenant(mockTenantId, roleName);
      
      expect(mockAxiosInstance.request).toHaveBeenCalledWith({
        method: 'post',
        url: `${PassflowEndpointPaths.tenantPath}/${mockTenantId}/role`,
        data: { name: roleName }
      });
      expect(result).toEqual(mockRoleResponse);
    });
    
    test('updateRole should call axios with correct parameters', async () => {
      const newName = 'Updated Role Name';
      const result = await tenantApi.updateRole(mockTenantId, mockRoleId, newName);
      
      expect(mockAxiosInstance.request).toHaveBeenCalledWith({
        method: 'put',
        url: `${PassflowEndpointPaths.tenantPath}/${mockTenantId}/role/${mockRoleId}`,
        data: { name: newName }
      });
      expect(result).toEqual(mockRoleResponse);
    });
    
    test('deleteRole should call axios with correct parameters', async () => {
      const result = await tenantApi.deleteRole(mockTenantId, mockRoleId);
      
      expect(mockAxiosInstance.request).toHaveBeenCalledWith({
        method: 'delete',
        url: `${PassflowEndpointPaths.tenantPath}/${mockTenantId}/role/${mockRoleId}`
      });
      expect(result).toEqual(mockStatusResponse);
    });
  });

  // 4. User Management in Tenants Tests
  describe('User Management in Tenants', () => {
    test('deleteUserFromTenant should call axios with correct parameters', async () => {
      const result = await tenantApi.deleteUserFromTenant(mockTenantId, mockUserId);
      
      expect(mockAxiosInstance.request).toHaveBeenCalledWith({
        method: 'delete',
        url: `${PassflowEndpointPaths.tenantPath}/${mockTenantId}/user/${mockUserId}`
      });
      expect(result).toEqual(mockStatusResponse);
    });
  });

  // 5. Invitation Management Tests
  describe('Invitation Management', () => {
    test('getGroupInvitations should call axios with correct parameters', async () => {
      const limit = 10;
      const skip = 0;
      const result = await tenantApi.getGroupInvitations(mockTenantId, mockGroupId, limit, skip);
      
      expect(mockAxiosInstance.request).toHaveBeenCalledWith({
        method: 'get',
        url: `${PassflowEndpointPaths.tenantPath}/${mockTenantId}/group/${mockGroupId}/invitations`,
        params: { limit, skip }
      });
      expect(result).toEqual(mockInvitationsResponse);
    });
    
    test('getTenantInvitations should call axios with correct parameters', async () => {
      const limit = 10;
      const skip = 0;
      const result = await tenantApi.getTenantInvitations(mockTenantId, limit, skip);
      
      expect(mockAxiosInstance.request).toHaveBeenCalledWith({
        method: 'get',
        url: `${PassflowEndpointPaths.tenantPath}/${mockTenantId}/invitations`,
        params: { limit, skip }
      });
      expect(result).toEqual(mockInvitationsResponse);
    });
    
    test('invalidateInviteById should call axios with correct parameters', async () => {
      const result = await tenantApi.invalidateInviteById(mockTenantId, mockGroupId, mockInviteId);
      
      expect(mockAxiosInstance.request).toHaveBeenCalledWith({
        method: 'delete',
        url: `${PassflowEndpointPaths.tenantPath}/${mockTenantId}/group/${mockGroupId}/invite/${mockInviteId}`
      });
      expect(result).toEqual({});
    });
    
    test('invalidateInviteByEmail should call axios with correct parameters', async () => {
      const result = await tenantApi.invalidateInviteByEmail(mockTenantId, mockGroupId, mockEmail);
      
      expect(mockAxiosInstance.request).toHaveBeenCalledWith({
        method: 'delete',
        url: `${PassflowEndpointPaths.tenantPath}/${mockTenantId}/group/${mockGroupId}/invite/email/${mockEmail}`
      });
      expect(result).toEqual({});
    });
  });
});