import { Mock, beforeEach, describe, expect, test, vi } from 'vitest';
import { TenantAPI } from '../../lib/api';
import { TenantService } from '../../lib/services/tenant-service';

// Mock dependencies
vi.mock('../../lib/api/tenant');

describe('TenantService', () => {
  // Setup for all tests
  let tenantService: TenantService;
  let mockTenantApi: {
    joinInvitation: Mock;
    createTenant: Mock;
  };

  const mockScopes = ['profile', 'email'];
  const mockTenantName = 'Test Organization';
  const mockInvitationToken = 'invitation-token-123';

  const mockTenantResponse = {
    name: mockTenantName,
  };

  const mockInviteResponse = {
    access_token: 'access-token-123',
    refresh_token: 'refresh-token-123',
    id_token: 'id-token-123',
  };

  beforeEach(() => {
    // Reset mocks
    vi.resetAllMocks();

    // Create mock instances
    mockTenantApi = {
      joinInvitation: vi.fn().mockResolvedValue(mockInviteResponse),
      createTenant: vi.fn().mockResolvedValue(mockTenantResponse),
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
});
