import axios from 'axios';
import {
  PassflowAuthorizationResponse,
  PassflowGroupResponse,
  PassflowInvitationsResponse,
  PassflowInviteResponse,
  PassflowRoleResponse,
  PassflowStatusResponse,
  PassflowTenantResponse,
  PassflowUserTenantMembershipResponse,
  TenantAPI,
} from '../api';
import { Logger, getDefaultLogger } from './logger';

/**
 * Service for managing tenants
 */
export class TenantService {
  private logger: Logger;

  constructor(
    private tenantAPI: TenantAPI,
    private scopes: string[],
    logger?: Logger,
  ) {
    this.logger = logger || getDefaultLogger();
  }

  /**
   * Handle Passflow API errors
   * @param error The error object
   * @param context Context information for logging
   * @throws Formatted error with Passflow API error details
   */
  private handlePassflowError(error: unknown, context: string): never {
    // Check if it's an Axios error with a response
    if (axios.isAxiosError(error) && error.response?.data) {
      const responseData = error.response.data;

      // Check if it's a Passflow API error format
      if (
        typeof responseData === 'object' &&
        responseData !== null &&
        'error' in responseData &&
        typeof responseData.error === 'object' &&
        responseData.error !== null
      ) {
        const passflowError = responseData.error as {
          id: string;
          message: string;
          status: number;
          location: string;
          time: string;
        };

        // Log the formatted error
        this.logger.error(`${context}: ${passflowError.id} - ${passflowError.message} (Status: ${passflowError.status})`);

        // Throw a new error with the formatted message
        throw new Error(`Passflow API Error: ${passflowError.id} - ${passflowError.message} (Status: ${passflowError.status})`);
      }
    }

    // If it's not a Passflow API error, log and rethrow
    this.logger.error(`${context}:`, error);
    if (error instanceof Error) {
      throw error;
    }
    throw new Error(String(error));
  }

  /**
   * Join a tenant invitation
   * @param token The invitation token
   * @param scopes Optional scopes to request
   * @returns Promise with invite response
   */
  async joinInvitation(token: string, scopes?: string[]): Promise<PassflowAuthorizationResponse> {
    try {
      const sscopes = scopes ?? this.scopes;
      return await this.tenantAPI.joinInvitation(token, sscopes);
    } catch (error) {
      this.handlePassflowError(error, 'Join invitation failed');
    }
  }

  /**
   * Create a new tenant
   * @param name The name of the tenant
   * @returns Promise with tenant response
   */
  async createTenant(name: string): Promise<PassflowTenantResponse> {
    try {
      return await this.tenantAPI.createTenant(name);
    } catch (error) {
      this.handlePassflowError(error, 'Tenant creation failed');
    }
  }

  // 1. Tenant Management

  /**
   * Get tenant details
   * @param tenantId Tenant ID
   * @returns Promise with tenant response
   */
  async getTenantDetails(tenantId: string): Promise<PassflowTenantResponse> {
    try {
      return await this.tenantAPI.getTenantDetails(tenantId);
    } catch (error) {
      this.handlePassflowError(error, `Get tenant details failed for tenant ID ${tenantId}`);
    }
  }

  /**
   * Update tenant name
   * @param tenantId Tenant ID
   * @param name New tenant name
   * @returns Promise with status response
   */
  async updateTenant(tenantId: string, name: string): Promise<PassflowStatusResponse> {
    try {
      return await this.tenantAPI.updateTenant(tenantId, name);
    } catch (error) {
      this.handlePassflowError(error, `Update tenant failed for tenant ID ${tenantId}`);
    }
  }

  /**
   * Delete a tenant
   * @param tenantId Tenant ID
   * @returns Promise with status response
   */
  async deleteTenant(tenantId: string): Promise<PassflowStatusResponse> {
    try {
      return await this.tenantAPI.deleteTenant(tenantId);
    } catch (error) {
      this.handlePassflowError(error, `Delete tenant failed for tenant ID ${tenantId}`);
    }
  }

  /**
   * Get user's tenant memberships
   * @returns Promise with user tenant membership response
   */
  async getUserTenantMembership(): Promise<PassflowUserTenantMembershipResponse> {
    try {
      return await this.tenantAPI.getUserTenantMembership();
    } catch (error) {
      this.handlePassflowError(error, 'Get user tenant memberships failed');
    }
  }

  // 2. Group Management

  /**
   * Create a group in a tenant
   * @param tenantId Tenant ID
   * @param name Group name
   * @returns Promise with group response
   */
  async createGroup(tenantId: string, name: string): Promise<PassflowGroupResponse> {
    try {
      return await this.tenantAPI.createGroup(tenantId, name);
    } catch (error) {
      this.handlePassflowError(error, `Group creation failed for tenant ID ${tenantId}`);
    }
  }

  /**
   * Get group information
   * @param tenantId Tenant ID
   * @param groupId Group ID
   * @returns Promise with group response
   */
  async getGroupInfo(tenantId: string, groupId: string): Promise<PassflowGroupResponse> {
    try {
      return await this.tenantAPI.getGroupInfo(tenantId, groupId);
    } catch (error) {
      this.handlePassflowError(error, `Get group info failed for tenant ID ${tenantId}, group ID ${groupId}`);
    }
  }

  /**
   * Update a group
   * @param tenantId Tenant ID
   * @param groupId Group ID
   * @param name New group name
   * @returns Promise with group response
   */
  async updateGroup(tenantId: string, groupId: string, name: string): Promise<PassflowGroupResponse> {
    try {
      return await this.tenantAPI.updateGroup(tenantId, groupId, name);
    } catch (error) {
      this.handlePassflowError(error, `Update group failed for tenant ID ${tenantId}, group ID ${groupId}`);
    }
  }

  /**
   * Delete a group
   * @param tenantId Tenant ID
   * @param groupId Group ID
   * @returns Promise with status response
   */
  async deleteGroup(tenantId: string, groupId: string): Promise<PassflowStatusResponse> {
    try {
      return await this.tenantAPI.deleteGroup(tenantId, groupId);
    } catch (error) {
      this.handlePassflowError(error, `Delete group failed for tenant ID ${tenantId}, group ID ${groupId}`);
    }
  }

  /**
   * Add a user to a group
   * @param tenantId Tenant ID
   * @param groupId Group ID
   * @param userId User ID
   * @param role Role to assign
   * @returns Promise with status response
   */
  async addUserToGroup(tenantId: string, groupId: string, userId: string, role: string): Promise<PassflowStatusResponse> {
    try {
      return await this.tenantAPI.addUserToGroup(tenantId, groupId, userId, role);
    } catch (error) {
      this.handlePassflowError(
        error,
        `Add user to group failed for tenant ID ${tenantId}, group ID ${groupId}, user ID ${userId}`,
      );
    }
  }

  /**
   * Remove user roles from a group
   * @param tenantId Tenant ID
   * @param groupId Group ID
   * @param userId User ID
   * @param roles Roles to remove
   * @returns Promise with status response
   */
  async removeUserRolesFromGroup(
    tenantId: string,
    groupId: string,
    userId: string,
    roles: string[],
  ): Promise<PassflowStatusResponse> {
    try {
      return await this.tenantAPI.removeUserRolesFromGroup(tenantId, groupId, userId, roles);
    } catch (error) {
      this.handlePassflowError(
        error,
        `Remove user roles from group failed for tenant ID ${tenantId}, group ID ${groupId}, user ID ${userId}`,
      );
    }
  }

  /**
   * Change user roles in a group
   * @param tenantId Tenant ID
   * @param groupId Group ID
   * @param userId User ID
   * @param roles New roles to assign
   * @returns Promise with status response
   */
  async changeUserRoles(tenantId: string, groupId: string, userId: string, roles: string[]): Promise<PassflowStatusResponse> {
    try {
      return await this.tenantAPI.changeUserRoles(tenantId, groupId, userId, roles);
    } catch (error) {
      this.handlePassflowError(
        error,
        `Change user roles failed for tenant ID ${tenantId}, group ID ${groupId}, user ID ${userId}`,
      );
    }
  }

  /**
   * Delete a user from a group
   * @param tenantId Tenant ID
   * @param groupId Group ID
   * @param userId User ID
   * @returns Promise with status response
   */
  async deleteUserFromGroup(tenantId: string, groupId: string, userId: string): Promise<PassflowStatusResponse> {
    try {
      return await this.tenantAPI.deleteUserFromGroup(tenantId, groupId, userId);
    } catch (error) {
      this.handlePassflowError(
        error,
        `Delete user from group failed for tenant ID ${tenantId}, group ID ${groupId}, user ID ${userId}`,
      );
    }
  }

  // 3. Role Management

  /**
   * Get roles for a tenant
   * @param tenantId Tenant ID
   * @returns Promise with array of role responses
   */
  async getRolesForTenant(tenantId: string): Promise<PassflowRoleResponse[]> {
    try {
      return await this.tenantAPI.getRolesForTenant(tenantId);
    } catch (error) {
      this.handlePassflowError(error, `Get roles for tenant failed for tenant ID ${tenantId}`);
    }
  }

  /**
   * Create a role for a tenant
   * @param tenantId Tenant ID
   * @param name Role name
   * @returns Promise with role response
   */
  async createRoleForTenant(tenantId: string, name: string): Promise<PassflowRoleResponse> {
    try {
      return await this.tenantAPI.createRoleForTenant(tenantId, name);
    } catch (error) {
      this.handlePassflowError(error, `Create role for tenant failed for tenant ID ${tenantId}`);
    }
  }

  /**
   * Update a role
   * @param tenantId Tenant ID
   * @param roleId Role ID
   * @param name New role name
   * @returns Promise with role response
   */
  async updateRole(tenantId: string, roleId: string, name: string): Promise<PassflowRoleResponse> {
    try {
      return await this.tenantAPI.updateRole(tenantId, roleId, name);
    } catch (error) {
      this.handlePassflowError(error, `Update role failed for tenant ID ${tenantId}, role ID ${roleId}`);
    }
  }

  /**
   * Delete a role
   * @param tenantId Tenant ID
   * @param roleId Role ID
   * @returns Promise with status response
   */
  async deleteRole(tenantId: string, roleId: string): Promise<PassflowStatusResponse> {
    try {
      return await this.tenantAPI.deleteRole(tenantId, roleId);
    } catch (error) {
      this.handlePassflowError(error, `Delete role failed for tenant ID ${tenantId}, role ID ${roleId}`);
    }
  }

  // 4. User Management in Tenants

  /**
   * Delete a user from a tenant
   * @param tenantId Tenant ID
   * @param userId User ID
   * @returns Promise with status response
   */
  async deleteUserFromTenant(tenantId: string, userId: string): Promise<PassflowStatusResponse> {
    try {
      return await this.tenantAPI.deleteUserFromTenant(tenantId, userId);
    } catch (error) {
      this.handlePassflowError(error, `Delete user from tenant failed for tenant ID ${tenantId}, user ID ${userId}`);
    }
  }

  // 5. Invitation Management

  /**
   * Get invitations to a group
   * @param tenantId Tenant ID
   * @param groupId Group ID
   * @param limit Maximum number of invitations to return
   * @param skip Number of invitations to skip
   * @returns Promise with invitations response
   */
  async getGroupInvitations(
    tenantId: string,
    groupId: string,
    limit: number,
    skip: number,
  ): Promise<PassflowInvitationsResponse> {
    try {
      return await this.tenantAPI.getGroupInvitations(tenantId, groupId, limit, skip);
    } catch (error) {
      this.handlePassflowError(error, `Get group invitations failed for tenant ID ${tenantId}, group ID ${groupId}`);
    }
  }

  /**
   * Get invitations to a tenant
   * @param tenantId Tenant ID
   * @param limit Maximum number of invitations to return
   * @param skip Number of invitations to skip
   * @returns Promise with invitations response
   */
  async getTenantInvitations(tenantId: string, limit: number, skip: number): Promise<PassflowInvitationsResponse> {
    try {
      return await this.tenantAPI.getTenantInvitations(tenantId, limit, skip);
    } catch (error) {
      this.handlePassflowError(error, `Get tenant invitations failed for tenant ID ${tenantId}`);
    }
  }

  /**
   * Invalidate an invitation by ID
   * @param tenantId Tenant ID
   * @param groupId Group ID
   * @param inviteId Invitation ID
   * @returns Promise with empty record
   */
  async invalidateInviteById(tenantId: string, groupId: string, inviteId: string): Promise<Record<string, never>> {
    try {
      return await this.tenantAPI.invalidateInviteById(tenantId, groupId, inviteId);
    } catch (error) {
      this.handlePassflowError(
        error,
        `Invalidate invite by ID failed for tenant ID ${tenantId}, group ID ${groupId}, invite ID ${inviteId}`,
      );
    }
  }

  /**
   * Invalidate an invitation by email
   * @param tenantId Tenant ID
   * @param groupId Group ID
   * @param email Email address
   * @returns Promise with empty record
   */
  async invalidateInviteByEmail(tenantId: string, groupId: string, email: string): Promise<Record<string, never>> {
    try {
      return await this.tenantAPI.invalidateInviteByEmail(tenantId, groupId, email);
    } catch (error) {
      this.handlePassflowError(
        error,
        `Invalidate invite by email failed for tenant ID ${tenantId}, group ID ${groupId}, email ${email}`,
      );
    }
  }
}
