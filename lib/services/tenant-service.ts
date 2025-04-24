import {
  PassflowGroupResponse,
  PassflowInvitationsResponse,
  PassflowInviteResponse,
  PassflowRoleResponse,
  PassflowStatusResponse,
  PassflowTenantResponse,
  PassflowUserTenantMembershipResponse,
  TenantAPI,
} from '../api';

/**
 * Service for managing tenants
 */
export class TenantService {
  constructor(
    private tenantAPI: TenantAPI,
    private scopes: string[],
  ) {}

  /**
   * Join a tenant invitation
   * @param token The invitation token
   * @param scopes Optional scopes to request
   * @returns Promise with invite response
   */
  joinInvitation(token: string, scopes?: string[]): Promise<PassflowInviteResponse> {
    const sscopes = scopes ?? this.scopes;
    return this.tenantAPI.joinInvitation(token, sscopes);
  }

  /**
   * Create a new tenant
   * @param name The name of the tenant
   * @returns Promise with tenant response
   */
  createTenant(name: string): Promise<PassflowTenantResponse> {
    return this.tenantAPI.createTenant(name);
  }

  // 1. Tenant Management

  /**
   * Get tenant details
   * @param tenantId Tenant ID
   * @returns Promise with tenant response
   */
  getTenantDetails(tenantId: string): Promise<PassflowTenantResponse> {
    return this.tenantAPI.getTenantDetails(tenantId);
  }

  /**
   * Update tenant name
   * @param tenantId Tenant ID
   * @param name New tenant name
   * @returns Promise with status response
   */
  updateTenant(tenantId: string, name: string): Promise<PassflowStatusResponse> {
    return this.tenantAPI.updateTenant(tenantId, name);
  }

  /**
   * Delete a tenant
   * @param tenantId Tenant ID
   * @returns Promise with status response
   */
  deleteTenant(tenantId: string): Promise<PassflowStatusResponse> {
    return this.tenantAPI.deleteTenant(tenantId);
  }

  /**
   * Get user's tenant memberships
   * @returns Promise with user tenant membership response
   */
  getUserTenantMembership(): Promise<PassflowUserTenantMembershipResponse> {
    return this.tenantAPI.getUserTenantMembership();
  }

  // 2. Group Management

  /**
   * Create a group in a tenant
   * @param tenantId Tenant ID
   * @param name Group name
   * @returns Promise with group response
   */
  createGroup(tenantId: string, name: string): Promise<PassflowGroupResponse> {
    return this.tenantAPI.createGroup(tenantId, name);
  }

  /**
   * Get group information
   * @param tenantId Tenant ID
   * @param groupId Group ID
   * @returns Promise with group response
   */
  getGroupInfo(tenantId: string, groupId: string): Promise<PassflowGroupResponse> {
    return this.tenantAPI.getGroupInfo(tenantId, groupId);
  }

  /**
   * Update a group
   * @param tenantId Tenant ID
   * @param groupId Group ID
   * @param name New group name
   * @returns Promise with group response
   */
  updateGroup(tenantId: string, groupId: string, name: string): Promise<PassflowGroupResponse> {
    return this.tenantAPI.updateGroup(tenantId, groupId, name);
  }

  /**
   * Delete a group
   * @param tenantId Tenant ID
   * @param groupId Group ID
   * @returns Promise with status response
   */
  deleteGroup(tenantId: string, groupId: string): Promise<PassflowStatusResponse> {
    return this.tenantAPI.deleteGroup(tenantId, groupId);
  }

  /**
   * Add a user to a group
   * @param tenantId Tenant ID
   * @param groupId Group ID
   * @param userId User ID
   * @param role Role to assign
   * @returns Promise with status response
   */
  addUserToGroup(tenantId: string, groupId: string, userId: string, role: string): Promise<PassflowStatusResponse> {
    return this.tenantAPI.addUserToGroup(tenantId, groupId, userId, role);
  }

  /**
   * Remove user roles from a group
   * @param tenantId Tenant ID
   * @param groupId Group ID
   * @param userId User ID
   * @param roles Roles to remove
   * @returns Promise with status response
   */
  removeUserRolesFromGroup(
    tenantId: string,
    groupId: string,
    userId: string,
    roles: string[],
  ): Promise<PassflowStatusResponse> {
    return this.tenantAPI.removeUserRolesFromGroup(tenantId, groupId, userId, roles);
  }

  /**
   * Change user roles in a group
   * @param tenantId Tenant ID
   * @param groupId Group ID
   * @param userId User ID
   * @param roles New roles to assign
   * @returns Promise with status response
   */
  changeUserRoles(tenantId: string, groupId: string, userId: string, roles: string[]): Promise<PassflowStatusResponse> {
    return this.tenantAPI.changeUserRoles(tenantId, groupId, userId, roles);
  }

  /**
   * Delete a user from a group
   * @param tenantId Tenant ID
   * @param groupId Group ID
   * @param userId User ID
   * @returns Promise with status response
   */
  deleteUserFromGroup(tenantId: string, groupId: string, userId: string): Promise<PassflowStatusResponse> {
    return this.tenantAPI.deleteUserFromGroup(tenantId, groupId, userId);
  }

  // 3. Role Management

  /**
   * Get roles for a tenant
   * @param tenantId Tenant ID
   * @returns Promise with array of role responses
   */
  getRolesForTenant(tenantId: string): Promise<PassflowRoleResponse[]> {
    return this.tenantAPI.getRolesForTenant(tenantId);
  }

  /**
   * Create a role for a tenant
   * @param tenantId Tenant ID
   * @param name Role name
   * @returns Promise with role response
   */
  createRoleForTenant(tenantId: string, name: string): Promise<PassflowRoleResponse> {
    return this.tenantAPI.createRoleForTenant(tenantId, name);
  }

  /**
   * Update a role
   * @param tenantId Tenant ID
   * @param roleId Role ID
   * @param name New role name
   * @returns Promise with role response
   */
  updateRole(tenantId: string, roleId: string, name: string): Promise<PassflowRoleResponse> {
    return this.tenantAPI.updateRole(tenantId, roleId, name);
  }

  /**
   * Delete a role
   * @param tenantId Tenant ID
   * @param roleId Role ID
   * @returns Promise with status response
   */
  deleteRole(tenantId: string, roleId: string): Promise<PassflowStatusResponse> {
    return this.tenantAPI.deleteRole(tenantId, roleId);
  }

  // 4. User Management in Tenants

  /**
   * Delete a user from a tenant
   * @param tenantId Tenant ID
   * @param userId User ID
   * @returns Promise with status response
   */
  deleteUserFromTenant(tenantId: string, userId: string): Promise<PassflowStatusResponse> {
    return this.tenantAPI.deleteUserFromTenant(tenantId, userId);
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
  getGroupInvitations(tenantId: string, groupId: string, limit: number, skip: number): Promise<PassflowInvitationsResponse> {
    return this.tenantAPI.getGroupInvitations(tenantId, groupId, limit, skip);
  }

  /**
   * Get invitations to a tenant
   * @param tenantId Tenant ID
   * @param limit Maximum number of invitations to return
   * @param skip Number of invitations to skip
   * @returns Promise with invitations response
   */
  getTenantInvitations(tenantId: string, limit: number, skip: number): Promise<PassflowInvitationsResponse> {
    return this.tenantAPI.getTenantInvitations(tenantId, limit, skip);
  }

  /**
   * Invalidate an invitation by ID
   * @param tenantId Tenant ID
   * @param groupId Group ID
   * @param inviteId Invitation ID
   * @returns Promise with empty record
   */
  invalidateInviteById(tenantId: string, groupId: string, inviteId: string): Promise<Record<string, never>> {
    return this.tenantAPI.invalidateInviteById(tenantId, groupId, inviteId);
  }

  /**
   * Invalidate an invitation by email
   * @param tenantId Tenant ID
   * @param groupId Group ID
   * @param email Email address
   * @returns Promise with empty record
   */
  invalidateInviteByEmail(tenantId: string, groupId: string, email: string): Promise<Record<string, never>> {
    return this.tenantAPI.invalidateInviteByEmail(tenantId, groupId, email);
  }
}
