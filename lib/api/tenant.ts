import { AxiosClient } from './axios-client';
import {
  PassflowConfig,
  PassflowCreateTenantPayload,
  PassflowEndpointPaths,
  PassflowInvitePayload,
  PassflowInviteResponse,
  PassflowTenantResponse,
} from './model';

// Response types
export type PassflowStatusResponse = {
  status: string;
};

export type PassflowGroupResponse = {
  id: string;
  name: string;
  default?: boolean;
  updated_at: string;
  created_at: string;
};

export type PassflowRoleResponse = {
  id: string;
  tenant_id: string;
  name: string;
};

export type PassflowUserTenantMembershipResponse = Record<
  string, // tenant_id
  {
    tenant_id: string;
    tenant_name: string;
    groups: Record<string, string[]>; // group_id -> role_ids[]
    group_names: Record<string, string>; // group_id -> group_name
  }
>;

export type PassflowInvitationItem = {
  id: string;
  archived: boolean;
  app_id: string;
  inviter_id: string;
  inviter_name: string;
  token: string;
  email: string;
  role: string;
  tenant: string;
  tenant_name: string;
  group: string;
  created_by: string;
  created_at: string;
  expires_at: string;
};

export type PassflowInvitationsResponse = {
  invites: PassflowInvitationItem[];
  next_page_skip: string;
};

// Request payload types
export type PassflowUpdateTenantPayload = {
  name: string;
};

export type PassflowCreateGroupPayload = {
  name: string;
};

export type PassflowUpdateGroupPayload = {
  name: string;
};

export type PassflowAddUserToGroupPayload = {
  user_id: string;
  role: string;
};

export type PassflowRemoveUserRolesPayload = {
  user_id: string;
  roles: string[];
};

export type PassflowChangeUserRolesPayload = {
  user_id: string;
  roles: string[];
};

export type PassflowCreateRolePayload = {
  name: string;
};

export type PassflowUpdateRolePayload = {
  name: string;
};

export class TenantAPI {
  protected axiosClient: AxiosClient;

  constructor(config: PassflowConfig) {
    this.axiosClient = new AxiosClient(config);
  }

  joinInvitation(token: string, scopes: string[]): Promise<PassflowInviteResponse> {
    const payload = {
      invite_token: token,
      scopes,
    };

    return this.axiosClient.post<PassflowInviteResponse, PassflowInvitePayload>(PassflowEndpointPaths.joinInvitation, payload);
  }

  createTenant(name: string): Promise<PassflowTenantResponse> {
    const payload = {
      name,
    };
    return this.axiosClient.post<PassflowTenantResponse, PassflowCreateTenantPayload>(
      PassflowEndpointPaths.tenantPath,
      payload,
    );
  }

  // 1. Tenant Management

  /**
   * Get tenant details
   * @param tenantId Tenant ID
   */
  getTenantDetails(tenantId: string): Promise<PassflowTenantResponse> {
    const path = `${PassflowEndpointPaths.tenantPath}/${tenantId}`;
    return this.axiosClient.get<PassflowTenantResponse>(path);
  }

  /**
   * Update tenant name
   * @param tenantId Tenant ID
   * @param name New tenant name
   */
  updateTenant(tenantId: string, name: string): Promise<PassflowStatusResponse> {
    const path = `${PassflowEndpointPaths.tenantPath}/${tenantId}`;
    const payload: PassflowUpdateTenantPayload = { name };
    return this.axiosClient.put<PassflowStatusResponse, PassflowUpdateTenantPayload>(path, payload);
  }

  /**
   * Delete a tenant
   * @param tenantId Tenant ID
   */
  deleteTenant(tenantId: string): Promise<PassflowStatusResponse> {
    const path = `${PassflowEndpointPaths.tenantPath}/${tenantId}`;
    return this.axiosClient.delete<PassflowStatusResponse>(path);
  }

  /**
   * Get user's tenant memberships
   */
  getUserTenantMembership(): Promise<PassflowUserTenantMembershipResponse> {
    return this.axiosClient.get<PassflowUserTenantMembershipResponse>(PassflowEndpointPaths.tenantPath);
  }

  // 2. Group Management

  /**
   * Create a group in a tenant
   * @param tenantId Tenant ID
   * @param name Group name
   */
  createGroup(tenantId: string, name: string): Promise<PassflowGroupResponse> {
    const path = `${PassflowEndpointPaths.tenantPath}/${tenantId}/group`;
    const payload: PassflowCreateGroupPayload = { name };
    return this.axiosClient.post<PassflowGroupResponse, PassflowCreateGroupPayload>(path, payload);
  }

  /**
   * Get group information
   * @param tenantId Tenant ID
   * @param groupId Group ID
   */
  getGroupInfo(tenantId: string, groupId: string): Promise<PassflowGroupResponse> {
    const path = `${PassflowEndpointPaths.tenantPath}/${tenantId}/group/${groupId}`;
    return this.axiosClient.get<PassflowGroupResponse>(path);
  }

  /**
   * Update a group
   * @param tenantId Tenant ID
   * @param groupId Group ID
   * @param name New group name
   */
  updateGroup(tenantId: string, groupId: string, name: string): Promise<PassflowGroupResponse> {
    const path = `${PassflowEndpointPaths.tenantPath}/${tenantId}/group/${groupId}`;
    const payload: PassflowUpdateGroupPayload = { name };
    return this.axiosClient.put<PassflowGroupResponse, PassflowUpdateGroupPayload>(path, payload);
  }

  /**
   * Delete a group
   * @param tenantId Tenant ID
   * @param groupId Group ID
   */
  deleteGroup(tenantId: string, groupId: string): Promise<PassflowStatusResponse> {
    const path = `${PassflowEndpointPaths.tenantPath}/${tenantId}/group/${groupId}`;
    return this.axiosClient.delete<PassflowStatusResponse>(path);
  }

  /**
   * Add a user to a group
   * @param tenantId Tenant ID
   * @param groupId Group ID
   * @param userId User ID
   * @param role Role to assign
   */
  addUserToGroup(tenantId: string, groupId: string, userId: string, role: string): Promise<PassflowStatusResponse> {
    const path = `${PassflowEndpointPaths.tenantPath}/${tenantId}/group/${groupId}/add`;
    const payload: PassflowAddUserToGroupPayload = { user_id: userId, role };
    return this.axiosClient.post<PassflowStatusResponse, PassflowAddUserToGroupPayload>(path, payload);
  }

  /**
   * Remove user roles from a group
   * @param tenantId Tenant ID
   * @param groupId Group ID
   * @param userId User ID
   * @param roles Roles to remove
   */
  removeUserRolesFromGroup(
    tenantId: string,
    groupId: string,
    userId: string,
    roles: string[],
  ): Promise<PassflowStatusResponse> {
    const path = `${PassflowEndpointPaths.tenantPath}/${tenantId}/group/${groupId}/remove_roles`;
    const payload: PassflowRemoveUserRolesPayload = { user_id: userId, roles };
    return this.axiosClient.post<PassflowStatusResponse, PassflowRemoveUserRolesPayload>(path, payload);
  }

  /**
   * Change user roles in a group
   * @param tenantId Tenant ID
   * @param groupId Group ID
   * @param userId User ID
   * @param roles New roles to assign
   */
  changeUserRoles(tenantId: string, groupId: string, userId: string, roles: string[]): Promise<PassflowStatusResponse> {
    const path = `${PassflowEndpointPaths.tenantPath}/${tenantId}/group/${groupId}/change`;
    const payload: PassflowChangeUserRolesPayload = { user_id: userId, roles };
    return this.axiosClient.post<PassflowStatusResponse, PassflowChangeUserRolesPayload>(path, payload);
  }

  /**
   * Delete a user from a group
   * @param tenantId Tenant ID
   * @param groupId Group ID
   * @param userId User ID
   */
  deleteUserFromGroup(tenantId: string, groupId: string, userId: string): Promise<PassflowStatusResponse> {
    const path = `${PassflowEndpointPaths.tenantPath}/${tenantId}/group/${groupId}/${userId}`;
    return this.axiosClient.delete<PassflowStatusResponse>(path);
  }

  // 3. Role Management

  /**
   * Get roles for a tenant
   * @param tenantId Tenant ID
   */
  getRolesForTenant(tenantId: string): Promise<PassflowRoleResponse[]> {
    const path = `${PassflowEndpointPaths.tenantPath}/${tenantId}/role`;
    return this.axiosClient.get<PassflowRoleResponse[]>(path);
  }

  /**
   * Create a role for a tenant
   * @param tenantId Tenant ID
   * @param name Role name
   */
  createRoleForTenant(tenantId: string, name: string): Promise<PassflowRoleResponse> {
    const path = `${PassflowEndpointPaths.tenantPath}/${tenantId}/role`;
    const payload: PassflowCreateRolePayload = { name };
    return this.axiosClient.post<PassflowRoleResponse, PassflowCreateRolePayload>(path, payload);
  }

  /**
   * Update a role
   * @param tenantId Tenant ID
   * @param roleId Role ID
   * @param name New role name
   */
  updateRole(tenantId: string, roleId: string, name: string): Promise<PassflowRoleResponse> {
    const path = `${PassflowEndpointPaths.tenantPath}/${tenantId}/role/${roleId}`;
    const payload: PassflowUpdateRolePayload = { name };
    return this.axiosClient.put<PassflowRoleResponse, PassflowUpdateRolePayload>(path, payload);
  }

  /**
   * Delete a role
   * @param tenantId Tenant ID
   * @param roleId Role ID
   */
  deleteRole(tenantId: string, roleId: string): Promise<PassflowStatusResponse> {
    const path = `${PassflowEndpointPaths.tenantPath}/${tenantId}/role/${roleId}`;
    return this.axiosClient.delete<PassflowStatusResponse>(path);
  }

  // 4. User Management in Tenants

  /**
   * Delete a user from a tenant
   * @param tenantId Tenant ID
   * @param userId User ID
   */
  deleteUserFromTenant(tenantId: string, userId: string): Promise<PassflowStatusResponse> {
    const path = `${PassflowEndpointPaths.tenantPath}/${tenantId}/user/${userId}`;
    return this.axiosClient.delete<PassflowStatusResponse>(path);
  }

  // 5. Invitation Management

  /**
   * Get invitations to a group
   * @param tenantId Tenant ID
   * @param groupId Group ID
   * @param limit Maximum number of invitations to return
   * @param skip Number of invitations to skip
   */
  getGroupInvitations(tenantId: string, groupId: string, limit: number, skip: number): Promise<PassflowInvitationsResponse> {
    const path = `${PassflowEndpointPaths.tenantPath}/${tenantId}/group/${groupId}/invitations`;
    return this.axiosClient.get<PassflowInvitationsResponse>(path, {
      params: { limit, skip },
    });
  }

  /**
   * Get invitations to a tenant
   * @param tenantId Tenant ID
   * @param limit Maximum number of invitations to return
   * @param skip Number of invitations to skip
   */
  getTenantInvitations(tenantId: string, limit: number, skip: number): Promise<PassflowInvitationsResponse> {
    const path = `${PassflowEndpointPaths.tenantPath}/${tenantId}/invitations`;
    return this.axiosClient.get<PassflowInvitationsResponse>(path, {
      params: { limit, skip },
    });
  }

  /**
   * Invalidate an invitation by ID
   * @param tenantId Tenant ID
   * @param groupId Group ID
   * @param inviteId Invitation ID
   */
  invalidateInviteById(tenantId: string, groupId: string, inviteId: string): Promise<Record<string, never>> {
    const path = `${PassflowEndpointPaths.tenantPath}/${tenantId}/group/${groupId}/invite/${inviteId}`;
    return this.axiosClient.delete<Record<string, never>>(path);
  }

  /**
   * Invalidate an invitation by email
   * @param tenantId Tenant ID
   * @param groupId Group ID
   * @param email Email address
   */
  invalidateInviteByEmail(tenantId: string, groupId: string, email: string): Promise<Record<string, never>> {
    const path = `${PassflowEndpointPaths.tenantPath}/${tenantId}/group/${groupId}/invite/email/${email}`;
    return this.axiosClient.delete<Record<string, never>>(path);
  }
}
