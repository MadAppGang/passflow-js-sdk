// lib/services/tenant-user-membership.ts

import type { PassflowGroup, PassflowRole, PassflowTenantResponse, PassflowUserInGroup } from '../api/model';

/**
 * Flat user representation
 */
export interface User {
  id: string;
  name: string | null;
  email: string | null;
  phone: string | null;
}

/**
 * Flat group representation
 */
export interface Group {
  id: string;
  name: string;
  default: boolean;
  updated_at: string;
  created_at: string;
}

/**
 * Flat role representation
 */
export interface Role {
  id: string;
  tenant_id: string;
  name: string;
}

/**
 * Maps a user to a group with specific roles
 */
export interface Membership {
  userId: string;
  groupId: string;
  roleIds: string[];
}

/**
 * Full tenant view with lookup maps
 */
export interface TenantData {
  tenant_id: string;
  tenant_name: string;
  users: User[];
  groups: Group[];
  roles: Role[];
  memberships: Membership[];
  usersById: Map<string, User>;
  groupsById: Map<string, Group>;
  rolesById: Map<string, Role>;
}

/**
 * Utility for transforming raw PassflowTenantResponse
 * into a flattened TenantData model with quick lookup methods.
 */
export class TenantUserMembership {
  private data: TenantData;

  constructor(raw: PassflowTenantResponse) {
    this.data = this.normalize(raw);
  }

  private normalize(raw: PassflowTenantResponse): TenantData {
    const users = new Map<string, User>();
    const groups = new Map<string, Group>();
    const roles = new Map<string, Role>();
    const memberships: Membership[] = [];

    // process groups
    raw.groups?.forEach((g: PassflowGroup) => {
      groups.set(g.id, {
        id: g.id,
        name: g.name,
        default: g.default ?? false,
        updated_at: g.updated_at,
        created_at: g.created_at,
      });
    });

    // process roles
    raw.roles?.forEach((r: PassflowRole) => {
      roles.set(r.id, {
        id: r.id,
        tenant_id: r.tenant_id,
        name: r.name,
      });
    });

    // process users and memberships
    raw.users_in_groups?.forEach((uig: PassflowUserInGroup) => {
      const u = uig.user;
      if (u && !users.has(u.id)) {
        users.set(u.id, {
          id: u.id,
          name: u.name ?? null,
          email: u.email ?? null,
          phone: u.phone ?? null,
        });
      }
      if (u && uig.group_id && groups.has(uig.group_id)) {
        memberships.push({
          userId: u.id,
          groupId: uig.group_id,
          roleIds: uig.roles?.map((r) => r.id) ?? [],
        });
      }
    });

    return {
      tenant_id: raw.tenant_id,
      tenant_name: raw.tenant_name,
      users: Array.from(users.values()),
      groups: Array.from(groups.values()),
      roles: Array.from(roles.values()),
      memberships,
      usersById: users,
      groupsById: groups,
      rolesById: roles,
    };
  }

  /**
   * Returns all users in the specified group.
   */
  getUsersInGroup(groupId: string): User[] {
    return this.data.memberships
      .filter((m) => m.groupId === groupId)
      .map((m) => this.data.usersById.get(m.userId))
      .filter((u): u is User => u !== undefined);
  }

  /**
   * Returns all groups to which the specified user belongs.
   */
  getGroupsForUser(userId: string): Group[] {
    return this.data.memberships
      .filter((m) => m.userId === userId)
      .map((m) => this.data.groupsById.get(m.groupId))
      .filter((g): g is Group => g !== undefined);
  }

  /**
   * Returns all roles that the specified user has in the specified group.
   */
  getUserRolesInGroup(userId: string, groupId: string): Role[] {
    const membership = this.data.memberships.find((m) => m.userId === userId && m.groupId === groupId);
    if (!membership) {
      return [];
    }
    return membership.roleIds.map((roleId) => this.data.rolesById.get(roleId)).filter((r): r is Role => r !== undefined);
  }

  /**
   * Returns the full TenantData object.
   */
  getData(): TenantData {
    return this.data;
  }
}
