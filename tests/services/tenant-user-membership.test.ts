/**
 * Tenant User Membership Tests
 *
 * Tests for the TenantUserMembership utility class that normalizes
 * raw Passflow tenant data into a flat, queryable structure.
 */
import { describe, expect, test } from 'vitest';
import type { PassflowTenantResponse } from '../../lib/api/model';
import { TenantUserMembership } from '../../lib/services/tenant-user-membership';

describe('TenantUserMembership', () => {
  const createMockTenantResponse = (): PassflowTenantResponse => ({
    tenant_id: 'tenant-123',
    tenant_name: 'Test Tenant',
    groups: [
      {
        id: 'group-1',
        name: 'Admins',
        default: true,
        updated_at: '2024-01-01T00:00:00Z',
        created_at: '2024-01-01T00:00:00Z',
      },
      {
        id: 'group-2',
        name: 'Users',
        default: false,
        updated_at: '2024-01-02T00:00:00Z',
        created_at: '2024-01-02T00:00:00Z',
      },
    ],
    roles: [
      { id: 'role-1', tenant_id: 'tenant-123', name: 'admin' },
      { id: 'role-2', tenant_id: 'tenant-123', name: 'viewer' },
    ],
    users_in_groups: [
      {
        user: {
          id: 'user-1',
          name: 'John Doe',
          email: 'john@example.com',
          phone: '+1234567890',
        },
        group_id: 'group-1',
        roles: [{ id: 'role-1', tenant_id: 'tenant-123', name: 'admin' }],
      },
      {
        user: {
          id: 'user-1',
          name: 'John Doe',
          email: 'john@example.com',
          phone: '+1234567890',
        },
        group_id: 'group-2',
        roles: [{ id: 'role-2', tenant_id: 'tenant-123', name: 'viewer' }],
      },
      {
        user: {
          id: 'user-2',
          name: 'Jane Smith',
          email: 'jane@example.com',
          phone: null,
        },
        group_id: 'group-2',
        roles: [{ id: 'role-2', tenant_id: 'tenant-123', name: 'viewer' }],
      },
    ],
  });

  describe('constructor and normalize', () => {
    test('creates TenantUserMembership from raw response', () => {
      const membership = new TenantUserMembership(createMockTenantResponse());
      expect(membership).toBeDefined();
    });

    test('normalizes tenant data correctly', () => {
      const membership = new TenantUserMembership(createMockTenantResponse());
      const data = membership.getData();

      expect(data.tenant_id).toBe('tenant-123');
      expect(data.tenant_name).toBe('Test Tenant');
      expect(data.users).toHaveLength(2);
      expect(data.groups).toHaveLength(2);
      expect(data.roles).toHaveLength(2);
      expect(data.memberships).toHaveLength(3);
    });

    test('creates lookup maps', () => {
      const membership = new TenantUserMembership(createMockTenantResponse());
      const data = membership.getData();

      expect(data.usersById.get('user-1')?.name).toBe('John Doe');
      expect(data.groupsById.get('group-1')?.name).toBe('Admins');
      expect(data.rolesById.get('role-1')?.name).toBe('admin');
    });

    test('handles missing optional fields', () => {
      const minimal: PassflowTenantResponse = {
        tenant_id: 'tenant-123',
        tenant_name: 'Minimal Tenant',
      };

      const membership = new TenantUserMembership(minimal);
      const data = membership.getData();

      expect(data.users).toHaveLength(0);
      expect(data.groups).toHaveLength(0);
      expect(data.roles).toHaveLength(0);
      expect(data.memberships).toHaveLength(0);
    });

    test('handles users with null fields', () => {
      const response: PassflowTenantResponse = {
        tenant_id: 'tenant-123',
        tenant_name: 'Test',
        groups: [
          {
            id: 'group-1',
            name: 'Default',
            updated_at: '2024-01-01T00:00:00Z',
            created_at: '2024-01-01T00:00:00Z',
          },
        ],
        users_in_groups: [
          {
            user: {
              id: 'user-1',
              name: null,
              email: null,
              phone: null,
            },
            group_id: 'group-1',
            roles: [],
          },
        ],
      };

      const membership = new TenantUserMembership(response);
      const data = membership.getData();

      expect(data.users[0].name).toBeNull();
      expect(data.users[0].email).toBeNull();
      expect(data.users[0].phone).toBeNull();
    });

    test('deduplicates users appearing in multiple groups', () => {
      const membership = new TenantUserMembership(createMockTenantResponse());
      const data = membership.getData();

      // user-1 appears in both groups but should only be in users array once
      expect(data.users).toHaveLength(2);
      expect(data.users.filter((u) => u.id === 'user-1')).toHaveLength(1);
    });
  });

  describe('getUsersInGroup', () => {
    test('returns users in specified group', () => {
      const membership = new TenantUserMembership(createMockTenantResponse());

      const admins = membership.getUsersInGroup('group-1');
      expect(admins).toHaveLength(1);
      expect(admins[0].name).toBe('John Doe');

      const users = membership.getUsersInGroup('group-2');
      expect(users).toHaveLength(2);
    });

    test('returns empty array for non-existent group', () => {
      const membership = new TenantUserMembership(createMockTenantResponse());

      const result = membership.getUsersInGroup('non-existent');
      expect(result).toEqual([]);
    });
  });

  describe('getGroupsForUser', () => {
    test('returns groups for specified user', () => {
      const membership = new TenantUserMembership(createMockTenantResponse());

      const groups = membership.getGroupsForUser('user-1');
      expect(groups).toHaveLength(2);
      expect(groups.map((g) => g.name).sort()).toEqual(['Admins', 'Users']);
    });

    test('returns single group for user in one group', () => {
      const membership = new TenantUserMembership(createMockTenantResponse());

      const groups = membership.getGroupsForUser('user-2');
      expect(groups).toHaveLength(1);
      expect(groups[0].name).toBe('Users');
    });

    test('returns empty array for non-existent user', () => {
      const membership = new TenantUserMembership(createMockTenantResponse());

      const result = membership.getGroupsForUser('non-existent');
      expect(result).toEqual([]);
    });
  });

  describe('getUserRolesInGroup', () => {
    test('returns roles for user in specified group', () => {
      const membership = new TenantUserMembership(createMockTenantResponse());

      const roles = membership.getUserRolesInGroup('user-1', 'group-1');
      expect(roles).toHaveLength(1);
      expect(roles[0].name).toBe('admin');
    });

    test('returns different roles for same user in different groups', () => {
      const membership = new TenantUserMembership(createMockTenantResponse());

      const adminRoles = membership.getUserRolesInGroup('user-1', 'group-1');
      const userRoles = membership.getUserRolesInGroup('user-1', 'group-2');

      expect(adminRoles[0].name).toBe('admin');
      expect(userRoles[0].name).toBe('viewer');
    });

    test('returns empty array for non-existent membership', () => {
      const membership = new TenantUserMembership(createMockTenantResponse());

      const result = membership.getUserRolesInGroup('user-2', 'group-1');
      expect(result).toEqual([]);
    });

    test('returns empty array for user with no roles in group', () => {
      const response: PassflowTenantResponse = {
        tenant_id: 'tenant-123',
        tenant_name: 'Test',
        groups: [
          {
            id: 'group-1',
            name: 'Default',
            updated_at: '2024-01-01T00:00:00Z',
            created_at: '2024-01-01T00:00:00Z',
          },
        ],
        users_in_groups: [
          {
            user: { id: 'user-1', email: 'test@example.com' },
            group_id: 'group-1',
            roles: [],
          },
        ],
      };

      const membership = new TenantUserMembership(response);
      const roles = membership.getUserRolesInGroup('user-1', 'group-1');
      expect(roles).toEqual([]);
    });
  });

  describe('getData', () => {
    test('returns complete TenantData object', () => {
      const membership = new TenantUserMembership(createMockTenantResponse());
      const data = membership.getData();

      expect(data).toHaveProperty('tenant_id');
      expect(data).toHaveProperty('tenant_name');
      expect(data).toHaveProperty('users');
      expect(data).toHaveProperty('groups');
      expect(data).toHaveProperty('roles');
      expect(data).toHaveProperty('memberships');
      expect(data).toHaveProperty('usersById');
      expect(data).toHaveProperty('groupsById');
      expect(data).toHaveProperty('rolesById');
    });
  });

  describe('edge cases', () => {
    test('handles users_in_groups with missing user', () => {
      const response: PassflowTenantResponse = {
        tenant_id: 'tenant-123',
        tenant_name: 'Test',
        groups: [
          {
            id: 'group-1',
            name: 'Default',
            updated_at: '2024-01-01T00:00:00Z',
            created_at: '2024-01-01T00:00:00Z',
          },
        ],
        users_in_groups: [
          {
            user: undefined as unknown as PassflowTenantResponse['users_in_groups'][0]['user'],
            group_id: 'group-1',
            roles: [],
          },
        ],
      };

      const membership = new TenantUserMembership(response);
      const data = membership.getData();

      expect(data.users).toHaveLength(0);
      expect(data.memberships).toHaveLength(0);
    });

    test('handles users_in_groups with non-existent group_id', () => {
      const response: PassflowTenantResponse = {
        tenant_id: 'tenant-123',
        tenant_name: 'Test',
        groups: [],
        users_in_groups: [
          {
            user: { id: 'user-1', email: 'test@example.com' },
            group_id: 'non-existent-group',
            roles: [],
          },
        ],
      };

      const membership = new TenantUserMembership(response);
      const data = membership.getData();

      // User should be added but no membership since group doesn't exist
      expect(data.users).toHaveLength(1);
      expect(data.memberships).toHaveLength(0);
    });

    test('handles group without default field', () => {
      const response: PassflowTenantResponse = {
        tenant_id: 'tenant-123',
        tenant_name: 'Test',
        groups: [
          {
            id: 'group-1',
            name: 'NoDefault',
            updated_at: '2024-01-01T00:00:00Z',
            created_at: '2024-01-01T00:00:00Z',
          } as unknown as PassflowTenantResponse['groups'][0],
        ],
      };

      const membership = new TenantUserMembership(response);
      const data = membership.getData();

      expect(data.groups[0].default).toBe(false);
    });
  });
});
