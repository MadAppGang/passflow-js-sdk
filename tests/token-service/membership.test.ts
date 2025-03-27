import { describe, test, expect } from 'vitest';
import { RawUserMembership, TenantMembership, parseMembership } from '../../lib/token-service';

describe('token membership', () => {
  describe('parse user membership', () => {
    test('empty user membership', () => {
      const raw: RawUserMembership = {};
      const membership = parseMembership(raw);
      expect(membership.tenants).toHaveLength(0);
      expect(membership.raw).toEqual(raw);
    });
    test('single tenant membership', () => {
      const raw: RawUserMembership = {
        tenant1ID: {
          tenant_id: 'tenant1ID',
          tenant_name: 'Jack workspace',
          root_group_id: '',
          groups: {
            group1ID: ['owner'],
          },
          group_names: {
            group1ID: 'group1 name',
          },
        },
      };
      const membership = parseMembership(raw);
      expect(membership.tenants).toHaveLength(1);
      expect(membership.tenants[0]).not.toBeUndefined();
      expect(membership.tenants[0]?.tenant.id).toBe('tenant1ID');
      expect(membership.tenants[0]?.groups).toHaveLength(1);

      const tenant1 = membership.tenants[0];
      expect(tenant1?.groups).not.toBeUndefined();
      if (tenant1 !== undefined) {
        expect(tenant1.groups).not.toBeUndefined();
        const group1 = (tenant1.groups ?? [])[0];
        if (group1 !== undefined) {
          expect(group1.group.id).toBe('group1ID');
          expect(group1.group.name).toBe('group1 name');
          expect(group1.roles).toEqual(['owner']);
        }
      }
    });
    test('single tenant with default group and multiply other groups', () => {
      const raw: RawUserMembership = {
        tenant1ID: {
          tenant_id: 'tenant1ID',
          tenant_name: 'Jack workspace',
          root_group_id: 'root_group_id',
          groups: {
            group1ID: ['owner', 'admin'],
            root_group_id: ['owner'],
            group2ID: ['user'],
          },
          group_names: {
            group1ID: 'group1 name',
            root_group_id: 'default',
            group2ID: 'some other group',
          },
        },
      };
      const membership: TenantMembership[] = [
        {
          tenant: { id: 'tenant1ID', name: 'Jack workspace' },
          groups: [
            {
              group: { id: 'group1ID', name: 'group1 name' },
              roles: ['owner', 'admin'],
            },
            {
              group: { id: 'root_group_id', name: 'default' },
              roles: ['owner'],
            },
            {
              group: { id: 'group2ID', name: 'some other group' },
              roles: ['user'],
            },
          ],
          tenantRoles: {
            group: { id: 'root_group_id', name: 'default' },
            roles: ['owner'],
          },
        },
      ];
      const parsed = parseMembership(raw);
      expect(parsed.tenants).toHaveLength(1);
      expect(parsed.tenants[0]).not.toBeUndefined();

      // eslint-disable-next-line max-nested-callbacks
      membership.sort((a, b) => a.tenant.id.localeCompare(b.tenant.id));
      // eslint-disable-next-line max-nested-callbacks
      parsed.tenants.sort((a, b) => a.tenant.id.localeCompare(b.tenant.id));

      expect(membership).toEqual(parsed.tenants);
      expect(raw).toEqual(parsed.raw);
    });
    test('single tenant with multiply tenant, unknown group name and undefined tenant', () => {
      const raw: RawUserMembership = {
        tenant1ID: {
          tenant_id: 'tenant1ID',
          tenant_name: 'Jack workspace',
          root_group_id: 'root_group_id',
          groups: {
            group1ID: ['owner', 'admin'],
            root_group_id: ['owner'],
            group2ID: ['user'],
          },
          group_names: {
            group1ID: 'group1 name',
            root_group_id: 'default',
          },
        },
        tenant2ID: {
          tenant_id: 'tenant2ID',
          tenant_name: 'MadAppGang workspace',
          root_group_id: '',
          groups: {
            group9ID: ['user'],
          },
          group_names: {
            group9ID: 'developers',
          },
        },
        // @ts-expect-error this is test case to cover undefined values parsing
        tenant3ID: undefined,
      };
      const membership: TenantMembership[] = [
        {
          tenant: { id: 'tenant1ID', name: 'Jack workspace' },
          groups: [
            {
              group: { id: 'group1ID', name: 'group1 name' },
              roles: ['owner', 'admin'],
            },
            {
              group: { id: 'root_group_id', name: 'default' },
              roles: ['owner'],
            },
            {
              group: { id: 'group2ID', name: 'unknown' },
              roles: ['user'],
            },
          ],
          tenantRoles: {
            group: { id: 'root_group_id', name: 'default' },
            roles: ['owner'],
          },
        },
        {
          tenant: { id: 'tenant2ID', name: 'MadAppGang workspace' },
          groups: [
            {
              group: { id: 'group9ID', name: 'developers' },
              roles: ['user'],
            },
          ],
        },
      ];
      const parsed = parseMembership(raw);
      expect(parsed.tenants).toHaveLength(2);
      expect(parsed.tenants[0]).not.toBeUndefined();
      expect(parsed.tenants[1]).not.toBeUndefined();

      // eslint-disable-next-line max-nested-callbacks
      membership.sort((a, b) => a.tenant.id.localeCompare(b.tenant.id));
      // eslint-disable-next-line max-nested-callbacks
      parsed.tenants.sort((a, b) => a.tenant.id.localeCompare(b.tenant.id));

      expect(membership).toEqual(parsed.tenants);
      expect(raw).toEqual(parsed.raw);
    });
  });
});
