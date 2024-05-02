import { DEFAULT_GROUP_NAME } from '../constants';

export type Tenant = {
  id: string;
  name: string;
};

export type TenantMembership = {
  tenant: Tenant;
  tenantMembership?: GroupMembership;
  groups?: GroupMembership[];
};

export type Group = {
  id: string;
  name: string;
};

export type GroupMembership = {
  group: Group;
  roles: string[];
};

export type RawUserMembership = {
  [key: string]: {
    tenant_id: string;
    groups: {
      [key: string]: string[];
    };
    group_names: { id: string; name: string }[];
  };
};

export type UserMembership = {
  raw: RawUserMembership;
  tenants: TenantMembership[];
};

// TODO: test the function
export const parseMembership = (raw: RawUserMembership): UserMembership => {
  const tenants: TenantMembership[] = [];
  let k: string;
  for (k in raw) {
    const v = raw[k];
    if (v === undefined) {
      continue;
    }
    const groupNames: {
      [key: string]: string;
    } = {};

    v.group_names.forEach((g) => {
      groupNames[g.id] = g.name;
    });
    if (v === undefined) {
      continue;
    }
    const tnt: TenantMembership = { tenant: { id: k, name: k }, groups: [] };
    let gk: string;
    for (gk in v.groups) {
      tnt.groups?.push({ group: { id: gk, name: groupNames[gk] ?? 'unknown' }, roles: v.groups[gk] ?? [] });
    }
    tnt.tenantMembership = tnt.groups?.find((g) => g.group.name === DEFAULT_GROUP_NAME);
    tenants.push(tnt);
  }
  return { raw, tenants };
};
