export type Tenant = {
  id: string;
  name: string;
};

export type TenantMembership = {
  tenant: Tenant;
  tenantRoles?: GroupMembership;
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
    tenant_name: string;
    tenant_roles?: string[];
    root_group_id: string;
    groups: {
      [key: string]: string[];
    };
    group_names: { [key: string]: string };
  };
};

export type UserMembership = {
  raw: RawUserMembership;
  tenants: TenantMembership[];
};

export const parseMembership = (raw: RawUserMembership): UserMembership => {
  const tenants: TenantMembership[] = [];
  let k: string;
  for (k in raw) {
    const v = raw[k];
    if (v === undefined) {
      continue;
    }
    const tnt: TenantMembership = { tenant: { id: v.tenant_id, name: v.tenant_name } };
    tnt.groups = v.groups ? Object.keys(v.groups).map((gk) => {
      const roles = v.groups[gk] || [];
      return { group: { id: gk, name: (v.group_names?.[gk]) ?? 'unknown' }, roles };
    }) : [];
    tnt.tenantRoles = tnt.groups?.find((g) => g.group.id === v.root_group_id);
    tenants.push(tnt);
  }
  return { raw, tenants };
};
