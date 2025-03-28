import { PassflowInviteResponse, PassflowTenantResponse, TenantAPI } from '../api';

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
}
