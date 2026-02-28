import { v4 as uuidv4 } from 'uuid';
import { afterAll, beforeAll, describe, expect, test } from 'vitest';
import { PassflowConfig, PassflowError } from '../../lib/api/model';
import { Passflow } from '../../lib/passflow';
import { adminLogin, checkRequiredEnvVars, createApp } from './setup';

describe('Passflow Tenant API Integration Tests', () => {
  // Store tokens and IDs for use in subsequent tests
  // uncomment to force run the tests
  process.env.INTEGRATION_TEST_RUN = 'true';
  let adminToken: string;
  let createdTenantId: string;
  let shouldRunTests = true;
  let testAppId: string;
  let passflow: Passflow;

  // Setup - Run before all tests
  beforeAll(async () => {
    // Check if required environment variables are set
    shouldRunTests = checkRequiredEnvVars();
    console.log('Tenant integration tests setup complete');

    if (!shouldRunTests) {
      return;
    }

    try {
      // Get admin token
      adminToken = await adminLogin();

      // Create a test app first to get an app ID
      const app = await createApp(adminToken, {
        name: 'Tenant Test App',
        description: 'App for testing tenant functionality',
        offline: true,
        type: 'web',
        redirect_urls: ['http://localhost:5500', 'https://jwt.io', 'http://127.0.0.1:5500'],
        origins: ['http://localhost:3000'],
        auth_strategies: [
          {
            type: 'internal',
            strategy: {
              identity: 'email',
              transport: 'none',
              challenge: 'password',
            },
          },
          {
            type: 'passkey',
            strategy: {},
          },
        ],
        registration_allowed: true,
        passwordless_registration_allowed: true,
        anonymous_registration_allowed: false,
        fim_merge_by_email_allowed: true,
        debug_otp_code_allowed: true,
        debug_otp_code_for_registration: '8765',
      });

      testAppId = app.id;

      // Create a Passflow instance with the app ID
      const config: PassflowConfig = {
        url: process.env.INTEGRATION_TEST_PASSFLOW_URL || 'http://localhost:8765',
        appId: testAppId,
      };

      // Register a new user using the Passflow SDK
      passflow = new Passflow(config);

      // Generate a unique email to avoid conflicts
      const uniqueId = uuidv4().substring(0, 8);
      const email = `test-user-${uniqueId}@example.com`;
      const password = 'Password123!';

      // Register the user
      await passflow.signUp({
        user: {
          email,
          password,
        },
      });

      console.log(`Test setup complete with App ID: ${testAppId}`);
    } catch (error) {
      console.error('Test setup failed:', error);
      shouldRunTests = false;
    }
  });

  test('Admin token, App ID, and User token should be valid', () => {
    // Skip test if required environment variables are not set
    if (!shouldRunTests) {
      return;
    }

    expect(adminToken).toBeDefined();
    expect(typeof adminToken).toBe('string');
    expect(adminToken.length).toBeGreaterThan(0);

    expect(testAppId).toBeDefined();
    expect(typeof testAppId).toBe('string');
    expect(testAppId.length).toBeGreaterThan(0);

    expect(passflow.tokensCache?.access_token).toBeDefined();
    expect(typeof passflow.tokensCache?.access_token).toBe('string');
    expect(passflow.tokensCache?.access_token.length).toBeGreaterThan(0);
  });

  // We no longer need a separate test for creating an app since we do it in beforeAll

  test('Create tenant should return the created tenant details', async () => {
    // Skip test if admin token is not available or env vars not set
    if (!adminToken || !shouldRunTests || !passflow) {
      return;
    }

    try {
      const tenant = await passflow.tenant.createTenant('Test Tenant');
      expect(tenant).toHaveProperty('tenant_id');
      expect(tenant).toHaveProperty('tenant_name');
      expect(tenant.tenant_name).toBe('Test Tenant');

      // Store the created tenant ID for further tests
      createdTenantId = tenant.tenant_id;

      // Log tenant details
      console.log('\nTest tenant created successfully!');
      console.log('----------------------------------');
      console.log(`Tenant ID: ${tenant.tenant_id}`);
      console.log(`Tenant Name: ${tenant.tenant_name}`);
      console.log('----------------------------------');
    } catch (error) {
      console.error('Create tenant test failed:', error);
      throw error;
    }
  });

  test('Get tenant details should return the tenant', async () => {
    // Skip test if admin token or tenant ID is not available or env vars not set
    if (!adminToken || !createdTenantId || !shouldRunTests || !passflow) {
      return;
    }

    try {
      const tenant = await passflow.tenant.getTenantDetails(createdTenantId);
      expect(tenant).toHaveProperty('tenant_id');
      expect(tenant.tenant_id).toBe(createdTenantId);
      expect(tenant.tenant_name).toBe('Test Tenant');
    } catch (error) {
      console.error('Get tenant details test failed:', error);
      throw error;
    }
  });

  test('Update tenant should return success status', async () => {
    // Skip test if admin token or tenant ID is not available or env vars not set
    if (!adminToken || !createdTenantId || !shouldRunTests || !passflow) {
      return;
    }

    try {
      const response = await passflow.tenant.updateTenant(createdTenantId, 'Updated Test Tenant');
      expect(response).toHaveProperty('status');
      expect(response.status).toBe('ok');

      // Verify the update by getting tenant details
      const tenant = await passflow.tenant.getTenantDetails(createdTenantId);
      expect(tenant.tenant_name).toBe('Updated Test Tenant');
    } catch (error) {
      console.error('Update tenant test failed:', error);
      throw error;
    }
  });

  test('Create group in tenant should return the created group details', async () => {
    // Skip test if admin token or tenant ID is not available or env vars not set
    if (!adminToken || !createdTenantId || !shouldRunTests || !passflow) {
      return;
    }

    try {
      const group = await passflow.tenant.createGroup(createdTenantId, 'Test Group');
      expect(group).toHaveProperty('id');
      expect(group).toHaveProperty('name');
      expect(group.name).toBe('Test Group');

      // Log group details
      console.log('\nTest group created successfully!');
      console.log('----------------------------------');
      console.log(`Group ID: ${group.id}`);
      console.log(`Group Name: ${group.name}`);
      console.log('----------------------------------');
    } catch (error) {
      console.error('Create group test failed:', error);
      throw error;
    }
  });

  test('Create role in tenant should return the created role details', async () => {
    // Skip test if admin token or tenant ID is not available or env vars not set
    if (!adminToken || !createdTenantId || !shouldRunTests || !passflow.tenant) {
      return;
    }

    try {
      const role = await passflow.tenant.createRoleForTenant(createdTenantId, 'Test Role');
      expect(role).toHaveProperty('id');
      expect(role).toHaveProperty('name');
      expect(role).toHaveProperty('tenant_id');
      expect(role.name).toBe('Test Role');
      expect(role.tenant_id).toBe(createdTenantId);

      // Log role details
      console.log('\nTest role created successfully!');
      console.log('----------------------------------');
      console.log(`Role ID: ${role.id}`);
      console.log(`Role Name: ${role.name}`);
      console.log('----------------------------------');
    } catch (error) {
      console.error('Create role test failed:', error);
      throw error;
    }
  });

  test('Get user tenant memberships should return tenant information', async () => {
    // Skip test if admin token is not available or env vars not set
    if (!adminToken || !shouldRunTests || !passflow.tenant) {
      return;
    }

    try {
      const memberships = await passflow.tenant.getUserTenantMembership();
      expect(memberships).toBeDefined();

      // Check if our created tenant is in the memberships
      if (createdTenantId && memberships[createdTenantId]) {
        expect(memberships[createdTenantId]).toHaveProperty('tenant_id');
        expect(memberships[createdTenantId]).toHaveProperty('tenant_name');
        expect(memberships[createdTenantId]).toHaveProperty('groups');
        expect(memberships[createdTenantId]).toHaveProperty('group_names');
        expect(memberships[createdTenantId].tenant_id).toBe(createdTenantId);
      }
    } catch (error) {
      console.error('Get user tenant memberships test failed:', error);
      throw error;
    }
  });

  test('Delete tenant should return success status', async () => {
    // Skip test if admin token or tenant ID is not available or env vars not set
    if (!adminToken || !createdTenantId || !shouldRunTests || !passflow.tenant) {
      return;
    }

    try {
      const response = await passflow.tenant.deleteTenant(createdTenantId);
      expect(response).toHaveProperty('status');
      expect(response.status).toBe('ok');

      // Log deletion
      console.log('\nTest tenant deleted successfully!');
      console.log('----------------------------------');
      console.log(`Tenant ID: ${createdTenantId}`);
      console.log('----------------------------------');
    } catch (error) {
      console.error('Delete tenant test failed:', error);
      throw error;
    }
  });

  test('Error handling should properly format Passflow API errors', async () => {
    // Skip test if admin token is not available or env vars not set
    if (!adminToken || !shouldRunTests || !passflow.tenant) {
      return;
    }

    try {
      // Use a non-existent tenant ID to trigger a real error from the API
      const nonExistentTenantId = 'non-existent-tenant-id-' + Date.now();

      // Call a method that should trigger the error
      await passflow.tenant.getTenantDetails(nonExistentTenantId);

      // If we get here, the test failed because the error wasn't thrown
      expect(true).toBe(false); // This should not be reached
    } catch (error) {
      // Check if the error is a PassflowError
      if (error instanceof PassflowError) {
        // Verify PassflowError properties
        expect(error.id).toBeDefined();
        expect(error.message).toBeDefined();
        expect(error.status).toBeDefined();
        expect(error.location).toBeDefined();
        expect(error.time).toBeDefined();

        // Verify the error ID is one of the expected values
        expect([
          'not_found',
          'error.storage.tenant.user.has.no.permission',
          'invalid.tenant_id',
          'error.permission_denied',
        ]).toContain(error.id);

        // Verify the status code is one of the expected values
        expect([400, 401, 403, 404, 500]).toContain(error.status);

        console.log('Received properly formatted PassflowError:', {
          id: error.id,
          message: error.message,
          status: error.status,
          location: error.location,
        });
      } else {
        // If it's not a PassflowError, it should at least be an Error with the expected format
        expect(error).toBeInstanceOf(Error);

        // The error message should be formatted as "Passflow API Error: {id} - {message} (Status: {status})"
        const errorMessage = (error as Error).message;
        console.log(errorMessage);
        expect(errorMessage).toContain('You have not permission to process the operation.');

        // It should contain either "not_found" or another error ID from the Passflow API
        const containsErrorId =
          errorMessage.includes('not_found') || errorMessage.includes('error.') || errorMessage.includes('invalid');

        expect(containsErrorId).toBe(true);

        // It should contain a status code
        const containsStatusCode =
          errorMessage.includes('Status: 400') ||
          errorMessage.includes('Status: 401') ||
          errorMessage.includes('Status: 403') ||
          errorMessage.includes('Status: 404') ||
          errorMessage.includes('Status: 500');

        expect(containsStatusCode).toBe(true);

        console.log('Received formatted error message:', errorMessage);
      }
    }
  });

  test('Tenant service should work after token refresh', async () => {
    // Skip test if required environment variables are not set
    if (!shouldRunTests || !passflow.tenant) {
      return;
    }

    try {
      // Get the current token
      const initialToken = passflow.getTokensCache()?.access_token;
      console.log('Initial token:', initialToken?.substring(0, 10) + '...');

      // Refresh the token
      const refreshedTokens = await passflow.refreshToken();
      const newToken = refreshedTokens.access_token;
      console.log('New token:', newToken.substring(0, 10) + '...');

      // Verify the token has changed
      expect(newToken).not.toBe(initialToken);

      // Try to get tenant memberships with the refreshed token
      const memberships = await passflow.tenant.getUserTenantMembership();

      // Verify we got a valid response
      expect(memberships).toBeDefined();
      console.log('Successfully retrieved tenant memberships after token refresh');

      // If we have a tenant ID, verify it's in the memberships
      if (createdTenantId && memberships[createdTenantId]) {
        expect(memberships[createdTenantId]).toHaveProperty('tenant_id');
        expect(memberships[createdTenantId].tenant_id).toBe(createdTenantId);
      }
    } catch (error) {
      console.error('Token refresh test failed:', error);
      throw error;
    }
  });

  // Add a cleanup function to run after all tests
  afterAll(async () => {
    // If we have a tenant ID that wasn't deleted, try to clean it up
    if (shouldRunTests && passflow.tenant && createdTenantId) {
      try {
        await passflow.tenant.deleteTenant(createdTenantId);
        console.log(`Cleaned up tenant: ${createdTenantId}`);
      } catch (error) {
        console.log(`Note: Could not clean up tenant ${createdTenantId}:`, error);
      }
    }
  });
});
