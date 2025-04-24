import { beforeAll, describe, expect, test } from 'vitest';
import { App, adminLogin, checkRequiredEnvVars, createApp, getAppDetails, getAppsList } from './setup';

describe('Passflow Admin API Integration Tests', () => {
  // Store the admin token for use in subsequent tests
  let adminToken: string;
  let createdAppId: string;
  let shouldRunTests = true;

  // Test app configuration
  const testApp = {
    name: 'The new super app',
    description: 'The app created in postman',
    offline: true,
    type: 'web',
    create_tenant_on_registration: 'optional',
    redirect_urls: [
      'http://localhost:5500',
      'https://jwt.io',
      'http://127.0.0.1:5500',
      'https://grub-evident-gnu.ngrok-free.app',
    ],
    origins: [
      'http://localhost:5500',
      'https://jwt.io',
      'http://127.0.0.1:5500',
      'http://grub-evident-gnu.ngrok-free.app',
      'http://localhost:5173',
    ],
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
      {
        type: 'internal',
        strategy: {
          identity: 'phone',
          transport: 'none',
          challenge: 'password',
        },
      },
      {
        type: 'internal',
        strategy: {
          identity: 'phone',
          transport: 'sms',
          challenge: 'otm',
        },
      },
      {
        type: 'internal',
        strategy: {
          identity: 'email',
          transport: 'email',
          challenge: 'magic_link',
        },
      },
    ],
    registration_allowed: true,
    passwordless_registration_allowed: true,
    anonymous_registration_allowed: false,
    fim_merge_by_email_allowed: true,
    debug_otp_code_allowed: true,
    debug_otp_code_for_registration: '8765',
  };

  // Setup - Run before all tests
  beforeAll(() => {
    // Check if required environment variables are set
    shouldRunTests = checkRequiredEnvVars();
    console.log('Integration tests setup complete - console.log is now allowed in tests');
  });

  test('Admin insecure login should return an access token', async () => {
    // Skip test if required environment variables are not set
    if (!shouldRunTests) {
      return;
    }

    try {
      adminToken = await adminLogin();
      expect(adminToken).toBeDefined();
      expect(typeof adminToken).toBe('string');
      expect(adminToken.length).toBeGreaterThan(0);
    } catch (error) {
      console.error('Admin login test failed:', error);
      throw error;
    }
  });

  test('Get apps list should return an array of apps', async () => {
    // Skip test if admin token is not available or env vars not set
    if (!adminToken || !shouldRunTests) {
      return;
    }

    try {
      const response = await getAppsList(adminToken);
      expect(response).toHaveProperty('apps');
      expect(Array.isArray(response.apps)).toBe(true);
    } catch (error) {
      console.error('Get apps list test failed:', error);
      throw error;
    }
  });

  test('Create app should return the created app details', async () => {
    // Skip test if admin token is not available or env vars not set
    if (!adminToken || !shouldRunTests) {
      return;
    }

    try {
      const app = await createApp(adminToken, testApp);
      expect(app).toHaveProperty('id');
      expect(app).toHaveProperty('secret');
      expect(app.name).toBe(testApp.name);
      expect(app.description).toBe(testApp.description);

      // Store the created app ID for potential cleanup or further tests
      createdAppId = app.id;

      // Log app details
      console.log('\nTest app created successfully!');
      console.log('----------------------------------');
      console.log(`App ID: ${app.id}`);
      console.log(`App Secret: ${app.secret}`);
      console.log(`App Name: ${app.name}`);
      console.log(`App Type: ${app.type}`);
      console.log('----------------------------------');
    } catch (error) {
      console.error('Create app test failed:', error);
      throw error;
    }
  });

  // Optional: Add a test to get the created app details
  test('Get created app details should return the app', async () => {
    // Skip test if admin token or app ID is not available or env vars not set
    if (!adminToken || !createdAppId || !shouldRunTests) {
      return;
    }

    try {
      const app = await getAppDetails(adminToken, createdAppId);
      expect(app).toHaveProperty('id');
      expect(app.id).toBe(createdAppId);
      expect(app.name).toBe(testApp.name);
    } catch (error) {
      console.error('Get app details test failed:', error);
      throw error;
    }
  });
});
