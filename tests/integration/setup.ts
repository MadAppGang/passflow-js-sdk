/**
 * Integration test setup for Passflow API
 *
 * This file provides utility functions and configuration for integration tests.
 * It handles environment variables and common API operations.
 */

import axios from 'axios';

// Configuration
export const config = {
  passflowUrl: process.env.INTEGRATION_TEST_PASSFLOW_URL || 'http://localhost:8765',
  adminEmail: process.env.INTEGRATION_TEST_ADMIN_EMAIL || 'admin@passflow.cloud',
  adminPhone: process.env.INTEGRATION_TEST_ADMIN_PHONE || '',
  adminPassword: process.env.INTEGRATION_TEST_ADMIN_PASSWORD || 'password',
  runIntegrationTests: process.env.INTEGRATION_TEST_RUN,
};

// Response types
export interface AdminLoginResponse {
  access_token: string;
}

export interface App {
  id: string;
  secret: string;
  active: boolean;
  name: string;
  description: string;
  offline: boolean;
  type: string;
  redirect_urls: string[];
  login_app_settings: unknown;
  custom_email_templates: boolean;
  auth_strategies: Array<{
    strategy: {
      identity?: string;
      challenge?: string;
      transport?: string;
      fim_type?: string;
    };
    type: string;
  }>;
  custom_sms_messages: unknown;
  registration_allowed: boolean;
  passwordless_registration_allowed: boolean;
  anonymous_registration_allowed: boolean;
  fim_merge_by_email_allowed: boolean;
  debug_otp_code_allowed: boolean;
  debug_otp_code_for_registration: string;
}

export interface AppsListResponse {
  apps: App[];
}

/**
 * Performs admin login using insecure login endpoint
 * @returns The admin access token
 */
export async function adminLogin(): Promise<string> {
  try {
    const response = await axios.post<AdminLoginResponse>(
      `${config.passflowUrl}/admin/auth/insecure_login`,
      {
        email: config.adminEmail,
        phone: config.adminPhone,
        password: config.adminPassword,
      },
      {
        headers: {
          'X-Passflow-ClientID': 'passflow_admin_panel_id',
          'Content-Type': 'application/json',
        },
      },
    );

    return response.data.access_token;
  } catch (error) {
    console.error('Admin login failed:', error);
    throw error;
  }
}

/**
 * Creates a test app using the admin API
 * @param token Admin access token
 * @param appConfig App configuration
 * @returns The created app details
 */
export async function createApp(
  token: string,
  appConfig: {
    name: string;
    description: string;
    offline: boolean;
    type: string;
    redirect_urls: string[];
    origins: string[];
    auth_strategies: Array<{
      strategy: {
        identity?: string;
        challenge?: string;
        transport?: string;
        fim_type?: string;
      };
      type: string;
    }>;
    registration_allowed: boolean;
    passwordless_registration_allowed: boolean;
    anonymous_registration_allowed: boolean;
    fim_merge_by_email_allowed: boolean;
    debug_otp_code_allowed: boolean;
    debug_otp_code_for_registration: string;
  },
): Promise<App> {
  try {
    const response = await axios.post<App>(`${config.passflowUrl}/admin/apps`, appConfig, {
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
    });

    return response.data;
  } catch (error) {
    console.error('App creation failed:', error);
    throw error;
  }
}

/**
 * Gets the list of apps using the admin API
 * @param token Admin access token
 * @returns List of apps
 */
export async function getAppsList(token: string): Promise<AppsListResponse> {
  try {
    const response = await axios.get<AppsListResponse>(`${config.passflowUrl}/admin/apps`, {
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
    });

    return response.data;
  } catch (error) {
    console.error('Get apps list failed:', error);
    throw error;
  }
}

/**
 * Gets app details by ID using the admin API
 * @param token Admin access token
 * @param appId App ID
 * @returns App details
 */
export async function getAppDetails(token: string, appId: string): Promise<App> {
  try {
    const response = await axios.get<App>(`${config.passflowUrl}/admin/apps/${appId}`, {
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
    });

    return response.data;
  } catch (error) {
    console.error(`Get app details failed for app ID ${appId}:`, error);
    throw error;
  }
}

/**
 * Checks if the required environment variables are set for integration tests
 * @returns True if all required environment variables are set, false otherwise
 */
export function checkRequiredEnvVars(): boolean {
  // if (!process.env.INTEGRATION_TEST_RUN) {
  //   console.warn('integration tests run disabled, exiting');
  //   return false;
  // }

  return true;
}

