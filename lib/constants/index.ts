// @ts-ignore - package.json is outside the TypeScript project
import packageJson from '../../package.json';

export const APP_ID_HEADER_KEY = 'X-Passflow-Clientid';
export const AUTHORIZATION_HEADER_KEY = 'Authorization';
export const DEVICE_ID_HEADER_KEY = 'X-Passflow-DeviceId';
export const DEVICE_TYPE_HEADER_KEY = 'X-Passflow-DeviceType';

/**
 * SDK version from package.json.
 * Useful for debugging and logging version information.
 */
export const SDK_VERSION = packageJson.version as string;

/**
 * Minimal set of scopes for basic authentication.
 * Includes only essential scopes: user ID, token refresh, and OpenID Connect.
 * Use this for applications that need minimal permissions.
 */
export const MINIMAL_DEFAULT_SCOPES = ['id', 'offline', 'openid'];

/**
 * Default scopes used by the SDK.
 * Includes comprehensive permissions: user ID, token refresh, tenant access, email, OIDC, and full tenant access.
 * Note: 'access:tenant:all' is a very permissive scope and may not be appropriate for all applications.
 * Consider using MINIMAL_DEFAULT_SCOPES or custom scopes for production applications.
 */
export const DEFAULT_SCOPES = ['id', 'offline', 'tenant', 'email', 'oidc', 'openid', 'access:tenant:all'];

export const PASSFLOW_CLOUD_URL = 'https://auth.passflow.cloud';
export const DEFAULT_GROUP_NAME = 'default';

// Popup configuration
export const POPUP_WIDTH = 500;
export const POPUP_HEIGHT = 600;
export const POPUP_POLL_INTERVAL_MS = 100;
export const POPUP_TIMEOUT_MS = 60000; // 60 seconds

// Token configuration
export const TOKEN_EXPIRY_BUFFER_SECONDS = 30; // Buffer time to consider token expired early

// Validation constraints
export const USERNAME_MIN_LENGTH = 3;
export const USERNAME_MAX_LENGTH = 30;
export const ERROR_MESSAGE_MAX_LENGTH = 200;
