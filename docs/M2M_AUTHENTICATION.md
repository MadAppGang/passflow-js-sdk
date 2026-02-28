# Passflow M2M (Machine-to-Machine) Authentication

## Table of Contents

- [Introduction](#introduction)
- [Quick Start](#quick-start)
  - [Basic Token Request](#basic-token-request)
  - [With Scopes](#with-scopes)
  - [With Automatic Refresh](#with-automatic-refresh)
- [Installation](#installation)
- [M2M Client](#m2m-client)
  - [Configuration](#configuration)
  - [Methods](#methods)
- [Token Management](#token-management)
  - [Token Lifecycle](#token-lifecycle)
  - [Automatic Refresh](#automatic-refresh)
  - [Token Caching](#token-caching)
- [Scopes and Audiences](#scopes-and-audiences)
- [Error Handling](#error-handling)
- [Best Practices](#best-practices)
- [API Reference](#api-reference)
  - [Types](#types)
  - [M2MClient Class](#m2mclient-class)
- [Examples](#examples)
  - [Backend Service Authentication](#backend-service-authentication)
  - [Microservices Communication](#microservices-communication)
  - [Scheduled Jobs](#scheduled-jobs)
  - [Multi-Tenant M2M](#multi-tenant-m2m)

---

## Introduction

Machine-to-Machine (M2M) authentication enables server-to-server communication without user involvement. It implements the OAuth 2.0 Client Credentials Grant (RFC 6749), allowing backend services, microservices, scheduled jobs, and automated scripts to authenticate and obtain access tokens.

**Key Features:**
- OAuth 2.0 Client Credentials Grant flow
- JWT access tokens with configurable lifetimes
- Scope-based authorization
- Audience validation
- Automatic token refresh
- Rate limiting protection
- Multi-tenant support

**Use Cases:**
- Backend service APIs calling other internal APIs
- Microservices authentication
- Scheduled jobs and cron tasks
- CI/CD pipeline integrations
- IoT device authentication
- Third-party service integrations

---

## Quick Start

### Basic Token Request

```typescript
import { M2MClient } from '@passflow/core';

// Initialize the M2M client
const m2m = new M2MClient({
  url: 'https://auth.yourapp.com',
  clientId: 'your-client-id',
  clientSecret: 'your-client-secret',
});

// Request an access token
const token = await m2m.getToken();
console.log('Access Token:', token.access_token);

// Use the token to call your API
const response = await fetch('https://api.yourapp.com/data', {
  headers: {
    'Authorization': `Bearer ${token.access_token}`,
  },
});
```

### With Scopes

```typescript
const m2m = new M2MClient({
  url: 'https://auth.yourapp.com',
  clientId: 'your-client-id',
  clientSecret: 'your-client-secret',
  scopes: ['users:read', 'orders:write'],
});

const token = await m2m.getToken();
// Token will include the requested scopes
```

### With Automatic Refresh

```typescript
const m2m = new M2MClient({
  url: 'https://auth.yourapp.com',
  clientId: 'your-client-id',
  clientSecret: 'your-client-secret',
  autoRefresh: true,
  refreshThreshold: 60, // Refresh when token expires in < 60 seconds
});

// Token is automatically refreshed when needed
const token = await m2m.getToken();
```

---

## Installation

```bash
npm install @passflow/core
# or
yarn add @passflow/core
# or
pnpm add @passflow/core
```

---

## M2M Client

### Configuration

Create an M2M client with your credentials:

```typescript
import { M2MClient, type M2MClientConfig } from '@passflow/core';

const config: M2MClientConfig = {
  // Required
  url: 'https://auth.yourapp.com',      // Passflow server URL
  clientId: 'your-client-id',            // M2M app client ID
  clientSecret: 'your-client-secret',    // M2M app client secret

  // Optional
  scopes: ['users:read', 'orders:write'], // Scopes to request
  audience: ['https://api.yourapp.com'],  // Target audiences
  autoRefresh: true,                       // Auto-refresh tokens (default: false)
  refreshThreshold: 60,                    // Seconds before expiry to refresh (default: 30)
  timeout: 10000,                          // Request timeout in ms (default: 10000)
  retries: 3,                              // Number of retry attempts (default: 3)
  retryDelay: 1000,                        // Delay between retries in ms (default: 1000)
};

const m2m = new M2MClient(config);
```

### Configuration Options

| Option | Type | Required | Default | Description |
|--------|------|----------|---------|-------------|
| `url` | `string` | Yes | - | Passflow server URL |
| `clientId` | `string` | Yes | - | M2M application client ID |
| `clientSecret` | `string` | Yes | - | M2M application client secret |
| `scopes` | `string[]` | No | `[]` | Scopes to request |
| `audience` | `string[]` | No | `[]` | Target audiences for the token |
| `autoRefresh` | `boolean` | No | `false` | Automatically refresh expiring tokens |
| `refreshThreshold` | `number` | No | `30` | Seconds before expiry to trigger refresh |
| `timeout` | `number` | No | `10000` | Request timeout in milliseconds |
| `retries` | `number` | No | `3` | Number of retry attempts on failure |
| `retryDelay` | `number` | No | `1000` | Delay between retries in milliseconds |

### Methods

#### `getToken(options?)`

Request an access token from the authorization server.

```typescript
// Basic usage
const token = await m2m.getToken();

// With options override
const token = await m2m.getToken({
  scopes: ['users:read'],           // Override default scopes
  audience: ['https://api.example.com'], // Override default audience
  forceRefresh: true,               // Force a new token request
});
```

**Returns:** `Promise<M2MTokenResponse>`

#### `getValidToken()`

Get a valid token, automatically refreshing if needed (when `autoRefresh` is enabled).

```typescript
// Always returns a valid, non-expired token
const token = await m2m.getValidToken();
```

**Returns:** `Promise<M2MTokenResponse>`

#### `getCachedToken()`

Get the currently cached token without making a request.

```typescript
const token = m2m.getCachedToken();
if (token && !m2m.isTokenExpired(token)) {
  console.log('Using cached token');
}
```

**Returns:** `M2MTokenResponse | null`

#### `isTokenExpired(token?)`

Check if a token is expired or about to expire.

```typescript
const token = m2m.getCachedToken();
if (m2m.isTokenExpired(token)) {
  console.log('Token is expired');
}

// With custom threshold (seconds)
if (m2m.isTokenExpired(token, 300)) {
  console.log('Token expires within 5 minutes');
}
```

**Returns:** `boolean`

#### `clearCache()`

Clear the cached token, forcing a new request on next `getToken()`.

```typescript
m2m.clearCache();
```

#### `revokeToken()` (if supported)

Revoke the current token.

```typescript
await m2m.revokeToken();
```

---

## Token Management

### Token Lifecycle

M2M tokens follow a simple lifecycle:

```
┌─────────────────┐
│   Request Token │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Token Issued   │
│  (cached)       │
└────────┬────────┘
         │
         ▼
┌─────────────────┐     ┌─────────────────┐
│  Token Valid    │────▶│  Use for API    │
│                 │     │  Requests       │
└────────┬────────┘     └─────────────────┘
         │
         │ (approaching expiry)
         ▼
┌─────────────────┐
│  Auto Refresh   │
│  (if enabled)   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  New Token      │
│  Issued         │
└─────────────────┘
```

### Automatic Refresh

Enable automatic token refresh to ensure you always have a valid token:

```typescript
const m2m = new M2MClient({
  url: 'https://auth.yourapp.com',
  clientId: 'your-client-id',
  clientSecret: 'your-client-secret',
  autoRefresh: true,
  refreshThreshold: 60, // Refresh 60 seconds before expiry
});

// This will automatically refresh the token if needed
const token = await m2m.getValidToken();
```

### Token Caching

Tokens are cached in memory by default:

```typescript
// First call - requests new token
const token1 = await m2m.getToken();

// Second call - returns cached token
const token2 = await m2m.getToken();

// Force new token request
const token3 = await m2m.getToken({ forceRefresh: true });
```

**Custom Cache Implementation:**

```typescript
import { M2MClient, type M2MTokenCache } from '@passflow/core';

// Custom Redis cache
const redisCache: M2MTokenCache = {
  async get(key: string): Promise<M2MTokenResponse | null> {
    const data = await redis.get(key);
    return data ? JSON.parse(data) : null;
  },
  async set(key: string, token: M2MTokenResponse, ttl: number): Promise<void> {
    await redis.set(key, JSON.stringify(token), 'EX', ttl);
  },
  async delete(key: string): Promise<void> {
    await redis.del(key);
  },
};

const m2m = new M2MClient({
  url: 'https://auth.yourapp.com',
  clientId: 'your-client-id',
  clientSecret: 'your-client-secret',
  cache: redisCache,
});
```

---

## Scopes and Audiences

### Scopes

Scopes define what actions the token allows. Use the `resource:action` format:

```typescript
const m2m = new M2MClient({
  url: 'https://auth.yourapp.com',
  clientId: 'your-client-id',
  clientSecret: 'your-client-secret',
  scopes: [
    'users:read',      // Read user data
    'users:write',     // Write user data
    'orders:read',     // Read orders
    'orders:write',    // Create/update orders
    'admin:manage',    // Administrative access
  ],
});
```

**Scope Validation:**
- Requested scopes must be within the M2M app's allowed scopes
- If you request scopes not allowed for the app, authentication will fail
- Empty scopes array requests no specific scopes

### Audiences

Audiences specify the intended recipients of the token:

```typescript
const m2m = new M2MClient({
  url: 'https://auth.yourapp.com',
  clientId: 'your-client-id',
  clientSecret: 'your-client-secret',
  audience: [
    'https://api.yourapp.com',
    'https://internal-api.yourapp.com',
  ],
});
```

**Audience Validation:**
- Requested audiences must be in the M2M app's allowed audiences
- The token's `aud` claim will contain the validated audiences
- APIs should validate the `aud` claim matches their expected value

---

## Error Handling

### Error Types

The M2M client throws `M2MError` for authentication failures:

```typescript
import { M2MClient, M2MError, M2MErrorCode } from '@passflow/core';

try {
  const token = await m2m.getToken();
} catch (error) {
  if (error instanceof M2MError) {
    console.error(`Error Code: ${error.code}`);
    console.error(`Message: ${error.message}`);
    console.error(`Status: ${error.status}`);

    switch (error.code) {
      case M2MErrorCode.InvalidClient:
        console.error('Invalid client credentials');
        break;
      case M2MErrorCode.InvalidScope:
        console.error('Requested scope not allowed');
        break;
      case M2MErrorCode.RateLimitExceeded:
        console.error('Rate limit exceeded, retry later');
        break;
      case M2MErrorCode.ServerError:
        console.error('Server error, retry with backoff');
        break;
    }
  }
}
```

### Error Codes

| Code | Description | Action |
|------|-------------|--------|
| `invalid_client` | Invalid client credentials | Verify client_id and client_secret |
| `invalid_request` | Malformed request | Check request parameters |
| `invalid_scope` | Requested scope not allowed | Request only allowed scopes |
| `invalid_grant` | Grant type not supported | Use `client_credentials` grant |
| `unauthorized_client` | Client not authorized for grant | Verify M2M app configuration |
| `rate_limit_exceeded` | Too many requests | Implement backoff and retry |
| `server_error` | Internal server error | Retry with exponential backoff |
| `temporarily_unavailable` | Service temporarily unavailable | Retry later |

### Retry Logic

The client includes built-in retry logic:

```typescript
const m2m = new M2MClient({
  url: 'https://auth.yourapp.com',
  clientId: 'your-client-id',
  clientSecret: 'your-client-secret',
  retries: 3,           // Retry up to 3 times
  retryDelay: 1000,     // Wait 1 second between retries
});
```

**Custom Retry Strategy:**

```typescript
import { M2MClient, type RetryStrategy } from '@passflow/core';

const exponentialBackoff: RetryStrategy = {
  shouldRetry: (error, attempt) => {
    // Retry on network errors and 5xx responses
    return attempt < 5 && (
      error.code === 'server_error' ||
      error.code === 'temporarily_unavailable' ||
      error.status >= 500
    );
  },
  getDelay: (attempt) => {
    // Exponential backoff: 1s, 2s, 4s, 8s, 16s
    return Math.pow(2, attempt) * 1000;
  },
};

const m2m = new M2MClient({
  url: 'https://auth.yourapp.com',
  clientId: 'your-client-id',
  clientSecret: 'your-client-secret',
  retryStrategy: exponentialBackoff,
});
```

---

## Best Practices

### 1. Secure Credential Storage

**Never hardcode credentials in source code:**

```typescript
// ❌ Bad - hardcoded credentials
const m2m = new M2MClient({
  clientId: 'abc123',
  clientSecret: 'super-secret-key',
});

// ✅ Good - environment variables
const m2m = new M2MClient({
  url: process.env.PASSFLOW_URL!,
  clientId: process.env.M2M_CLIENT_ID!,
  clientSecret: process.env.M2M_CLIENT_SECRET!,
});
```

**Use secret managers in production:**

```typescript
import { SecretsManager } from '@aws-sdk/client-secrets-manager';

const secretsManager = new SecretsManager({ region: 'us-east-1' });

async function getM2MClient(): Promise<M2MClient> {
  const secret = await secretsManager.getSecretValue({
    SecretId: 'passflow/m2m-credentials',
  });

  const credentials = JSON.parse(secret.SecretString!);

  return new M2MClient({
    url: credentials.url,
    clientId: credentials.clientId,
    clientSecret: credentials.clientSecret,
  });
}
```

### 2. Request Minimum Required Scopes

```typescript
// ❌ Bad - requesting all scopes
const m2m = new M2MClient({
  clientId: process.env.M2M_CLIENT_ID!,
  clientSecret: process.env.M2M_CLIENT_SECRET!,
  scopes: ['users:read', 'users:write', 'admin:all', 'orders:*'],
});

// ✅ Good - request only what you need
const m2m = new M2MClient({
  clientId: process.env.M2M_CLIENT_ID!,
  clientSecret: process.env.M2M_CLIENT_SECRET!,
  scopes: ['users:read'], // Only read access needed
});
```

### 3. Handle Rate Limits Gracefully

```typescript
import { M2MClient, M2MError } from '@passflow/core';

async function getTokenWithRateLimitHandling(m2m: M2MClient): Promise<string> {
  try {
    const token = await m2m.getToken();
    return token.access_token;
  } catch (error) {
    if (error instanceof M2MError && error.code === 'rate_limit_exceeded') {
      // Check rate limit headers
      const retryAfter = error.headers?.['retry-after'];
      const waitTime = retryAfter ? parseInt(retryAfter) * 1000 : 60000;

      console.log(`Rate limited. Retrying in ${waitTime}ms`);
      await new Promise(resolve => setTimeout(resolve, waitTime));

      return getTokenWithRateLimitHandling(m2m);
    }
    throw error;
  }
}
```

### 4. Use Token Caching

```typescript
// ✅ Good - cache tokens to reduce requests
const m2m = new M2MClient({
  url: process.env.PASSFLOW_URL!,
  clientId: process.env.M2M_CLIENT_ID!,
  clientSecret: process.env.M2M_CLIENT_SECRET!,
  autoRefresh: true,
  refreshThreshold: 60, // Refresh 1 minute before expiry
});

// This service instance should be reused (singleton pattern)
export const m2mService = m2m;
```

### 5. Rotate Secrets Regularly

```typescript
// Implement secret rotation
async function rotateM2MSecret(): Promise<void> {
  const adminClient = new PassflowAdmin({
    url: process.env.PASSFLOW_URL!,
    apiKey: process.env.ADMIN_API_KEY!,
  });

  // Rotate the secret
  const { client_secret } = await adminClient.rotateM2MSecret(
    process.env.M2M_CLIENT_ID!
  );

  // Update secret in your secret manager
  await updateSecretInVault('m2m-client-secret', client_secret);

  // Clear token cache to use new credentials
  m2mService.clearCache();
}
```

### 6. Log Token Usage (Without Exposing Secrets)

```typescript
import { M2MClient } from '@passflow/core';

const m2m = new M2MClient({
  url: process.env.PASSFLOW_URL!,
  clientId: process.env.M2M_CLIENT_ID!,
  clientSecret: process.env.M2M_CLIENT_SECRET!,
  onTokenRequest: (request) => {
    // ✅ Log request metadata, not secrets
    console.log('Token requested', {
      clientId: request.clientId,
      scopes: request.scopes,
      timestamp: new Date().toISOString(),
    });
  },
  onTokenResponse: (response) => {
    console.log('Token received', {
      expiresIn: response.expires_in,
      scopes: response.scope,
      tokenType: response.token_type,
    });
  },
});
```

---

## API Reference

### Types

```typescript
/**
 * M2M Client configuration options
 */
export type M2MClientConfig = {
  /** Passflow server URL */
  url: string;

  /** M2M application client ID */
  clientId: string;

  /** M2M application client secret */
  clientSecret: string;

  /** Scopes to request (default: []) */
  scopes?: string[];

  /** Target audiences for the token */
  audience?: string[];

  /** Automatically refresh tokens before expiry (default: false) */
  autoRefresh?: boolean;

  /** Seconds before expiry to trigger refresh (default: 30) */
  refreshThreshold?: number;

  /** Request timeout in milliseconds (default: 10000) */
  timeout?: number;

  /** Number of retry attempts on failure (default: 3) */
  retries?: number;

  /** Delay between retries in milliseconds (default: 1000) */
  retryDelay?: number;

  /** Custom retry strategy */
  retryStrategy?: RetryStrategy;

  /** Custom token cache implementation */
  cache?: M2MTokenCache;

  /** Callback for token requests (for logging/metrics) */
  onTokenRequest?: (request: M2MTokenRequestInfo) => void;

  /** Callback for token responses (for logging/metrics) */
  onTokenResponse?: (response: M2MTokenResponse) => void;
};

/**
 * Token request options
 */
export type M2MTokenRequestOptions = {
  /** Override default scopes */
  scopes?: string[];

  /** Override default audience */
  audience?: string[];

  /** Force a new token request, ignoring cache */
  forceRefresh?: boolean;
};

/**
 * OAuth 2.0 token response
 */
export type M2MTokenResponse = {
  /** The access token */
  access_token: string;

  /** Token type (always "Bearer") */
  token_type: 'Bearer';

  /** Token lifetime in seconds */
  expires_in: number;

  /** Granted scopes (space-separated) */
  scope?: string;

  /** Timestamp when token was issued */
  issued_at?: number;
};

/**
 * Parsed M2M JWT token claims
 */
export type M2MTokenClaims = {
  /** Issuer (Passflow server URL) */
  iss: string;

  /** Subject (client_id) */
  sub: string;

  /** Audience (target APIs) */
  aud: string[];

  /** Issued at timestamp */
  iat: number;

  /** Expiration timestamp */
  exp: number;

  /** Token type ("m2m") */
  type: 'm2m';

  /** Client ID */
  client_id: string;

  /** Tenant ID (for tenant-scoped M2M apps) */
  tenant_id?: string;

  /** Granted scopes */
  scopes: string[];
};

/**
 * M2M authentication error
 */
export class M2MError extends Error {
  /** OAuth 2.0 error code */
  code: M2MErrorCode;

  /** Error description */
  message: string;

  /** HTTP status code */
  status: number;

  /** Response headers (for rate limit info) */
  headers?: Record<string, string>;

  /** Original error (if wrapped) */
  cause?: Error;
}

/**
 * M2M error codes (OAuth 2.0 compliant)
 */
export enum M2MErrorCode {
  InvalidRequest = 'invalid_request',
  InvalidClient = 'invalid_client',
  InvalidGrant = 'invalid_grant',
  InvalidScope = 'invalid_scope',
  UnauthorizedClient = 'unauthorized_client',
  UnsupportedGrantType = 'unsupported_grant_type',
  RateLimitExceeded = 'rate_limit_exceeded',
  ServerError = 'server_error',
  TemporarilyUnavailable = 'temporarily_unavailable',
}

/**
 * Custom token cache interface
 */
export interface M2MTokenCache {
  /** Get cached token */
  get(key: string): Promise<M2MTokenResponse | null>;

  /** Cache a token with TTL */
  set(key: string, token: M2MTokenResponse, ttl: number): Promise<void>;

  /** Delete cached token */
  delete(key: string): Promise<void>;
}

/**
 * Custom retry strategy interface
 */
export interface RetryStrategy {
  /** Determine if request should be retried */
  shouldRetry(error: M2MError, attempt: number): boolean;

  /** Get delay before next retry in milliseconds */
  getDelay(attempt: number): number;
}
```

### M2MClient Class

```typescript
export class M2MClient {
  /**
   * Create a new M2M client
   * @param config - Client configuration
   */
  constructor(config: M2MClientConfig);

  /**
   * Request an access token
   * @param options - Optional request overrides
   * @returns Token response
   * @throws M2MError on authentication failure
   */
  getToken(options?: M2MTokenRequestOptions): Promise<M2MTokenResponse>;

  /**
   * Get a valid token, automatically refreshing if needed
   * @returns Valid token response
   * @throws M2MError on authentication failure
   */
  getValidToken(): Promise<M2MTokenResponse>;

  /**
   * Get the currently cached token
   * @returns Cached token or null
   */
  getCachedToken(): M2MTokenResponse | null;

  /**
   * Check if a token is expired
   * @param token - Token to check (uses cached if not provided)
   * @param threshold - Seconds before expiry to consider expired
   * @returns true if expired or about to expire
   */
  isTokenExpired(token?: M2MTokenResponse, threshold?: number): boolean;

  /**
   * Parse token claims from a JWT
   * @param token - JWT access token
   * @returns Decoded token claims
   */
  parseToken(token: string): M2MTokenClaims;

  /**
   * Clear the token cache
   */
  clearCache(): void;

  /**
   * Revoke the current token (if revocation endpoint is supported)
   * @throws M2MError on revocation failure
   */
  revokeToken(): Promise<void>;
}
```

---

## Examples

### Backend Service Authentication

```typescript
// services/api-client.ts
import { M2MClient } from '@passflow/core';

const m2m = new M2MClient({
  url: process.env.PASSFLOW_URL!,
  clientId: process.env.M2M_CLIENT_ID!,
  clientSecret: process.env.M2M_CLIENT_SECRET!,
  scopes: ['users:read', 'orders:read'],
  autoRefresh: true,
});

export async function fetchUsers(): Promise<User[]> {
  const token = await m2m.getValidToken();

  const response = await fetch('https://api.yourapp.com/users', {
    headers: {
      'Authorization': `Bearer ${token.access_token}`,
      'Content-Type': 'application/json',
    },
  });

  if (!response.ok) {
    throw new Error(`API error: ${response.status}`);
  }

  return response.json();
}
```

### Microservices Communication

```typescript
// services/order-service.ts
import { M2MClient } from '@passflow/core';
import axios from 'axios';

class OrderService {
  private m2m: M2MClient;
  private httpClient: typeof axios;

  constructor() {
    this.m2m = new M2MClient({
      url: process.env.PASSFLOW_URL!,
      clientId: process.env.ORDER_SERVICE_CLIENT_ID!,
      clientSecret: process.env.ORDER_SERVICE_CLIENT_SECRET!,
      scopes: ['orders:write', 'inventory:read', 'payments:process'],
      autoRefresh: true,
    });

    this.httpClient = axios.create({
      baseURL: process.env.INTERNAL_API_URL,
      timeout: 5000,
    });

    // Add auth interceptor
    this.httpClient.interceptors.request.use(async (config) => {
      const token = await this.m2m.getValidToken();
      config.headers.Authorization = `Bearer ${token.access_token}`;
      return config;
    });
  }

  async createOrder(orderData: CreateOrderRequest): Promise<Order> {
    // Check inventory
    const inventory = await this.httpClient.get(
      `/inventory/${orderData.productId}`
    );

    if (inventory.data.quantity < orderData.quantity) {
      throw new Error('Insufficient inventory');
    }

    // Process payment
    const payment = await this.httpClient.post('/payments', {
      amount: orderData.totalAmount,
      currency: 'USD',
    });

    // Create order
    const order = await this.httpClient.post('/orders', {
      ...orderData,
      paymentId: payment.data.id,
    });

    return order.data;
  }
}

export const orderService = new OrderService();
```

### Scheduled Jobs

```typescript
// jobs/sync-data.ts
import { M2MClient, M2MError } from '@passflow/core';
import { CronJob } from 'cron';

const m2m = new M2MClient({
  url: process.env.PASSFLOW_URL!,
  clientId: process.env.SYNC_JOB_CLIENT_ID!,
  clientSecret: process.env.SYNC_JOB_CLIENT_SECRET!,
  scopes: ['data:sync', 'reports:write'],
  retries: 5,
  retryDelay: 2000,
});

async function syncData(): Promise<void> {
  console.log('Starting data sync job...');

  try {
    const token = await m2m.getToken();

    // Fetch data from external API
    const externalData = await fetch('https://external-api.com/data', {
      headers: { 'Authorization': `Bearer ${token.access_token}` },
    });

    // Process and store data
    const data = await externalData.json();
    await processAndStoreData(data);

    console.log(`Sync completed: ${data.length} records processed`);
  } catch (error) {
    if (error instanceof M2MError) {
      console.error(`M2M authentication failed: ${error.code} - ${error.message}`);
      // Send alert to monitoring
      await sendAlert('M2M auth failure in sync job', error);
    } else {
      console.error('Sync job failed:', error);
    }
    throw error;
  }
}

// Run every hour
const job = new CronJob('0 * * * *', syncData);
job.start();
```

### Multi-Tenant M2M

```typescript
// services/tenant-api-client.ts
import { M2MClient } from '@passflow/core';

// Create separate M2M clients for each tenant
const tenantClients = new Map<string, M2MClient>();

function getClientForTenant(tenantId: string): M2MClient {
  if (!tenantClients.has(tenantId)) {
    const credentials = getTenantCredentials(tenantId);

    const client = new M2MClient({
      url: process.env.PASSFLOW_URL!,
      clientId: credentials.clientId,
      clientSecret: credentials.clientSecret,
      scopes: ['tenant:read', 'tenant:write'],
      autoRefresh: true,
    });

    tenantClients.set(tenantId, client);
  }

  return tenantClients.get(tenantId)!;
}

export async function fetchTenantData(tenantId: string): Promise<TenantData> {
  const client = getClientForTenant(tenantId);
  const token = await client.getValidToken();

  // Token will include tenant_id claim
  const claims = client.parseToken(token.access_token);
  console.log(`Fetching data for tenant: ${claims.tenant_id}`);

  const response = await fetch(`${process.env.API_URL}/tenant/data`, {
    headers: {
      'Authorization': `Bearer ${token.access_token}`,
    },
  });

  return response.json();
}
```

### Express Middleware for Token Injection

```typescript
// middleware/m2m-auth.ts
import { M2MClient } from '@passflow/core';
import type { Request, Response, NextFunction } from 'express';

const m2m = new M2MClient({
  url: process.env.PASSFLOW_URL!,
  clientId: process.env.M2M_CLIENT_ID!,
  clientSecret: process.env.M2M_CLIENT_SECRET!,
  autoRefresh: true,
});

// Extend Express Request type
declare global {
  namespace Express {
    interface Request {
      m2mToken?: string;
    }
  }
}

export async function m2mAuthMiddleware(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    const token = await m2m.getValidToken();
    req.m2mToken = token.access_token;
    next();
  } catch (error) {
    console.error('Failed to obtain M2M token:', error);
    res.status(503).json({ error: 'Service authentication failed' });
  }
}

// Usage in routes
import express from 'express';
const app = express();

app.use('/api/internal', m2mAuthMiddleware);

app.get('/api/internal/data', async (req, res) => {
  const response = await fetch('https://internal-service.com/data', {
    headers: { 'Authorization': `Bearer ${req.m2mToken}` },
  });
  res.json(await response.json());
});
```

---

## Security Considerations

1. **Never expose client secrets** - Store in environment variables or secret managers
2. **Use HTTPS** - Always use encrypted connections
3. **Minimize scope** - Request only the scopes you need
4. **Rotate secrets regularly** - Implement automated secret rotation
5. **Monitor usage** - Track token requests for anomalies
6. **Handle errors securely** - Don't expose internal errors to clients
7. **Validate tokens server-side** - Always validate tokens in your APIs

---

## Troubleshooting

### Common Issues

**Error: `invalid_client`**
- Verify `clientId` and `clientSecret` are correct
- Ensure the M2M app is active
- Check that the app has M2M type

**Error: `invalid_scope`**
- Requested scopes must be in the app's allowed scopes
- Check for typos in scope names

**Error: `rate_limit_exceeded`**
- Implement token caching to reduce requests
- Use exponential backoff for retries
- Contact admin to increase rate limit

**Error: Network timeout**
- Check network connectivity
- Verify the Passflow server URL
- Increase timeout configuration

---

## Migration from Other OAuth Libraries

### From `client-oauth2`

```typescript
// Before (client-oauth2)
import ClientOAuth2 from 'client-oauth2';

const oauth = new ClientOAuth2({
  clientId: 'client-id',
  clientSecret: 'client-secret',
  accessTokenUri: 'https://auth.example.com/oauth/token',
});

const token = await oauth.credentials.getToken();

// After (@passflow/core)
import { M2MClient } from '@passflow/core';

const m2m = new M2MClient({
  url: 'https://auth.example.com',
  clientId: 'client-id',
  clientSecret: 'client-secret',
});

const token = await m2m.getToken();
```

### From `simple-oauth2`

```typescript
// Before (simple-oauth2)
import { ClientCredentials } from 'simple-oauth2';

const client = new ClientCredentials({
  client: { id: 'client-id', secret: 'client-secret' },
  auth: { tokenHost: 'https://auth.example.com' },
});

const token = await client.getToken({ scope: 'read write' });

// After (@passflow/core)
import { M2MClient } from '@passflow/core';

const m2m = new M2MClient({
  url: 'https://auth.example.com',
  clientId: 'client-id',
  clientSecret: 'client-secret',
  scopes: ['read', 'write'],
});

const token = await m2m.getToken();
```

---

## Changelog

### Version 0.2.0 (Upcoming)
- Added M2M authentication support
- Added `M2MClient` class
- Added automatic token refresh
- Added custom cache support
- Added retry strategies

---

## Support

- **Documentation**: [https://docs.passflow.cloud/m2m](https://docs.passflow.cloud/m2m)
- **GitHub Issues**: [https://github.com/madappgang/passflow-js-sdk/issues](https://github.com/madappgang/passflow-js-sdk/issues)
- **Email**: support@passflow.cloud
