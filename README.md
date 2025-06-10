# Passflow JavaScript SDK Documentation

## Changelog

### Version 0.1.45

- Fixed bug related to null/undefined checks in the codebase

## Table of Contents

- [Passflow JavaScript SDK Documentation](#passflow-javascript-sdk-documentation)
  - [Changelog](#changelog)
    - [Version 0.1.45](#version-0145)
  - [Table of Contents](#table-of-contents)
  - [Quick Start Examples](#quick-start-examples)
    - [Basic Initialization](#basic-initialization)
    - [Simple Authentication](#simple-authentication)
    - [Quick Passwordless Authentication](#quick-passwordless-authentication)
    - [Basic Passkey Usage](#basic-passkey-usage)
    - [Quick Password Reset](#quick-password-reset)
    - [Basic Tenant Creation](#basic-tenant-creation)
    - [Simple Event Subscription](#simple-event-subscription)
  - [Introduction](#introduction)
  - [Installation](#installation)
  - [Getting Started](#getting-started)
    - [Initialization](#initialization)
    - [Session Management](#session-management)
  - [Authentication](#authentication)
    - [Sign In](#sign-in)
    - [Sign Up](#sign-up)
    - [Sign Out](#sign-out)
    - [Passwordless Authentication](#passwordless-authentication)
    - [Federated Authentication](#federated-authentication)
    - [Passkey Authentication](#passkey-authentication)
    - [Password Reset](#password-reset)
  - [Token Management](#token-management)
  - [Tenant Management](#tenant-management)
  - [Invitation Management](#invitation-management)
  - [Events and Subscriptions](#events-and-subscriptions)
  - [Error Handling](#error-handling)
  - [API Reference](#api-reference)
    - [Passflow Class](#passflow-class)
      - [Constructor](#constructor)
      - [Methods](#methods)
    - [Services](#services)
    - [Types](#types)
      - [PassflowConfig](#passflowconfig)
      - [Tokens](#tokens)
      - [Token](#token)
      - [PassflowSignInPayload](#passflowsigninpayload)
      - [PassflowSignUpPayload](#passflowsignuppayload)
      - [UserMembership](#usermembership)
      - [PassflowEvent](#passflowevent)
  - [Detailed Examples](#detailed-examples)
    - [Complete Sign In Flow](#complete-sign-in-flow)
    - [Authentication with Passkeys](#authentication-with-passkeys)
    - [Multi-tenant Application](#multi-tenant-application)

## Quick Start Examples

### Basic Initialization

```javascript
import { Passflow } from "passflow-js";

// Minimal initialization with just the required appId
const passflow = new Passflow({
  appId: "your-app-id",
});

// Simple session setup
passflow.session({
  createSession: () => console.log("User is authenticated"),
  expiredSession: () => console.log("User session expired"),
});
```

### Simple Authentication

```javascript
// Basic sign in with just email and password
const simpleSignIn = async () => {
  try {
    await passflow.signIn({
      email: "user@example.com",
      password: "password123",
    });
    console.log("Signed in successfully");
  } catch (error) {
    console.error("Sign in failed", error);
  }
};

// Basic sign up with minimal user info
const simpleSignUp = async () => {
  try {
    await passflow.signUp({
      user: {
        email: "user@example.com",
        password: "password123",
      },
    });
    console.log("Registered successfully");
  } catch (error) {
    console.error("Registration failed", error);
  }
};

// Simple logout
const simpleSignOut = async () => {
  await passflow.logOut();
};
```

### Quick Passwordless Authentication

```javascript
// Start passwordless flow with just email
const simplePasswordless = async () => {
  try {
    const response = await passflow.passwordlessSignIn({
      email: "user@example.com",
      challenge_type: "otp",
      redirect_url: window.location.origin,
    });
    console.log("Check your email for the code");
    return response.challenge_id;
  } catch (error) {
    console.error("Failed to start passwordless flow", error);
  }
};

// Complete with just the challenge ID and OTP
const completeSimplePasswordless = async (challengeId, otp) => {
  try {
    await passflow.passwordlessSignInComplete({
      challenge_id: challengeId,
      otp: otp,
    });
    console.log("Authentication successful");
  } catch (error) {
    console.error("Failed to complete passwordless flow", error);
  }
};
```

### Basic Passkey Usage

```javascript
// Register a passkey with minimal options
const simplePasskeyRegister = async () => {
  try {
    await passflow.passkeyRegister({
      relying_party_id: window.location.hostname,
      redirect_url: window.location.origin,
      scopes: ["id", "offline"],
    });
    console.log("Passkey registered");
  } catch (error) {
    console.error("Passkey registration failed", error);
  }
};

// Authenticate with minimal options
const simplePasskeyAuthenticate = async () => {
  try {
    await passflow.passkeyAuthenticate({
      relying_party_id: window.location.hostname,
    });
    console.log("Authenticated with passkey");
  } catch (error) {
    console.error("Passkey authentication failed", error);
  }
};
```

### Quick Password Reset

```javascript
// Send reset email with just the email address
const simplePasswordReset = async () => {
  try {
    await passflow.sendPasswordResetEmail({
      email: "user@example.com",
    });
    console.log("Password reset email sent");
  } catch (error) {
    console.error("Failed to send reset email", error);
  }
};
```

### Basic Tenant Creation

```javascript
// Create a tenant with just a name
const simpleCreateTenant = async () => {
  try {
    await passflow.createTenant("My Organization");
    console.log("Tenant created");
  } catch (error) {
    console.error("Failed to create tenant", error);
  }
};
```

### Simple Event Subscription

```javascript
// Subscribe to authentication events with minimal setup
passflow.subscribe({
  onAuthChange: (eventType) => {
    console.log(`Auth event occurred: ${eventType}`);
  },
});
```

## Introduction

Passflow JavaScript SDK is a client library for interacting with the Passflow authentication service. It provides a comprehensive set of features for user authentication, token management, tenant management, and more. The SDK supports various authentication methods including email/password, passwordless, passkeys (WebAuthn), and federated identity providers.

## Installation

```bash
npm install passflow-js
# or
yarn add passflow-js
```

## Getting Started

### Initialization

Import and initialize the Passflow client with your configuration:

```javascript
import { Passflow } from "passflow-js";

const passflow = new Passflow({
  url: "https://auth.passflow.cloud", // or your custom URL
  appId: "your-app-id",
  scopes: [
    "id",
    "offline",
    "tenant",
    "email",
    "oidc",
    "openid",
    "access:tenant:all",
  ], // optional, these are the defaults
  createTenantForNewUser: false, // optional
  parseQueryParams: true, // optional, will parse tokens from URL query params
  keyStoragePrefix: "myapp", // optional, prefix for localStorage keys
});
```

### Session Management

Setup session management to handle authentication state:

```javascript
passflow.session({
  createSession: (tokens) => {
    console.log("Session created", tokens);
    // Set your app's authenticated state
  },
  expiredSession: () => {
    console.log("Session expired");
    // Clear your app's authenticated state
  },
  doRefresh: true, // automatically refresh tokens when expired
});
```

## Authentication

### Sign In

```javascript
// Sign in with email and password
const signIn = async () => {
  try {
    const response = await passflow.signIn({
      email: "user@example.com",
      password: "password123",
      scopes: ["id", "offline", "tenant", "email"], // optional
    });
    console.log("Signed in successfully", response);
  } catch (error) {
    console.error("Sign in failed", error);
  }
};
```

### Sign Up

```javascript
// Register a new user
const signUp = async () => {
  try {
    const response = await passflow.signUp({
      user: {
        email: "user@example.com",
        password: "password123",
        given_name: "John",
        family_name: "Doe",
        // Additional optional user fields
      },
      scopes: ["id", "offline", "tenant", "email"], // optional
      create_tenant: true, // optional
    });
    console.log("Registered successfully", response);
  } catch (error) {
    console.error("Registration failed", error);
  }
};
```

### Sign Out

```javascript
// Log out the current user
const signOut = async () => {
  try {
    await passflow.logOut();
    console.log("Signed out successfully");
  } catch (error) {
    console.error("Sign out failed", error);
  }
};
```

### Passwordless Authentication

```javascript
// Start passwordless authentication flow
const startPasswordless = async () => {
  try {
    const response = await passflow.passwordlessSignIn({
      email: "user@example.com",
      challenge_type: "otp", // or 'magic_link'
      redirect_url: "https://yourapp.com/auth/callback",
    });
    console.log("Passwordless authentication started", response);
    // Store the challenge_id for the next step
  } catch (error) {
    console.error("Passwordless authentication failed", error);
  }
};

// Complete passwordless authentication flow
const completePasswordless = async (challengeId, otp) => {
  try {
    const response = await passflow.passwordlessSignInComplete({
      challenge_id: challengeId,
      otp: otp,
    });
    console.log("Passwordless authentication completed", response);
  } catch (error) {
    console.error("Passwordless authentication completion failed", error);
  }
};
```

### Federated Authentication

```javascript
// Sign in with a provider using popup
passflow.federatedAuthWithPopup(
  "google", // or 'facebook'
  "https://yourapp.com/auth/callback",
  ["id", "offline", "tenant", "email"] // optional scopes
);

// Sign in with a provider using redirect
passflow.federatedAuthWithRedirect(
  "google", // or 'facebook'
  "https://yourapp.com/auth/callback",
  ["id", "offline", "tenant", "email"] // optional scopes
);
```

### Passkey Authentication

```javascript
// Register a new passkey
const registerPasskey = async () => {
  try {
    const response = await passflow.passkeyRegister({
      passkey_display_name: "My Passkey",
      passkey_username: "user@example.com",
      relying_party_id: window.location.hostname,
      redirect_url: "https://yourapp.com/auth/callback",
      scopes: ["id", "offline", "tenant", "email"], // optional
    });
    console.log("Passkey registered successfully", response);
  } catch (error) {
    console.error("Passkey registration failed", error);
  }
};

// Authenticate with a passkey
const authenticateWithPasskey = async () => {
  try {
    const response = await passflow.passkeyAuthenticate({
      relying_party_id: window.location.hostname,
      scopes: ["id", "offline", "tenant", "email"], // optional
    });
    console.log("Passkey authentication successful", response);
  } catch (error) {
    console.error("Passkey authentication failed", error);
  }
};

// Add additional passkey to user account
const addPasskey = async () => {
  try {
    await passflow.addUserPasskey({
      relyingPartyId: window.location.hostname,
      passkeyUsername: "user@example.com",
      passkeyDisplayName: "My Secondary Passkey",
    });
    console.log("Passkey added successfully");
  } catch (error) {
    console.error("Adding passkey failed", error);
  }
};

// Manage user passkeys
const managePasskeys = async () => {
  try {
    // Get all passkeys
    const passkeys = await passflow.getUserPasskeys();
    console.log("User passkeys", passkeys);

    // Rename a passkey
    await passflow.renameUserPasskey("New Name", "passkey-id");

    // Delete a passkey
    await passflow.deleteUserPasskey("passkey-id");
  } catch (error) {
    console.error("Passkey management failed", error);
  }
};
```

### Password Reset

```javascript
// Send password reset email
const sendResetEmail = async () => {
  try {
    await passflow.sendPasswordResetEmail({
      email: "user@example.com",
      reset_page_url: "https://yourapp.com/reset-password",
    });
    console.log("Password reset email sent");
  } catch (error) {
    console.error("Sending password reset email failed", error);
  }
};

// Reset password (after receiving reset token)
const resetPassword = async (newPassword) => {
  try {
    // The token should be in the URL query parameters
    const response = await passflow.resetPassword(newPassword);
    console.log("Password reset successful", response);
  } catch (error) {
    console.error("Password reset failed", error);
  }
};
```

## Token Management

```javascript
// Check if user is authenticated
const isAuthenticated = passflow.isAuthenticated();

// Get current tokens
const tokens = passflow.getTokensCache();

// Get parsed tokens (decoded JWT payload)
const parsedTokens = passflow.getParsedTokenCache();

// Manually refresh token
const refreshToken = async () => {
  try {
    const response = await passflow.refreshToken();
    console.log("Token refreshed", response);
  } catch (error) {
    console.error("Token refresh failed", error);
  }
};

// Set tokens manually
const setTokens = async (tokens) => {
  try {
    await passflow.setTokens({
      access_token: tokens.access_token,
      refresh_token: tokens.refresh_token,
      id_token: tokens.id_token,
      scopes: tokens.scopes,
    });
  } catch (error) {
    console.error("Setting tokens failed", error);
  }
};

// Handle tokens from redirect
const handleRedirect = () => {
  const tokens = passflow.handleTokensRedirect();
  if (tokens) {
    console.log("Tokens received from redirect", tokens);
  }
};
```

## Tenant Management

```javascript
// Create a new tenant
const createTenant = async () => {
  try {
    const response = await passflow.createTenant("My Organization", true);
    console.log("Tenant created", response);
  } catch (error) {
    console.error("Tenant creation failed", error);
  }
};

// Join a tenant via invitation
const joinTenant = async (invitationToken) => {
  try {
    const response = await passflow.joinInvitation(invitationToken);
    console.log("Joined tenant", response);
  } catch (error) {
    console.error("Joining tenant failed", error);
  }
};
```

## Invitation Management

```javascript
// Request an invitation link
const requestInvite = async () => {
  try {
    const response = await passflow.requestInviteLink({
      email: "newuser@example.com",
      tenant: "tenant-id", // optional
      group: "group-id", // optional
      role: "role-name", // optional
      callback: "https://yourapp.com/onboarding", // optional
      send_to_email: true, // optional
    });
    console.log("Invitation link created", response);
  } catch (error) {
    console.error("Creating invitation link failed", error);
  }
};

// Get all active invitations
const getInvitations = async () => {
  try {
    const invitations = await passflow.getInvitations({
      tenant_id: "tenant-id", // optional
      group_id: "group-id", // optional
      skip: 0, // optional
      limit: 10, // optional
    });
    console.log("Active invitations", invitations);
  } catch (error) {
    console.error("Getting invitations failed", error);
  }
};

// Delete an invitation
const deleteInvitation = async (token) => {
  try {
    await passflow.deleteInvitation(token);
    console.log("Invitation deleted");
  } catch (error) {
    console.error("Deleting invitation failed", error);
  }
};
```

## Events and Subscriptions

```javascript
// Define a subscriber
const subscriber = {
  onAuthChange: (eventType, source) => {
    console.log(`Auth event: ${eventType}`, source);

    // Handle different event types
    switch (eventType) {
      case "signin":
        // Handle sign in
        break;
      case "signout":
        // Handle sign out
        break;
      case "register":
        // Handle registration
        break;
      case "error":
        // Handle error
        break;
      case "refresh":
        // Handle token refresh
        break;
    }
  },
};

// Subscribe to all events
passflow.subscribe(subscriber);

// Subscribe to specific events
passflow.subscribe(subscriber, ["signin", "signout"]);

// Unsubscribe from all events
passflow.unsubscribe(subscriber);

// Unsubscribe from specific events
passflow.unsubscribe(subscriber, ["error"]);
```

## Error Handling

Errors thrown by the SDK are typically instances of `PassflowError` which include details about the error:

```javascript
try {
  await passflow.signIn({
    email: "user@example.com",
    password: "wrong-password",
  });
} catch (error) {
  if (error instanceof PassflowError) {
    console.error(`Error ID: ${error.id}`);
    console.error(`Error Message: ${error.message}`);
    console.error(`Status Code: ${error.status}`);
    console.error(`Location: ${error.location}`);
    console.error(`Time: ${error.time}`);
  } else {
    console.error("Unknown error:", error);
  }
}
```

## API Reference

### Passflow Class

The main class that provides access to all functionality of the SDK.

#### Constructor

```typescript
constructor(config: PassflowConfig)
```

Configuration options:

- `url`: The URL of the Passflow service (default: 'https://auth.passflow.cloud')
- `appId`: Your application ID
- `scopes`: Token scopes to request (default: ['id', 'offline', 'tenant', 'email', 'oidc', 'openid', 'access:tenant:all'])
- `createTenantForNewUser`: Whether to create a tenant for new users (default: false)
- `parseQueryParams`: Whether to parse tokens from URL query parameters (default: false)
- `keyStoragePrefix`: Prefix for localStorage keys

#### Methods

**Authentication Methods**

| Method                                                     | Description                            |
| ---------------------------------------------------------- | -------------------------------------- |
| `session({ createSession, expiredSession, doRefresh })`    | Set up session management              |
| `signIn(payload)`                                          | Sign in with email/password            |
| `signUp(payload)`                                          | Register a new user                    |
| `logOut()`                                                 | Sign out the current user              |
| `passwordlessSignIn(payload)`                              | Start passwordless authentication      |
| `passwordlessSignInComplete(payload)`                      | Complete passwordless authentication   |
| `federatedAuthWithPopup(provider, redirectUrl, scopes)`    | Sign in with a provider using popup    |
| `federatedAuthWithRedirect(provider, redirectUrl, scopes)` | Sign in with a provider using redirect |
| `passkeyRegister(payload)`                                 | Register a new passkey                 |
| `passkeyAuthenticate(payload)`                             | Authenticate with a passkey            |
| `sendPasswordResetEmail(payload)`                          | Send password reset email              |
| `resetPassword(newPassword, scopes)`                       | Reset password                         |

**Token Methods**

| Method                     | Description                    |
| -------------------------- | ------------------------------ |
| `isAuthenticated()`        | Check if user is authenticated |
| `getTokensCache()`         | Get current tokens             |
| `getParsedTokenCache()`    | Get parsed tokens              |
| `refreshToken()`           | Refresh the access token       |
| `setTokens(tokens)`        | Set tokens manually            |
| `handleTokensRedirect()`   | Handle tokens from redirect    |
| `authRedirectUrl(options)` | Generate an auth redirect URL  |
| `authRedirect(options)`    | Redirect to the auth page      |

**Tenant Methods**

| Method                             | Description                  |
| ---------------------------------- | ---------------------------- |
| `createTenant(name, refreshToken)` | Create a new tenant          |
| `joinInvitation(token, scopes)`    | Join a tenant via invitation |

**Invitation Methods**

| Method                       | Description                |
| ---------------------------- | -------------------------- |
| `requestInviteLink(payload)` | Request an invitation link |
| `getInvitations(options)`    | Get all active invitations |
| `deleteInvitation(token)`    | Delete an invitation       |

**Passkey Methods**

| Method                               | Description                   |
| ------------------------------------ | ----------------------------- |
| `getUserPasskeys()`                  | Get all user passkeys         |
| `renameUserPasskey(name, passkeyId)` | Rename a passkey              |
| `deleteUserPasskey(passkeyId)`       | Delete a passkey              |
| `addUserPasskey(options)`            | Add a passkey to user account |

**Event Methods**

| Method                            | Description                  |
| --------------------------------- | ---------------------------- |
| `subscribe(subscriber, events)`   | Subscribe to auth events     |
| `unsubscribe(subscriber, events)` | Unsubscribe from auth events |

### Services

The SDK includes several services that handle specific functionality:

- `AuthService`: Handles authentication and session management
- `UserService`: Handles user-related operations
- `TenantService`: Handles tenant operations
- `InvitationService`: Handles invitation operations
- `DeviceService`: Manages device identification
- `TokenService`: Handles token parsing and validation
- `StorageManager`: Manages token storage

### Types

Key types used in the SDK:

#### PassflowConfig

```typescript
type PassflowConfig = {
  url?: string;
  appId?: string;
  scopes?: string[];
  createTenantForNewUser?: boolean;
  parseQueryParams?: boolean;
  keyStoragePrefix?: string;
};
```

#### Tokens

```typescript
type Tokens = {
  access_token: string;
  id_token?: string;
  refresh_token?: string;
  scopes?: string[];
};
```

#### Token

```typescript
type Token = {
  aud: string[];
  exp: number;
  iat: number;
  iss: string;
  jti: string;
  sub: string;
  type: string;
  email?: string;
  passflow_tm?: RawUserMembership;
  payload?: unknown;
  membership?: UserMembership;
};
```

#### PassflowSignInPayload

```typescript
type PassflowSignInPayload = {
  password: string;
  scopes?: string[];
  email?: string;
  phone?: string;
  username?: string;
} & ({ email: string } | { phone: string } | { username: string });
```

#### PassflowSignUpPayload

```typescript
type PassflowSignUpPayload = {
  user: PassflowUserPayload;
  scopes?: string[];
  create_tenant?: boolean;
  anonymous?: boolean;
  invite?: string;
};
```

#### UserMembership

```typescript
type UserMembership = {
  raw: RawUserMembership;
  tenants: TenantMembership[];
};
```

#### PassflowEvent

```typescript
enum PassflowEvent {
  SignIn = "signin",
  Register = "register",
  SignOut = "signout",
  Error = "error",
  Refresh = "refresh",
}
```

## Detailed Examples

### Complete Sign In Flow

```javascript
import { Passflow, PassflowError } from "passflow-js";

// Initialize Passflow
const passflow = new Passflow({
  appId: "your-app-id",
  parseQueryParams: true,
});

// Set up session management
passflow.session({
  createSession: (tokens) => {
    // Store authentication state
    localStorage.setItem("isAuthenticated", "true");

    // Update UI
    document.getElementById("login-form").style.display = "none";
    document.getElementById("user-dashboard").style.display = "block";
  },
  expiredSession: () => {
    // Clear authentication state
    localStorage.removeItem("isAuthenticated");

    // Update UI
    document.getElementById("login-form").style.display = "block";
    document.getElementById("user-dashboard").style.display = "none";
  },
  doRefresh: true,
});

// Handle form submission
document
  .getElementById("login-form")
  .addEventListener("submit", async (event) => {
    event.preventDefault();

    const email = document.getElementById("email").value;
    const password = document.getElementById("password").value;

    try {
      await passflow.signIn({ email, password });
      // Login successful - session callback will handle UI update
    } catch (error) {
      if (error instanceof PassflowError) {
        document.getElementById("error-message").textContent = error.message;
      } else {
        document.getElementById("error-message").textContent =
          "An unexpected error occurred";
        console.error(error);
      }
    }
  });

// Handle logout
document.getElementById("logout-button").addEventListener("click", async () => {
  await passflow.logOut();
  // Logout successful - session callback will handle UI update
});

// Check for redirect tokens on page load
window.addEventListener("load", () => {
  const tokens = passflow.handleTokensRedirect();
  if (tokens) {
    console.log("Authenticated via redirect");
  }
});
```

### Authentication with Passkeys

```javascript
import { Passflow } from "passflow-js";

// Initialize Passflow
const passflow = new Passflow({
  appId: "your-app-id",
});

// Set up session management
passflow.session({
  createSession: (tokens) => {
    console.log("Session created", tokens);
  },
  expiredSession: () => {
    console.log("Session expired");
  },
  doRefresh: true,
});

// Handle passkey registration
document
  .getElementById("register-passkey-button")
  .addEventListener("click", async () => {
    try {
      const email = document.getElementById("email").value;

      await passflow.passkeyRegister({
        passkey_display_name: "My Passkey",
        passkey_username: email,
        relying_party_id: window.location.hostname,
        redirect_url: window.location.origin,
        scopes: ["id", "offline", "tenant", "email"],
      });

      alert("Passkey registered successfully!");
    } catch (error) {
      alert(`Passkey registration failed: ${error.message}`);
      console.error(error);
    }
  });

// Handle passkey authentication
document
  .getElementById("login-with-passkey-button")
  .addEventListener("click", async () => {
    try {
      await passflow.passkeyAuthenticate({
        relying_party_id: window.location.hostname,
      });

      alert("Authenticated with passkey successfully!");
    } catch (error) {
      alert(`Passkey authentication failed: ${error.message}`);
      console.error(error);
    }
  });
```

### Multi-tenant Application

```javascript
import { Passflow, PassflowEvent } from "passflow-js";

// Initialize Passflow
const passflow = new Passflow({
  appId: "your-app-id",
});

// Track current tenant
let currentTenant = null;

// Set up session management
passflow.session({
  createSession: (tokens) => {
    const parsedTokens = passflow.getParsedTokenCache();
    if (parsedTokens?.access_token?.membership?.tenants?.length > 0) {
      currentTenant = parsedTokens.access_token.membership.tenants[0];
      updateTenantUI();
    } else {
      showCreateTenantUI();
    }
  },
  expiredSession: () => {
    currentTenant = null;
    showLoginUI();
  },
  doRefresh: true,
});

// Subscribe to auth events
passflow.subscribe({
  onAuthChange: (eventType) => {
    if (
      eventType === PassflowEvent.SignIn ||
      eventType === PassflowEvent.Register
    ) {
      const parsedTokens = passflow.getParsedTokenCache();
      if (parsedTokens?.access_token?.membership?.tenants?.length > 0) {
        currentTenant = parsedTokens.access_token.membership.tenants[0];
        updateTenantUI();
      } else {
        showCreateTenantUI();
      }
    }
  },
});

// Create tenant function
async function createNewTenant() {
  const tenantName = document.getElementById("tenant-name").value;
  try {
    await passflow.createTenant(tenantName, true);
    const parsedTokens = passflow.getParsedTokenCache();
    currentTenant = parsedTokens.access_token.membership.tenants[0];
    updateTenantUI();
  } catch (error) {
    console.error("Failed to create tenant", error);
    alert(`Failed to create tenant: ${error.message}`);
  }
}

// Invite user function
async function inviteUser() {
  const email = document.getElementById("invite-email").value;
  try {
    const response = await passflow.requestInviteLink({
      email,
      tenant: currentTenant.tenant.id,
      send_to_email: true,
    });
    alert(`Invitation sent to ${email}`);
    console.log("Invitation link:", response.link);
  } catch (error) {
    console.error("Failed to invite user", error);
    alert(`Failed to invite user: ${error.message}`);
  }
}

// UI update functions
function updateTenantUI() {
  document.getElementById("tenant-name-display").textContent =
    currentTenant.tenant.name;
  document.getElementById("tenant-id-display").textContent =
    currentTenant.tenant.id;
  document.getElementById("tenant-section").style.display = "block";
  document.getElementById("create-tenant-section").style.display = "none";
}

function showCreateTenantUI() {
  document.getElementById("tenant-section").style.display = "none";
  document.getElementById("create-tenant-section").style.display = "block";
}

function showLoginUI() {
  document.getElementById("tenant-section").style.display = "none";
  document.getElementById("create-tenant-section").style.display = "none";
  document.getElementById("login-section").style.display = "block";
}

// Event listeners
document
  .getElementById("create-tenant-form")
  .addEventListener("submit", (e) => {
    e.preventDefault();
    createNewTenant();
  });

document.getElementById("invite-form").addEventListener("submit", (e) => {
  e.preventDefault();
  inviteUser();
});
```
