# User Authentication Service Library Documentation

## Table of Contents

1.  [Introduction](#introduction)
2.  [File Structure](#file-structure)
3.  [Core Concepts](#core-concepts)
    - [Tokens](#tokens)
    - [Storage Management](#storage-management)
    - [Event System](#event-system)
    - [Service Orchestration](#service-orchestration)
4.  [API Reference](#api-reference)
    - [Types](#types)
      - [`Tokens`](#tokens-type)
      - [`ParsedTokens`](#parsedtokens-type)
      - [`SessionParams`](#sessionparams-type)
      - [`Storage` (Interface)](#storage-interface)
      - [`StorageManagerParams`](#storagemanagerparams-interface)
      - [`TokenType`](#tokentype-enum)
      - [`PassflowEvent` (Enum)](#passflowevent-enum)
      - [`PassflowSubscriber` (Interface)](#passflowsubscriber-interface)
    - [Classes](#classes)
      - [`StorageManager`](#storagemanager-class)
      - [`Token`](#token-class)
      - [`TokenService`](#tokenservice-class)
      - [`AuthService`](#authservice-class)
5.  [Usage Example](#usage-example)
6.  [Event Handling](#event-handling)

---

## 1. Introduction

This library provides a comprehensive solution for managing user authentication within client-side JavaScript/TypeScript applications. It handles token storage, parsing (including basic JWT validation), session lifecycle management (checking validity, refreshing), and provides an event system to react to authentication state changes.

The library is designed to be modular, separating concerns into distinct components: storage management, token handling, and the main authentication service logic. This promotes maintainability and allows for easier testing and potential replacement of individual parts (like the storage mechanism).

---

## 2. File Structure

Based on the comments in the provided code, the library appears to be organized into the following files:

- `./lib/types/index.ts`: Contains shared type definitions (`Tokens`, `ParsedTokens`, `SessionParams`) used across different modules of the library.
- `./lib/storage-manager/index.ts`: Defines the `Storage` interface (the contract for how storage should work), `StorageManagerParams` interface (for configuration), and the `StorageManager` class itself, responsible for the actual interaction with browser storage.
- `./lib/token-service/index.ts`: Defines the `TokenType` enum (to differentiate token types), the `Token` class (representing a single parsed token with utility methods), and the `TokenService` class (for parsing raw tokens and performing validation).
- `./lib/auth-service/index.ts`: Defines the `PassflowEvent` enum (listing possible authentication states/events), `PassflowSubscriber` interface (for objects that want to listen to events), and the main `AuthService` class which orchestrates the overall authentication flow and event dispatching.

---

## 3. Core Concepts

### Tokens

- **Raw Tokens (`Tokens` type):** This is the basic structure `{ access_token: string; id_token?: string; refresh_token?: string; scopes?: string[] }` representing the tokens exactly as they might be received from your authentication server's API endpoint.
- **Parsed Tokens (`Token` class, `ParsedTokens` type):** Raw token strings are transformed into instances of the `Token` class. If a token string follows the JSON Web Token (JWT) format, this class automatically decodes the header and payload sections, making claims easily accessible. The `ParsedTokens` type mirrors the `Tokens` type but holds `Token` objects instead of strings.
- **Validation:** The library primarily focuses on _expiration_ validation using the standard `exp` claim found in JWTs. The `Token.isExpired()` method checks if the current time is past the time specified in the `exp` claim. It doesn't perform signature verification, which should typically happen server-side or using a more specialized JWT library if needed client-side.

### Storage Management

- The `StorageManager` class acts as an intermediary between the authentication logic and the browser's actual storage mechanism (like `localStorage` or `sessionStorage`).
- **Abstraction:** It allows the library (and your application) to interact with storage using a consistent API (`setItem`, `getItem`, `removeItem`) without needing to know the specifics of the underlying storage.
- **Configuration:** You can provide your own storage implementation (e.g., for React Native, or an in-memory store for testing) and add a prefix to all storage keys to avoid collisions with other data stored on the same domain.

### Event System

- The `AuthService` uses a standard **publish-subscribe (pub/sub)** pattern. It maintains a list of subscribers interested in authentication state changes.
- **Events (`PassflowEvent`):** When significant actions occur (like login, logout, session check, token refresh attempt, session expiration), the `AuthService` "publishes" or "notifies" subscribers by calling their `onAuthChange` method, passing the specific `PassflowEvent` type.
- **Subscribers (`PassflowSubscriber`):** Any part of your application (like UI components, data fetching services) can implement the `PassflowSubscriber` interface and register itself with the `AuthService` to receive these notifications and react accordingly. This decouples the components from the `AuthService`.

### Service Orchestration

- The `AuthService` is the central coordinator. It utilizes the `StorageManager` to save and load token data and the `TokenService` to interpret and validate these tokens.
- It manages the overall **session lifecycle**:
  - `checkSession()`: Verifies if valid tokens exist in storage. If the access token is expired but a valid refresh token exists (and `doRefresh` is enabled), it attempts to refresh the tokens (_Note: the refresh API call itself is marked `TODO`_). It then updates its internal state and notifies subscribers about the outcome (active session, no session, expired session).
  - `setTokens()`: Called after a successful login to store the new tokens.
  - `logout()`: Clears the session data and notifies subscribers.

---

## 4. API Reference

### Types

#### `Tokens` (Type)

Defines the structure for raw authentication tokens, typically received from an API.

```typescript
// Defined in: ./lib/types/index.ts
export type Tokens = {
  access_token: string;
  id_token?: string; // Optional ID token
  refresh_token?: string; // Optional refresh token
  scopes?: string[]; // Optional list of granted scopes
};
ParsedTokens (Type)Defines the structure holding parsed Token objects.// Defined in: ./lib/types/index.ts
import { Token } from '../token-service';

export type ParsedTokens = {
  access_token: Token;
  id_token?: Token;
  refresh_token?: Token;
  scopes?: string[];
};
SessionParams (Type)Configuration parameters passed to the AuthService constructor.// Defined in: ./lib/types/index.ts
export type SessionParams = {
  // Callback function invoked when a session is successfully created or tokens are updated (e.g., after login or refresh).
  createSession?: (tokens?: Tokens) => void;
  // Callback function invoked when the session expires and cannot be refreshed, or immediately upon calling logout.
  expiredSession?: () => void;
  // Flag to enable (true) or disable (false) automatic token refresh using the refresh token. Defaults to true.
  doRefresh?: boolean;
};
Storage (Interface)Defines the required methods for any storage implementation used by StorageManager.// Defined in: ./lib/storage-manager/index.ts
export type Storage = {
  setItem: (key: string, value: string) => void;
  getItem: (key: string) => string | null;
  removeItem: (key: string) => void;
};
StorageManagerParams (Interface)Configuration parameters for the StorageManager constructor.// Defined in: ./lib/storage-manager/index.ts
export interface StorageManagerParams {
  // The storage implementation conforming to the `Storage` interface. Defaults to browser `localStorage`.
  storage?: Storage;
  // An optional string prefix added to all keys used in storage to prevent naming conflicts.
  prefix?: string;
}
TokenType (Enum)Enumerates the different types of tokens managed, primarily used as keys for storage.// Defined in: ./lib/token-service/index.ts
export enum TokenType {
  ACCESS = 'access_token',
  ID = 'id_token',
  REFRESH = 'refresh_token',
}
PassflowEvent (Enum)Enumerates the distinct types of authentication events emitted by AuthService.// Defined in: ./lib/auth-service/index.ts
enum PassflowEvent {
  CHECKING_SESSION = 'CHECKING_SESSION', // Fired when checkSession() begins its process.
  NO_SESSION = 'NO_SESSION', // Fired by checkSession() if no valid tokens are found initially and refresh isn't possible/successful.
  SESSION_ACTIVE = 'SESSION_ACTIVE', // Fired by checkSession() when a valid, non-expired access token is confirmed (either initially or after refresh).
  LOGOUT = 'LOGOUT', // Fired after logout() successfully clears tokens and state.
  LOGIN = 'LOGIN', // Fired after setTokens() successfully stores and parses new tokens.
  SESSION_EXPIRED = 'SESSION_EXPIRED', // Fired by checkSession() when the access token is expired and refresh fails or is disabled.
  REFRESHING_SESSION = 'REFRESHING_SESSION', // Fired just before the (TODO) refresh API call is attempted.
  ERROR = 'ERROR', // Fired if an error occurs during the refresh process. The error object might be passed as the 'source'.
}
PassflowSubscriber (Interface)Defines the contract for objects that wish to subscribe to AuthService events.// Defined in: ./lib/auth-service/index.ts
interface PassflowSubscriber {
  /**
   * Method called by AuthService when a subscribed event occurs.
   * @param event The type of event that occurred (PassflowEvent).
   * @param source Typically the AuthService instance itself, or potentially an error object for ERROR events.
   */
  onAuthChange(event: PassflowEvent, source: unknown): void;
}
ClassesStorageManager ClassFile: ./lib/storage-manager/index.tsPurpose: Handles the low-level details of reading from and writing to the chosen storage mechanism (localStorage, sessionStorage, or custom). Ensures consistent key naming, optionally applying a prefix.Key Methods:constructor(params?: StorageManagerParams): Sets up the storage mechanism (defaulting to localStorage) and the key prefix.setTokens(tokens: Tokens): Persists the provided raw token strings and scopes.getTokens(): Tokens: Retrieves all stored raw token strings and scopes.getToken(type: TokenType): string | null: Retrieves a specific raw token string by its type.removeTokens(): Deletes all authentication-related tokens and scopes from storage.Includes methods for getting/setting/removing deviceId, invitationToken, and previousRedirectUrl using the same storage mechanism and prefix.Token ClassFile: ./lib/token-service/index.tsPurpose: Represents an individual token. If the token is a JWT, it decodes the header and payload for easy access. Provides utility methods like checking expiration.Key Methods:constructor(value: string): Takes the raw token string. Attempts to decode it as a JWT.isExpired(threshold?: number): boolean: Checks the exp claim against the current time. Returns true if expired, not a JWT, or no exp claim exists. The optional threshold (in seconds) allows checking if the token will expire within that future timeframe.getClaim(claim: string): any: Accesses a specific claim from the decoded JWT payload (e.g., getClaim('sub'), getClaim('email')). Returns undefined if the claim doesn't exist or the token isn't a valid JWT payload.Properties:value: string: The original, raw token string.header: any: The decoded JWT header object, or undefined.payload: any: The decoded JWT payload object, or undefined.TokenService ClassFile: ./lib/token-service/index.tsPurpose: Acts as a service layer for token operations. Uses StorageManager to get raw tokens and then uses the Token class to parse and validate them.Key Methods:constructor(storageManager: StorageManager): Requires an instance of StorageManager.parseToken(tokenValue: string): Token: Utility to create a Token instance from a raw string.parseTokens(tokens?: Tokens): ParsedTokens | null: Converts a raw Tokens object into a ParsedTokens object containing Token instances.getParsedTokens(): ParsedTokens | null: The main method to get the current tokens from storage and return them as parsed Token objects.validateToken(token?: Token): boolean: Simple validation: checks if the token object exists and is not expired according to token.isExpired().isAccessTokenExpired(): boolean: Convenience method to check the expiration of the currently stored access token.isRefreshTokenExpired(): boolean: Convenience method to check the expiration of the currently stored refresh token.getClaim(claim: string, tokenType: TokenType = TokenType.ACCESS): any: Retrieves a specific claim from either the access token (default) or the ID token stored in storage.AuthService ClassFile: ./lib/auth-service/index.tsPurpose: The primary interface for the application to interact with the authentication system. It coordinates StorageManager and TokenService, manages the session state machine, handles the refresh logic (partially implemented), and notifies subscribers of state changes.Key Methods:constructor(storageManager, tokenService, params?: SessionParams): Initializes the service with its dependencies and configuration (callbacks, refresh behavior).setTokens(tokens?: Tokens): Call this after a successful login. It stores the tokens via StorageManager, updates its internal state with the parsed tokens from TokenService, notifies subscribers with the LOGIN event, and triggers the createSession callback.checkSession(): Promise<void>: Call this on application startup. It checks storage for tokens, validates them (especially the access token). If the access token is expired but a valid refresh token exists and doRefresh is true, it attempts the refresh flow (notifies REFRESHING_SESSION, calls the TODO refresh logic, then potentially calls setTokens on success or notifies SESSION_EXPIRED on failure). Finally, it notifies SESSION_ACTIVE, NO_SESSION, or SESSION_EXPIRED based on the outcome.logout(): Promise<void>: Call this to end the user session. It removes tokens via StorageManager, clears internal state, notifies subscribers with the LOGOUT event, and triggers the expiredSession callback.getTokens(): ParsedTokens | null: Returns the current parsed tokens held in the service's state (useful for direct access if needed, but often claims are retrieved via TokenService.getClaim).isLoggedIn(): boolean: A simple check based on the internal state – returns true if a valid (parsed and non-expired) access token is currently held by the service.subscribe(subscriber: PassflowSubscriber, events?: PassflowEvent[]): Registers a listener for authentication events. Can specify particular events or listen to all.unsubscribe(subscriber: PassflowSubscriber, events?: PassflowEvent[]): Removes a listener.Internal State: Holds the current ParsedTokens (this.tokens) and the session validity status (this.loggedIn).Refresh Logic: The refreshSession method outlines the steps but crucially marks the actual API call to exchange the refresh token for new tokens as // TODO: Implement refresh token logic. This part needs to be filled in with your specific API endpoint call.5. Usage ExampleThis example demonstrates initializing the services, subscribing to events for UI updates, checking the session on load, and handling login/logout triggers.import {
  StorageManager,
  TokenService,
  AuthService,
  PassflowEvent,
  PassflowSubscriber,
  Tokens // Import Tokens type if needed for callbacks or login function signature
} from './your-auth-library'; // Adjust import path as necessary

// --- 1. Initialization ---

// Use default localStorage with a specific prefix for keys
const storageManager = new StorageManager({ prefix: 'myWebAppAuth' });
const tokenService = new TokenService(storageManager);

// Instantiate the main service
const authService = new AuthService(storageManager, tokenService, {
  // Optional: Called on successful login or token refresh
  createSession: (rawTokens?: Tokens) => {
    console.log('AuthService: Session is active.', rawTokens ? 'Tokens provided.' : 'Using existing tokens.');
    // Maybe trigger fetching user-specific data here
    // fetchUserData(rawTokens.access_token);
  },
  // Optional: Called on logout or when session expires and cannot be refreshed
  expiredSession: () => {
    console.log('AuthService: Session ended or expired.');
    // Redirect to login page or clear user-specific state
    // clearUserData();
    // window.location.href = '/login';
  },
  // Explicitly enable auto-refresh (this is the default)
  doRefresh: true,
});

// --- 2. Event Subscription (Example: Simple UI Updater) ---

class SimpleAuthUI implements PassflowSubscriber {
  private statusEl: HTMLElement | null;
  private loginBtn: HTMLElement | null;
  private logoutBtn: HTMLElement | null;
  private userInfoEl: HTMLElement | null;

  constructor() {
    // Assume these elements exist in your HTML
    this.statusEl = document.getElementById('auth-status-display');
    this.loginBtn = document.getElementById('login-button');
    this.logoutBtn = document.getElementById('logout-button');
    this.userInfoEl = document.getElementById('user-info');
  }

  updateStatus(text: string) {
    if (this.statusEl) this.statusEl.textContent = text;
    console.log(`UI Update: ${text}`); // Log UI changes
  }

  showLoggedInState(isLoggedIn: boolean) {
     if (this.loginBtn) this.loginBtn.style.display = isLoggedIn ? 'none' : 'inline-block';
     if (this.logoutBtn) this.logoutBtn.style.display = isLoggedIn ? 'inline-block' : 'none';
     if (this.userInfoEl) this.userInfoEl.style.display = isLoggedIn ? 'block' : 'none';
  }

  displayUserInfo() {
    if (this.userInfoEl && authService.isLoggedIn()) {
       // Use TokenService to get claims from the currently stored token
       const email = tokenService.getClaim('email');
       const name = tokenService.getClaim('name') ?? 'User';
       this.userInfoEl.textContent = `Welcome, ${name} (${email ?? 'no email'})`;
    } else if (this.userInfoEl) {
       this.userInfoEl.textContent = '';
    }
  }

  onAuthChange(event: PassflowEvent, source: unknown) {
    console.log(`Auth Event Received by UI: ${event}`);
    switch (event) {
      case PassflowEvent.CHECKING_SESSION:
        this.updateStatus('Verifying session...');
        this.showLoggedInState(false); // Assume logged out until confirmed
        break;
      case PassflowEvent.REFRESHING_SESSION:
        this.updateStatus('Refreshing session...');
        break;
      case PassflowEvent.SESSION_ACTIVE:
      case PassflowEvent.LOGIN:
        this.updateStatus('Logged In');
        this.showLoggedInState(true);
        this.displayUserInfo(); // Display user info based on token claims
        break;
      case PassflowEvent.NO_SESSION:
      case PassflowEvent.LOGOUT:
      case PassflowEvent.SESSION_EXPIRED:
        this.updateStatus('Logged Out');
        this.showLoggedInState(false);
         this.displayUserInfo(); // Clear user info
        break;
      case PassflowEvent.ERROR:
         this.updateStatus('Authentication Error!');
         console.error('Auth Error Source:', source);
         this.showLoggedInState(false); // Treat error as logged out
         this.displayUserInfo();
         break;
    }
  }
}

// Instantiate and subscribe the UI updater
const authUI = new SimpleAuthUI();
authService.subscribe(authUI);

// --- 3. Application Startup Logic ---

document.addEventListener('DOMContentLoaded', () => {
  console.log('App Loaded. Checking session...');
  authService.checkSession()
    .then(() => {
      console.log('Initial session check finished.');
      // Initial UI state is set by the event handler, but you could
      // force an update here if needed based on authService.isLoggedIn()
    })
    .catch(error => {
      // This catch might be redundant if the ERROR event is handled,
      // but useful for logging unexpected issues in checkSession itself.
      console.error('Critical error during initial session check:', error);
      authUI.updateStatus('Error checking session.');
      authUI.showLoggedInState(false);
    });

  // --- 4. Hook up Login/Logout Triggers ---

  // Example: Assuming you have a function that calls your backend API for login
  async function performApiLogin(username, password): Promise<Tokens | null> {
      // Replace with your actual API call
      console.log(`Simulating API login for ${username}...`);
      await new Promise(res => setTimeout(res, 500)); // Simulate network delay
      // On successful API login, return the tokens
      // This is dummy data - replace with your actual API response structure
      const dummyTokens: Tokens = {
          access_token: `jwt.accesstoken.${Date.now()}.payload`,
          refresh_token: `jwt.refreshtoken.${Date.now()}.payload`,
          id_token: `jwt.idtoken.${Date.now()}.payload`,
          scopes: ["read", "write"]
      };
      return dummyTokens;
      // On failure, return null or throw an error
      // return null;
  }

  // Attach to login button click
  const loginButton = document.getElementById('login-button');
  loginButton?.addEventListener('click', async () => {
      authUI.updateStatus('Logging in...');
      try {
          // Get credentials from form inputs (not shown)
          const username = 'testuser';
          const password = 'password';
          const tokens = await performApiLogin(username, password);
          if (tokens) {
              authService.setTokens(tokens); // This triggers LOGIN event and createSession callback
          } else {
              authUI.updateStatus('Login failed (API).');
          }
      } catch (error) {
          console.error('Login API call failed:', error);
          authUI.updateStatus('Login failed (Error).');
      }
  });

  // Attach to logout button click
  const logoutButton = document.getElementById('logout-button');
  logoutButton?.addEventListener('click', () => {
      authService.logout(); // This triggers LOGOUT event and expiredSession callback
  });

}); // End DOMContentLoaded

// --- 5. Cleanup (Example) ---
// If your application framework has component lifecycle hooks (e.g., React useEffect cleanup, Angular OnDestroy)
// remember to unsubscribe to prevent memory leaks:
// window.addEventListener('beforeunload', () => {
//   authService.unsubscribe(authUI);
// });

6. Event Handling Deep DiveThe event system is core to making the library flexible and allowing different parts of your application to react to authentication changes without being tightly coupled.How it Works: AuthService maintains a Map where keys are subscriber objects and values are either null (subscribe to all events) or a Set of specific PassflowEvents to listen for. When an event occurs (e.g., setTokens calls notify(this, PassflowEvent.LOGIN)), the notify method iterates through the map. For each subscriber, it checks if the subscriber wants all events (null) or if the specific event type is in their Set. If the condition matches, it calls the subscriber's onAuthChange method.Subscribing:authService.subscribe(myComponent): myComponent will receive all PassflowEvent notifications.authService.subscribe(myLogger, [PassflowEvent.LOGIN, PassflowEvent.LOGOUT, PassflowEvent.ERROR]): myLogger will only receive notifications for login, logout, and error events.Unsubscribing: It's crucial to call `authService.unsubscribe(
```
