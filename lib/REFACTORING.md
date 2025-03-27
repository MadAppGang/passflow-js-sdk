# Passflow SDK Refactoring

## Overview

This document describes how the Passflow SDK was refactored to improve maintainability and extensibility by breaking down the monolithic `Passflow` class into smaller, more focused service classes. The refactoring follows the principles of single responsibility and separation of concerns.

## Refactoring Approach

1. **Service Extraction**: Related functionality from the large `Passflow` class was extracted into domain-specific service classes:
   - `AuthService`: Handles authentication-related functionality
   - `UserService`: Manages user-related operations
   - `TenantService`: Handles tenant operations
   - `InvitationService`: Manages invitation-related functionality

2. **Dependency Injection**: Services are injected with their required dependencies, making them more testable and decoupled.

3. **Facade Pattern**: The main `Passflow` class now acts as a facade, delegating calls to the appropriate services while maintaining the same public API.

## Folder Structure

```
lib/
├── api/                   # API client interfaces
├── services/              # Domain-specific services
│   ├── auth-service.ts    # Authentication service
│   ├── invitation-service.ts  # Invitation management service
│   ├── tenant-service.ts  # Tenant operations service
│   ├── user-service.ts    # User operations service
│   └── index.ts           # Service exports
├── store.ts               # Event store
├── passflow.ts            # Main facade class
├── index.ts               # Main entry point
└── REFACTORING.md         # This documentation
```

Tests for the services can be found in:

```
tests/
└── services/              # Service tests
    ├── auth-service.test.ts
    ├── invitation-service.test.ts
    ├── tenant-service.test.ts
    └── user-service.test.ts
```

## Benefits

1. **Improved Maintainability**: Smaller, focused classes are easier to understand and modify.
2. **Better Testability**: Services can be tested in isolation with mocked dependencies.
3. **Enhanced Extensibility**: New functionality can be added to the appropriate service without modifying the entire codebase.
4. **Code Reusability**: Services can be reused across different parts of the application.
5. **Clearer Responsibilities**: Each service has a well-defined responsibility.

## Implementation Status

1. ✅ Create the new service classes
   - ✅ AuthService
   - ✅ UserService
   - ✅ TenantService
   - ✅ InvitationService

2. ✅ Refactor the `Passflow` class to use these services
   - ✅ Replace direct API calls with service method calls
   - ✅ Maintain the same public API

3. ✅ Update dependencies and imports
   - ✅ Create improved store implementation
   - ✅ Update token service integration

4. ✅ Integration and Testing
   - ✅ Fully replace old implementation with refactored code
   - ✅ Add unit tests for services

## Running Tests

To run the service tests:

```bash
# Run all tests
npm run test

# Run only service tests
npm run test:services

# Run tests with coverage report
npm run test:coverage

# Run tests with UI
npm run test:ui
```

## Implementation Details

### Service Initialization

Services are initialized with their dependencies in the Passflow constructor:

```typescript
// Initialize domain services with dependencies
this.authService = new AuthService(
  this.authApi,
  this.deviceService,
  this.storageManager,
  this.tokenService,
  this.subscribeStore,
  this.scopes,
  this.createTenantForNewUser,
  this.origin,
  this.url,
  { 
    createSession: this.createSessionCallback, 
    expiredSession: this.expiredSessionCallback 
  },
  this.appId
);
```

### Method Delegation

Methods delegate to the appropriate service while managing shared state:

```typescript
signIn(payload: PassflowSignInPayload): Promise<PassflowAuthorizationResponse> {
  return this.authService.signIn(payload)
    .then(response => {
      this.setTokensCache(response);
      return response;
    });
}
```

## Test Coverage

The test suite includes comprehensive tests for each service:

- **AuthService**: Tests for authentication, token management, and session handling
- **UserService**: Tests for user passkey management
- **TenantService**: Tests for tenant creation and invitation joining
- **InvitationService**: Tests for invitation creation, listing, and deletion

Each test file mocks the necessary dependencies to isolate the service being tested. Tests use Vitest, which provides a modern and fast testing experience with a familiar API.

## Usage Example

```typescript
import { Passflow, PassflowEvent } from '@passflow/sdk';

// Initialize SDK
const passflow = new Passflow({
  url: 'https://api.passflow.example',
  appId: 'my-app-id',
});

// Use the SDK
await passflow.signIn({
  email: 'user@example.com',
  password: 'securePassword123',
});
```

The refactoring is now complete and fully integrated into the main codebase. The public API remains unchanged, ensuring backward compatibility while providing a more maintainable and extensible internal structure. 