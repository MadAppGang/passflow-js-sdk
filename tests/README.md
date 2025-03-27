# Passflow SDK Tests

This directory contains tests for the refactored Passflow SDK. The test suite is designed to test each service in isolation, ensuring that the decoupled architecture works correctly.

## Test Structure

```
tests/
├── services/              # Service tests
│   ├── auth-service.test.ts      # Authentication service tests
│   ├── invitation-service.test.ts # Invitation service tests
│   ├── tenant-service.test.ts    # Tenant service tests
│   └── user-service.test.ts      # User service tests
├── setup.ts               # Vitest setup and mocks
└── README.md             # This file
```

## Testing Patterns

The test suite follows these patterns:

1. **Mock Dependencies**: Each service is tested in isolation by mocking its dependencies.
2. **Test Public API**: Focus on testing the public API of each service, not internal methods.
3. **Verify Behavior**: Ensure each service correctly interacts with its dependencies.
4. **Complete Coverage**: Test all edge cases and error handling, not just happy paths.

## Running Tests

To run the tests:

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

## Mock Implementation

The test suite uses Vitest's mocking capabilities to mock dependencies. For example:

```typescript
// Mock dependencies
vi.mock('../../lib/api/auth');
vi.mock('../../lib/device-service');
vi.mock('../../lib/storage-manager');
vi.mock('../../lib/token-service');
vi.mock('../../lib/store');
```

Common browser APIs (like `window.location`, `localStorage`, and `URLSearchParams`) are mocked in the `setup.ts` file to provide a consistent testing environment.

## Test Examples

Each test file includes examples of:

1. **Setup**: Creating mock dependencies and initializing the service
2. **Parameter Testing**: Ensuring correct parameters are passed to dependencies
3. **Return Value Testing**: Verifying the service returns correct values
4. **Error Handling**: Testing how the service handles errors
5. **State Management**: Checking that the service updates state correctly

## Adding New Tests

When adding new services or modifying existing ones:

1. Create a new test file in the appropriate directory
2. Mock all dependencies
3. Test all public methods
4. Verify correct interaction with dependencies
5. Test error handling and edge cases 