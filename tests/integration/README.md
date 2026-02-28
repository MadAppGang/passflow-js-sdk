# Passflow API Integration Tests

This directory contains integration tests for the Passflow API, focusing on the admin API functionality.

## Setup

The integration tests require a running Passflow API instance to test against. You need to set the following environment variables before running the tests:

- `PASSFLOW_URL`: The URL of the Passflow API to test against (e.g., `http://localhost:8080`)
- `ADMIN_EMAIL`: The email address for admin login
- `ADMIN_PHONE`: The phone number for admin login (optional)
- `ADMIN_PASSWORD`: The password for admin login

## Running the Tests

To run the integration tests, use the following command:

```bash
# Set environment variables (replace with your actual values)
export PASSFLOW_URL=http://localhost:8080
export ADMIN_EMAIL=admin@example.com
export ADMIN_PASSWORD=your_password
export ADMIN_PHONE=123456789  # Optional

# Run the integration tests
npm test tests/integration
```

Or with pnpm:

```bash
# Set environment variables (replace with your actual values)
export PASSFLOW_URL=http://localhost:8080
export ADMIN_EMAIL=admin@example.com
export ADMIN_PASSWORD=your_password
export ADMIN_PHONE=123456789  # Optional

# Run the integration tests
pnpm test tests/integration
```

## Test Coverage

The integration tests cover the following functionality:

1. **Admin Authentication**
   - Insecure login with email and password to get an admin access token

2. **App Management**
   - Listing all apps
   - Creating a new app
   - Retrieving app details

## Test Files

- `setup.ts`: Contains utility functions and configuration for the integration tests
- `admin.test.ts`: Tests for the admin API functionality

## Adding New Tests

When adding new tests, follow these guidelines:

1. Use the utility functions in `setup.ts` for common operations
2. Check for required environment variables before running tests
3. Add proper error handling and assertions
4. Document the purpose and requirements of the tests

## Troubleshooting

If the tests fail, check the following:

1. Ensure the Passflow API is running and accessible at the URL specified in `PASSFLOW_URL`
2. Verify that the admin credentials are correct
3. Check the console output for specific error messages
4. Ensure you have the correct permissions to perform the operations being tested