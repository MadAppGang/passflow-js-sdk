# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

### Package Management
- Uses pnpm as package manager (requires pnpm@10.8.0+)
- `pnpm install` - Install dependencies

### Build and Development
- `pnpm build` - Full production build (clean + vite build + TypeScript declarations)
- `pnpm watch` - Watch mode for development
- `pnpm dev` - Development server
- `pnpm clean` - Remove build artifacts

### Testing
- `pnpm test` - Run all tests with vitest
- `pnpm test:services` - Run only service tests
- `pnpm test:coverage` - Run tests with coverage report
- `pnpm test:ui` - Run tests with vitest UI

### Code Quality
- `pnpm lint` - Check code with Biome linter
- `pnpm lint:fix` - Fix linting issues
- `pnpm format` - Format code with Biome
- `pnpm lint:format:fix` - Fix linting and formatting
- `pnpm ci` - Run CI checks (lint + format check)

## Architecture Overview

### Core Structure
The SDK is organized around a main `Passflow` class that orchestrates multiple specialized services:

- **Main Entry Point**: `lib/passflow.ts` - Main SDK class that coordinates all functionality
- **API Layer**: `lib/api/` - HTTP client wrappers for different API endpoints (auth, user, tenant, etc.)
- **Services Layer**: `lib/services/` - Business logic services that handle specific domains
- **Storage**: `lib/storage-manager/` - Token and data persistence
- **Event System**: `lib/store.ts` - Event subscription and notification system

### Key Services
- `AuthService` - Authentication flows, session management
- `UserService` - User operations, passkey management
- `TenantService` - Multi-tenant operations
- `InvitationService` - User invitation workflows
- `TokenCacheService` - Token caching, refresh, and validation
- `DeviceService` - Device identification for security

### Token Management
- Tokens are cached in memory via `TokenCacheService`
- Persistent storage handled by `StorageManager` (localStorage)
- Automatic refresh when tokens expire (if configured)
- JWT parsing and validation in `token-service/`

### Event System
- Centralized event notifications via `PassflowStore`
- Events: signin, signout, register, error, refresh
- Subscribers can listen to all or specific events

### Configuration
- Main config passed to `Passflow` constructor
- Default scopes: `['id', 'offline', 'tenant', 'email', 'oidc', 'openid', 'access:tenant:all']`
- Supports custom Passflow server URLs (defaults to passflow.cloud)

### Testing Strategy
- Unit tests for services in `tests/services/`
- Integration tests in `tests/integration/`
- Uses vitest with jsdom environment
- Coverage focused on services layer
- Fake storage implementation for testing

### Build System
- TypeScript compilation with declaration files
- Vite for bundling (both ESM and CJS outputs)
- Biome for linting and formatting
- Supports both import and require usage