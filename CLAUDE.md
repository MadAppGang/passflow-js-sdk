# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

### Package Management
- pnpm 12, pinned by `packageManager`; dependency age policy in `pnpm-workspace.yaml` (see CONTRIBUTING.md)
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
- JWT parsing and validation in `token-service/`
- Every refresh goes through ONE refresh controller per `Passflow` instance (`lib/refresh/`, created
  by `AuthService` as `authService.refresh`): `refreshToken()`, `getTokens(true)`,
  `getTokensWithRefresh()`, the axios pre-request refresh (`AxiosClient.setRefreshHandler`) and the
  upgrade commit. Nothing else may call `/auth/refresh`.
  - `controller.ts` state machine (single flight, joiners, retry schedule, strikes, blocked wait);
    `fence.ts` every storage read/write of the refresh path (compare-and-set save, forward-only
    adoption by refresh JWT `sub`/`sid`/`iat`); `coordinator.ts` Web Lock `passflow-refresh` +
    BroadcastChannel `passflow-auth` (or local); `classify.ts` error id first, status fallback;
    `resolve.ts` picks `refreshCoordination` (`'web-locks'` default, `'none'`, custom).
  - Failures: transient (network, 429, 5xx) keeps tokens and retries 1/3/10/30 s then every 60 s
    (+ `floor(step × 0.2 × random)`, ≥ Retry-After); auth ids strike, `refreshStrikes` (3) ends the
    session; `error.token.blocked` never signs out (20 s successor wait, then this tab only).
  - Events: `Refresh.source`, `RefreshFailing`/`RefreshRecovered` once per episode, one `Error`
    per failure (dedupe in `lib/error-report.ts`, `operation` always set), one `SignOut`.
  - Contract and exact schedule: `docs/token-refresh.md`. Real-SDK multi-tab tests run N `Passflow`
    instances over the fakes in `tests/refresh/fakes.ts` via `tests/refresh/sdk-tabs.ts`.
- Wording for new tokens in code, tests and docs: "issue", "issued" or "new token pair" only (a
  release check greps for the alternative).

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
- TypeScript declarations are emitted by `tsc` to `dist/.tsc` and bundled by rolldown-plugin-dts into `dist/index.d.ts` + `dist/index.d.cts` (`rolldown.dts.config.mjs`); `dist/.tsc` is removed after bundling
- Vite for bundling (both ESM and CJS outputs)
- Biome for linting and formatting
- Supports both import and require usage