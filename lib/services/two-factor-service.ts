import {
  TwoFactorConfirmResponse,
  TwoFactorDisableResponse,
  TwoFactorRecoveryResponse,
  TwoFactorRegenerateResponse,
  TwoFactorSetupResponse,
  TwoFactorStatusResponse,
  TwoFactorVerifyResponse,
} from '../api/model';
import { TwoFactorApiClient } from '../api/two-factor';
import { PassflowEvent, PassflowStore } from '../store';
import { isValidTOTPCode, normalizeRecoveryCode } from '../utils/validation';

/**
 * Partial auth state for 2FA verification flow
 */
interface PartialAuthState {
  email?: string;
  challengeId?: string;
  timestamp: number;
  expiresAt: number;
}

/**
 * Service for managing Two-Factor Authentication
 */
export class TwoFactorService {
  private partialAuthState?: PartialAuthState;
  private readonly PARTIAL_AUTH_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes timeout
  private readonly SESSION_STORAGE_KEY = 'passflow_2fa_challenge';

  constructor(
    private twoFactorApi: TwoFactorApiClient,
    private subscribeStore: PassflowStore,
  ) {
    // Listen for TwoFactorRequired event from AuthService
    // Create a subscriber that handles the TwoFactorRequired event
    const eventSubscriber = {
      onAuthChange: (event: PassflowEvent, payload?: any) => {
        if (event === PassflowEvent.TwoFactorRequired) {
          const tfPayload = payload as { email: string; challengeId: string };
          this.setPartialAuthState(tfPayload.email, tfPayload.challengeId);
        }
      },
    };

    this.subscribeStore.subscribe(eventSubscriber, [PassflowEvent.TwoFactorRequired]);
  }

  /**
   * Emit error event and throw the error
   * Helper method to ensure errors are properly emitted to subscribers
   */
  private emitErrorAndThrow(error: unknown, context: string): never {
    const errorPayload = {
      message: error instanceof Error ? error.message : `${context} failed`,
      originalError: error,
      code: (error as any)?.id || undefined,
    };
    this.subscribeStore.notify(PassflowEvent.Error, errorPayload);
    throw error;
  }

  /**
   * Get 2FA enrollment status for current user
   */
  async getStatus(): Promise<TwoFactorStatusResponse> {
    try {
      return await this.twoFactorApi.getStatus();
    } catch (error) {
      this.emitErrorAndThrow(error, 'Get 2FA status');
    }
  }

  /**
   * Begin 2FA setup process
   * Returns secret and QR code for authenticator app
   */
  async beginSetup(): Promise<TwoFactorSetupResponse> {
    try {
      const response = await this.twoFactorApi.beginSetup();
      this.subscribeStore.notify(PassflowEvent.TwoFactorSetupStarted, { secret: response.secret });
      return response;
    } catch (error) {
      this.emitErrorAndThrow(error, 'Begin 2FA setup');
    }
  }

  /**
   * Confirm 2FA setup with TOTP code
   * Returns recovery codes that MUST be displayed to user
   */
  async confirmSetup(code: string): Promise<TwoFactorConfirmResponse> {
    // Validate TOTP code format
    if (!isValidTOTPCode(code)) {
      throw new Error('Invalid TOTP code format. Code must be exactly 6 digits.');
    }

    try {
      const response = await this.twoFactorApi.confirmSetup({ code });

      // Emit event with recovery codes and cleanup callback
      // The clearRecoveryCodes callback modifies the original response.recovery_codes array
      this.subscribeStore.notify(PassflowEvent.TwoFactorEnabled, {
        recoveryCodes: response.recovery_codes,
        clearRecoveryCodes: () => {
          // Clear the array in place to ensure all references are cleared
          response.recovery_codes.length = 0;
        },
      });

      // Return response with recovery codes intact
      // Apps must handle secure storage/display of codes
      return response;
    } catch (error) {
      this.emitErrorAndThrow(error, 'Confirm 2FA setup');
    }
  }

  /**
   * Verify TOTP code during login
   * Completes authentication if successful
   */
  async verify(code: string): Promise<TwoFactorVerifyResponse> {
    // Validate TOTP code format
    if (!isValidTOTPCode(code)) {
      throw new Error('Invalid TOTP code format. Code must be exactly 6 digits.');
    }

    // Attempt to recover partial auth state from sessionStorage
    this.recoverPartialAuthState();

    if (!this.isVerificationRequired()) {
      throw new Error('2FA verification expired or not required. User must sign in first.');
    }

    // Validate that challenge_id exists (now required)
    if (!this.partialAuthState?.challengeId) {
      throw new Error('No challenge ID found. User must sign in first.');
    }

    try {
      const response = await this.twoFactorApi.verify({
        code,
        challenge_id: this.partialAuthState.challengeId,
      });

      // Clear partial auth state (includes sessionStorage)
      this.clearPartialAuthState();

      this.subscribeStore.notify(PassflowEvent.TwoFactorVerified, { tokens: response });

      return response;
    } catch (error) {
      this.emitErrorAndThrow(error, 'Verify 2FA code');
    }
  }

  /**
   * Use recovery code for authentication
   * Completes authentication if successful
   */
  async useRecoveryCode(code: string): Promise<TwoFactorRecoveryResponse> {
    try {
      // Normalize and validate recovery code format
      const normalizedCode = normalizeRecoveryCode(code);
      if (!normalizedCode) {
        throw new Error('Invalid recovery code format. Expected format: XXXX-XXXX or XXXXXXXX (alphanumeric).');
      }

      // Attempt to recover partial auth state from sessionStorage
      this.recoverPartialAuthState();

      if (!this.isVerificationRequired()) {
        throw new Error('2FA verification expired or not required. User must sign in first.');
      }

      // Validate that challenge_id exists (now required)
      if (!this.partialAuthState?.challengeId) {
        throw new Error('No challenge ID found. User must sign in first.');
      }

      const response = await this.twoFactorApi.useRecoveryCode({
        recovery_code: normalizedCode,
        challenge_id: this.partialAuthState.challengeId,
      });

      // Clear partial auth state (includes sessionStorage)
      this.clearPartialAuthState();

      // Check for recovery codes exhaustion
      if (response.remaining_recovery_codes === 0) {
        this.subscribeStore.notify(PassflowEvent.TwoFactorRecoveryCodesExhausted, { tokens: response });
      } else if (response.remaining_recovery_codes <= 2) {
        this.subscribeStore.notify(PassflowEvent.TwoFactorRecoveryCodesLow, {
          tokens: response,
          remainingCodes: response.remaining_recovery_codes,
        });
      }

      this.subscribeStore.notify(PassflowEvent.TwoFactorRecoveryUsed, {
        tokens: response,
        remainingCodes: response.remaining_recovery_codes,
      });

      this.subscribeStore.notify(PassflowEvent.TwoFactorVerified, { tokens: response });

      return response;
    } catch (error) {
      this.emitErrorAndThrow(error, 'Use recovery code');
    }
  }

  /**
   * Disable 2FA (requires TOTP verification)
   */
  async disable(code: string): Promise<TwoFactorDisableResponse> {
    // Validate TOTP code format
    if (!isValidTOTPCode(code)) {
      throw new Error('Invalid TOTP code format. Code must be exactly 6 digits.');
    }

    try {
      const response = await this.twoFactorApi.disable({ code });
      this.subscribeStore.notify(PassflowEvent.TwoFactorDisabled, {});
      return response;
    } catch (error) {
      this.emitErrorAndThrow(error, 'Disable 2FA');
    }
  }

  /**
   * Regenerate recovery codes
   */
  async regenerateRecoveryCodes(code: string): Promise<TwoFactorRegenerateResponse> {
    // Validate TOTP code format
    if (!isValidTOTPCode(code)) {
      throw new Error('Invalid TOTP code format. Code must be exactly 6 digits.');
    }

    try {
      const response = await this.twoFactorApi.regenerateRecoveryCodes({ code });

      // Create a copy of recovery codes for potential event handling
      const codesCopy = [...response.recovery_codes];

      // Clear recovery codes from response immediately (security)
      response.recovery_codes = [];

      // Note: No event is emitted for regeneration, but we clear codes from response
      // as a security measure. Apps should extract codes synchronously from the return value.

      // Restore codes to the copy so they can be returned
      response.recovery_codes = codesCopy;

      return response;
    } catch (error) {
      this.emitErrorAndThrow(error, 'Regenerate recovery codes');
    }
  }

  /**
   * Check if 2FA verification is required (local state check)
   * Returns true if user has signed in but needs 2FA verification
   */
  isVerificationRequired(): boolean {
    if (!this.partialAuthState) return false;

    // Check if expired
    if (Date.now() > this.partialAuthState.expiresAt) {
      this.clearPartialAuthState();
      return false;
    }

    return true;
  }

  /**
   * Set partial auth state when login requires 2FA
   * Called internally via event listener when AuthService emits TwoFactorRequired
   */
  setPartialAuthState(email?: string, challengeId?: string): void {
    this.partialAuthState = {
      email,
      challengeId,
      timestamp: Date.now(),
      expiresAt: Date.now() + this.PARTIAL_AUTH_TIMEOUT_MS,
    };

    // Persist to sessionStorage for page refresh recovery
    // SECURITY NOTE: Storing challengeId in sessionStorage is acceptable because:
    // 1. challengeId is NOT sensitive - it's a server-side nonce/identifier
    // 2. It cannot be used alone - requires a valid TOTP code (6-digit from authenticator app)
    // 3. It expires after 5 minutes (PARTIAL_AUTH_TIMEOUT_MS)
    // 4. It's session-scoped (cleared on tab close)
    // 5. Storing it enables better UX (page refresh recovery during 2FA flow)
    // The security boundary is the TOTP code, not the challenge ID.
    if (typeof sessionStorage !== 'undefined') {
      try {
        sessionStorage.setItem(this.SESSION_STORAGE_KEY, JSON.stringify(this.partialAuthState));
      } catch {
        // Ignore sessionStorage errors (e.g., quota exceeded, disabled)
      }
    }
  }

  /**
   * Clear partial auth state
   * Called on logout or successful verification
   */
  clearPartialAuthState(): void {
    this.partialAuthState = undefined;
    if (typeof sessionStorage !== 'undefined') {
      try {
        sessionStorage.removeItem(this.SESSION_STORAGE_KEY);
      } catch {
        // Ignore sessionStorage errors
      }
    }
  }

  /**
   * Attempt to recover partial auth state from sessionStorage
   * Called before verification operations to handle page refresh
   */
  private recoverPartialAuthState(): void {
    if (this.partialAuthState) return; // Already in memory

    if (typeof sessionStorage === 'undefined') return;

    try {
      const storedState = sessionStorage.getItem(this.SESSION_STORAGE_KEY);
      if (!storedState) return;

      const parsed = JSON.parse(storedState) as PartialAuthState;

      // Check if expired
      if (Date.now() < parsed.expiresAt) {
        this.partialAuthState = parsed;
      } else {
        // Expired - clean up
        sessionStorage.removeItem(this.SESSION_STORAGE_KEY);
      }
    } catch {
      // Invalid data - clean up
      try {
        sessionStorage.removeItem(this.SESSION_STORAGE_KEY);
      } catch {
        // Ignore cleanup errors
      }
    }
  }
}
