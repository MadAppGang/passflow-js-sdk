import {
  TwoFactorConfirmResponse,
  TwoFactorDisableResponse,
  TwoFactorRecoveryResponse,
  TwoFactorRegenerateResponse,
  TwoFactorSetupMagicLinkSession,
  TwoFactorSetupMagicLinkValidationResponse,
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
  tfaToken?: string;
  timestamp: number;
  expiresAt: number;
}

/** Payload for TwoFactorRequired event */
interface TwoFactorRequiredPayload {
  email: string;
  challengeId: string;
  tfaToken: string;
}

/** Error with optional id field */
interface ErrorWithId extends Error {
  id?: string;
}

/**
 * Service for managing Two-Factor Authentication
 */
export class TwoFactorService {
  private partialAuthState?: PartialAuthState;
  private readonly PARTIAL_AUTH_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes timeout
  private readonly SESSION_STORAGE_KEY = 'passflow_2fa_challenge';

  // TOTP digit configuration (6 or 8 digits)
  // This field is used throughout the service for TOTP validation and API responses
  private totpDigits: 6 | 8 = 6; // Default to 6 for backward compatibility

  // Magic link session storage (in-memory only for security - no persistence)
  private magicLinkSession?: TwoFactorSetupMagicLinkSession;

  constructor(
    private twoFactorApi: TwoFactorApiClient,
    private subscribeStore: PassflowStore,
  ) {
    // Listen for TwoFactorRequired event from AuthService
    // Create a subscriber that handles the TwoFactorRequired event
    const eventSubscriber = {
      onAuthChange: (event: PassflowEvent, payload?: unknown) => {
        if (event === PassflowEvent.TwoFactorRequired) {
          const tfPayload = payload as TwoFactorRequiredPayload;
          this.setPartialAuthState(tfPayload.email, tfPayload.challengeId, tfPayload.tfaToken);
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
    const errorWithId = error as ErrorWithId;
    const errorPayload = {
      message: error instanceof Error ? error.message : `${context} failed`,
      originalError: error,
      code: errorWithId?.id || undefined,
    };
    this.subscribeStore.notify(PassflowEvent.Error, errorPayload);
    throw error;
  }

  /**
   * Get 2FA enrollment status for current user
   */
  async getStatus(): Promise<TwoFactorStatusResponse> {
    try {
      const response = await this.twoFactorApi.getStatus();
      // Store totp_digits from backend response
      if (response.totp_digits) {
        this.totpDigits = response.totp_digits;
      }
      return response;
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
      // Store totp_digits from backend response
      if (response.totp_digits) {
        this.totpDigits = response.totp_digits;
      }
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
    // Validate TOTP code format with configured digits
    if (!isValidTOTPCode(code, this.totpDigits)) {
      throw new Error(`Invalid TOTP code format. Code must be exactly ${this.totpDigits} digits.`);
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
    // Validate TOTP code format with configured digits
    if (!isValidTOTPCode(code, this.totpDigits)) {
      throw new Error(`Invalid TOTP code format. Code must be exactly ${this.totpDigits} digits.`);
    }

    // Attempt to recover partial auth state from sessionStorage
    this.recoverPartialAuthState();

    if (!this.isVerificationRequired()) {
      throw new Error('2FA verification expired or not required. User must sign in first.');
    }

    // Validate that tfa_token exists (now required)
    if (!this.partialAuthState?.tfaToken) {
      throw new Error('No TFA token found. User must sign in first.');
    }

    try {
      const response = await this.twoFactorApi.verify({
        code,
        tfa_token: this.partialAuthState.tfaToken,
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

      // Validate that tfa_token exists (now required)
      if (!this.partialAuthState?.tfaToken) {
        throw new Error('No TFA token found. User must sign in first.');
      }

      const response = await this.twoFactorApi.useRecoveryCode({
        recovery_code: normalizedCode,
        tfa_token: this.partialAuthState.tfaToken,
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
    // Validate TOTP code format with configured digits
    if (!isValidTOTPCode(code, this.totpDigits)) {
      throw new Error(`Invalid TOTP code format. Code must be exactly ${this.totpDigits} digits.`);
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
    // Validate TOTP code format with configured digits
    if (!isValidTOTPCode(code, this.totpDigits)) {
      throw new Error(`Invalid TOTP code format. Code must be exactly ${this.totpDigits} digits.`);
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
    // Attempt to recover partial auth state from sessionStorage
    // This is needed when the Passflow instance is recreated (e.g., due to React state changes)
    // but the 2FA challenge data was stored by a previous instance
    this.recoverPartialAuthState();

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
  setPartialAuthState(email?: string, challengeId?: string, tfaToken?: string): void {
    this.partialAuthState = {
      email,
      challengeId,
      tfaToken,
      timestamp: Date.now(),
      expiresAt: Date.now() + this.PARTIAL_AUTH_TIMEOUT_MS,
    };

    // Persist to sessionStorage for page refresh recovery
    // SECURITY NOTE: Storing tfaToken in sessionStorage is acceptable because:
    // 1. The tfaToken is a JWT with short expiration (5 minutes)
    // 2. It cannot be used alone - requires a valid TOTP code (6-digit from authenticator app)
    // 3. It expires after 5 minutes (PARTIAL_AUTH_TIMEOUT_MS and JWT expiration)
    // 4. It's session-scoped (cleared on tab close)
    // 5. Storing it enables better UX (page refresh recovery during 2FA flow)
    // The security boundary is the TOTP code, not the TFA token.
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

  // ============================================
  // Magic Link 2FA Setup Methods
  // ============================================

  /**
   * Validate magic link token for 2FA setup
   *
   * This method validates an admin-generated magic link token and
   * creates a scoped session (scope: "2fa_setup") that can ONLY be
   * used for completing 2FA setup operations.
   *
   * Session characteristics:
   * - Stored in memory only (no persistence across page reloads)
   * - Short-lived (typically 1 hour expiration)
   * - Cannot be refreshed
   * - Cannot be promoted to full authentication
   * - Only valid for 2FA setup endpoints
   *
   * @param token - Magic link token from URL parameter
   * @returns Validation response with session details
   */
  async validateTwoFactorSetupMagicLink(token: string): Promise<TwoFactorSetupMagicLinkValidationResponse> {
    // Call backend validation endpoint (API client handles all error cases)
    const response = await this.twoFactorApi.validateTwoFactorSetupMagicLink(token);

    // If validation successful, store session in memory
    if (response.success && response.sessionToken && response.userId) {
      this.magicLinkSession = {
        sessionToken: response.sessionToken,
        userId: response.userId,
        appId: response.appId,
        scope: '2fa_setup',
        timestamp: Date.now(),
        expiresAt: Date.now() + (response.expiresIn || 3600) * 1000,
      };

      // Emit success event
      this.subscribeStore.notify(PassflowEvent.TwoFactorSetupMagicLinkValidated, {
        userId: response.userId,
        appId: response.appId,
        expiresIn: response.expiresIn || 3600,
        sessionToken: response.sessionToken,
      });
    } else if (response.error) {
      // Emit failure event
      this.subscribeStore.notify(PassflowEvent.TwoFactorSetupMagicLinkFailed, {
        error: response.error,
      });
    }

    return response;
  }

  /**
   * Get current magic link session (if any)
   * Used by React SDK to access session token for API calls
   *
   * @returns Active magic link session or null if none/expired
   */
  getMagicLinkSession(): TwoFactorSetupMagicLinkSession | null {
    if (!this.magicLinkSession) return null;

    // Check if expired
    if (Date.now() > this.magicLinkSession.expiresAt) {
      this.clearMagicLinkSession();
      return null;
    }

    return this.magicLinkSession;
  }

  /**
   * Clear magic link session
   * Called after successful setup completion or on error
   */
  clearMagicLinkSession(): void {
    this.magicLinkSession = undefined;
  }

  /**
   * Check if magic link session is active
   * Used by React SDK to determine if form can use magic link auth
   */
  hasMagicLinkSession(): boolean {
    return this.getMagicLinkSession() !== null;
  }

  /**
   * Get the session token from magic link session (if active)
   * Used by AxiosClient for injecting auth header on 2FA setup endpoints
   */
  getMagicLinkSessionToken(): string | null {
    const session = this.getMagicLinkSession();
    return session?.sessionToken || null;
  }

  /**
   * Get configured TOTP digit count
   * Returns the number of digits (6 or 8) for TOTP codes
   * Useful for UI components that need to render the correct number of input fields
   */
  getTotpDigits(): 6 | 8 {
    return this.totpDigits;
  }
}
