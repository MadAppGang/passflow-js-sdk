/**
 * Passflow Store
 *
 * Event subscription system using the Observer pattern.
 * Manages authentication event notifications to subscribers.
 * Supports filtered subscriptions for specific event types.
 *
 * @module store
 */

import type { TwoFactorMethod } from './api/model';
import { markReported, notifyError } from './error-report';
import type { EventOrigin, RefreshErrorInfo, RefreshTrigger, SessionExpiredReason } from './refresh/types';
import { ParsedTokens, Tokens } from './types';

/**
 * Passflow event types
 */
export enum PassflowEvent {
  SignIn = 'signin',
  SignInStart = 'signin:start',
  Register = 'register',
  RegisterStart = 'register:start',
  /** A sign-up, sign-in or password change is waiting for the email to be proven (no session yet). */
  EmailVerificationRequired = 'email-verification:required',
  SignOut = 'signout',
  SessionRestored = 'session:restored',
  SessionExpired = 'session:expired',
  Error = 'error',
  Refresh = 'refresh',
  RefreshStart = 'refresh:start',
  TokenCacheExpired = 'token-cache-expired',
  TwoFactorRequired = '2fa:required',
  TwoFactorSetupStarted = '2fa:setup_started',
  TwoFactorEnabled = '2fa:enabled',
  TwoFactorDisabled = '2fa:disabled',
  TwoFactorVerified = '2fa:verified',
  TwoFactorRecoveryUsed = '2fa:recovery_used',
  TwoFactorRecoveryCodesLow = '2fa:recovery_low',
  TwoFactorRecoveryCodesExhausted = '2fa:recovery_exhausted',
  TwoFactorSetupMagicLinkValidated = '2fa:magic_link_validated',
  TwoFactorSetupMagicLinkFailed = '2fa:magic_link_failed',
  TwoFactorChallengeReceived = 'two_factor_challenge_received',
  TwoFactorMethodSwitched = 'two_factor_method_switched',
  TwoFactorDeviceTrusted = 'two_factor_device_trusted',
  /** Token refresh entered a transient-failure episode (once per episode, per tab). */
  RefreshFailing = 'refresh:failing',
  /** The transient-failure episode ended with a successful refresh or adoption. */
  RefreshRecovered = 'refresh:recovered',
}

/**
 * The SDK operation that failed (`ErrorPayload.operation`). The SDK sets it on every `Error` it
 * emits, so a subscriber can tell a failed sign-in from a failed refresh without parsing messages.
 */
export type PassflowOperation =
  // sign-in and session
  | 'sign-in'
  | 'sign-up'
  | 'passwordless.start'
  | 'passwordless.complete'
  | 'passwordless.wait'
  | 'passwordless.approval'
  | 'password-reset.send'
  | 'password-reset.complete'
  | 'email-verification.complete'
  | 'passkey.register'
  | 'passkey.authenticate'
  | 'federated.popup'
  | 'federated.redirect'
  | 'auth-redirect.url'
  | 'auth-redirect'
  | 'auth.is-authenticated'
  | 'session.check'
  | 'tokens.get'
  | 'tokens.load'
  | 'tokens.from-url'
  | 'refresh'
  | 'upgrade.commit'
  | 'log-out'
  | 'reset'
  // settings, passkeys, tenants, invitations
  | 'settings.app'
  | 'settings.all'
  | 'settings.password-policy'
  | 'settings.passkey'
  | 'passkey.list'
  | 'passkey.rename'
  | 'passkey.delete'
  | 'passkey.add'
  | 'tenant.create'
  | 'invitation.join'
  | 'invitation.request-link'
  | 'invitation.list'
  | 'invitation.delete'
  | 'invitation.resend'
  | 'invitation.get-link'
  // two-factor
  | '2fa.status'
  | '2fa.setup.begin'
  | '2fa.setup.confirm'
  | '2fa.enrollment.read'
  | '2fa.enrollment.setup-link'
  | '2fa.verify'
  | '2fa.recovery.use'
  | '2fa.disable'
  | '2fa.recovery.regenerate'
  | '2fa.methods.available'
  | '2fa.methods.registered'
  | '2fa.method.setup.start'
  | '2fa.method.setup.complete'
  | '2fa.method.remove'
  | '2fa.challenge.request'
  | '2fa.challenge.verify'
  | '2fa.method.switch'
  | '2fa.trusted-devices.list'
  | '2fa.trusted-devices.revoke';

/**
 * Error payload interface for structured error information
 */
export interface ErrorPayload {
  message: string;
  code?: string | number;
  details?: unknown;
  originalError?: unknown;
  /** The operation that failed. Always set by the SDK. */
  operation?: PassflowOperation;
  /** For operation `refresh` | `upgrade.commit`: what asked for the refresh. */
  source?: RefreshTrigger;
  /** For operation `refresh` | `upgrade.commit`: how the failure was classified and what follows. */
  refresh?: RefreshErrorInfo;
}

/** An `Error` payload as the SDK reports it: `operation` is required. */
export type OperationErrorPayload = ErrorPayload & { operation: PassflowOperation };

/** Which call produced an `EmailVerificationRequired` event. */
export type PassflowEmailVerificationOperation = 'sign-up' | 'sign-in' | 'reset-password';

/**
 * Event-specific payload types
 */
export type PassflowEventPayload = {
  [PassflowEvent.SignIn]: {
    tokens?: Tokens;
    parsedTokens?: ParsedTokens;
    /** `'other-tab'` only when an ended tab revives on a new session found in storage. Absent on this tab's own sign-in. */
    origin?: EventOrigin;
    /** Set only when a federated redirect landed here and this instance exchanged its code. */
    source?: 'federated-landing';
  };
  [PassflowEvent.SignInStart]: { email?: string; provider?: string };
  [PassflowEvent.Register]: { tokens?: Tokens; parsedTokens?: ParsedTokens };
  [PassflowEvent.RegisterStart]: { email?: string };
  [PassflowEvent.EmailVerificationRequired]: {
    /** The address the code or link went to, when the SDK knows it. */
    email?: string;
    /** Present when a code was emailed; absent when a link was emailed instead. */
    challengeId?: string;
    operation: PassflowEmailVerificationOperation;
  };
  [PassflowEvent.SignOut]: {
    /** `sub` of the session that ended, when known. */
    userId?: string;
    /** Always set by the SDK. `'other-tab'`: another tab signed out, or shared storage was emptied. */
    origin?: EventOrigin;
  };
  [PassflowEvent.SessionRestored]: { id: string; email?: string; username?: string; [key: string]: unknown };
  [PassflowEvent.SessionExpired]: {
    reason: SessionExpiredReason;
    /** Always set by the SDK. */
    origin?: EventOrigin;
  };
  [PassflowEvent.Error]: ErrorPayload;
  [PassflowEvent.Refresh]: {
    tokens?: Tokens;
    parsedTokens?: ParsedTokens;
    /**
     * Always set by the SDK. `'refresh'`: this tab's request; `'upgrade'`: this tab's step-up
     * commit; `'adopted'`: tokens this tab did not request (another tab's, or found in storage).
     */
    source?: 'refresh' | 'upgrade' | 'adopted';
  };
  [PassflowEvent.RefreshStart]: { tokenId?: string };
  [PassflowEvent.TokenCacheExpired]: { isExpired: boolean };
  [PassflowEvent.TwoFactorRequired]: {
    email: string;
    challengeId: string;
    tfaToken: string;
  };
  [PassflowEvent.TwoFactorSetupStarted]: { secret: string; method?: TwoFactorMethod };
  [PassflowEvent.TwoFactorEnabled]: { recoveryCodes: string[]; clearRecoveryCodes: () => void };
  [PassflowEvent.TwoFactorDisabled]: Record<string, never>;
  [PassflowEvent.TwoFactorVerified]: { tokens?: Tokens };
  [PassflowEvent.TwoFactorRecoveryUsed]: { tokens?: Tokens; remainingCodes: number };
  [PassflowEvent.TwoFactorRecoveryCodesLow]: { tokens?: Tokens; remainingCodes: number };
  [PassflowEvent.TwoFactorRecoveryCodesExhausted]: { tokens?: Tokens };
  [PassflowEvent.TwoFactorSetupMagicLinkValidated]: {
    userId: string;
    appId?: string | null;
    expiresIn: number;
    sessionToken: string;
  };
  [PassflowEvent.TwoFactorSetupMagicLinkFailed]: {
    error: {
      code: 'INVALID_TOKEN' | 'EXPIRED_TOKEN' | 'REVOKED_TOKEN' | 'ALREADY_USED' | 'RATE_LIMITED' | 'SERVER_ERROR';
      message: string;
      retryAfter?: number;
    };
  };
  [PassflowEvent.TwoFactorChallengeReceived]: {
    challengeId: string;
    method: TwoFactorMethod;
    alternativeMethods: TwoFactorMethod[];
  };
  [PassflowEvent.TwoFactorMethodSwitched]: {
    challengeId: string;
    method: TwoFactorMethod;
    alternativeMethods: TwoFactorMethod[];
  };
  [PassflowEvent.TwoFactorDeviceTrusted]: Record<string, never>;
  [PassflowEvent.RefreshFailing]: {
    /** Epoch ms of the episode's first transient failure. */
    since: number;
    /** Epoch ms of the shared pending retry, when known. */
    nextRetryAt?: number;
    /** `'this-tab'` when this tab's own request failed. */
    origin: EventOrigin;
  };
  [PassflowEvent.RefreshRecovered]: {
    /** Same value as the `RefreshFailing` that opened the episode. */
    since: number;
    /** `'this-tab'`: own request succeeded; `'other-tab'`: adopted another tab's tokens. */
    origin: EventOrigin;
  };
};

/**
 * Passflow subscriber interface
 */
export interface PassflowSubscriber {
  onAuthChange<E extends PassflowEvent>(eventType: E, payload?: PassflowEventPayload[E]): void;
}

/**
 * Store for managing Passflow event subscriptions
 */
export class PassflowStore {
  private subscribers: Map<PassflowSubscriber, Set<PassflowEvent> | null> = new Map();

  /**
   * Subscribe to authentication events
   * @param subscriber The subscriber to register
   * @param events Optional specific events to subscribe to
   */
  subscribe(subscriber: PassflowSubscriber, events?: PassflowEvent[]): void {
    if (events?.length) {
      const eventSet = new Set<PassflowEvent>(events);
      this.subscribers.set(subscriber, eventSet);
    } else {
      this.subscribers.set(subscriber, null);
    }
  }

  /**
   * Unsubscribe from authentication events
   * @param subscriber The subscriber to unregister
   * @param events Optional specific events to unsubscribe from
   */
  unsubscribe(subscriber: PassflowSubscriber, events?: PassflowEvent[]): void {
    if (!events?.length) {
      this.subscribers.delete(subscriber);
      return;
    }

    const subscribedEvents = this.subscribers.get(subscriber);
    if (!subscribedEvents) {
      return;
    }

    events.forEach((event) => subscribedEvents.delete(event));
    if (subscribedEvents.size === 0) {
      this.subscribers.delete(subscriber);
    }
  }

  /**
   * Notify subscribers of an event
   * @param eventType The type of event that occurred
   * @param payload Event-specific payload data
   */
  notify<E extends PassflowEvent>(eventType: E, payload?: PassflowEventPayload[E]): void {
    // A direct Error notify still delivers, but its error object counts as reported, so an outer
    // `notifyError` for the same object stays silent (innermost reporter wins).
    if (eventType === PassflowEvent.Error) markReported(this, (payload as ErrorPayload | undefined)?.originalError);
    this.subscribers.forEach((events, subscriber) => {
      if (!events || events.has(eventType)) {
        subscriber.onAuthChange?.(eventType, payload);
      }
    });
  }

  /**
   * Notify subscribers of an error, at most once per error object (`notifyError` in `error-report.ts`).
   * @returns whether the event was emitted
   */
  notifyError(payload: OperationErrorPayload): boolean {
    return notifyError(this, payload);
  }
}
