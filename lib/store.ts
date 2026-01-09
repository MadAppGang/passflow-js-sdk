/**
 * Passflow Store
 *
 * Event subscription system using the Observer pattern.
 * Manages authentication event notifications to subscribers.
 * Supports filtered subscriptions for specific event types.
 *
 * @module store
 */

import { ParsedTokens, Tokens } from './types';

/**
 * Passflow event types
 */
export enum PassflowEvent {
  SignIn = 'signin',
  SignInStart = 'signin:start',
  Register = 'register',
  RegisterStart = 'register:start',
  SignOut = 'signout',
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
}

/**
 * Error payload interface for structured error information
 */
export interface ErrorPayload {
  message: string;
  code?: string | number;
  details?: unknown;
  originalError?: unknown;
}

/**
 * Event-specific payload types
 */
export type PassflowEventPayload = {
  [PassflowEvent.SignIn]: { tokens?: Tokens; parsedTokens?: ParsedTokens };
  [PassflowEvent.SignInStart]: { email?: string; provider?: string };
  [PassflowEvent.Register]: { tokens?: Tokens; parsedTokens?: ParsedTokens };
  [PassflowEvent.RegisterStart]: { email?: string };
  [PassflowEvent.SignOut]: { userId?: string };
  [PassflowEvent.Error]: ErrorPayload;
  [PassflowEvent.Refresh]: { tokens?: Tokens; parsedTokens?: ParsedTokens };
  [PassflowEvent.RefreshStart]: { tokenId?: string };
  [PassflowEvent.TokenCacheExpired]: { isExpired: boolean };
  [PassflowEvent.TwoFactorRequired]: { email: string; challengeId: string };
  [PassflowEvent.TwoFactorSetupStarted]: { secret: string };
  [PassflowEvent.TwoFactorEnabled]: { recoveryCodes: string[]; clearRecoveryCodes: () => void };
  [PassflowEvent.TwoFactorDisabled]: Record<string, never>;
  [PassflowEvent.TwoFactorVerified]: { tokens?: Tokens };
  [PassflowEvent.TwoFactorRecoveryUsed]: { tokens?: Tokens; remainingCodes: number };
  [PassflowEvent.TwoFactorRecoveryCodesLow]: { tokens?: Tokens; remainingCodes: number };
  [PassflowEvent.TwoFactorRecoveryCodesExhausted]: { tokens?: Tokens };
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
    this.subscribers.forEach((events, subscriber) => {
      if (!events || events.has(eventType)) {
        subscriber.onAuthChange?.(eventType, payload);
      }
    });
  }
}
