/**
 * Passflow event types
 */
export enum PassflowEvent {
  SignIn = 'signin',
  Register = 'register',
  SignOut = 'signout',
  Error = 'error',
  Refresh = 'refresh',
}

/**
 * Passflow subscriber interface
 */
export interface PassflowSubscriber {
  onAuthChange: (eventType: PassflowEvent, source?: unknown) => void;
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
   * @param source The source of the event
   * @param eventType The type of event that occurred
   */
  notify(source: unknown, eventType: PassflowEvent): void {
    this.subscribers.forEach((events, subscriber) => {
      if (!events || events.has(eventType)) {
        subscriber.onAuthChange(eventType, source);
      }
    });
  }
}
