// AoothEvent store event

import { Aooth } from './aooth';

export enum AoothEvent {
  SignIn = 'aooth_event_signin',
  SignOut = 'aooth_event_signout',
  Register = 'aooth_event_register',
  Refresh = 'aooth_event_refresh',
  Error = 'aooth_event_error',
}

export interface AoothSubscriber {
  aoothEvent(a: Aooth, t: AoothEvent): void;
}

type subscribersMap = {
  [key in AoothEvent]?: AoothSubscriber[];
};

// AoothStore - event store to manage subscribers
export class AoothStore {
  private allEvents = [AoothEvent.SignIn, AoothEvent.SignOut, AoothEvent.Register, AoothEvent.Error];
  private subscribers: subscribersMap = {};
  constructor() {}

  subscribe(s: AoothSubscriber, t?: AoothEvent[]) {
    const types = !t || !t.length ? this.allEvents : t;
    types.forEach((tt) => (this.subscribers[tt] = [...(this.subscribers[tt] ?? []), s]));
  }

  unsubscribe(s: AoothSubscriber, t?: AoothEvent[]) {
    const types = !t || !t.length ? this.allEvents : t;
    types.forEach((tt) => (this.subscribers[tt] = this.subscribers[tt]?.filter((ss) => ss !== s)));
  }

  notify(a: Aooth, t: AoothEvent) {
    this.subscribers[t]?.forEach((s) => s.aoothEvent(a, t));
  }
}
