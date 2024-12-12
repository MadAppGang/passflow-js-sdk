// PassflowEvent store event

import { Passflow } from './passflow';

export enum PassflowEvent {
  SignIn = 'passflow_event_signin',
  SignOut = 'passflow_event_signout',
  Register = 'passflow_event_register',
  Refresh = 'passflow_event_refresh',
  Error = 'passflow_event_error',
}

export interface PassflowSubscriber {
  passflowEvent(a: Passflow, t: PassflowEvent): void;
}

type subscribersMap = {
  [key in PassflowEvent]?: PassflowSubscriber[];
};

// PassflowStore - event store to manage subscribers
export class PassflowStore {
  private allEvents = [PassflowEvent.SignIn, PassflowEvent.SignOut, PassflowEvent.Register, PassflowEvent.Error];
  private subscribers: subscribersMap = {};
  constructor() {}

  subscribe(s: PassflowSubscriber, t?: PassflowEvent[]) {
    const types = !t || !t.length ? this.allEvents : t;
    types.forEach((tt) => (this.subscribers[tt] = [...(this.subscribers[tt] ?? []), s]));
  }

  unsubscribe(s: PassflowSubscriber, t?: PassflowEvent[]) {
    const types = !t || !t.length ? this.allEvents : t;
    types.forEach((tt) => (this.subscribers[tt] = this.subscribers[tt]?.filter((ss) => ss !== s)));
  }

  notify(a: Passflow, t: PassflowEvent) {
    this.subscribers[t]?.forEach((s) => s.passflowEvent(a, t));
  }
}
