/**
 * One `Error` event per failure (PFL-792, architecture §2.5 and §8).
 *
 * Kept apart from `store.ts` on purpose: unit tests automock that module, and the services must
 * still reach the real dedupe through it. This module imports nothing at runtime, so `store.ts`
 * can use it without an import cycle.
 *
 * @module error-report
 */

import type { OperationErrorPayload, PassflowEvent, PassflowStore } from './store';

/** `PassflowEvent.Error`, spelled out so this module needs no runtime import of `store.ts`. */
const ERROR_EVENT = 'error' as PassflowEvent.Error;

/**
 * Error objects already reported, per store. Keyed by the store object itself, so the dedupe also
 * holds for test doubles that implement only `notify`.
 */
const reportedErrors = new WeakMap<object, WeakSet<object>>();

/**
 * Records `error` as reported through `store`. Returns `false` when it was already recorded.
 * Primitives (and an absent error) are never recorded: they carry no identity.
 */
export const markReported = (store: object, error: unknown): boolean => {
  if ((typeof error !== 'object' && typeof error !== 'function') || error === null) return true;
  let seen = reportedErrors.get(store);
  if (!seen) {
    seen = new WeakSet();
    reportedErrors.set(store, seen);
  }
  if (seen.has(error)) return false;
  seen.add(error);
  return true;
};

/**
 * Emits `PassflowEvent.Error` once per error object per store instance.
 *
 * The innermost reporter wins: a service reports a failure with its specific `operation` and
 * rethrows; an outer wrapper that catches the same object and calls this again reports nothing.
 * An `originalError` that is not an object (or is absent) is always reported.
 *
 * @returns whether the event was emitted
 */
export const notifyError = (store: Pick<PassflowStore, 'notify'>, payload: OperationErrorPayload): boolean => {
  if (!markReported(store, payload.originalError)) return false;
  store.notify(ERROR_EVENT, payload);
  return true;
};
