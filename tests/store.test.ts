/**
 * PassflowStore error reporting (PFL-792, architecture §2.5, §8): one `Error` per failure.
 */
import { describe, expect, test, vi } from 'vitest';
import { markReported, notifyError } from '../lib/error-report';
import { type ErrorPayload, PassflowEvent, PassflowStore } from '../lib/store';

const subscribe = (store: PassflowStore) => {
  const onAuthChange = vi.fn();
  store.subscribe({ onAuthChange });
  const errors = () =>
    onAuthChange.mock.calls.filter(([event]) => event === PassflowEvent.Error).map(([, p]) => p as ErrorPayload);
  return { onAuthChange, errors };
};

describe('notifyError', () => {
  test('reports an error object once; the innermost reporter keeps its operation', () => {
    const store = new PassflowStore();
    const { errors } = subscribe(store);
    const error = new Error('boom');

    expect(notifyError(store, { message: 'boom', originalError: error, operation: '2fa.status' })).toBe(true);
    expect(notifyError(store, { message: 'boom', originalError: error, operation: 'log-out' })).toBe(false);

    expect(errors()).toEqual([{ message: 'boom', originalError: error, operation: '2fa.status' }]);
  });

  test('different error objects are each reported', () => {
    const store = new PassflowStore();
    const { errors } = subscribe(store);

    notifyError(store, { message: 'a', originalError: new Error('a'), operation: 'sign-in' });
    notifyError(store, { message: 'b', originalError: new Error('b'), operation: 'sign-in' });

    expect(errors().map((p) => p.message)).toEqual(['a', 'b']);
  });

  test.each([
    ['absent', undefined],
    ['a string', 'boom'],
    ['a number', 42],
    ['null', null],
  ])('an originalError that is %s is never deduplicated', (_label, originalError) => {
    const store = new PassflowStore();
    const { errors } = subscribe(store);

    notifyError(store, { message: 'x', originalError, operation: 'reset' });
    notifyError(store, { message: 'x', originalError, operation: 'reset' });

    expect(errors()).toHaveLength(2);
  });

  test('the dedupe is per store instance', () => {
    const first = new PassflowStore();
    const second = new PassflowStore();
    const a = subscribe(first);
    const b = subscribe(second);
    const error = new Error('shared');

    notifyError(first, { message: 'shared', originalError: error, operation: 'tokens.get' });
    notifyError(second, { message: 'shared', originalError: error, operation: 'tokens.get' });

    expect(a.errors()).toHaveLength(1);
    expect(b.errors()).toHaveLength(1);
  });

  test('a direct notify(Error) counts as the inner report, so a later notifyError stays silent', () => {
    const store = new PassflowStore();
    const { errors } = subscribe(store);
    const error = new Error('inner');

    store.notify(PassflowEvent.Error, { message: 'inner', originalError: error });
    notifyError(store, { message: 'inner', originalError: error, operation: 'tokens.get' });

    expect(errors()).toEqual([{ message: 'inner', originalError: error }]);
  });

  test('notify of another event does not mark its payload', () => {
    const store = new PassflowStore();
    const { errors } = subscribe(store);
    const error = new Error('x');

    // A non-Error event whose payload happens to hold the object must not suppress a later report.
    store.notify(PassflowEvent.SignOut, { originalError: error } as never);
    notifyError(store, { message: 'x', originalError: error, operation: 'log-out' });

    expect(errors()).toHaveLength(1);
  });

  test('works with a store double that implements only notify', () => {
    const notify = vi.fn();
    const store = { notify };
    const error = new Error('x');

    notifyError(store, { message: 'x', originalError: error, operation: 'sign-up' });
    notifyError(store, { message: 'x', originalError: error, operation: 'sign-up' });

    expect(notify).toHaveBeenCalledTimes(1);
    expect(notify).toHaveBeenCalledWith(PassflowEvent.Error, { message: 'x', originalError: error, operation: 'sign-up' });
  });

  test('PassflowStore.notifyError delegates to the same dedupe', () => {
    const store = new PassflowStore();
    const { errors } = subscribe(store);
    const error = new Error('x');

    expect(store.notifyError({ message: 'x', originalError: error, operation: 'settings.app' })).toBe(true);
    expect(notifyError(store, { message: 'x', originalError: error, operation: 'settings.all' })).toBe(false);

    expect(errors()).toEqual([{ message: 'x', originalError: error, operation: 'settings.app' }]);
  });

  test('markReported reports true once per object and always for primitives', () => {
    const owner = {};
    const error = new Error('x');
    expect(markReported(owner, error)).toBe(true);
    expect(markReported(owner, error)).toBe(false);
    expect(markReported(owner, 'x')).toBe(true);
    expect(markReported(owner, 'x')).toBe(true);
  });
});

describe('PassflowEvent refresh members', () => {
  test('RefreshFailing and RefreshRecovered have their wire names', () => {
    expect(PassflowEvent.RefreshFailing).toBe('refresh:failing');
    expect(PassflowEvent.RefreshRecovered).toBe('refresh:recovered');
  });
});
