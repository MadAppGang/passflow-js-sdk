/**
 * One `fetch` patch point, many middlewares.
 *
 * This module exists because of a bug, not a requirement (architecture §4.3,
 * reaffirmed by §13.5's "what survives supersession"). Two features that each do
 * `globalThis.fetch = wrapper` in an effect and restore their captured original
 * in cleanup compose as `A(B(native))`, and whichever cleanup runs first assigns
 * a fetch that predates the other patch. React guarantees no cleanup ordering
 * across sibling effects, nor across a parent/child boundary under Strict Mode
 * double-invocation, so one of the two interceptors silently disappears —
 * non-deterministically, and only in composed mounts.
 *
 * The fix is to make the patch a shared resource with reference-counted
 * ownership: the registry installs exactly one wrapper on the first
 * registration, composes the registered middlewares by priority on every call,
 * and removes the wrapper on the last removal. **Teardown is the registry's
 * responsibility, not any caller's** — no caller captures or restores
 * `globalThis.fetch` itself, which is precisely the ownership mistake being
 * retired.
 *
 * Composition is a Decorator chain, not a Chain of Responsibility: every
 * middleware MUST delegate to `next`. A link that may legitimately swallow a
 * request would mean a stranger's `fetch` call can vanish inside our wrapper, so
 * non-delegation is detected per invocation and reported as a named error rather
 * than left to surface as a hung promise (§9.4/R7).
 *
 * SSR safety is a stated non-functional requirement and is structural here:
 * `globalThis` is read only inside `install()` and inside the state reader,
 * never at module scope. Importing this module on a server touches no global and
 * throws nothing; `registerFetchMiddleware` returns a no-op unregister when
 * there is no `fetch` to patch (§9.4/R6).
 *
 * The module is generic. It knows nothing about upgrades, OIDC or Passflow
 * endpoints — only about ordering, ownership and delegation.
 */

/** A `fetch`-shaped function: the platform `fetch`, or the next link in the chain. */
export type FetchLike = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

/**
 * A registered interception layer.
 *
 * It receives the next link explicitly rather than closing over a captured
 * global, which is what lets the chain be rebuilt per call and reordered by
 * priority without any middleware knowing its neighbours.
 */
export type FetchMiddleware = (next: FetchLike, input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

export type RegisterOptions = {
  /** Lower runs OUTER (further from the network). Ties break by registration order. */
  priority: number;
  /** Diagnostic label, surfaced in the error thrown when a middleware fails to delegate. */
  name: string;
};

/**
 * Outer layer. The OIDC AuthFlow interceptor must observe the response the
 * caller will actually receive — including a replayed one — because it follows a
 * `redirect_url` out of that body. Placed inside the upgrade middleware it would
 * inspect the raw 401, do nothing, and the page would then navigate on a
 * response the caller never saw.
 */
export const FETCH_PRIORITY_OIDC = 10;

/**
 * Inner layer. The upgrade middleware must see the raw 401 and replace it before
 * anything upstream forms an opinion about it.
 */
export const FETCH_PRIORITY_UPGRADE = 20;

/** Thrown when a registered middleware resolves without ever calling `next`. */
export class FetchMiddlewareContractError extends Error {
  /** The `name` the offending middleware was registered under. */
  readonly middlewareName: string;

  constructor(middlewareName: string) {
    super(
      `Passflow fetch middleware '${middlewareName}' resolved without calling next(). ` +
        'Every registered middleware must delegate exactly once; swallowing a request would ' +
        "drop a caller's fetch inside the Passflow wrapper.",
    );
    this.name = 'FetchMiddlewareContractError';
    this.middlewareName = middlewareName;
  }
}

type RegistryEntry = {
  readonly middleware: FetchMiddleware;
  readonly name: string;
  readonly priority: number;
  /** Registration sequence, used only as a stable tie-break within one priority. */
  readonly seq: number;
};

/** Registered entries, unsorted. Sorting happens per call so order is never stale. */
let entries: RegistryEntry[] = [];

/** Monotonic registration counter. Never reset while entries are live. */
let nextSeq = 0;

/** True once we have assigned our wrapper and have not restored over it. */
let installed = false;

/** The `fetch` captured at install time — the innermost link of every chain. */
let capturedFetch: FetchLike | undefined;

/** The exact function we assigned to `globalThis.fetch`, used for identity checks. */
let ourWrapper: FetchLike | undefined;

/** Outer-first: ascending priority, then registration order. */
const byPriority = (a: RegistryEntry, b: RegistryEntry): number => a.priority - b.priority || a.seq - b.seq;

const globalScope = (): typeof globalThis | undefined => (typeof globalThis === 'undefined' ? undefined : globalThis);

/**
 * Runs the chain from `index` outward-in, ending at the captured fetch.
 *
 * `chain` is a snapshot taken when the call started: a registration or removal
 * that lands mid-flight changes the next call, never this one. Each frame
 * records whether its middleware delegated, so a non-delegating middleware is
 * named in the error rather than leaving the caller to guess which layer ate the
 * request.
 */
const dispatch = async (
  chain: readonly RegistryEntry[],
  index: number,
  input: RequestInfo | URL,
  init?: RequestInit,
): Promise<Response> => {
  if (index >= chain.length) {
    const target = capturedFetch;
    if (!target) {
      // Unreachable while installed: the capture and the assignment happen
      // together in install(). Explicit rather than a TypeError on undefined.
      throw new Error('Passflow fetch registry: no captured fetch to delegate to.');
    }
    return target(input, init);
  }

  const entry = chain[index];
  if (!entry) {
    return dispatch(chain, chain.length, input, init);
  }

  let delegated = false;
  const next: FetchLike = (nextInput, nextInit) => {
    delegated = true;
    return dispatch(chain, index + 1, nextInput, nextInit);
  };

  const response = await entry.middleware(next, input, init);
  if (!delegated) {
    throw new FetchMiddlewareContractError(entry.name);
  }
  return response;
};

/**
 * Assigns our single wrapper, capturing the current `fetch` as the chain's
 * innermost link.
 *
 * Returns false when there is nothing to patch — no global scope, or no callable
 * `fetch` — which is the SSR path. Nothing throws there: an import-time failure
 * in a server bundle is the only outcome that actually matters.
 */
const install = (): boolean => {
  const scope = globalScope();
  if (!scope || typeof scope.fetch !== 'function') {
    return false;
  }

  const native = scope.fetch.bind(scope) as FetchLike;
  const wrapper: FetchLike = (input, init) => dispatch([...entries].sort(byPriority), 0, input, init);

  capturedFetch = native;
  ourWrapper = wrapper;
  scope.fetch = wrapper as typeof scope.fetch;
  installed = true;
  return true;
};

/**
 * Removes our wrapper — but only if it is still the value we assigned.
 *
 * If a third party patched on top of us, their wrapper very likely captured ours
 * as its own next link. Restoring the captured fetch would clobber a stranger's
 * patch; so we leave ours in place and let it degrade to a pass-through, which
 * an empty middleware list already is. This is the pre-existing
 * unconditional-restore hazard in `passflow-provider.tsx` fixed by construction
 * (§9.4/R5).
 *
 * `installed` deliberately stays true in that case. Clearing it would let a
 * later registration install a SECOND wrapper while the first is still reachable
 * through the stranger's chain — the nesting collision this registry exists to
 * prevent.
 */
const uninstall = (): void => {
  const scope = globalScope();
  if (!scope || !ourWrapper) {
    return;
  }
  if (scope.fetch !== (ourWrapper as unknown as typeof scope.fetch)) {
    return;
  }

  if (capturedFetch) {
    scope.fetch = capturedFetch as typeof scope.fetch;
  }
  installed = false;
  ourWrapper = undefined;
  capturedFetch = undefined;
};

/**
 * Registers a middleware, installing the one global patch on the FIRST
 * registration, and returns an idempotent unregister that removes the patch on
 * the LAST removal.
 *
 * Safe in both directions and under Strict Mode's double-invoke: ownership is by
 * reference count over entry identity, so register/unregister/register of the
 * same middleware, and removals in any order relative to other registrations,
 * all converge. The returned function is bound to this one registration — a
 * second call does nothing, and registering the same middleware twice yields two
 * independent entries and two independent unregisters (§9.4/R8).
 */
export const registerFetchMiddleware = (middleware: FetchMiddleware, opts: RegisterOptions): (() => void) => {
  if (!installed && !install()) {
    // SSR, or a runtime with no fetch: nothing is patched and nothing is queued.
    // A no-op unregister keeps the caller's cleanup path identical either way.
    return () => {
      /* nothing was registered, so there is nothing to remove */
    };
  }

  const entry: RegistryEntry = {
    middleware,
    name: opts.name,
    priority: opts.priority,
    seq: nextSeq++,
  };
  entries.push(entry);

  let removed = false;
  return () => {
    if (removed) {
      return;
    }
    removed = true;
    entries = entries.filter((candidate) => candidate !== entry);
    if (entries.length === 0) {
      uninstall();
    }
  };
};

/**
 * Test and diagnostic read of the registry.
 *
 * `names` is in execution order, outermost first. `foreignPatch` is computed
 * live rather than remembered, so it reports a stranger's patch as soon as it
 * lands, not only once a teardown has declined to restore over it.
 */
export const fetchRegistryState = (): { installed: boolean; names: string[]; foreignPatch: boolean } => {
  const scope = globalScope();
  return {
    installed,
    names: [...entries].sort(byPriority).map((entry) => entry.name),
    foreignPatch: installed && !!scope && !!ourWrapper && scope.fetch !== (ourWrapper as unknown as typeof scope.fetch),
  };
};
