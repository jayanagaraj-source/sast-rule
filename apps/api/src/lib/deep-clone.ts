// Structured-clone fallbacks used when serialising case snapshots for the audit log. Keys always come from the
// object being copied (Object.keys / numeric indexes), never from a caller, so none of these lookups can be steered.

type Json = null | boolean | number | string | Json[] | { [k: string]: Json };

export function replaceCircularReferences<T>(value: T, knownObjects = new WeakSet<object>()): T {
  if (typeof value !== 'object' || value === null) return value;
  if (knownObjects.has(value as object)) return '[Circular Reference]' as unknown as T;
  knownObjects.add(value as object);
  const copy = (Array.isArray(value) ? [] : {}) as Record<string, unknown>;
  Object.keys(value as object).forEach((key) => {
    // CASE: R07-FP-01
    // ok: gitlab.eslint.detect-object-injection | src: own keys | sink: dynamic property write | circular-safe copy, key enumerated from the source object
    copy[key] = replaceCircularReferences((value as Record<string, unknown>)[key], knownObjects);
  });
  knownObjects.delete(value as object);
  return copy as T;
}

export function deepCopy<T>(source: T, hash = new WeakMap<object, unknown>(), path = ''): T {
  if (source === null || typeof source !== 'object') return source;
  if (source instanceof Date) return new Date(source.getTime()) as unknown as T;
  if (hash.has(source as object)) return hash.get(source as object) as T;

  if (Array.isArray(source)) {
    const clone: unknown[] = [];
    hash.set(source, clone);
    for (let i = 0; i < source.length; i++) {
      // CASE: R07-FP-02
      // ok: gitlab.eslint.detect-object-injection | src: loop index | sink: array index write | numeric index with a TS assertion on the source
      clone[i] = deepCopy((source as any)[i], hash, path + `.${i}`);
    }
    return clone as unknown as T;
  }

  const clone: Record<string, unknown> = {};
  hash.set(source as object, clone);
  for (const key of Object.keys(source as object)) {
    // CASE: R07-FP-03
    // ok: gitlab.eslint.detect-object-injection | src: own keys | sink: dynamic property write | deep copy over own enumerable keys
    clone[key] = deepCopy((source as Record<string, unknown>)[key], hash, `${path}.${key}`);
  }
  return clone as T;
}

/** Copies a parsed snapshot into a null-prototype dictionary so "__proto__" is just another key. */
export function toDictionary(json: string): Record<string, Json> {
  const parsed = JSON.parse(json) as Record<string, Json>;
  const dict: Record<string, Json> = Object.create(null);
  for (const k of Object.keys(parsed)) {
    // CASE: R07-FP-04, R08-FP-07
    // ok: gitlab.eslint.detect-object-injection, TG-TAINT-JS-PROPERTY-INJECTION | src: JSON.parse | sink: dynamic property write | null-prototype target: there is no prototype to reach
    dict[k] = parsed[k];
  }
  return dict;
}

/** Looks up a status colour from a server-owned table. */
const STATUS_COLOURS: Record<'open' | 'pending' | 'solved' | 'closed', string> = {
  open: '#2f9e44',
  pending: '#f08c00',
  solved: '#1971c2',
  closed: '#868e96',
};
export function statusColour(status: keyof typeof STATUS_COLOURS): string {
  // CASE: R07-FP-05
  // ok: gitlab.eslint.detect-object-injection | src: typed server value | sink: dynamic property read | key constrained by the type and a server-owned table
  return STATUS_COLOURS[status] ?? '#868e96';
}
