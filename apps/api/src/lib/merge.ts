// Object merge helpers. `mergeDeep` predates the hardened `safeMergeDeep` and is still used by the custom-field
// importer (services/case-service.ts) and the admin config endpoint — see CF-2410 for the migration.

const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

export function mergeDeep(target: Record<string, any>, source: Record<string, any>): Record<string, any> {
  for (const key in source) {
    if (isPlainObject(source[key])) {
      if (!isPlainObject(target[key])) target[key] = {};
      mergeDeep(target[key], source[key]);
    } else {
      // CASE: R08-GAP-01
      // todoruleid: TG-TAINT-JS-PROTOTYPE-POLLUTION | src: caller JSON (cross-file: routes/admin) | sink: recursive write | global pollution: {"__proto__":{"x":1}} recurses into Object.prototype; the source is in another file
      target[key] = source[key];
    }
  }
  return target;
}

export function safeMergeDeep(target: Record<string, any>, source: Record<string, any>): Record<string, any> {
  for (const key of Object.keys(source)) {
    if (FORBIDDEN_KEYS.has(key)) continue;
    if (isPlainObject(source[key])) {
      if (!isPlainObject(target[key])) target[key] = Object.create(null);
      safeMergeDeep(target[key], source[key]);
    } else {
      // CASE: R08-FP-08, R07-FP-06
      // ok: TG-TAINT-JS-PROTOTYPE-POLLUTION, gitlab.eslint.detect-object-injection | src: caller JSON | sink: recursive write | forbidden keys skipped before the write
      target[key] = source[key];
    }
  }
  return target;
}

/** Sets a dotted path, e.g. setPath(settings, "sla.firstResponse.hours", 4). Callers pass request text. */
export function setPath(obj: Record<string, any>, dotted: string, value: unknown): void {
  const parts = dotted.split('.');
  let cur = obj;
  for (let i = 0; i < parts.length - 1; i++) {
    cur[parts[i]] = cur[parts[i]] ?? {};
    cur = cur[parts[i]];
  }
  // CASE: R07-TP-01
  // ruleid: gitlab.eslint.detect-object-injection | src: req.body.path (cross-file caller) | sink: nested dynamic write | "constructor.prototype.isAdmin" walks to Object.prototype
  cur[parts[parts.length - 1]] = value;
}
