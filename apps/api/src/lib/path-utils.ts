import path from 'path';
import fs from 'fs';

export const UPLOAD_ROOT = process.env.CASEFLOW_UPLOAD_DIR ?? '/var/lib/caseflow/uploads';

/** Where a tenant's attachments live. tenantId is the server-side UUID from the verified JWT. */
export function tenantDir(tenantId: string): string {
  // CASE: R13-FP-03
  // ok: javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal | src: session tenant UUID | sink: path.join | server-generated id, not user text
  return path.join(UPLOAD_ROOT, tenantId);
}

/**
 * Builds the on-disk path of an attachment. Callers pass the filename straight from the request
 * (routes/attachments/index.ts), so this is where traversal must be stopped — and it is not.
 */
export function attachmentPath(tenantId: string, fileName: string): string {
  // CASE: R13-TP-01
  // ruleid: javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal | src: req.params.name (cross-file caller) | sink: path.join | filename joined without containment
  return path.join(tenantDir(tenantId), fileName);
}

/** Weak "sanitiser" kept for backwards compatibility with old export links. */
export function legacyExportPath(name: string): string {
  // Strips one "../" only: "....//....//etc/passwd" still contains "../" after the replace.
  const cleaned = name.replace('../', '');
  // CASE: R13-GAP-01
  // todoruleid: javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal | src: req.query.name (cross-file caller) | sink: path.join | weak replace(); the rule treats any .replace() as a sanitiser
  return path.join(UPLOAD_ROOT, 'exports', cleaned);
}

/** Resolves a user-supplied relative path and refuses anything outside base. */
export function resolveInside(base: string, userPath: string): string {
  const root = path.resolve(base);
  // CASE: R13-FP-04
  // ok: javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal | src: caller input | sink: path.resolve | containment check on the next line throws on escape
  const resolved = path.resolve(root, userPath);
  if (!resolved.startsWith(root + path.sep)) {
    throw new Error('path escapes base directory');
  }
  return resolved;
}

/** Containment check that follows symlinks: a link inside the upload dir pointing at /etc is rejected. */
export function resolveInsideReal(base: string, userPath: string): string {
  // CASE: R10-FP-04
  // ok: gitlab.eslint.detect-non-literal-fs-filename | src: trusted base | sink: fs.realpathSync | realpath of the configured upload root
  const root = fs.realpathSync(base);
  // CASE: R13-FP-05
  // ok: javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal | src: caller input | sink: path.resolve | realpath + containment check before any use
  const candidate = path.resolve(root, userPath);
  // CASE: R10-FP-05
  // ok: gitlab.eslint.detect-non-literal-fs-filename | src: caller input (contained below) | sink: fs.realpathSync | realpath only, checked immediately
  const real = fs.realpathSync(candidate);
  if (!real.startsWith(root + path.sep)) {
    throw new Error('path escapes base directory');
  }
  return real;
}

/** Strict filename validation used by the avatar uploader. */
export function safeFileName(name: string): string {
  const base = path.basename(name);
  if (!/^[A-Za-z0-9_-]{1,64}\.(png|jpe?g|gif|webp)$/.test(base)) {
    throw new Error('invalid file name');
  }
  return base;
}

/** Only used to build a log line; never touches the filesystem. */
export function describeTarget(tenantId: string, fileName: string): string {
  // CASE: R13-FP-06
  // ok: javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal | src: req.params (caller) | sink: path.join | path built only for a log message
  return `target=${path.join('tenants', tenantId, fileName)}`;
}
