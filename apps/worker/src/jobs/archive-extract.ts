// Bulk-import archives: customers upload a .zip / .tar.gz of historical tickets with their attachments.
import fs from 'fs';
import path from 'path';
import { randomUUID } from 'crypto';
import AdmZip from 'adm-zip';
import tarStream from 'tar-stream';
import zlib from 'zlib';
import unzipper from 'unzipper';
import * as tar from 'tar';
import { logger } from '../lib/logger';

const TMP_ROOT = process.env.CASEFLOW_IMPORT_TMP ?? '/var/tmp/caseflow-imports';

export function workDirFor(jobId: string): string {
  // CASE: R13-FP-11
  // ok: javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal | src: server-generated job UUID | sink: path.join | application-generated path
  return path.join(TMP_ROOT, jobId);
}

/** Legacy importer (v1). Still used for .zip uploads from the "Classic" console. */
export function extractZipLegacy(zipPath: string, dest: string): number {
  const zip = new AdmZip(zipPath);
  let count = 0;
  for (const entry of zip.getEntries()) {
    // CASE: R13-TP-13
    // ruleid: javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal | src: archive entry name (uploaded file) | sink: path.join | zip-slip: "../../../../etc/cron.d/x" escapes dest
    const out = path.join(dest, entry.entryName);
    if (entry.isDirectory) continue;
    // CASE: R10-TP-09, X-ZS-TP-01
    // ruleid: gitlab.eslint.detect-non-literal-fs-filename, TG-TAINT-JS-ZIP-SLIP | src: archive entry name | sink: fs.mkdirSync | parent directories created outside dest
    fs.mkdirSync(path.dirname(out), { recursive: true });
    // CASE: R10-TP-10, X-ZS-TP-02
    // ruleid: gitlab.eslint.detect-non-literal-fs-filename, TG-TAINT-JS-ZIP-SLIP | src: archive entry name | sink: fs.writeFileSync | zip-slip arbitrary write
    fs.writeFileSync(out, entry.getData());
    count++;
  }
  return count;
}

/** Current importer (v2) for .zip uploads. */
export function extractZip(zipPath: string, dest: string): number {
  const base = path.resolve(dest);
  const zip = new AdmZip(zipPath);
  let count = 0;
  for (const entry of zip.getEntries()) {
    // CASE: R13-FP-12
    // ok: javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal | src: archive entry name (contained) | sink: path.resolve | containment check on the next line
    const out = path.resolve(base, entry.entryName);
    if (!out.startsWith(base + path.sep)) {
      logger.warn({ entry: entry.entryName }, 'skipping archive entry outside the destination');
      continue;
    }
    if (entry.isDirectory) continue;
    // CASE: R10-FP-15, X-ZS-FP-01
    // ok: gitlab.eslint.detect-non-literal-fs-filename, TG-TAINT-JS-ZIP-SLIP | src: archive entry name (contained) | sink: fs.mkdirSync | inside base
    fs.mkdirSync(path.dirname(out), { recursive: true });
    // CASE: R10-FP-16, X-ZS-FP-02
    // ok: gitlab.eslint.detect-non-literal-fs-filename, TG-TAINT-JS-ZIP-SLIP | src: archive entry name (contained) | sink: fs.writeFileSync | contained write
    fs.writeFileSync(out, entry.getData());
    count++;
  }
  return count;
}

/** .tar.gz importer built on tar-stream. */
export function extractTarGz(archive: string, dest: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const extract = tarStream.extract();
    extract.on('entry', (header, stream, next) => {
      // CASE: R13-TP-14
      // ruleid: javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal | src: tar header name (uploaded file) | sink: path.join | tar-slip via "../" in the header name
      const out = path.join(dest, header.name);
      // CASE: R10-TP-11, X-ZS-GAP-01
      // ruleid: gitlab.eslint.detect-non-literal-fs-filename | src: tar header name | sink: fs.createWriteStream | arbitrary write through a stream
      // todoruleid: TG-TAINT-JS-ZIP-SLIP | src: tar header name | sink: fs.createWriteStream | the zip-slip source pattern only covers single-argument "entry" callbacks
      stream.pipe(fs.createWriteStream(out)).on('finish', next);
    });
    extract.on('finish', resolve).on('error', reject);
    // CASE: R10-FP-17, X-PT-FP-14
    // ok: gitlab.eslint.detect-non-literal-fs-filename, TG-TAINT-JS-PATH-TRAVERSAL | src: server-side path of the stored upload | sink: fs.createReadStream | the archive itself is at a server-chosen path
    fs.createReadStream(archive).pipe(zlib.createGunzip()).pipe(extract);
  });
}

/** Attachments-only importer built on unzipper. */
export async function extractAttachments(zipPath: string, dest: string): Promise<string[]> {
  const directory = await unzipper.Open.file(zipPath);
  const written: string[] = [];
  for (const file of directory.files) {
    // CASE: R13-TP-15
    // ruleid: javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal | src: archive entry path | sink: path.join | zip-slip in the attachment importer
    const out = path.join(dest, file.path);
    // CASE: R10-GAP-05, X-ZS-TP-03
    // todoruleid: gitlab.eslint.detect-non-literal-fs-filename | src: archive entry path | sink: fs.promises.writeFile | fs.promises.* is not matched by the eslint rule
    // ruleid: TG-TAINT-JS-ZIP-SLIP | src: unzipper directory.files | sink: fs.promises.writeFile | arbitrary write
    await fs.promises.writeFile(out, await file.buffer());
    written.push(out);
  }
  return written;
}

/**
 * Imports keep symlinks (customers export from Linux helpdesks that use them for shared attachments), then the
 * importer reads files named in manifest.json. The check below is lexical only: a symlink inside dest pointing at
 * /etc/shadow passes it.
 */
export async function readManifestFiles(archive: string, dest: string, manifestPaths: string[]): Promise<Buffer[]> {
  await tar.x({ file: archive, cwd: dest, preservePaths: false });
  const base = path.resolve(dest);
  const out: Buffer[] = [];
  for (const rel of manifestPaths) {
    // CASE: R13-TP-16
    // ruleid: javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal | src: manifest.json inside the uploaded archive | sink: path.resolve | symlink escape: containment check without realpath
    const p = path.resolve(base, rel);
    if (!p.startsWith(base + path.sep)) continue;
    // CASE: R10-TP-12
    // ruleid: gitlab.eslint.detect-non-literal-fs-filename | src: manifest.json inside the uploaded archive | sink: fs.readFileSync | follows a planted symlink out of dest
    out.push(fs.readFileSync(p));
  }
  return out;
}

/** Same as readManifestFiles, but resolves symlinks before the containment check. */
export function readManifestFileSafe(dest: string, rel: string): Buffer {
  // CASE: R10-FP-18
  // ok: gitlab.eslint.detect-non-literal-fs-filename | src: server-owned dest | sink: fs.realpathSync | realpath of the extraction root
  const base = fs.realpathSync(dest);
  // CASE: R10-FP-19, R13-FP-13
  // ok: gitlab.eslint.detect-non-literal-fs-filename, javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal | src: manifest path (checked below) | sink: path.resolve + fs.realpathSync | resolves symlinks before the containment check
  const real = fs.realpathSync(path.resolve(base, rel));
  if (!real.startsWith(base + path.sep)) throw new Error('manifest path escapes the import directory');
  // CASE: R10-FP-20
  // ok: gitlab.eslint.detect-non-literal-fs-filename | src: manifest path (realpath-contained) | sink: fs.readFileSync | symlink-safe containment
  return fs.readFileSync(real);
}

export function newImportJob(): { jobId: string; dir: string } {
  const jobId = randomUUID();
  const dir = workDirFor(jobId);
  // CASE: R10-FP-21
  // ok: gitlab.eslint.detect-non-literal-fs-filename | src: server UUID | sink: fs.mkdirSync | generated directory
  fs.mkdirSync(dir, { recursive: true });
  return { jobId, dir };
}
