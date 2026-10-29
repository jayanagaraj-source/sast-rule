import * as fs from 'fs/promises';
import path from 'path';
import { randomUUID } from 'crypto';
import { logger } from '../lib/logger';

export interface AttachmentMetadata {
  id: string;
  tenantId: string;
  originalName: string;
  contentType: string;
  size: number;
  sha256: string;
  uploadedBy: string;
}

/** Disk-backed metadata cache next to each stored attachment. */
export class StorageService {
  constructor(private readonly root: string) {}

  private getMetadataPath(identifier: string): string {
    // CASE: R13-TP-12
    // ruleid: javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal | src: identifier (request-supplied via saveClientMetadata) | sink: path.join | identifier is not validated inside the helper
    return path.join(this.root, 'meta', `${identifier}.json`);
  }

  /** Server-side upload pipeline: the identifier is a fresh UUID minted here. */
  async saveMetadata(metadata: Omit<AttachmentMetadata, 'id'>): Promise<string> {
    const identifier = randomUUID();
    // CASE: R10-FP-12, X-PT-FP-11
    // ok: gitlab.eslint.detect-non-literal-fs-filename, TG-TAINT-JS-PATH-TRAVERSAL | src: server UUID | sink: fs.writeFile | safe metadata cache write keyed by a generated id
    await fs.writeFile(this.getMetadataPath(identifier), JSON.stringify({ ...metadata, id: identifier }), { encoding: 'utf-8' });
    return identifier;
  }

  /** Desktop sync client pushes metadata for files it uploaded earlier, keyed by the id it sends. */
  async saveClientMetadata(identifier: string, metadata: AttachmentMetadata): Promise<void> {
    // CASE: R10-GAP-04, X-PT-GAP-04
    // todoruleid: gitlab.eslint.detect-non-literal-fs-filename, TG-TAINT-JS-PATH-TRAVERSAL | src: req.body.id (cross-file caller) | sink: fs.writeFile | request-supplied id "../../../etc/cron.d/x" escapes meta/; `import * as fs` is not matched by the eslint rule and the request source is in another file
    await fs.writeFile(this.getMetadataPath(identifier), JSON.stringify(metadata), { encoding: 'utf-8' });
  }

  async readMetadata(identifier: string): Promise<AttachmentMetadata | null> {
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(identifier)) return null;
    try {
      // CASE: R10-FP-13, X-PT-FP-12
      // ok: gitlab.eslint.detect-non-literal-fs-filename, TG-TAINT-JS-PATH-TRAVERSAL | src: caller id (UUID-validated) | sink: fs.readFile | id must be a UUID, so no separators can appear
      return JSON.parse(await fs.readFile(this.getMetadataPath(identifier), 'utf-8'));
    } catch (err) {
      logger.debug({ err, identifier }, 'metadata cache miss');
      return null;
    }
  }
}

/** Not the filesystem: an in-memory LRU with fs-like method names, used by the preview renderer. */
export class PreviewCache {
  private readonly entries = new Map<string, Buffer>();

  readFile(key: string): Buffer | undefined {
    return this.entries.get(key);
  }

  writeFile(key: string, data: Buffer): void {
    if (this.entries.size > 500) this.entries.delete(this.entries.keys().next().value!);
    this.entries.set(key, data);
  }
}

export const previewCache = new PreviewCache();

export function cachePreview(req: { params: { name: string } }, data: Buffer): void {
  // CASE: R10-FP-14, X-PT-FP-13
  // ok: gitlab.eslint.detect-non-literal-fs-filename, TG-TAINT-JS-PATH-TRAVERSAL | src: req.params.name | sink: PreviewCache.writeFile | not the fs module: an in-memory Map with an fs-like method name
  previewCache.writeFile(req.params.name, data);
}

export const storageService = new StorageService(process.env.CASEFLOW_STORAGE_ROOT ?? '/var/lib/caseflow/storage');
