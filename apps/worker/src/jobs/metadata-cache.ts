// Caches third-party record metadata (CRM contacts, chat transcripts) on local disk between sync runs.
import fs from 'fs-extra';
import path from 'path';
import { randomUUID } from 'crypto';
import type { QueueMessage } from '../lib/queue-consumer';

export interface RecordMetadata {
  source: 'crm' | 'chat' | 'helpdesk';
  externalId: string;
  etag: string;
  fetchedAt: string;
}

export class MetadataCache {
  constructor(private readonly dir: string) {}

  private getMetadataPath(identifier: string): string {
    // CASE: R13-TP-18
    // ruleid: javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal | src: identifier (third-party id from the sync queue, see storeFromWebhook) | sink: path.join | not validated in the helper
    return path.join(this.dir, `${identifier}.json`);
  }

  /** Normal sync: the cache key is a UUID we mint and map to the external id in Postgres. */
  async store(metadata: RecordMetadata): Promise<string> {
    const identifier = randomUUID();
    // CASE: R10-FP-23, X-PT-FP-16
    // ok: gitlab.eslint.detect-non-literal-fs-filename, TG-TAINT-JS-PATH-TRAVERSAL | src: server UUID | sink: fs.writeFile | safe metadata write under a generated name
    await fs.writeFile(this.getMetadataPath(identifier), JSON.stringify(metadata), { encoding: 'utf-8' });
    return identifier;
  }

  /** Webhook-triggered sync: the CRM tells us which record changed; we key the cache by its external id. */
  async storeFromWebhook(msg: QueueMessage<{ externalId: string; metadata: RecordMetadata }>): Promise<void> {
    const identifier = msg.payload.externalId;
    // CASE: R10-TP-14
    // ruleid: gitlab.eslint.detect-non-literal-fs-filename | src: queue message (externalId from an inbound CRM webhook) | sink: fs.writeFile | "../../../app/.env" overwrites files outside the cache
    await fs.writeFile(this.getMetadataPath(identifier), JSON.stringify(msg.payload.metadata), { encoding: 'utf-8' });
  }

  async load(identifier: string): Promise<RecordMetadata | null> {
    if (!/^[0-9a-f-]{36}$/.test(identifier)) return null;
    // CASE: R10-FP-24, X-PT-FP-17
    // ok: gitlab.eslint.detect-non-literal-fs-filename, TG-TAINT-JS-PATH-TRAVERSAL | src: caller id (UUID shape enforced) | sink: fs.readJson | validated path
    return (await fs.pathExists(this.getMetadataPath(identifier))) ? fs.readJson(this.getMetadataPath(identifier)) : null;
  }
}
