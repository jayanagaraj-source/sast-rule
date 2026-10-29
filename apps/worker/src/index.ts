import { on, run } from './lib/queue-consumer';
import { MetadataCache } from './jobs/metadata-cache';
import { logger } from './lib/logger';

// eslint-disable-next-line @typescript-eslint/no-var-requires
const { handleImport } = require('./jobs/import-job');

const cache = new MetadataCache(process.env.CASEFLOW_METADATA_DIR ?? '/var/cache/caseflow/metadata');

on('import.csv', async (msg) => {
  const rows = handleImport(msg);
  logger.info({ rows: rows.length, id: msg.id }, 'import finished');
});
on('crm.record-changed', (msg) => cache.storeFromWebhook(msg));

run(process.env.REDIS_URL ?? 'redis://localhost:6379/0').catch((err) => {
  logger.fatal({ err }, 'worker crashed');
  process.exit(1);
});
