'use strict';

// Consumes "import.csv" queue messages produced by POST /imports (apps/api). The message carries the original
// upload filename and the tenant's column-mapping file, both chosen by the customer.
const fs = require('fs');
const path = require('path');
const { parse } = require('csv-parse/sync');
const { logger } = require('../lib/logger');

const IMPORT_DIR = process.env.CASEFLOW_IMPORT_DIR || '/var/lib/caseflow/imports';
const MAX_FIELD_LENGTH = 512;

function readUpload(msg) {
  // CASE: R13-TP-17
  // ruleid: javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal | src: queue message (original upload filename) | sink: path.join | "../../config/production.json" leaves the import dir
  const file = path.join(IMPORT_DIR, msg.payload.tenantId, msg.payload.fileName);
  // CASE: R10-TP-13, X-PT-GAP-05
  // ruleid: gitlab.eslint.detect-non-literal-fs-filename | src: queue message | sink: fs.readFileSync | arbitrary read of server files into the import
  // todoruleid: TG-TAINT-JS-PATH-TRAVERSAL | src: queue message | sink: fs.readFileSync | queue messages are not taint sources
  return fs.readFileSync(file, 'utf8');
}

function compileMapping(mapping) {
  return mapping.columns.map((col) => ({
    target: col.target,
    // CASE: R11-TP-07
    // ruleid: SAST-011 | src: imported mapping file (customer upload) | sink: new RegExp + match | customer regex run on every CSV cell
    matcher: col.pattern ? new RegExp(col.pattern) : null,
  }));
}

function applyMapping(rows, mapping) {
  const compiled = compileMapping(mapping);
  return rows.map((row) => {
    const out = {};
    for (const col of compiled) {
      const raw = String(row[col.target] || '');
      const m = col.matcher ? raw.match(col.matcher) : null;
      // CASE: R07-FP-15, X-RPI-FP-04
      // ok: gitlab.eslint.detect-object-injection, javascript.express.security.audit.remote-property-injection.remote-property-injection | src: mapping target (validated against TARGET_FIELDS before compile) | sink: dynamic property write | targets are validated in handleImport
      out[col.target] = m ? m[0] : raw;
    }
    return out;
  });
}

const TARGET_FIELDS = new Set(['subject', 'requesterEmail', 'priority', 'createdAt', 'externalId']);

function handleImport(msg) {
  const mapping = JSON.parse(readUpload({ payload: { ...msg.payload, fileName: msg.payload.mappingFile } }));
  if (!mapping.columns.every((c) => TARGET_FIELDS.has(c.target))) throw new Error('unknown target column');
  const rows = parse(readUpload(msg), { columns: true, skip_empty_lines: true });
  const trimmed = rows.map((r) => {
    const copy = {};
    for (const key of Object.keys(r)) {
      // CASE: R07-FP-16
      // ok: gitlab.eslint.detect-object-injection | src: CSV header (own keys) | sink: dynamic property write | copying own keys into a fresh object, values truncated
      copy[key] = String(r[key]).slice(0, MAX_FIELD_LENGTH);
    }
    return copy;
  });
  // CASE: R11-FP-12
  // ok: SAST-011 | src: static | sink: String.split | static linear delimiter regex on bounded fields
  const tags = trimmed.flatMap((r) => String(r.tags || '').split(/\s*,\s*/));
  logger.info({ rows: trimmed.length, tags: tags.length }, 'import parsed');
  return applyMapping(trimmed, mapping);
}

module.exports = { handleImport };
