// CSV / PDF report generation. ESM TypeScript module (.mts) consumed by routes/exports and the worker.
import { pg } from '../lib/db.js';
import { escapeRegExp } from '../lib/regex-utils.js';

export interface ReportFilter {
  subjectPattern?: string;
  excludeWords?: string[];
  delimiter?: string;
}

interface Row {
  id: string;
  subject: string;
  status: string;
  body: string;
}

function toCsv(rows: Row[]): string {
  const esc = (v: string) => `"${v.replace(/"/g, '""')}"`;
  return ['id,subject,status', ...rows.map((r) => [r.id, r.subject, r.status].map(esc).join(','))].join('\n');
}

export const reportService = {
  async casesCsv(tenantId: string, filter: ReportFilter = {}): Promise<string> {
    const { rows } = await pg.query<Row>('SELECT id, subject, status, body FROM cases WHERE tenant_id = $1', [tenantId]);
    let selected = rows;
    if (filter.subjectPattern) {
      // CASE: R11-TP-05
      // ruleid: SAST-011 | src: req.body.filter.subjectPattern (export form) | sink: new RegExp + String.search | user regex over every subject in the tenant
      const re = new RegExp(filter.subjectPattern);
      selected = selected.filter((r) => r.subject.search(re) !== -1);
    }
    if (filter.excludeWords?.length) {
      // CASE: R11-FP-09
      // ok: SAST-011 | src: req.body.filter.excludeWords (escaped) | sink: new RegExp | each word escaped before joining
      const exclude = new RegExp(filter.excludeWords.map(escapeRegExp).join('|'));
      selected = selected.filter((r) => !exclude.test(r.subject));
    }
    return toCsv(selected);
  },

  async bodyColumns(tenantId: string, filter: ReportFilter): Promise<string[][]> {
    const { rows } = await pg.query<Row>('SELECT body FROM cases WHERE tenant_id = $1', [tenantId]);
    // CASE: R11-TP-06
    // ruleid: SAST-011 | src: req.body.filter.delimiter | sink: new RegExp + String.split | user-chosen delimiter regex (e.g. "(\\s*,?)*;") over large bodies
    const splitter = new RegExp(filter.delimiter ?? ',');
    return rows.map((r) => r.body.split(splitter));
  },

  extractOrderNumbers(body: string): string[] {
    // Quadratic: ".*" inside a global match over unbounded e-mail bodies (O(n^2) on long lines without a match).
    // CASE: R11-GAP-02
    // todoruleid: SAST-011 | src: inbound email body (queue message) | sink: matchAll on static regex | quadratic backtracking in a static literal; the rule only inspects new RegExp(var)
    return [...body.matchAll(/\s*order\s*#?\s*(\d+).*\s*$/gm)].map((m) => m[1]);
  },

  normaliseWhitespace(body: string): string {
    // CASE: R11-FP-10
    // ok: SAST-011 | src: static | sink: String.replace | static linear regex
    return body.replace(/[ \t]+/g, ' ');
  },
};
