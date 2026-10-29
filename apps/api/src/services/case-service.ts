import { randomUUID } from 'crypto';
import { pg } from '../lib/db';
import { mergeDeep } from '../lib/merge';

export interface CaseRow {
  id: string;
  tenantId: string;
  subject: string;
  status: string;
  priority: 'low' | 'normal' | 'high' | 'urgent';
  assigneeId: string | null;
  slaBreached: boolean;
  meta: Record<string, unknown> | null;
  customFields: Record<string, unknown>;
  createdAt: Date;
  updatedAt: Date;
}

class CaseEntity {
  constructor(props: Partial<CaseRow>) {
    // CASE: R08-FP-21
    // ok: JS-002 | src: DB row | sink: Object.assign(this, props) | constructor copying its own typed props from a DB row
    Object.assign(this, props);
  }
}

export class CaseService {
  async get(tenantId: string, id: string): Promise<CaseRow> {
    const { rows } = await pg.query<CaseRow>('SELECT * FROM cases WHERE tenant_id = $1 AND id = $2', [tenantId, id]);
    if (!rows[0]) throw Object.assign(new Error('case not found'), { status: 404 });
    return new CaseEntity(rows[0]) as CaseRow;
  }

  async save(row: CaseRow): Promise<void> {
    await pg.query(
      'UPDATE cases SET subject=$3, status=$4, priority=$5, assignee_id=$6, meta=$7, custom_fields=$8 WHERE tenant_id=$1 AND id=$2',
      [row.tenantId, row.id, row.subject, row.status, row.priority, row.assigneeId, row.meta, row.customFields],
    );
  }

  async create(data: Partial<CaseRow>): Promise<CaseRow> {
    const row = { ...data, id: randomUUID(), createdAt: new Date(), updatedAt: new Date() } as CaseRow;
    await pg.query('INSERT INTO cases (id, tenant_id, subject, status, priority) VALUES ($1,$2,$3,$4,$5)', [
      row.id, row.tenantId, row.subject, row.status ?? 'open', row.priority ?? 'normal',
    ]);
    return row;
  }

  /** Called from PUT /cases/:id/custom with the raw request body. */
  async applyCustomFields(tenantId: string, id: string, data: Record<string, unknown>): Promise<void> {
    const entity = await this.get(tenantId, id);
    // CASE: R08-TP-14
    // ruleid: JS-002 | src: req.body (cross-file: routes/cases/index.ts) | sink: Object.assign | mass assignment into the entity; the route passes req.body straight through
    Object.assign(entity, data);
    entity.customFields = mergeDeep(entity.customFields ?? {}, (data.customFields as Record<string, unknown>) ?? {});
    await this.save(entity);
  }
}

export const caseService = new CaseService();
