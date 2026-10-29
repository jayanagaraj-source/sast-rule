import { Router, Request, Response, NextFunction } from 'express';
import axios from 'axios';
import { pg } from '../../lib/db';
import { logger } from '../../lib/logger';
import { wordsMatcher, escapeRegExp } from '../../lib/regex-utils';
import { caseService, CaseRow } from '../../services/case-service';
import { requireAuth, AuthedRequest } from '../middleware';

export const casesRouter = Router();
casesRouter.use(requireAuth);

const EDITABLE_FIELDS = ['subject', 'priority', 'status', 'assigneeId'] as const;
const STATUS_TRANSITIONS: Record<string, string[]> = {
  open: ['pending', 'solved'],
  pending: ['open', 'solved'],
  solved: ['open', 'closed'],
};
const DNS_LABEL = /^[a-z0-9][a-z0-9-]{1,38}[a-z0-9]$/;

function pick<T extends object, K extends keyof T>(obj: T, keys: readonly K[]): Pick<T, K> {
  const out = {} as Pick<T, K>;
  for (const k of keys) if (k in obj) out[k] = obj[k];
  return out;
}

const tenantOf = (req: Request) => (req as AuthedRequest).tenantId;

casesRouter.get('/', async (req: Request, res: Response) => {
  const q = String(req.query.q ?? '');
  // CASE: R11-TP-03
  // ruleid: SAST-011 | src: req.query.q | sink: new RegExp + test | raw search text compiled as a regex and run over every subject
  const matcher = new RegExp(q);
  const { rows } = await pg.query<CaseRow>('SELECT id, subject FROM cases WHERE tenant_id = $1 LIMIT 500', [tenantOf(req)]);
  res.json(rows.filter((r) => matcher.test(r.subject)));
});

casesRouter.get('/search', async (req: Request, res: Response) => {
  const matcher = wordsMatcher(String(req.query.words ?? '').split(/\s+/));
  const { rows } = await pg.query<CaseRow>('SELECT id, subject FROM cases WHERE tenant_id = $1', [tenantOf(req)]);
  res.json(rows.filter((r) => matcher.test(r.subject)));
});

casesRouter.get('/highlight/:id', async (req: Request, res: Response) => {
  const row = await caseService.get(tenantOf(req), req.params.id);
  // CASE: R11-TP-04
  // ruleid: SAST-011 | src: req.query.term | sink: new RegExp + replace | user regex applied to the full (unbounded) case body
  const term = new RegExp(String(req.query.term));
  res.json({ html: row.subject.replace(term, (m) => `<mark>${m}</mark>`) });
});

casesRouter.get('/by-tag', async (req: Request, res: Response) => {
  // CASE: R11-FP-07
  // ok: SAST-011 | src: req.query.tag (escaped) | sink: new RegExp | escaped before compiling
  const tagRe = new RegExp(escapeRegExp(String(req.query.tag ?? '')));
  const { rows } = await pg.query('SELECT id, tags FROM cases WHERE tenant_id = $1', [tenantOf(req)]);
  res.json(rows.filter((r) => r.tags.some((t: string) => tagRe.test(t))));
});

casesRouter.get('/validate-reference', (req: Request, res: Response) => {
  const ref = String(req.query.ref ?? '');
  // CASE: R11-GAP-01
  // todoruleid: SAST-011 | src: req.query.ref | sink: regex literal test | static nested quantifier (x+)+ on request input: exponential backtracking; rule only inspects new RegExp(var)
  const ok = /^([a-zA-Z0-9]+)+$/.test(ref);
  res.json({ ok });
});

casesRouter.get('/validate-email', (req: Request, res: Response) => {
  const email = String(req.query.email ?? '').slice(0, 254);
  // CASE: R11-FP-08
  // ok: SAST-011 | src: req.query.email (bounded) | sink: regex literal test | linear pattern, input capped at 254 chars
  res.json({ ok: /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) });
});

casesRouter.patch('/:id', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const row = await caseService.get(tenantOf(req), req.params.id);
    // CASE: R08-TP-05
    // ruleid: JS-002 | src: req.body | sink: Object.assign | mass assignment: any column (tenantId, slaBreached) can be overwritten
    Object.assign(row, req.body);
    await caseService.save(row);
    res.json(row);
  } catch (err) {
    next(err);
  }
});

casesRouter.patch('/:id/status', async (req: Request, res: Response) => {
  const row = await caseService.get(tenantOf(req), req.params.id);
  const next = String(req.body.status);
  if (!STATUS_TRANSITIONS[row.status]?.includes(next)) return res.status(409).json({ error: 'bad transition' });
  // CASE: R08-FP-14
  // ok: JS-002 | src: req.body.status (validated) | sink: Object.assign | fixed-key object literal, only status changes
  Object.assign(row, { status: next, updatedAt: new Date() });
  await caseService.save(row);
  res.json(row);
});

casesRouter.put('/:id/fields', async (req: Request, res: Response) => {
  const row = await caseService.get(tenantOf(req), req.params.id);
  const changes = pick(req.body as Partial<CaseRow>, EDITABLE_FIELDS);
  // CASE: R08-FP-15
  // ok: JS-002 | src: req.body (pick allowlist) | sink: Object.assign | pick() keeps only four editable keys
  Object.assign(row, changes);
  await caseService.save(row);
  res.json(row);
});

casesRouter.put('/:id/custom', async (req: Request, res: Response) => {
  // Route hands the raw body to the service; the assignment itself is in services/case-service.ts.
  await caseService.applyCustomFields(tenantOf(req), req.params.id, req.body);
  res.sendStatus(204);
});

casesRouter.post('/:id/clone', async (req: Request, res: Response) => {
  const src = await caseService.get(tenantOf(req), req.params.id);
  // CASE: R08-GAP-02
  // todoruleid: JS-002 | src: req.body | sink: object spread | mass assignment via native spread into the INSERT payload; the rule only matches Object.assign
  const copy = { ...src, ...req.body, id: undefined };
  res.status(201).json(await caseService.create(copy));
});

casesRouter.post('/:id/meta', async (req: Request, res: Response) => {
  const row = await caseService.get(tenantOf(req), req.params.id);
  const meta = (row.meta ?? {}) as Record<string, unknown>;
  // CASE: R07-TP-05, X-RPI-TP-04
  // ruleid: gitlab.eslint.detect-object-injection, javascript.express.security.audit.remote-property-injection.remote-property-injection | src: req.body.key | sink: dynamic property write | attacker-chosen key and value written into case metadata
  meta[req.body.key] = req.body.value;
  await caseService.save({ ...row, meta });
  res.json(meta);
});

casesRouter.get('/:id/field', async (req: Request, res: Response) => {
  const row = (await caseService.get(tenantOf(req), req.params.id)) as any;
  const field = String(req.query.name);
  // CASE: R07-TP-06
  // ruleid: gitlab.eslint.detect-object-injection | src: req.query.name | sink: dynamic property read | name=requesterPasswordHash or internalNotes leaks hidden columns
  res.json({ value: row[field] });
});

casesRouter.delete('/:id/meta/:field', async (req: Request, res: Response) => {
  const row = await caseService.get(tenantOf(req), req.params.id);
  // CASE: R07-TP-07
  // ruleid: gitlab.eslint.detect-object-injection | src: req.params.field | sink: delete | unsafe deletion of an arbitrary property (can drop tenantId before save)
  delete (row as any)[req.params.field];
  await caseService.save(row);
  res.sendStatus(204);
});

casesRouter.post('/:id/sync-fields', async (req: Request, res: Response) => {
  // Tenants live on <domain>.<APP_URL>. The domain is re-validated here as a DNS label: the tenants table is
  // writable by tenant admins, so the stored value is not trusted on its own.
  const tenant = await pg.query('SELECT domain_name FROM tenants WHERE id = $1', [tenantOf(req)]);
  const domainName = String(tenant.rows[0]?.domain_name ?? '');
  if (!DNS_LABEL.test(domainName)) return res.status(409).json({ error: 'tenant domain invalid' });
  const caseId = encodeURIComponent(req.params.id);
  // CASE: R04-FP-03
  // ok: TG-TAINT-JS-SSRF | src: validated tenant label + req.params path segment | sink: axios.get | host = DNS-label-validated subdomain of our own zone; request value only in the path
  const { data } = await axios.get(`${process.env.API_PROTOCOL}://${domainName}.${process.env.APP_URL}/cases/${caseId}/fields`);
  res.json(data);
});

casesRouter.post('/sync-fields-for', async (req: Request, res: Response) => {
  // Support tooling: sync the fields of a case on a tenant named in the request body.
  const domainName = req.body.domain;
  const caseId = req.body.caseId;
  // CASE: R04-TP-01
  // ruleid: TG-TAINT-JS-SSRF | src: req.body.domain | sink: axios.get | domain "evil.example/x?" makes the host attacker-chosen
  const { data } = await axios.get(`${process.env.API_PROTOCOL}://${domainName}.${process.env.APP_URL}/cases/${caseId}/fields`);
  res.json(data);
});

casesRouter.get('/:id/crm', async (req: Request, res: Response) => {
  // CASE: R04-FP-04
  // ok: TG-TAINT-JS-SSRF | src: req.params.id (path only) | sink: fetch | fixed https host, user value only in the path
  const r = await fetch(`https://api.partner-crm.example/v2/cases/${encodeURIComponent(req.params.id)}`);
  res.status(r.status).json(await r.json());
});

casesRouter.get('/:id/crm-env', async (req: Request, res: Response) => {
  // CASE: R04-FP-05
  // ok: TG-TAINT-JS-SSRF | src: env host + req.params path | sink: fetch | env-owned base URL, request value only in the path
  const r = await fetch(`${process.env.CRM_BASE_URL}/v2/cases/${encodeURIComponent(req.params.id)}`);
  res.status(r.status).json(await r.json());
});

casesRouter.get('/crm-search', async (req: Request, res: Response) => {
  // CASE: R04-FP-06
  // ok: TG-TAINT-JS-SSRF | src: req.query.q (query string only) | sink: axios.get | fixed host, user value is a query parameter
  const r = await axios.get('https://api.partner-crm.example/v2/search?q=' + encodeURIComponent(String(req.query.q)));
  res.json(r.data);
});

casesRouter.get('/preview-link', async (req: Request, res: Response) => {
  // CASE: R04-TP-02
  // ruleid: TG-TAINT-JS-SSRF | src: req.query.url | sink: axios.get | link preview fetches any URL, e.g. http://169.254.169.254/
  const r = await axios.get(String(req.query.url), { timeout: 3000, maxRedirects: 0 });
  logger.info({ status: r.status }, 'link preview fetched');
  res.json({ title: /<title>([^<]{0,300})<\/title>/i.exec(r.data)?.[1] ?? null });
});
