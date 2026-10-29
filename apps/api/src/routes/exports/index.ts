import { Router, Request, Response } from 'express';
import fse from 'fs-extra';
import path from 'path';
import { randomUUID } from 'crypto';
import { reportService } from '../../services/report-service.mjs';
import { legacyExportPath, UPLOAD_ROOT } from '../../lib/path-utils';
import { requireAuth, requireAdmin, AuthedRequest } from '../middleware';

export const exportsRouter = Router();
exportsRouter.use(requireAuth);

const EXPORT_DIR = path.join(UPLOAD_ROOT, 'exports');
const FS_OPS = { archive: 'move', duplicate: 'copy' } as const;
const tenantOf = (req: Request) => (req as AuthedRequest).tenantId;

exportsRouter.post('/', async (req: Request, res: Response) => {
  const csv = await reportService.casesCsv(tenantOf(req), req.body.filter);
  // CASE: R13-TP-09
  // ruleid: javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal | src: req.body.fileName | sink: path.join | user-chosen export filename
  const out = path.join(EXPORT_DIR, `${req.body.fileName}.csv`);
  // CASE: R10-TP-06, X-PT-TP-07
  // ruleid: gitlab.eslint.detect-non-literal-fs-filename, TG-TAINT-JS-PATH-TRAVERSAL | src: req.body.fileName | sink: fse.writeFile | arbitrary write via fs-extra ("../../app/server.js")
  await fse.writeFile(out, csv, { encoding: 'utf-8' });
  res.status(201).json({ file: path.basename(out) });
});

exportsRouter.post('/scheduled', async (req: Request, res: Response) => {
  const csv = await reportService.casesCsv(tenantOf(req), req.body.filter);
  const id = randomUUID();
  // CASE: R10-FP-11, X-PT-FP-10
  // ok: gitlab.eslint.detect-non-literal-fs-filename, TG-TAINT-JS-PATH-TRAVERSAL | src: server UUID | sink: fse.writeFile | export written under a generated name
  await fse.writeFile(path.join(EXPORT_DIR, `${id}.csv`), csv);
  res.status(201).json({ id });
});

exportsRouter.get('/legacy', async (req: Request, res: Response) => {
  const p = legacyExportPath(String(req.query.name));
  // CASE: R10-TP-07, X-PT-TP-08
  // ruleid: gitlab.eslint.detect-non-literal-fs-filename, TG-TAINT-JS-PATH-TRAVERSAL | src: req.query.name (weak replace, cross-file) | sink: fse.readFile | "....//....//etc/passwd" survives the single replace
  res.send(await fse.readFile(p));
});

exportsRouter.post('/:id/:op', requireAdmin, async (req: Request, res: Response) => {
  const op = FS_OPS[req.params.op as keyof typeof FS_OPS];
  if (!op) return res.status(400).end();
  // CASE: R13-TP-10
  // ruleid: javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal | src: req.params.id | sink: path.join | export id is not validated as a UUID
  const src = path.join(EXPORT_DIR, `${req.params.id}.csv`);
  // CASE: R13-TP-11
  // ruleid: javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal | src: req.params.id | sink: path.join | same id reused for the destination
  const dest = path.join(EXPORT_DIR, 'archive', `${req.params.id}.csv`);
  // CASE: R10-GAP-03, X-PT-GAP-03
  // todoruleid: gitlab.eslint.detect-non-literal-fs-filename, TG-TAINT-JS-PATH-TRAVERSAL | src: req.params.id | sink: dynamic fs method fse[op] | method chosen at runtime; neither rule matches computed member calls
  await (fse as any)[op](src, dest);
  res.sendStatus(204);
});

// On-prem Windows installer: exports land in C:\ProgramData\Caseflow\exports.
exportsRouter.get('/win/:name', async (req: Request, res: Response) => {
  // CASE: R13-GAP-02
  // todoruleid: javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal | src: req.params.name | sink: path.win32.join | "..\\..\\Windows\\win.ini" with win32 semantics; the rule only binds the `path` module object
  const p = path.win32.join('C:\\ProgramData\\Caseflow\\exports', req.params.name);
  // CASE: R10-TP-08, X-PT-TP-09
  // ruleid: gitlab.eslint.detect-non-literal-fs-filename, TG-TAINT-JS-PATH-TRAVERSAL | src: req.params.name | sink: fse.readFile | read of a Windows path built from request input
  res.send(await fse.readFile(p));
});
