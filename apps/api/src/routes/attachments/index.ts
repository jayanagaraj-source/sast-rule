import { Router, Request, Response } from 'express';
import fs from 'fs';
import { promises as fsp } from 'fs';
import path from 'path';
import { randomUUID } from 'crypto';
import multer from 'multer';
import { requireAuth, AuthedRequest } from '../middleware';
import { UPLOAD_ROOT, tenantDir, attachmentPath, resolveInside, safeFileName, describeTarget } from '../../lib/path-utils';
import { logger } from '../../lib/logger';

export const attachmentsRouter = Router();
attachmentsRouter.use(requireAuth);

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 25 * 1024 * 1024 } });
const TEMPLATE_DIR = path.join(__dirname, '../../../assets/attachment-templates');
const ALLOWED_TEMPLATES = new Set(['nda.pdf', 'rma-form.pdf', 'return-label.pdf']);
const tenantOf = (req: Request) => (req as AuthedRequest).tenantId;

attachmentsRouter.get('/download/:name', (req: Request, res: Response) => {
  // CASE: R13-TP-02
  // ruleid: javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal | src: req.params.name | sink: path.join | /download/..%2f..%2fetc%2fpasswd escapes the upload dir
  const filePath = path.join(UPLOAD_ROOT, tenantOf(req), req.params.name);
  // CASE: R10-TP-01, X-PT-TP-01
  // ruleid: gitlab.eslint.detect-non-literal-fs-filename, TG-TAINT-JS-PATH-TRAVERSAL | src: req.params.name | sink: fs.createReadStream | arbitrary file read streamed to the client
  fs.createReadStream(filePath).pipe(res);
});

attachmentsRouter.delete('/:name', async (req: Request, res: Response) => {
  const target = attachmentPath(tenantOf(req), req.params.name);
  logger.info(describeTarget(tenantOf(req), req.params.name));
  // CASE: R10-GAP-01, X-PT-TP-02
  // todoruleid: gitlab.eslint.detect-non-literal-fs-filename | src: req.params.name (cross-file helper) | sink: fsp.unlink | arbitrary deletion; `import { promises as fsp }` is not a form the eslint rule recognises
  // ruleid: TG-TAINT-JS-PATH-TRAVERSAL | src: req.params.name (cross-file helper) | sink: fsp.unlink | arbitrary file deletion
  await fsp.unlink(target);
  res.sendStatus(204);
});

attachmentsRouter.post('/:name/rename', async (req: Request, res: Response) => {
  const dir = tenantDir(tenantOf(req));
  // CASE: R13-FP-07
  // ok: javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal | src: req.params.name (contained) | sink: resolveInside | helper throws on escape
  const from = resolveInside(dir, req.params.name);
  // CASE: R13-TP-03
  // ruleid: javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal | src: req.body.newName | sink: path.join | destination joined without checks
  const to = path.join(dir, req.body.newName);
  // CASE: R10-TP-02, X-PT-TP-03
  // ruleid: gitlab.eslint.detect-non-literal-fs-filename, TG-TAINT-JS-PATH-TRAVERSAL | src: req.body.newName | sink: fs.renameSync | rename writes to an attacker-chosen destination
  fs.renameSync(from, to);
  res.sendStatus(204);
});

attachmentsRouter.post('/folders', (req: Request, res: Response) => {
  // CASE: R13-TP-04
  // ruleid: javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal | src: req.body.folder | sink: path.join | folder name joined into the tenant dir
  const folder = path.join(tenantDir(tenantOf(req)), req.body.folder);
  // CASE: R10-TP-03, X-PT-GAP-01
  // ruleid: gitlab.eslint.detect-non-literal-fs-filename | src: req.body.folder | sink: fs.mkdirSync | directory creation outside the tenant dir
  // todoruleid: TG-TAINT-JS-PATH-TRAVERSAL | src: req.body.folder | sink: fs.mkdirSync | mkdir is not in the taint rule's sink list
  fs.mkdirSync(folder, { recursive: true });
  res.sendStatus(201);
});

attachmentsRouter.get('/list', async (req: Request, res: Response) => {
  // CASE: R13-TP-05
  // ruleid: javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal | src: req.query.dir | sink: path.resolve | ?dir=../../ lists other tenants
  const dir = path.resolve(tenantDir(tenantOf(req)), String(req.query.dir ?? '.'));
  // CASE: R10-GAP-02, X-PT-TP-04
  // todoruleid: gitlab.eslint.detect-non-literal-fs-filename | src: req.query.dir | sink: fs.promises.readdir | fs.promises.* is not matched by the eslint rule
  // ruleid: TG-TAINT-JS-PATH-TRAVERSAL | src: req.query.dir | sink: fs.promises.readdir | listing of an arbitrary directory
  res.json(await fs.promises.readdir(dir));
});

attachmentsRouter.post('/', upload.single('file'), async (req: Request, res: Response) => {
  const id = randomUUID();
  // CASE: R13-FP-08
  // ok: javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal | src: server UUID | sink: path.join | filename generated server-side
  const dest = path.join(tenantDir(tenantOf(req)), `${id}.bin`);
  // CASE: X-PT-FP-03
  // ok: TG-TAINT-JS-PATH-TRAVERSAL | src: server UUID | sink: fsp.writeFile | write to a server-generated name
  await fsp.writeFile(dest, req.file!.buffer);
  res.status(201).json({ id, originalName: req.file!.originalname });
});

attachmentsRouter.post('/avatar', upload.single('file'), (req: Request, res: Response) => {
  const name = safeFileName(req.body.name);
  // CASE: R13-FP-09
  // ok: javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal | src: req.body.name (strictly validated) | sink: path.join | basename + ^[A-Za-z0-9_-]{1,64}\.(png|...)$ check
  const dest = path.join(UPLOAD_ROOT, 'avatars', name);
  // CASE: R10-FP-06, X-PT-FP-04
  // ok: gitlab.eslint.detect-non-literal-fs-filename, TG-TAINT-JS-PATH-TRAVERSAL | src: req.body.name (strictly validated) | sink: fs.writeFileSync | name validated by safeFileName
  fs.writeFileSync(dest, req.file!.buffer);
  res.sendStatus(204);
});

attachmentsRouter.get('/templates/:t', (req: Request, res: Response) => {
  if (!ALLOWED_TEMPLATES.has(req.params.t)) return res.status(404).end();
  // CASE: R13-FP-10
  // ok: javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal | src: req.params.t (allowlisted) | sink: path.join | value is one of three fixed filenames
  const p = path.join(TEMPLATE_DIR, req.params.t);
  // CASE: R10-FP-07, X-PT-FP-05
  // ok: gitlab.eslint.detect-non-literal-fs-filename, TG-TAINT-JS-PATH-TRAVERSAL | src: req.params.t (allowlisted) | sink: fs.readFileSync | allowlisted template read
  res.type('pdf').send(fs.readFileSync(p));
});

attachmentsRouter.get('/view', (req: Request, res: Response) => {
  const p = resolveInside(tenantDir(tenantOf(req)), String(req.query.path));
  // CASE: R10-FP-08, X-PT-FP-06
  // ok: gitlab.eslint.detect-non-literal-fs-filename, TG-TAINT-JS-PATH-TRAVERSAL | src: req.query.path (contained) | sink: fs.readFileSync | path checked by resolveInside
  res.send(fs.readFileSync(p));
});

attachmentsRouter.get('/shared', (req: Request, res: Response) => {
  const root = path.resolve(UPLOAD_ROOT, 'shared');
  // CASE: R13-AMB-01
  // tg-either: javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal | src: req.query.p | sink: path.resolve | lexical containment holds; escape needs a symlink planted in shared/ (shared/ only receives server-generated files)
  const p = path.resolve(root, String(req.query.p));
  if (!p.startsWith(root + path.sep)) return res.status(400).end();
  // CASE: R10-AMB-01, X-PT-AMB-01
  // tg-either: gitlab.eslint.detect-non-literal-fs-filename, TG-TAINT-JS-PATH-TRAVERSAL | src: req.query.p | sink: fs.readFileSync | safe unless a symlink exists inside shared/
  res.send(fs.readFileSync(p));
});

attachmentsRouter.get('/legacy', (req: Request, res: Response) => {
  const raw = String(req.query.file ?? '');
  if (raw.includes('..')) return res.status(400).end();
  const name = decodeURIComponent(raw);
  // CASE: R13-TP-06
  // ruleid: javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal | src: req.query.file | sink: path.join | ".." check runs before decoding, so %2e%2e%2f bypasses it
  const p = path.join(UPLOAD_ROOT, 'legacy', name);
  // CASE: R10-TP-04, X-PT-TP-05
  // ruleid: gitlab.eslint.detect-non-literal-fs-filename, TG-TAINT-JS-PATH-TRAVERSAL | src: req.query.file | sink: fs.readFileSync | encoded traversal read
  res.send(fs.readFileSync(p));
});

attachmentsRouter.get('/export/:name', (req: Request, res: Response) => {
  // CASE: R13-TP-07, X-PT-TP-06
  // ruleid: javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal, TG-TAINT-JS-PATH-TRAVERSAL | src: req.params.name | sink: res.download | download of a joined user path
  res.download(path.join(UPLOAD_ROOT, 'exports', req.params.name));
});

attachmentsRouter.get('/inline/:name', (req: Request, res: Response) => {
  // CASE: X-PT-FP-07
  // ok: TG-TAINT-JS-PATH-TRAVERSAL | src: req.params.name | sink: res.sendFile with root | express rejects paths outside { root }
  res.sendFile(req.params.name, { root: path.join(UPLOAD_ROOT, 'inline') });
});
