import express, { Request, Response } from 'express';
import { userService, UserRecord } from '../../services/user-service';
import { requireAuth, requireAdmin, AuthedRequest } from '../middleware';

export const usersRouter = express.Router();
usersRouter.use(requireAuth);

const PROFILE_FIELDS = new Set(['displayName', 'locale', 'timezone', 'signature']);
const PUBLIC_FIELDS = ['id', 'displayName', 'email', 'locale'] as const;

// Arrow handler: profile update.
usersRouter.put('/me', async (req: Request, res: Response) => {
  const user = await userService.findById((req as AuthedRequest).userId);
  // CASE: R08-TP-07
  // ruleid: JS-002 | src: req.body | sink: Object.assign | mass assignment: {"role":"admin","tenantId":"<other>"} escalates
  Object.assign(user, req.body);
  await userService.save(user);
  res.json(userService.toPublic(user));
});

// Classic function handler: admin edits another user.
usersRouter.put('/:id', requireAdmin, async function updateUser(req: Request, res: Response) {
  const user = await userService.findById(req.params.id);
  const patch = req.body as Partial<UserRecord>;
  // CASE: R08-TP-08
  // ruleid: JS-002 | src: req.body (variable hop) | sink: Object.assign | mass assignment: passwordHash / mfaSecret writable
  Object.assign(user, patch);
  await userService.save(user);
  res.json(userService.toPublic(user));
});

usersRouter.put('/me/preferences', async (req: Request, res: Response) => {
  const user = await userService.findById((req as AuthedRequest).userId);
  const prefs: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(req.body ?? {})) {
    if (!PROFILE_FIELDS.has(k)) continue;
    // CASE: R07-FP-12, X-RPI-FP-03
    // ok: gitlab.eslint.detect-object-injection, javascript.express.security.audit.remote-property-injection.remote-property-injection | src: req.body key (allowlisted) | sink: dynamic property write | key checked against a fixed Set first
    prefs[k] = v;
  }
  // CASE: R08-FP-16
  // ok: JS-002 | src: req.body (allowlisted) | sink: Object.assign | only allowlisted keys reach the target
  Object.assign(user, prefs);
  await userService.save(user);
  res.json(userService.toPublic(user));
});

usersRouter.post('/', requireAdmin, async (req: Request, res: Response) => {
  // CASE: R08-TP-09
  // ruleid: JS-002 | src: req.body | sink: Object.assign (3 args) | mass assignment: the request body wins over the defaults
  const record = Object.assign({}, userService.defaults(), req.body);
  res.status(201).json(userService.toPublic(await userService.create(record)));
});

usersRouter.post('/invite', requireAdmin, async (req: Request, res: Response) => {
  const invite = { email: String(req.body.email), role: 'agent' as const };
  // CASE: R08-FP-17
  // ok: JS-002 | src: server defaults + two fixed fields | sink: Object.assign | no request object is merged
  const record = Object.assign(userService.defaults(), invite);
  res.status(201).json(userService.toPublic(await userService.create(record)));
});

usersRouter.get('/:id/attribute', requireAdmin, async (req: Request, res: Response) => {
  const user = await userService.findById(req.params.id);
  // CASE: R07-TP-08
  // ruleid: gitlab.eslint.detect-object-injection | src: req.query.field | sink: dynamic property read | ?field=passwordHash returns the hash
  res.json({ value: (user as any)[req.query.field as string] });
});

usersRouter.get('/:id/public', async (req: Request, res: Response) => {
  const user = await userService.findById(req.params.id);
  const field = String(req.query.field);
  if (!(PUBLIC_FIELDS as readonly string[]).includes(field)) return res.status(400).end();
  // CASE: R07-FP-13
  // ok: gitlab.eslint.detect-object-injection | src: req.query.field (allowlisted) | sink: dynamic property read | strict allowlist checked first
  res.json({ value: user[field as (typeof PUBLIC_FIELDS)[number]] });
});

usersRouter.post('/:id/unlock', requireAdmin, async (req: Request, res: Response) => {
  // CASE: R07-TP-09
  // ruleid: gitlab.eslint.detect-object-injection | src: req.body.method | sink: dynamic method call | ?method=deleteAccount (or any service method) is invoked
  await (userService as any)[req.body.method](req.params.id);
  res.sendStatus(204);
});
