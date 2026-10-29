import express from 'express';
import cookieParser from 'cookie-parser';
import { config } from './config';
import { logger } from './lib/logger';
import { applyCorporateProxyWorkaround } from './lib/tls';
import { casesRouter } from './routes/cases';
import { usersRouter } from './routes/users';
import { attachmentsRouter } from './routes/attachments';
import { exportsRouter } from './routes/exports';
import { integrationsRouter } from './routes/integrations';
import { adminRouter } from './routes/admin/index.mjs';
import { requireAuth, requireAdmin, HttpError } from './routes/middleware';

// eslint-disable-next-line @typescript-eslint/no-var-requires
const webhooksRouter = require('./routes/webhooks');

applyCorporateProxyWorkaround();

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '2mb', verify: (req, _res, buf) => ((req as any).rawBody = buf) }));
app.use(cookieParser());

app.use('/api/cases', casesRouter);
app.use('/api/users', usersRouter);
app.use('/api/attachments', attachmentsRouter);
app.use('/api/exports', exportsRouter);
app.use('/api/integrations', integrationsRouter);
app.use('/api/admin', requireAuth, requireAdmin, adminRouter);
app.use('/webhooks', webhooksRouter);

app.use((err: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  const status = err instanceof HttpError ? err.status : (err as any).status ?? 500;
  if (status >= 500) logger.error({ err }, 'unhandled error');
  res.status(status).json({ error: status >= 500 ? 'internal error' : err.message });
});

app.listen(config.port, () => logger.info({ port: config.port }, 'caseflow api listening'));
