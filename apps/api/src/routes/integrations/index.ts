import { Router, Request, Response } from 'express';
import axios from 'axios';
import { postJson, postToAllowedWebhook, createVerifiedClient } from '../../lib/http-client';
import { integrationClient } from '../../services/integration-client.cjs';
import { requireAuth, requireAdmin, AuthedRequest } from '../middleware';
import { pg } from '../../lib/db';

export const integrationsRouter = Router();
integrationsRouter.use(requireAuth, requireAdmin);

const PROVIDER_HOSTS: Record<string, string> = {
  helpdesk: 'helpdesk.example',
  desk: 'desk.example',
  crm: 'my.crm.example',
};
const SUBDOMAIN = /^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$/;

// "Test connection" button in Settings → Integrations → Custom webhook (sink is in lib/http-client.ts).
integrationsRouter.post('/test-connection', async (req: Request, res: Response) => {
  const status = await postJson(req.body.endpoint, { type: 'caseflow.ping' });
  res.json({ ok: status < 400, status });
});

integrationsRouter.post('/test-connection/raw', async (req: Request, res: Response) => {
  const { endpoint, token } = req.body as { endpoint: string; token?: string };
  // CASE: R04-TP-03
  // ruleid: TG-TAINT-JS-SSRF | src: req.body.endpoint | sink: axios(config) | axios config object with a user-supplied url (multi-line)
  const r = await axios({
    url: endpoint,
    method: 'GET',
    headers: token ? { Authorization: `Bearer ${token}` } : {},
    timeout: 5000,
  });
  res.json({ ok: true, status: r.status });
});

integrationsRouter.post('/test-connection/base', async (req: Request, res: Response) => {
  const client = createVerifiedClient(req.body.baseUrl);
  // CASE: R04-GAP-02
  // todoruleid: TG-TAINT-JS-SSRF | src: req.body.baseUrl | sink: axios instance baseURL | the sink call only sees "/api/v2/me"; baseURL is set on the instance
  const r = await client.get('/api/v2/me');
  res.json({ ok: true, status: r.status });
});

integrationsRouter.post('/test-connection/post', async (req: Request, res: Response) => {
  // CASE: R04-TP-04
  // ruleid: TG-TAINT-JS-SSRF | src: req.body.endpoint | sink: axios.post | TS non-null + type assertion on the source
  const r = await axios.post(req.body!.endpoint as string, { ping: true });
  res.json({ status: r.status });
});

integrationsRouter.post('/test-connection/provider', async (req: Request, res: Response) => {
  const provider = String(req.body.provider);
  const subdomain = String(req.body.subdomain);
  const baseHost = PROVIDER_HOSTS[provider];
  if (!baseHost || !SUBDOMAIN.test(subdomain)) return res.status(400).json({ error: 'invalid provider or subdomain' });
  // CASE: R04-FP-07
  // ok: TG-TAINT-JS-SSRF | src: req.body (validated) | sink: axios.get | host = validated DNS label + allowlisted provider domain
  const r = await axios.get(`https://${subdomain}.${baseHost}/api/v2/users/me.json`, { timeout: 5000 });
  res.json({ status: r.status });
});

integrationsRouter.post('/test-connection/chat', async (req: Request, res: Response) => {
  const url = new URL(String(req.body.webhookUrl));
  if (url.protocol !== 'https:' || url.hostname !== 'hooks.chat.example') return res.status(400).end();
  // CASE: R04-FP-08
  // ok: TG-TAINT-JS-SSRF | src: req.body.webhookUrl (hostname pinned) | sink: fetch | exact hostname and scheme check before the call
  const r = await fetch(url, { method: 'POST', body: JSON.stringify({ text: 'Caseflow connected' }) });
  res.json({ status: r.status });
});

integrationsRouter.post('/test-connection/allowlisted', async (req: Request, res: Response) => {
  res.json({ status: await postToAllowedWebhook(String(req.body.webhookUrl), { ping: true }) });
});

integrationsRouter.post('/:id/sync', async (req: Request, res: Response) => {
  // The CRM base URL was typed in by the tenant admin when the integration was created (not validated).
  const { rows } = await pg.query('SELECT base_url FROM integrations WHERE id = $1 AND tenant_id = $2', [
    req.params.id,
    (req as AuthedRequest).tenantId,
  ]);
  // CASE: R04-GAP-03
  // todoruleid: TG-TAINT-JS-SSRF | src: DB row written by a tenant user | sink: fetch | second-order SSRF; DB rows are not taint sources
  const r = await fetch(`${rows[0].base_url}/api/contacts?updated_since=${encodeURIComponent(String(req.query.since))}`);
  res.json(await r.json());
});

integrationsRouter.post('/:id/proxy', async (req: Request, res: Response) => {
  res.json(await integrationClient.proxy(req.body.host, req.body.path));
});
