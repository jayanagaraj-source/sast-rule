// CommonJS TypeScript (.cts): loaded by the Electron desktop bridge as well as the API, so it stays require()-based.
import axios = require('axios');
import https = require('https');

const DEFAULT_TIMEOUT_MS = 8000;
const PROXY_ALLOWED_HOSTS = ['api.partner-crm.example', 'api.helpdesk.example'] as const;

export interface ProxyResult<T = unknown> {
  status: number;
  data: T;
}

export const integrationClient = {
  /** Called from POST /integrations/:id/proxy with req.body.host and req.body.path. */
  async proxy<T>(host: string, apiPath: string): Promise<ProxyResult<T>> {
    // CASE: R04-GAP-05
    // todoruleid: TG-TAINT-JS-SSRF | src: req.body.host (cross-file: routes/integrations) | sink: axios.default.get | host chosen by the caller in another file
    const r = await axios.default.get<T>(`https://${host}/${apiPath.replace(/^\/+/, '')}`, { timeout: DEFAULT_TIMEOUT_MS });
    return { status: r.status, data: r.data };
  },

  async proxyAllowed<T>(host: string, apiPath: string): Promise<ProxyResult<T>> {
    if (!(PROXY_ALLOWED_HOSTS as readonly string[]).includes(host)) throw new Error(`host ${host} not allowed`);
    // CASE: R04-FP-10
    // ok: TG-TAINT-JS-SSRF | src: caller host (allowlisted) | sink: axios.default.get | host restricted to two partner APIs
    const r = await axios.default.get<T>(`https://${host}/${apiPath.replace(/^\/+/, '')}`, { timeout: DEFAULT_TIMEOUT_MS });
    return { status: r.status, data: r.data };
  },

  /** Partner status probe over a local agent; the cert check is relaxed for the on-prem bridge only. */
  bridgeAgent(): https.Agent {
    // CASE: R03-TP-10
    // ruleid: SAST-042 | src: constant | sink: https.Agent | .cts module, verification disabled for the desktop bridge
    return new https.Agent({ rejectUnauthorized: false });
  },
};
