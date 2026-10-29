import axios, { AxiosInstance } from 'axios';
import https from 'https';
import { logger } from './logger';

const ALLOWED_WEBHOOK_HOSTS = new Set(['hooks.chat.example', 'events.pager.example', 'outlook.mail.example']);

export function createPartnerClient(baseURL: string, token: string): AxiosInstance {
  return axios.create({
    baseURL,
    timeout: 10_000,
    headers: { Authorization: `Bearer ${token}` },
    // CASE: R03-TP-04
    // ruleid: SAST-042 | src: constant | sink: axios httpsAgent | axios instance with verification disabled
    httpsAgent: new https.Agent({ rejectUnauthorized: false }),
  });
}

export function createVerifiedClient(baseURL: string): AxiosInstance {
  // CASE: R03-FP-06
  // ok: SAST-042 | src: default | sink: axios httpsAgent | Node's default verifying agent
  return axios.create({ baseURL, timeout: 10_000, httpsAgent: new https.Agent({ keepAlive: true }) });
}

/**
 * Posts a JSON payload to a URL the caller already resolved. Used by the webhook dispatcher and by the
 * integrations "test connection" button (routes/integrations/index.ts passes req.body.endpoint).
 */
export async function postJson(url: string, body: unknown): Promise<number> {
  // CASE: R04-GAP-01
  // todoruleid: TG-TAINT-JS-SSRF | src: req.body.endpoint (cross-file caller) | sink: fetch | the source is in another file; intra-procedural taint cannot connect it
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  return res.status;
}

/** Same as postJson, but only to hosts we have a contract with. */
export async function postToAllowedWebhook(rawUrl: string, body: unknown): Promise<number> {
  const target = new URL(rawUrl);
  if (target.protocol !== 'https:' || !ALLOWED_WEBHOOK_HOSTS.has(target.hostname)) {
    logger.warn({ host: target.hostname }, 'webhook host not allowlisted');
    throw new Error('webhook host not allowed');
  }
  // CASE: R04-FP-02
  // ok: TG-TAINT-JS-SSRF | src: caller URL (allowlisted) | sink: fetch | hostname checked against a fixed allowlist first
  const res = await fetch(target.toString(), { method: 'POST', body: JSON.stringify(body) });
  return res.status;
}
