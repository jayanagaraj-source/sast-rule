import axios from 'axios';

export const API_BASE = import.meta.env.VITE_API_BASE ?? 'https://api.caseflow.example';
export const LEGACY_REPORTS_DOCS = 'http://docs.legacy-reports.example/v1/export-format.html';

export interface CaseSummary {
  id: string;
  subject: string;
  status: 'open' | 'pending' | 'solved' | 'closed';
  updatedAt: string;
}

function authHeader(): Record<string, string> {
  const token = sessionStorage.getItem('cf_token');
  return token ? { Authorization: `Bearer ${token}` } : {};
}

// CASE: R06-FP-02
// ok: typescript.react.security.react-insecure-request.react-insecure-request | src: constant | sink: axios.create baseURL | HTTPS base URL from build config
export const api = axios.create({ baseURL: API_BASE, headers: authHeader() });

// The partner CRM sandbox has no TLS; the "Contacts" side panel still talks to it in the EU region.
// CASE: R06-GAP-02
// todoruleid: typescript.react.security.react-insecure-request.react-insecure-request | src: constant | sink: axios.create baseURL | plaintext baseURL; the rule only inspects literal URLs passed to axios.<verb>() / fetch()
export const crmSandbox = axios.create({ baseURL: 'http://sandbox.partner-crm.example/api', timeout: 5000 });

export async function listCases(): Promise<CaseSummary[]> {
  // CASE: R06-FP-03
  // ok: typescript.react.security.react-insecure-request.react-insecure-request | src: constant | sink: axios.get | relative URL on the HTTPS API instance
  const { data } = await api.get<CaseSummary[]>('/cases');
  return data;
}

export async function fetchPartnerContacts(email: string): Promise<unknown[]> {
  // CASE: R06-TP-01
  // ruleid: typescript.react.security.react-insecure-request.react-insecure-request | src: constant | sink: fetch | partner contact lookup over plaintext HTTP (customer e-mail in the query)
  const r = await fetch("http://api.partner-crm.example/v1/contacts?email=" + encodeURIComponent(email));
  return r.json();
}

export async function chargeCard(cardToken: string, amountCents: number): Promise<void> {
  // CASE: R06-TP-02
  // ruleid: typescript.react.security.react-insecure-request.react-insecure-request | src: constant | sink: axios.post | payment token sent to the billing service over unencrypted HTTP
  await axios.post("http://billing.internal.example/v1/charges", { cardToken, amountCents }, { headers: authHeader() });
}

export async function downloadLegacyReport(reportId: string): Promise<Blob> {
  // CASE: R06-TP-03
  // ruleid: typescript.react.security.react-insecure-request.react-insecure-request | src: constant | sink: fetch | bearer token sent in the Authorization header over HTTP
  const r = await fetch("http://legacy-reports.caseflow.example/export", {
    method: 'POST',
    headers: { ...authHeader(), 'content-type': 'application/json' },
    body: JSON.stringify({ reportId }),
  });
  return r.blob();
}

export async function getFeatureFlags(): Promise<Record<string, boolean>> {
  if (import.meta.env.DEV) {
    // CASE: R06-FP-04
    // ok: typescript.react.security.react-insecure-request.react-insecure-request | src: constant | sink: fetch | Vite dev proxy on localhost
    return (await fetch("http://localhost:4000/api/dev/flags")).json();
  }
  // CASE: R06-FP-05
  // ok: typescript.react.security.react-insecure-request.react-insecure-request | src: constant | sink: fetch | HTTPS endpoint
  return (await fetch("https://flags.caseflow.example/v1/flags")).json();
}

export async function regionalHealth(region: 'eu' | 'us' | 'ap'): Promise<number> {
  // CASE: R06-GAP-03
  // todoruleid: typescript.react.security.react-insecure-request.react-insecure-request | src: typed region | sink: fetch (template literal) | dynamic http URL built at runtime; the rule only matches string literals
  const r = await fetch(`http://${region}.health.caseflow.example/ping`);
  return r.status;
}

export function legacyDocsLink(): string {
  // CASE: R06-FP-06
  // ok: typescript.react.security.react-insecure-request.react-insecure-request | src: constant | sink: none | URL stored for display only, never requested
  return LEGACY_REPORTS_DOCS;
}
