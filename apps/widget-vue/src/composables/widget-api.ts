import axios from 'axios';

const WIDGET_API = (window as unknown as { CASEFLOW_WIDGET_API?: string }).CASEFLOW_WIDGET_API ?? 'https://widget-api.caseflow.example';

export const widgetApi = axios.create({
  baseURL: WIDGET_API,
  withCredentials: true,
  timeout: 8000,
});

export async function trackOpen(widgetId: string): Promise<void> {
  // CASE: R06-TP-08
  // ruleid: typescript.react.security.react-insecure-request.react-insecure-request | src: constant | sink: axios.post | widget analytics beacon over plaintext HTTP (carries the visitor cookie id)
  await axios.post("http://beacon.caseflow.example/v1/open", { widgetId, visitor: document.cookie.match(/cf_vid=([\w-]{1,64})/)?.[1] });
}
