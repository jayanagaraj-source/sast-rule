// Builds the daily digest e-mail (templates/email/digest.hbs) for every agent.
import Handlebars from 'handlebars';
import fs from 'fs';
import path from 'path';
import { logger } from '../lib/logger';

const TEMPLATE_PATH = path.join(__dirname, '../../../api/src/templates/email/digest.hbs');

interface DigestCase {
  subject: string;
  status: string;
  lastMessageHtml: string;
}

/** Server-built summary list rendered with triple-stash in digest.hbs: every value is escaped here. */
export function buildElements(cases: DigestCase[]): string {
  return `<ul>${cases.map((c) => `<li>${Handlebars.escapeExpression(c.subject)} — ${Handlebars.escapeExpression(c.status)}</li>`).join('')}</ul>`;
}

export function renderDigest(view: { clientLogo: string; tableWidth: number; cases: DigestCase[]; agent: { signatureHtml: string } }): string {
  // CASE: R10-FP-22, X-PT-FP-15
  // ok: gitlab.eslint.detect-non-literal-fs-filename, TG-TAINT-JS-PATH-TRAVERSAL | src: constant | sink: fs.readFileSync | template path fixed at module load
  const template = Handlebars.compile(fs.readFileSync(TEMPLATE_PATH, 'utf-8'));
  const html = template({ ...view, elements: buildElements(view.cases) });
  logger.debug({ bytes: html.length }, 'digest rendered');
  return html;
}
