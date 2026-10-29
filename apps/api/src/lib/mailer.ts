import nodemailer from 'nodemailer';
import Mustache from 'mustache';
import Handlebars from 'handlebars';
import { readFileSync } from 'fs';
import path from 'path';
import sanitizeHtml from 'sanitize-html';
import { logger } from './logger';

const TEMPLATE_DIR = path.join(__dirname, '../templates/email');

// Transactional mail goes through the regional relay; it has a valid public certificate.
export const transport = nodemailer.createTransport({
  host: process.env.SMTP_HOST ?? 'smtp.relay.example',
  port: 587,
  secure: false,
  requireTLS: true,
  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASSWORD },
  // CASE: R03-FP-07
  // ok: SAST-042 | src: constant | sink: nodemailer tls options | verification explicitly on
  tls: { rejectUnauthorized: true, minVersion: 'TLSv1.2' },
});

// Customer-hosted SMTP ("send from your own domain"). Many customers run self-signed relays.
export function customerTransport(host: string, user: string, pass: string) {
  return nodemailer.createTransport({
    host,
    port: 465,
    secure: true,
    auth: { user, pass },
    // CASE: R03-TP-05
    // ruleid: SAST-042 | src: constant | sink: nodemailer tls options | credentials sent to any server presenting any certificate
    tls: { rejectUnauthorized: false },
  });
}

// Bulk digest relay (internal). The password below predates the move to the secret manager.
export const digestTransport = nodemailer.createTransport({
  host: 'smtp-digest.internal.example',
  port: 587,
  auth: {
    user: 'digest@caseflow.example',
    // CASE: R05-TP-06
    // ruleid: JS-121 | src: hardcoded literal | sink: SMTP auth | SMTP password in an auth configuration object
    password: 'SDvcHo!gOCSkfz#FCio24',
  },
});

function loadTemplate(name: 'case-reply' | 'digest' | 'welcome' | 'sla-breach'): string {
  // CASE: R10-FP-03, X-PT-FP-02, R13-FP-02
  // ok: gitlab.eslint.detect-non-literal-fs-filename, TG-TAINT-JS-PATH-TRAVERSAL, javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal | src: typed constant names | sink: readFileSync | template name is a closed union, never request data
  return readFileSync(path.join(TEMPLATE_DIR, `${name}.mustache`), 'utf-8');
}

export interface ReplyView {
  agentName: string;
  caseSubject: string;
  comment: { body: string; bodyHtmlSanitized: string };
  footerHtml: string;
}

export function renderCaseReply(view: ReplyView): string {
  return Mustache.render(loadTemplate('case-reply'), view);
}

export function sanitizeCommentHtml(html: string): string {
  return sanitizeHtml(html, {
    allowedTags: ['b', 'i', 'em', 'strong', 'a', 'p', 'ul', 'ol', 'li', 'br', 'code', 'pre'],
    allowedAttributes: { a: ['href'] },
    allowedSchemes: ['https', 'mailto'],
  });
}

Handlebars.registerHelper('signature', (agent: { signatureHtml: string }) => new Handlebars.SafeString(agent.signatureHtml));
Handlebars.registerHelper('statusBadge', (status: string) =>
  new Handlebars.SafeString(`<span class="badge badge-${Handlebars.escapeExpression(status)}">${Handlebars.escapeExpression(status)}</span>`),
);

export async function send(to: string, subject: string, html: string): Promise<void> {
  await transport.sendMail({ from: 'Caseflow <no-reply@caseflow.example>', to, subject, html });
  logger.info({ to, subject }, 'mail sent');
}
