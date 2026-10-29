# caseflow

> **Intentionally vulnerable synthetic application.** caseflow exists to evaluate static-analysis (SAST) rules. It
> contains deliberate security defects next to safe look-alikes, each labelled with the behaviour a correct rule
> should have. Do not deploy it, do not reuse its code, and do not run it against real systems. Every credential
> in it is a random, inactive value generated for this repository; every hostname is a reserved `.example` /
> `.test` / `.invalid` name or a loopback address.

## Application overview

caseflow is a multi-tenant customer-support and case-management SaaS: tenants receive customer requests by e-mail,
chat widget and webhooks, agents work them as cases in an admin console, customers follow them in a portal, and
background jobs import history, build reports and sync third-party CRMs and helpdesks.

Business capabilities represented in the code:

| Capability | Where |
|---|---|
| Authentication, roles and tenant-aware access control | `apps/api/src/routes/middleware.ts`, `services/user-service.ts` |
| Case creation, updates, comments, search | `apps/api/src/routes/cases/`, `services/case-service.ts` |
| Attachments and file storage, metadata cache | `routes/attachments/`, `lib/path-utils.ts`, `services/storage-service.ts` |
| CSV / report generation, exports | `routes/exports/`, `services/report-service.mts`, `services/reports-dotnet` |
| Webhook receivers and outbound callbacks | `routes/webhooks/` |
| CRM, chat and ticketing integrations ("node"-style connectors) | `apps/api/src/integrations/`, `routes/integrations/`, `services/integration-client.cts` |
| Notification and e-mail templates | `apps/api/src/templates/email/`, `lib/mailer.ts`, `services/legacy-php/resources/views` |
| Admin settings and tenant branding | `routes/admin/`, `apps/portal-angular/src/app/branding` |
| Background jobs, queues, archive extraction, digest | `apps/worker/src/` |
| Admin console (React), customer widget (Vue 3), customer portal (Angular) | `apps/web-react`, `apps/widget-vue`, `apps/portal-angular` |
| Polyglot satellite services | `services/*` |
| CI, release and deploy pipelines | `.github/workflows`, `.github/actions` |

## Architecture

```
                    ┌──────────────┐  ┌──────────────┐  ┌────────────────┐
  agents ──────────▶│ web-react    │  │ widget-vue   │  │ portal-angular │◀── customers
                    └──────┬───────┘  └──────┬───────┘  └───────┬────────┘
                           └──────── HTTPS ──┴──────────────────┘
                                         ▼
     gateway-go (Go, TLS termination) ──▶ apps/api (Express + TypeScript, Koa v1 compatibility app)
                                         │   ├─ Postgres / MySQL (billing) / MongoDB (events) / Redis
                                         │   ├─ outbound: CRM, chat, helpdesk, customer webhooks, SMTP
                                         │   └─ Redis streams ──▶ apps/worker (imports, archives, digests, CRM sync)
                                         │
     ingest-py (FastAPI)   billing-java (Spring Boot)   reports-dotnet (ASP.NET Core)
     notifier-ruby (Rails) legacy-php (Laravel + Twig help centre)
```

## Modules

| Path | Stack | Notes |
|---|---|---|
| `apps/api` | Node 24, Express, Koa, TypeScript + JS (`.ts .mts .cts .js .mjs .cjs`) | REST API, connectors, e-mail templates (`.mustache .hbs .handlebars .html`) |
| `apps/worker` | TypeScript + CommonJS | Redis-stream consumer: CSV imports, zip/tar extraction, metadata cache, digests |
| `apps/web-react` | React 18 (`.tsx .jsx .ts .js`), axios, jQuery (classic console) | Agent admin console |
| `apps/widget-vue` | Vue 3 (Options API, Composition API `setup()`, `<script setup lang="ts">`) | Embeddable support widget |
| `apps/portal-angular` | Angular 18 (`.component.html` + `.ts`, decorators) | Customer portal |
| `services/ingest-py` | Python 3.11, FastAPI, requests, httpx | Inbound e-mail ingestion |
| `services/gateway-go` | Go, `net/http`, `crypto/tls` | API gateway |
| `services/billing-java` | Java 21, Spring Boot | Invoice search |
| `services/legacy-php` | PHP 8.2, Laravel, Twig (`.twig`) | Legacy help centre |
| `services/notifier-ruby` | Ruby 3.3, Rails | Notification subscriptions |
| `services/reports-dotnet` | C#, ASP.NET Core 8 | Report builder filters |
| `.github/workflows`, `.github/actions` | GitHub Actions (`.yml`, `.yaml`, reusable workflow, composite action) | CI, release, deploy |
| `ops/`, `deploy/` | Non-GitHub-Actions YAML (runbook automation, Kubernetes, compose) | Negative controls for the workflow rule |

## Security benchmark purpose

The repository is a labelled corpus for measuring precision and recall of 13 TigerGate SAST rule categories in code
that looks like a real customer's production repository: cases sit inside realistic handlers and helpers, flows
cross functions and files, and most files mix vulnerable and safe variants of the same operation.

All case files live in ordinary source directories that TigerGate scans. Paths and names excluded by
`workers/pkg/scanscope/scanscope.go` (for example `test/`, `tests/`, `spec/`, `fixtures/`, `mocks/`, `dist/`,
`build/`, `out/`, `target/`, `env/`, `vendor/`, `generated/`, `docs/`, `*.test.*`, `*.spec.*`, `*_test.go`,
`*Test.java`, `*.min.js`) are not used. Dev-only shapes (for example `apps/api/src/devtools/seed-local.ts`) are
labelled for how a rule should treat them in a scanned path.

### Rule categories

| # | Rule ID | Served for |
|---|---|---|
| R01 | `javascript.express.security.audit.xss.mustache.explicit-unescape.template-explicit-unescape` | regex on `*.mustache`, `*.hbs`, `*.html` |
| R02 | `generic.html-templates.security.unquoted-attribute-var.unquoted-attribute-var` | generic on `*.html`, `*.mustache`, `*.hbs`, `*.twig` |
| R03 | `SAST-042` | JS, TS, Python, Go |
| R04 | `TG-TAINT-JS-SSRF` | JS, TS |
| R05 | `JS-121` | JS, TS |
| R06 | `typescript.react.security.react-insecure-request.react-insecure-request` | JS, TS (incl. JSX/TSX) |
| R07 | `gitlab.eslint.detect-object-injection` | JS, TS |
| R08 | `JS-002`, `TG-TAINT-JS-PROTOTYPE-POLLUTION`, `TG-TAINT-JS-PROPERTY-INJECTION` | JS, TS |
| R09 | `yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag` | YAML |
| R10 | `gitlab.eslint.detect-non-literal-fs-filename` | JS, TS |
| R11 | `SAST-011` | JS, TS, Java, PHP, Ruby, C# |
| R12 | `javascript.vue.security.audit.xss.templates.avoid-v-html.avoid-v-html` | regex on `*.vue` |
| R13 | `javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal` | JS, TS |

Three overlap rules are labelled on the same statements so their expected behaviour is explicit:
`TG-TAINT-JS-PATH-TRAVERSAL` and `TG-TAINT-JS-ZIP-SLIP` (R10/R13 code) and
`javascript.express.security.audit.remote-property-injection.remote-property-injection` (R07/R08 code).

Non-JS services contain JS-only shapes (`dict.update` / `array_merge` / `Hash#merge`, path joins, fixed-host HTTP
calls) labelled `ok:` for the JS-only rule IDs, as negative controls proving those rules stay silent outside
JavaScript and TypeScript.

### Label conventions

Every case is a `CASE:` comment followed by one or more label comments directly above the labelled statement, in the
file's own comment syntax (`//`, `#`, `<!-- -->`, `{{! }}`, `{# #}`):

```ts
// CASE: R08-TP-07
// ruleid: JS-002 | src: req.body | sink: Object.assign | mass assignment: any column can be overwritten
Object.assign(row, req.body);
```

| Label | Meaning |
|---|---|
| `ruleid: <ID>` | Real vulnerability; the rule is expected to report this statement. |
| `ok: <ID>` | Safe code; the rule must not report it. |
| `todoruleid: <ID>` | Real vulnerability the current rule cannot cover by design (documented gap). |
| `todook: <ID>` | Safe code the current rule's pattern is known to match (documented false positive). |
| `tg-either: <ID>` | Context-dependent; reporting and not reporting are both acceptable. |

Several rules may share a statement (`ruleid: gitlab.eslint.detect-non-literal-fs-filename, TG-TAINT-JS-PATH-TRAVERSAL`);
the `CASE:` line then lists one case ID per rule, in the same order. Case IDs are `R<nn>-<TP|FP|GAP|KFP|AMB>-<nn>`
(`X-<rule>-…` for overlap rules). After `|`, each label records the attack source, the sink, and the reason.
`CASES.md` is the complete inventory, with file:line links and the per-category totals.

Labels describe the expected security behaviour decided from the data flow: source trust, validation and
sanitisation, reachability and framework behaviour. `todoruleid` is used only where the rule's documented scope
cannot express the case. `ruleid` is used wherever a correct implementation of the rule should report.

### Known coverage gaps (`todoruleid`)

| Category | Gap |
|---|---|
| R01 / R02 | `.handlebars` templates are not in either rule's file list. |
| R03 | Computed values (`rejectUnauthorized: !isProd`, `InsecureSkipVerify: cfg.Flag`), `NODE_TLS_REJECT_UNAUTHORIZED = '0'`, MongoDB `tlsAllowInvalidCertificates`, Python `ssl.CERT_NONE` and `ssl._create_unverified_context()`. |
| R04 | Cross-file helpers, axios instance `baseURL`, `undici.request`, second-order SSRF from DB rows. |
| R05 | Misspelled credential keys (`client_secrert`). |
| R06 | `axios.create({ baseURL: 'http://…' })`, runtime-built URLs, Angular `HttpClient`. |
| R07 | `Reflect.set` / `Object.defineProperty` with attacker-chosen names. |
| R08 | Object spread mass assignment, cross-file recursive merge, `lodash.merge`. |
| R09 | `docker://image:tag` references, job-level `uses:` of external reusable workflows. |
| R10 | `import { promises as fsp }`, `fs.promises.*`, `import * as fs`, computed `fse[op]()` calls. |
| R11 | Static nested-quantifier / quadratic regex literals; Python (not served); Java, PHP, Ruby and C# regex APIs (rule patterns are JS/Python-specific). |
| R13 | `path.win32.join`, weak `.replace('../', '')` (treated as a sanitiser by the rule). |

### Alternative sinks (outside the 13 rules)

These are realistic HTML-injection sinks that none of the 13 benchmark rules owns. They are deliberately unlabelled:

- `apps/web-react/src/components/CaseComments.tsx` — React `dangerouslySetInnerHTML` (DOMPurify-sanitised).
- `apps/widget-vue/src/components/ProfileCard.vue` — `innerHTML` via a template ref, and render-function `innerHTML`.
- `apps/portal-angular/src/app/case-detail/case-detail.component.html` — Angular `[innerHTML]` (Angular-sanitised).

TigerGate does not support dependency-lock enforcement for GitHub Actions (for example a required SHA-pinning
policy), so no case covers it.

## Safety limitations

- Synthetic code: it is written to parse and read like production code, not to be built or run. No dependencies are
  installed or committed.
- Credentials are random strings generated when the repository was created. They are inactive and belong to no
  service. Placeholders (`changeme`, `<your-…>`, AWS documentation keys) are intentionally fake.
- Never execute the vulnerable paths (archive extraction, regex filters, outbound requests) outside an isolated
  sandbox. Regex cases with catastrophic backtracking are documented, never run.
- Hostnames are reserved example names. `169.254.169.254` appears only as an SSRF target in a comment.
