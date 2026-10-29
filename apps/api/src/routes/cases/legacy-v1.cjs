// Legacy Koa app still serving the v1 public API for customers on the 2021 SDK. CommonJS, no build step.
const Koa = require('koa');
const Router = require('@koa/router');
const bodyParser = require('koa-bodyparser');
const fs = require('fs');
const path = require('path');
const { pg } = require('../../lib/db');

const app = new Koa();
const router = new Router({ prefix: '/v1' });
const KB_DIR = path.join(__dirname, '../../../assets/kb');

router.put('/contacts/:id', async (ctx) => {
  const { rows } = await pg.query('SELECT * FROM contacts WHERE id = $1', [ctx.params.id]);
  const contact = rows[0];
  // CASE: R08-TP-06
  // ruleid: JS-002 | src: ctx.request.body | sink: Object.assign | mass assignment: Koa body copied onto the DB row
  Object.assign(contact, ctx.request.body);
  await pg.query('UPDATE contacts SET data = $2 WHERE id = $1', [contact.id, contact]);
  ctx.body = contact;
});

router.get('/kb/:article', async (ctx) => {
  // CASE: R13-TP-08
  // ruleid: javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal | src: ctx.params.article | sink: path.join | Koa route param joined into the KB path
  const file = path.join(KB_DIR, ctx.params.article + '.md');
  // CASE: R10-TP-05, X-PT-GAP-02
  // ruleid: gitlab.eslint.detect-non-literal-fs-filename | src: ctx.params.article | sink: fs.readFileSync | CommonJS fs read of a request-derived path
  // todoruleid: TG-TAINT-JS-PATH-TRAVERSAL | src: ctx.params.article | sink: fs.readFileSync | Koa ctx.params is not in the taint rule's source list
  ctx.body = fs.readFileSync(file, 'utf8');
});

router.get('/kb-index', async (ctx) => {
  // CASE: R10-FP-09, X-PT-FP-08
  // ok: gitlab.eslint.detect-non-literal-fs-filename, TG-TAINT-JS-PATH-TRAVERSAL | src: static | sink: fs.readdirSync | constant directory
  ctx.body = fs.readdirSync(KB_DIR);
});

router.get('/build-info', async (ctx) => {
  // CASE: R10-FP-10, X-PT-FP-09
  // ok: gitlab.eslint.detect-non-literal-fs-filename, TG-TAINT-JS-PATH-TRAVERSAL | src: static | sink: fs.readFileSync | literal path
  ctx.body = fs.readFileSync('/etc/caseflow/build-info.txt', 'utf8');
});

app.use(bodyParser()).use(router.routes());
module.exports = app;
