// Tenant administration endpoints. Plain ESM JavaScript: this module predates the TypeScript migration.
import express from 'express';
import { pg } from '../../lib/db.js';
import { logger } from '../../lib/logger.js';
import { mergeDeep, safeMergeDeep, setPath } from '../../lib/merge.js';

export const adminRouter = express.Router();

// Per-tenant settings, cached in-process and flushed to Postgres every 30s.
const tenantSettings = new Map();
const runtimeConfig = {
  sla: { firstResponseHours: 4, resolutionHours: 48 },
  branding: { primaryColor: '#3b5bdb', logoUrl: '' },
  notifications: { digest: 'daily' },
};
const FROZEN_LIMITS = Object.freeze({ maxAgents: 500, maxQueues: 50 });
const SETTING_KEYS = ['locale', 'timezone', 'businessHours', 'autoCloseDays'];

const maintenance = {
  reindex: (tenantId) => pg.query('SELECT reindex_tenant($1)', [tenantId]),
  recount: (tenantId) => pg.query('SELECT recount_tenant($1)', [tenantId]),
  purgeTenant: (tenantId) => pg.query('SELECT purge_tenant($1)', [tenantId]),
};
const SAFE_ACTIONS = new Set(['reindex', 'recount']);

function settingsFor(tenantId) {
  if (!tenantSettings.has(tenantId)) tenantSettings.set(tenantId, {});
  return tenantSettings.get(tenantId);
}

adminRouter.post('/settings', (req, res) => {
  const settings = settingsFor(req.tenantId);
  // CASE: R07-TP-02, X-RPI-TP-01
  // ruleid: gitlab.eslint.detect-object-injection, javascript.express.security.audit.remote-property-injection.remote-property-injection | src: req.body.key | sink: dynamic property write | arbitrary property write: key="isTrial" or "__proto__"
  settings[req.body.key] = req.body.value;
  res.json(settings);
});

adminRouter.post('/settings/safe', function (req, res) {
  const settings = settingsFor(req.tenantId);
  const key = req.body.key;
  if (!SETTING_KEYS.includes(key)) return res.status(400).end();
  // CASE: R07-FP-07, X-RPI-FP-01
  // ok: gitlab.eslint.detect-object-injection, javascript.express.security.audit.remote-property-injection.remote-property-injection | src: req.body.key (allowlisted) | sink: dynamic property write | strict allowlist checked above
  settings[key] = req.body.value;
  res.json(settings);
});

adminRouter.post('/settings/dict', (req, res) => {
  const overrides = tenantSettings.get(`${req.tenantId}:overrides`) ?? new Map();
  // CASE: R07-FP-08
  // ok: gitlab.eslint.detect-object-injection | src: req.body.key | sink: Map.set | Map entries never touch a prototype
  overrides.set(req.body.key, req.body.value);
  tenantSettings.set(`${req.tenantId}:overrides`, overrides);
  // CASE: R07-FP-09
  // ok: gitlab.eslint.detect-object-injection | src: req.query.key | sink: Map.get | Map lookup
  res.json({ value: overrides.get(req.query.key) ?? null });
});

adminRouter.post('/settings/path', (req, res) => {
  // Sets nested settings like "sla.firstResponseHours"; the write is in lib/merge.ts setPath().
  setPath(settingsFor(req.tenantId), String(req.body.path), req.body.value);
  res.json(settingsFor(req.tenantId));
});

adminRouter.post('/maintenance', async (req, res) => {
  // CASE: R07-TP-03
  // ruleid: gitlab.eslint.detect-object-injection | src: req.query.action | sink: dynamic method call | ?action=purgeTenant runs a privileged handler
  await maintenance[req.query.action](req.tenantId);
  res.sendStatus(202);
});

adminRouter.post('/maintenance/safe', async (req, res) => {
  const action = String(req.query.action);
  if (!SAFE_ACTIONS.has(action)) return res.status(400).end();
  // CASE: R07-FP-10
  // ok: gitlab.eslint.detect-object-injection | src: req.query.action (allowlisted) | sink: dynamic method call | only reindex/recount callable
  await maintenance[action](req.tenantId);
  res.sendStatus(202);
});

adminRouter.put('/config', (req, res) => {
  // CASE: R08-TP-02
  // ruleid: JS-002 | src: req.body.section + req.body.values | sink: Object.assign | global pollution: section="__proto__" makes the target Object.prototype
  Object.assign(runtimeConfig[req.body.section], req.body.values);
  res.json(runtimeConfig);
});

adminRouter.put('/config/:section', (req, res) => {
  if (!Object.prototype.hasOwnProperty.call(runtimeConfig, req.params.section)) return res.status(404).end();
  const section = runtimeConfig[req.params.section];
  const values = {};
  for (const k of Object.keys(section)) if (Object.prototype.hasOwnProperty.call(req.body, k)) values[k] = req.body[k];
  // CASE: R08-FP-09
  // ok: JS-002 | src: req.body (keys limited to existing section keys) | sink: Object.assign | safe configuration update
  Object.assign(section, values);
  res.json(runtimeConfig);
});

adminRouter.put('/config/deep', (req, res) => {
  // Sink of the unsafe recursive merge is in lib/merge.ts (cross-file).
  mergeDeep(runtimeConfig, req.body);
  // CASE: R08-FP-10
  // ok: TG-TAINT-JS-PROTOTYPE-POLLUTION | src: req.body | sink: safeMergeDeep | hardened merge skips __proto__ / constructor / prototype
  safeMergeDeep(runtimeConfig, req.body);
  res.json(runtimeConfig);
});

adminRouter.put('/config/:section/:key', (req, res) => {
  // CASE: R08-TP-03, X-RPI-TP-02
  // ruleid: TG-TAINT-JS-PROTOTYPE-POLLUTION, javascript.express.security.audit.remote-property-injection.remote-property-injection | src: req.params | sink: obj[a][b] = c | global pollution with section="__proto__"
  runtimeConfig[req.params.section][req.params.key] = req.body.value;
  res.json(runtimeConfig);
});

adminRouter.put('/config/:section/:key/guarded', (req, res) => {
  const { section, key } = req.params;
  if (section === '__proto__' || section === 'constructor' || key === '__proto__') return res.status(400).end();
  if (!Object.prototype.hasOwnProperty.call(runtimeConfig, section)) return res.status(404).end();
  // CASE: R08-FP-11
  // ok: TG-TAINT-JS-PROTOTYPE-POLLUTION | src: req.params (guarded) | sink: obj[a][b] = c | section must be an own key; __proto__/constructor rejected
  runtimeConfig[section][key] = req.body.value;
  res.json(runtimeConfig);
});

adminRouter.put('/config/reflect', (req, res) => {
  // CASE: R07-GAP-01
  // todoruleid: gitlab.eslint.detect-object-injection | src: req.body.key | sink: Reflect.set | attacker-chosen property name via Reflect.set; the rule only matches obj[key]
  Reflect.set(runtimeConfig.notifications, req.body.key, req.body.value);
  res.json(runtimeConfig.notifications);
});

adminRouter.put('/config/define', (req, res) => {
  // CASE: R07-GAP-02
  // todoruleid: gitlab.eslint.detect-object-injection | src: req.body.name | sink: Object.defineProperty | attacker-chosen name can shadow toJSON / hasOwnProperty
  Object.defineProperty(runtimeConfig.branding, req.body.name, { value: req.body.value, enumerable: true });
  res.json(runtimeConfig.branding);
});

adminRouter.put('/limits', (req, res) => {
  // CASE: R08-FP-12
  // ok: JS-002 | src: req.body | sink: Object.assign onto a frozen object | target is frozen: in strict mode the assign throws and nothing is modified
  try { Object.assign(FROZEN_LIMITS, req.body); } catch (err) { logger.warn({ err }, 'limits are read-only'); }
  res.json(FROZEN_LIMITS);
});

adminRouter.post('/import-settings', (req, res) => {
  const imported = JSON.parse(req.body.json);
  const out = {};
  for (const [k, v] of Object.entries(imported)) {
    // CASE: R08-TP-04, R07-TP-04, X-RPI-TP-03
    // ruleid: TG-TAINT-JS-PROPERTY-INJECTION, gitlab.eslint.detect-object-injection, javascript.express.security.audit.remote-property-injection.remote-property-injection | src: JSON.parse(req.body.json) | sink: dynamic property write | imported keys written unchecked (e.g. "toString")
    out[k] = v;
  }
  res.json(out);
});

adminRouter.post('/import-settings/safe', (req, res) => {
  const imported = JSON.parse(req.body.json);
  const out = Object.create(null);
  for (const k of Object.keys(imported)) {
    if (!SETTING_KEYS.includes(k)) continue;
    // CASE: R08-FP-13, R07-FP-11, X-RPI-FP-02
    // ok: TG-TAINT-JS-PROPERTY-INJECTION, gitlab.eslint.detect-object-injection, javascript.express.security.audit.remote-property-injection.remote-property-injection | src: JSON.parse (allowlisted keys) | sink: dynamic write | allowlist + null-prototype target
    out[k] = imported[k];
  }
  res.json(out);
});
