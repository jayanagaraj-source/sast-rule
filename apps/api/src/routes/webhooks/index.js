'use strict';

// Webhook receivers and outbound subscription callbacks. CommonJS (still loaded by the legacy bootstrap).
const express = require('express');
const http = require('http');
const https = require('https');
const crypto = require('crypto');
const got = require('got');
const fetch = require('node-fetch');
const { request: undiciRequest } = require('undici');
const _ = require('lodash');
const deepmerge = require('deepmerge');
const { pg } = require('../../lib/db');
const { logger } = require('../../lib/logger');
const { enqueue } = require('../../services/queue');

const router = express.Router();

const DEFAULT_DELIVERY = { retries: 3, timeoutMs: 5000, format: 'json' };

function verifySignature(req) {
  const sig = Buffer.from(req.get('x-caseflow-signature-256') || '');
  const mac = Buffer.from(crypto.createHmac('sha256', process.env.WEBHOOK_INBOUND_SECRET).update(req.rawBody).digest('hex'));
  return sig.length === mac.length && crypto.timingSafeEqual(sig, mac);
}

// Customers register a callback URL; we POST a "subscription confirmed" event to it.
router.post('/subscriptions', async function subscribe(req, res) {
  const callbackUrl = req.body.callbackUrl;
  // CASE: R04-TP-05
  // ruleid: TG-TAINT-JS-SSRF | src: req.body.callbackUrl | sink: node-fetch | webhook callback fetched server-side (internal hosts reachable)
  const r = await fetch(callbackUrl, { method: 'POST', body: JSON.stringify({ type: 'subscription.confirmed' }) });
  await pg.query('INSERT INTO webhook_subscriptions (tenant_id, url) VALUES ($1, $2)', [req.tenantId, callbackUrl]);
  res.status(r.ok ? 201 : 422).end();
});

router.post('/subscriptions/verify', async (req, res) => {
  // CASE: R04-TP-06
  // ruleid: TG-TAINT-JS-SSRF | src: req.body.callbackUrl | sink: fetch (redirect: follow) | follows redirects wherever the attacker URL points
  const r = await fetch(req.body.callbackUrl, { redirect: 'follow' });
  res.json({ status: r.status });
});

router.post('/relay', (req, res) => {
  const upstream = 'http://' + req.headers['x-forwarded-host'] + '/internal/relay';
  // CASE: R04-TP-07
  // ruleid: TG-TAINT-JS-SSRF | src: req.headers x-forwarded-host (string concatenation) | sink: http.get | header-chosen host
  http.get(upstream, (r) => r.pipe(res));
});

router.get('/replay', (req, res) => {
  const target = new URL(req.cookies.replay_target);
  // CASE: R04-TP-08
  // ruleid: TG-TAINT-JS-SSRF | src: req.cookies.replay_target | sink: https.request | new URL() over a cookie value
  const out = https.request(target, { method: 'POST' }, (r) => res.sendStatus(r.statusCode));
  out.end(JSON.stringify({ replay: true }));
});

router.post('/forward/:host', async (req, res) => {
  // CASE: R04-TP-09
  // ruleid: TG-TAINT-JS-SSRF | src: req.params.host | sink: got | path-param host in a template literal
  const body = await got(`https://${req.params.host}/hooks/caseflow`, { method: 'POST', json: req.body }).text();
  res.send(body);
});

router.post('/forward-undici', async (req, res) => {
  // CASE: R04-GAP-04
  // todoruleid: TG-TAINT-JS-SSRF | src: req.body.url | sink: undici.request | undici.request is not in the rule's sink list
  const { statusCode } = await undiciRequest(req.body.url, { method: 'POST', body: JSON.stringify(req.body.event) });
  res.json({ statusCode });
});

router.post('/status-page', async (req, res) => {
  // CASE: R04-FP-09
  // ok: TG-TAINT-JS-SSRF | src: constant URL | sink: got | trusted fixed integration endpoint; request data only in the JSON body
  const body = await got('https://status.caseflow.example/api/v1/incidents', { method: 'POST', json: { note: req.body.note } }).json();
  res.json(body);
});

router.post('/inbound/:tenant', async (req, res) => {
  if (!verifySignature(req)) return res.status(401).end();
  // Old integrations send the event as a JSON string in "payload".
  const event = JSON.parse(req.body.payload);
  const delivery = {};
  // CASE: R08-TP-10
  // ruleid: JS-002 | src: JSON.parse(req.body.payload) | sink: Object.assign | target-object prototype mutation: "__proto__" in the payload swaps delivery's prototype
  Object.assign(delivery, event);
  // CASE: R08-FP-18
  // ok: JS-002 | src: constant defaults | sink: Object.assign | server constants copied onto a fresh object
  const settings = Object.assign({}, DEFAULT_DELIVERY);
  await enqueue('webhook.inbound', { tenant: req.params.tenant, type: delivery.type, settings });
  res.sendStatus(202);
});

router.post('/inbound/:tenant/fields', (req, res) => {
  const fields = JSON.parse(req.body.fields);
  const mapping = {};
  for (const section of Object.keys(fields)) {
    // CASE: R08-AMB-02, X-RPI-AMB-01
    // tg-either: TG-TAINT-JS-PROPERTY-INJECTION, javascript.express.security.audit.remote-property-injection.remote-property-injection | src: JSON.parse(req.body.fields) | sink: dynamic write | writes mapping["__proto__"] = Object.prototype, a no-op; the harm is the next write
    mapping[section] = mapping[section] || {};
    for (const name of Object.keys(fields[section])) {
      // CASE: R08-TP-11, X-RPI-TP-05
      // ruleid: TG-TAINT-JS-PROTOTYPE-POLLUTION, javascript.express.security.audit.remote-property-injection.remote-property-injection | src: JSON.parse(req.body.fields) | sink: obj[a][b] = c | global pollution: section="__proto__" writes Object.prototype[name]
      mapping[section][name] = fields[section][name];
    }
  }
  res.json(mapping);
});

router.post('/inbound/:tenant/defaults', (req, res) => {
  const merged = {};
  // CASE: R08-TP-12
  // ruleid: TG-TAINT-JS-PROTOTYPE-POLLUTION | src: req.body | sink: lodash.defaultsDeep | global pollution with {"__proto__":{...}} on vulnerable lodash
  _.defaultsDeep(merged, req.body, DEFAULT_DELIVERY);
  res.json(merged);
});

router.post('/inbound/:tenant/set', (req, res) => {
  const target = {};
  // CASE: R08-TP-13
  // ruleid: TG-TAINT-JS-PROTOTYPE-POLLUTION | src: req.body.path | sink: lodash.set | global pollution with path "constructor.prototype.isAdmin"
  _.set(target, req.body.path, req.body.value);
  res.json(target);
});

router.post('/inbound/:tenant/set-safe', (req, res) => {
  const ALLOWED = new Set(['retries', 'timeoutMs', 'format']);
  if (!ALLOWED.has(req.body.path)) return res.status(400).end();
  const target = Object.create(null);
  // CASE: R08-FP-19
  // ok: TG-TAINT-JS-PROTOTYPE-POLLUTION | src: req.body.path (allowlisted) | sink: lodash.set | one of three flat keys into a null-prototype object
  _.set(target, req.body.path, req.body.value);
  res.json(target);
});

router.post('/inbound/:tenant/merge', (req, res) => {
  // CASE: R08-GAP-03
  // todoruleid: TG-TAINT-JS-PROTOTYPE-POLLUTION | src: req.body | sink: lodash.merge | lodash.merge (<4.17.12) is not in the sink list (only mergeWith/defaultsDeep)
  const merged = _.merge({}, DEFAULT_DELIVERY, req.body);
  // CASE: R08-FP-20
  // ok: TG-TAINT-JS-PROTOTYPE-POLLUTION | src: req.body | sink: deepmerge | deepmerge >=4 skips __proto__ and constructor keys; result is a fresh object
  const cfg = deepmerge(DEFAULT_DELIVERY, req.body);
  logger.info({ merged, cfg }, 'merged delivery config');
  res.json(cfg);
});

module.exports = router;
