// Legacy admin widgets (pre-2022), still bundled for the "Classic" console. CommonJS + jQuery.
const axios = require('axios');
const $ = require('jquery');

const WIDGET_DEFAULTS = { theme: 'light', compact: false, columns: ['subject', 'status'] };

function loadQueueStats(queueId) {
  // CASE: R06-TP-04
  // ruleid: typescript.react.security.react-insecure-request.react-insecure-request | src: constant | sink: axios.get | plaintext HTTP request from the browser
  return axios.get("http://stats.caseflow.example/queues/" + queueId);
}

function archiveQueue(queueId, token) {
  // CASE: R06-TP-05
  // ruleid: typescript.react.security.react-insecure-request.react-insecure-request | src: constant | sink: axios(config) | session token sent over HTTP in an axios config object
  return axios({ url: "http://stats.caseflow.example/queues/archive", method: 'post', data: { queueId, token } });
}

function removeQueue(queueId) {
  // CASE: R06-FP-07
  // ok: typescript.react.security.react-insecure-request.react-insecure-request | src: constant | sink: axios.delete | HTTPS
  return axios.delete("https://api.caseflow.example/queues/" + queueId);
}

function debugInspector() {
  // CASE: R06-FP-08
  // ok: typescript.react.security.react-insecure-request.react-insecure-request | src: constant | sink: fetch | loopback-only developer endpoint (Node inspector), development builds only
  return fetch("http://127.0.0.1:9229/json/list");
}

function restoreWidgetOptions() {
  // Options are shared via URL fragments: /classic#{"compact":true}
  const fromHash = JSON.parse(decodeURIComponent(window.location.hash.slice(1) || '{}'));
  const widgetOptions = {};
  // CASE: R08-TP-15
  // ruleid: TG-TAINT-JS-PROTOTYPE-POLLUTION | src: URL fragment via JSON.parse | sink: jQuery deep extend | global pollution: #{"__proto__":{"isAdmin":true}} on jQuery < 3.4
  $.extend(true, widgetOptions, fromHash);
  // CASE: R08-FP-22
  // ok: TG-TAINT-JS-PROTOTYPE-POLLUTION | src: constant defaults | sink: jQuery deep extend | trusted defaults only
  $.extend(true, widgetOptions, WIDGET_DEFAULTS);
  return widgetOptions;
}

module.exports = { loadQueueStats, archiveQueue, removeQueue, debugInspector, restoreWidgetOptions };
