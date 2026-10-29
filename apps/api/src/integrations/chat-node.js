'use strict';

// Live-chat connector: receives conversation events from the chat vendor and turns them into cases.
const axios = require('axios');
const { caseService } = require('../services/case-service');

const CHAT_API = 'https://api.chat.example/v2';

const chatConfig = {
  workspace: 'caseflow-prod',
  // CASE: R05-TP-05
  // ruleid: JS-121 | src: hardcoded literal | sink: Authorization header | vendor API key committed in a CommonJS module
  apiKey: 'ck_live_QLyX2fiCkK9w3CZMg8MX90iC37TozxBH',
  // CASE: R05-FP-19
  // ok: JS-121 | src: env var | sink: signature check | webhook secret from the environment
  webhookSecret: process.env.CHAT_WEBHOOK_SECRET,
};

async function fetchConversation(conversationId) {
  // CASE: R04-FP-01
  // ok: TG-TAINT-JS-SSRF | src: event id (path only) | sink: axios.get | fixed vendor host
  const { data } = await axios.get(`${CHAT_API}/conversations/${encodeURIComponent(conversationId)}`, {
    headers: { Authorization: `Bearer ${chatConfig.apiKey}` },
  });
  return data;
}

/** Called by routes/webhooks with the (unauthenticated) vendor event body. */
async function onConversationClosed(tenantId, event) {
  const conversation = await fetchConversation(event.conversationId);
  const draft = { tenantId, subject: conversation.title, status: 'open', priority: 'normal' };
  // CASE: R08-TP-01
  // ruleid: JS-002 | src: webhook payload (event.fields) | sink: Object.assign | mass assignment: the event can set status, priority or tenantId on the new case
  Object.assign(draft, event.fields);
  return caseService.create(draft);
}

function applyTheme(widgetEl, theme) {
  // CASE: R08-FP-02
  // ok: JS-002 | src: tenant theme | sink: Object.assign(el.style, ...) | DOM style update, no prototype or privilege impact
  Object.assign(widgetEl.style, { color: theme.text, background: theme.background });
}

module.exports = { fetchConversation, onConversationClosed, applyTheme };
