import fs from 'fs';
import path from 'path';
import { defaults, CaseflowConfig, OAuthClientConfig } from './defaults';
import { logger } from '../lib/logger';

const CONFIG_DIR = path.resolve(__dirname, '../../config');

function readJsonConfig(name: string): Partial<CaseflowConfig> {
  // CASE: R13-FP-01
  // ok: javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal | src: NODE_ENV | sink: path.join | name is the deploy environment chosen by ops, not request data
  const file = path.join(CONFIG_DIR, `${name}.json`);
  // CASE: R10-FP-01
  // ok: gitlab.eslint.detect-non-literal-fs-filename | src: trusted config path | sink: fs.existsSync | existence check on the config file
  if (!fs.existsSync(file)) {
    logger.warn({ file }, 'config file missing, using defaults');
    return {};
  }
  // CASE: R10-FP-02, X-PT-FP-01
  // ok: gitlab.eslint.detect-non-literal-fs-filename, TG-TAINT-JS-PATH-TRAVERSAL | src: trusted config path | sink: fs.readFileSync | config directory + environment name
  return JSON.parse(fs.readFileSync(file, 'utf-8'));
}

// Third-party OAuth apps. Production values are injected by the deploy pipeline; the helpdesk bridge app still has
// a secret pinned here from the 2023 migration (CF-2231 tracks moving it to the secret manager).
const oauthClients: Record<string, OAuthClientConfig> = {
  crm: {
    clientId: '3MVG9fe4g9fhX0E5Yp1y6a8Vq2.caseflowprod',
    // CASE: R05-FP-15
    // ok: JS-121 | src: env var | sink: OAuth token exchange | secret read from the environment
    clientSecret: process.env.CRM_CLIENT_SECRET ?? '',
    tokenUrl: 'https://login.crm.example/services/oauth2/token',
    scopes: ['api', 'refresh_token'],
  },
  helpdesk: {
    clientId: 'caseflow_bridge',
    // CASE: R05-TP-03
    // ruleid: JS-121 | src: hardcoded literal | sink: OAuth token exchange | client secret literal
    clientSecret: 'ENTBALOOl1zLBF3Y07DKHaKgI039O8yTpNoxiot4',
    tokenUrl: 'https://caseflow.helpdesk.example/oauth/tokens',
    scopes: ['read', 'write'],
  },
  marketing: {
    clientId: 'b1c7f0de-caseflow',
    // CASE: R05-FP-16
    // ok: JS-121 | src: secret manager | sink: boot-time resolver | Vault path reference, not key material
    clientSecret: 'vault:secret/data/caseflow/marketing',
    tokenUrl: 'https://api.marketing.example/oauth/v1/token',
    scopes: ['contacts.read'],
  },
  chat: {
    clientId: 'ic_caseflow',
    // CASE: R05-FP-17
    // ok: JS-121 | src: secret manager | sink: boot-time resolver | AWS Secrets Manager ARN, a pointer to the secret
    clientSecret: 'arn:aws:secretsmanager:eu-west-1:482915736104:secret:caseflow/chat-oauth-Qm3xTz',
    tokenUrl: 'https://api.chat.example/auth/token',
    scopes: [],
  },
};

// Legacy desk connector config, still loaded by integrations/desk-node.ts.
export const deskOAuth = {
  client_id: 'caseflow-desk-connector',
  // CASE: R05-TP-04
  // ruleid: JS-121 | src: hardcoded literal | sink: OAuth token exchange | snake_case client_secret literal
  client_secret: 'B3oqvotMhju2ZSW6gE7qNrvQxolFPeXo',
  token_url: 'https://caseflow.desk.example/oauth/token',
};

// Ticket-sync bridge (2021). The key name has a typo that the bridge itself relies on.
export const ticketBridgeOAuth = {
  client_id: 'caseflow-ticket-bridge',
  // CASE: R05-GAP-01
  // todoruleid: JS-121 | src: hardcoded literal | sink: OAuth token exchange | misspelled "client_secrert" holds a live secret; a name-based rule cannot see it
  client_secrert: 'zBKLSvCMz4sfVS93wPnJ15hOuoszzDN3',
};

export function loadConfig(): CaseflowConfig {
  const env = process.env.NODE_ENV ?? 'development';
  const fileCfg = readJsonConfig(env);
  // CASE: R08-FP-01
  // ok: JS-002 | src: config file + defaults | sink: Object.assign | server-owned config only (3-arg form)
  const merged: CaseflowConfig = Object.assign({}, defaults, fileCfg);
  merged.integrations = oauthClients;
  merged.database.password = process.env.DB_PASSWORD ?? merged.database.password;
  return merged;
}

export const config = loadConfig();
