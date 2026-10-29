// Built-in defaults. Anything secret must come from the environment or the secret manager; values here are either
// non-sensitive or deliberate fallbacks that ops signed off on (see CF-2231 for the ones still to be moved).

export interface OAuthClientConfig {
  clientId: string;
  clientSecret: string;
  tokenUrl: string;
  scopes: string[];
}

export interface CaseflowConfig {
  env: string;
  port: number;
  publicUrl: string;
  database: {
    host: string;
    port: number;
    user: string;
    password: string;
    database: string;
    tls: 'disable' | 'require' | 'verify-full';
  };
  redisUrl: string;
  auth: {
    jwtIssuer: string;
    jwtSecret: string;
    sessionCookie: string;
    tokenType: string;
    passwordPolicyRegex: string;
  };
  integrations: Record<string, OAuthClientConfig>;
  uploads: { dir: string; maxBytes: number };
}

export const SIGNATURE_HEADER = 'X-Caseflow-Signature-256';

export const defaults: CaseflowConfig = {
  env: 'development',
  port: 8080,
  publicUrl: 'http://localhost:8080',
  database: {
    host: 'localhost',
    port: 5432,
    user: 'caseflow',
    // CASE: R05-FP-01
    // ok: JS-121 | src: empty literal | sink: config object | empty default; the real value comes from DB_PASSWORD at load time
    password: '',
    database: 'caseflow',
    tls: 'require',
  },
  redisUrl: 'redis://localhost:6379/0',
  auth: {
    jwtIssuer: 'https://auth.caseflow.example',
    // CASE: R05-FP-02
    // ok: JS-121 | src: env var | sink: config object | value read from the environment, no literal secret
    jwtSecret: process.env.CASEFLOW_JWT_SECRET ?? '',
    // CASE: R05-FP-03
    // ok: JS-121 | src: constant | sink: config object | cookie NAME, not a credential
    sessionCookie: 'caseflow_session_token',
    // CASE: R05-FP-04
    // ok: JS-121 | src: constant | sink: config object | "Bearer" is an auth scheme name, not a secret
    tokenType: 'Bearer',
    // CASE: R05-FP-05
    // ok: JS-121 | src: constant | sink: config object | validation pattern whose name contains "password"
    passwordPolicyRegex: '^(?=.*[A-Z])(?=.*\\d).{12,128}$',
  },
  integrations: {},
  uploads: { dir: '/var/lib/caseflow/uploads', maxBytes: 25 * 1024 * 1024 },
};

export const accountRecoveryCopy = {
  // CASE: R05-FP-06
  // ok: JS-121 | src: constant | sink: UI copy | label text with a credential-like identifier
  secretQuestionLabel: 'What was the name of the street you grew up on?',
  // CASE: R05-FP-07
  // ok: JS-121 | src: constant | sink: UI copy | help text, identifier ends in "hint"
  passwordHint: 'Use at least twelve characters including a number',
};

// Fallback used by the on-prem appliance image when the operator skipped the setup wizard.
// CASE: R05-TP-01
// ruleid: JS-121 | src: hardcoded literal | sink: DB login | real database password literal shipped in source
export const APPLIANCE_DB_PASSWORD = 'ataPhQ!DKdqcNb%werSVz';

// CASE: R05-TP-02
// ruleid: JS-121 | src: hardcoded literal | sink: HMAC signing | outbound webhook signing key, a live credential
export const webhookSigningKey = 'acc4d0a01cb88a0aebff5bef2342929996c3d61bd849cd2e89f55fd0c18c305c';
