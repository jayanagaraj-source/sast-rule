import https from 'https';
import tls from 'tls';
import { readFileSync } from 'fs';
import { Agent as UndiciAgent } from 'undici';
import { logger } from './logger';

const PARTNER_CA = '/etc/caseflow/partner-ca.pem';
const ALLOW_SELF_SIGNED_IN_CI = false;

// On-prem customers sometimes terminate TLS on appliances with self-signed certs. Integration settings expose an
// "Allow self-signed certificates" toggle; when it is set we hand out this agent.
// CASE: R03-TP-06
// ruleid: SAST-042 | src: constant | sink: https.Agent | agent that accepts any certificate
export const permissiveAgent = new https.Agent({ rejectUnauthorized: false, keepAlive: true });

// CASE: R03-FP-08
// ok: SAST-042 | src: constant | sink: https.Agent | pinned partner CA with verification on
export const partnerAgent = new https.Agent({ ca: readFileSync(PARTNER_CA), rejectUnauthorized: true, keepAlive: true });

// CASE: R03-FP-09
// ok: SAST-042 | src: default | sink: https.Agent | Node verifies certificates by default
export const defaultAgent = new https.Agent({ keepAlive: true, maxSockets: 64 });

// British spelling is silently ignored by Node, so verification stays ON here.
// CASE: R03-FP-10
// ok: SAST-042 | src: constant | sink: https.Agent | "rejectUnauthorised" is not a Node option; the agent still verifies
export const legacyAgent = new https.Agent({ rejectUnauthorised: false } as https.AgentOptions);

export function undiciDispatcher(allowSelfSigned: boolean) {
  if (allowSelfSigned) {
    // CASE: R03-TP-07
    // ruleid: SAST-042 | src: tenant setting | sink: undici Agent connect options | verification off for tenant-chosen hosts
    return new UndiciAgent({ connect: { rejectUnauthorized: false } });
  }
  return new UndiciAgent({ connect: { ca: readFileSync(PARTNER_CA) } });
}

export function ciAgent(): https.Agent {
  if (ALLOW_SELF_SIGNED_IN_CI) {
    // CASE: R03-FP-11
    // ok: SAST-042 | src: constant false guard | sink: https.Agent | unreachable: the guarding constant is always false
    return new https.Agent({ rejectUnauthorized: false });
  }
  return defaultAgent;
}

export function probeTlsEndpoint(host: string, port = 443): Promise<string> {
  return new Promise((resolve, reject) => {
    const socket = tls.connect(
      {
        host,
        port,
        servername: host,
        // CASE: R03-TP-08
        // ruleid: SAST-042 | src: constant | sink: tls.connect | verification disabled inside a multi-line options object
        rejectUnauthorized: false,
      },
      () => {
        const cert = socket.getPeerCertificate();
        socket.end();
        resolve(cert.fingerprint256);
      },
    );
    socket.on('error', reject);
  });
}

export function fetchPartnerStatus(path: string): Promise<number> {
  return new Promise((resolve, reject) => {
    const req = https.request(
      // CASE: R03-TP-09
      // ruleid: SAST-042 | src: constant | sink: https.request | options object turning verification off
      { host: 'status.partner-crm.example', path, method: 'GET', rejectUnauthorized: false },
      (res) => resolve(res.statusCode ?? 0),
    );
    req.on('error', reject);
    req.end();
  });
}

export function applyCorporateProxyWorkaround(): void {
  if (process.env.CASEFLOW_CORP_PROXY === '1') {
    logger.warn('corporate MITM proxy detected; disabling TLS verification for the process');
    // CASE: R03-GAP-03
    // todoruleid: SAST-042 | src: env var | sink: process env | process-wide kill switch for certificate validation; not one of the rule's patterns
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
  }
}

// CASE: R03-FP-12
// ok: SAST-042 | src: comment | sink: none | the insecure option only appears in a comment (CF-1402 removed it)
// const legacyOpts = { rejectUnauthorized: false };
