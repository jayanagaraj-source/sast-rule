import { Pool, PoolConfig } from 'pg';
import mysql from 'mysql2/promise';
import { MongoClient } from 'mongodb';
import Redis from 'ioredis';
import { readFileSync } from 'fs';
import { config } from '../config';

const isProd = config.env === 'production';
const RDS_CA_BUNDLE = '/etc/ssl/certs/rds-global-bundle.pem';

// Strict TLS is always on for the primary database.
const STRICT_TLS = true;

function pgTls(): PoolConfig['ssl'] {
  switch (config.database.tls) {
    case 'disable':
      return false;
    case 'verify-full':
      // CASE: R03-FP-01
      // ok: SAST-042 | src: constant | sink: pg ssl options | verification explicitly on, with the RDS CA bundle
      return { rejectUnauthorized: true, ca: readFileSync(RDS_CA_BUNDLE, 'utf-8') };
    default:
      // Staging RDS proxies present a cert for *.proxy-xyz; ops asked to skip verification there until CF-1880.
      // CASE: R03-GAP-01
      // todoruleid: SAST-042 | src: NODE_ENV | sink: pg ssl options | computed value: verification is off in every non-prod deploy (reachable); rule only knows the literal false
      return { rejectUnauthorized: !isProd };
  }
}

export const pg = new Pool({
  host: config.database.host,
  port: config.database.port,
  user: config.database.user,
  password: config.database.password,
  database: config.database.database,
  ssl: pgTls(),
  max: 20,
});

// Reporting replica (read-only) — managed by the analytics team.
export const reportingPool = new Pool({
  connectionString: process.env.REPORTING_DATABASE_URL,
  // CASE: R03-TP-01
  // ruleid: SAST-042 | src: constant | sink: pg ssl options | pg client accepting any certificate
  ssl: { rejectUnauthorized: false },
});

// Audit log database, always verified.
export const auditPool = new Pool({
  connectionString: process.env.AUDIT_DATABASE_URL,
  // CASE: R03-FP-02
  // ok: SAST-042 | src: constant | sink: pg ssl options | STRICT_TLS is a const true
  ssl: { rejectUnauthorized: STRICT_TLS, ca: readFileSync(RDS_CA_BUNDLE, 'utf-8') },
});

export async function legacyBillingConnection() {
  return mysql.createConnection({
    host: process.env.BILLING_MYSQL_HOST,
    user: 'caseflow_ro',
    password: process.env.BILLING_MYSQL_PASSWORD,
    database: 'billing',
    ssl: {
      // CASE: R03-TP-02
      // ruleid: SAST-042 | src: constant | sink: mysql2 ssl options | nested multi-line options object
      rejectUnauthorized: false,
    },
  });
}

export async function archiveConnection() {
  return mysql.createConnection({
    uri: process.env.ARCHIVE_MYSQL_URL,
    // CASE: R03-FP-03
    // ok: SAST-042 | src: default | sink: mysql2 ssl profile | "Amazon RDS" profile verifies against the bundled CA
    ssl: 'Amazon RDS',
  });
}

export const mongo = new MongoClient(process.env.MONGO_URL ?? 'mongodb://localhost:27017', {
  tls: true,
  // CASE: R03-GAP-02
  // todoruleid: SAST-042 | src: constant | sink: mongodb options | driver-specific spelling of "accept invalid certs", not in the rule's patterns
  tlsAllowInvalidCertificates: true,
});

export const eventsMongo = new MongoClient(process.env.EVENTS_MONGO_URL ?? 'mongodb://localhost:27017', {
  tls: true,
  // CASE: R03-FP-04
  // ok: SAST-042 | src: constant | sink: mongodb options | invalid certificates rejected
  tlsAllowInvalidCertificates: false,
  tlsCAFile: RDS_CA_BUNDLE,
});

export const redis = new Redis(config.redisUrl, {
  // CASE: R03-TP-03
  // ruleid: SAST-042 | src: constant | sink: ioredis tls options | verification disabled for the cache cluster
  tls: { rejectUnauthorized: false, servername: process.env.REDIS_SNI },
  maxRetriesPerRequest: 3,
});

export const sessionRedis = new Redis(process.env.SESSION_REDIS_URL ?? config.redisUrl, {
  // CASE: R03-FP-05
  // ok: SAST-042 | src: default | sink: ioredis tls options | TLS with default verification
  tls: { servername: process.env.SESSION_REDIS_SNI },
});
