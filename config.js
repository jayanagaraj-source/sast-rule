'use strict';

// Database connection settings per environment, in the sequelize-cli config.js layout
// (`sequelize db:migrate --env <name>` reads the matching key).
//
// SAST reproduction file: Sequelize TLS options seen by both SAST-042 and
// javascript.sequelize.security.audit.sequelize-tls-disabled-cert-validation.
// Nothing here is executed; hosts use reserved .example/.test/.invalid names and
// passwords come from the environment only.

const https = require('https');

module.exports = {
  // Test case 1 - PostgreSQL, certificate validation disabled (insecure).
  // Expected: SAST-042 on the rejectUnauthorized line, Sequelize rule on the object.
  reporting: {
    host: 'reporting-db.caseflow.example',
    port: 5432,
    database: 'caseflow_reporting',
    username: 'caseflow_reporting_app',
    password: process.env.REPORTING_DB_PASSWORD,
    dialect: 'postgres',
    dialectOptions: {
      ssl: {
        rejectUnauthorized: false
      }
    }
  },

  // Test case 2 - MySQL, certificate validation disabled (insecure).
  // Expected: SAST-042 on the rejectUnauthorized line, Sequelize rule on the object.
  billing: {
    host: 'billing-db.caseflow.test',
    port: 3306,
    database: 'caseflow_billing',
    username: 'caseflow_billing_app',
    password: process.env.BILLING_DB_PASSWORD,
    dialect: 'mysql',
    dialectOptions: {
      ssl: {
        rejectUnauthorized: false
      }
    }
  },

  // Test case 3 - MariaDB, certificate validation disabled (insecure).
  // Expected: SAST-042 on the rejectUnauthorized line, Sequelize rule on the object.
  legacy: {
    host: 'legacy-db.caseflow.invalid',
    port: 3307,
    database: 'caseflow_legacy',
    username: 'caseflow_legacy_app',
    password: process.env.LEGACY_DB_PASSWORD,
    dialect: 'mariadb',
    dialectOptions: {
      ssl: {
        rejectUnauthorized: false
      }
    }
  },

  // Test case 4 - PostgreSQL, certificate validation enabled (secure).
  // Expected: no finding from either rule.
  production: {
    host: 'primary-db.caseflow.example',
    port: 5432,
    database: 'caseflow_production',
    username: 'caseflow_app',
    password: process.env.PRODUCTION_DB_PASSWORD,
    dialect: 'postgres',
    dialectOptions: {
      ssl: {
        rejectUnauthorized: true
      }
    }
  },

  // Test case 5 - standalone HTTPS agent (not Sequelize), validation disabled (insecure).
  // Expected: SAST-042 only; the Sequelize rule needs a dialect and must stay silent.
  partnerAgent: new https.Agent({
    keepAlive: true,
    rejectUnauthorized: false
  })
};
