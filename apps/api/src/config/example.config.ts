/**
 * Example self-hosted configuration, rendered into the admin console's "Self-hosting" help page and copied by
 * `caseflow init`. Every credential below is a placeholder the operator must replace; none of them work.
 */
export const exampleSelfHostedConfig = {
  database: {
    url: 'postgres://caseflow@db.internal.example:5432/caseflow',
    // CASE: R05-FP-08
    // ok: JS-121 | src: placeholder | sink: documentation | angle-bracket placeholder
    password: '<your-database-password>',
  },
  smtp: {
    host: 'smtp.example.com',
    // CASE: R05-FP-09
    // ok: JS-121 | src: placeholder | sink: documentation | literal "changeme"
    password: 'changeme',
  },
  storage: {
    // CASE: R05-FP-10
    // ok: JS-121 | src: placeholder | sink: documentation | AWS documentation example key id
    awsAccessKeyId: 'AKIAIOSFODNN7EXAMPLE',
    // CASE: R05-FP-11
    // ok: JS-121 | src: placeholder | sink: documentation | AWS documentation example secret key
    awsSecretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
  },
  billing: {
    // CASE: R05-FP-12
    // ok: JS-121 | src: placeholder | sink: documentation | masked key made of one repeated character
    paymentsSecretKey: 'sk_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
  },
  auth: {
    // CASE: R05-FP-13
    // ok: JS-121 | src: placeholder | sink: documentation | instruction text in place of a value
    sessionSecret: 'replace-with-64-random-hex-characters',
    // CASE: R05-FP-14
    // ok: JS-121 | src: placeholder | sink: documentation | redaction mask
    jwtSecret: '****************************',
  },
};
