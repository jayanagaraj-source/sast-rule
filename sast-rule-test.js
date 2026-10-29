'use strict';

// SAST benchmark fixture: unsafe format strings (CWE-134) and object injection.
//
// Rules under test:
//   javascript.lang.security.audit.unsafe-formatstring.unsafe-formatstring
//   TG-TAINT-JS-FORMAT-STRING
//   gitlab.eslint.detect-object-injection
//   TG-TAINT-JS-OBJECT-INJECTION
//   javascript.express.security.audit.remote-property-injection.remote-property-injection
//
// Every function is an isolated test case. Nothing calls them, nothing is exported,
// and no server is started; `req`/`res` are only parameter names.
// Case IDs: F-* = format string, O-* = object injection; TP = should be reported, FP = safe.

const util = require("util");

// ---------------------------------------------------------------------------
// Part 1A — format string, real vulnerability candidates (expected: detect)
// ---------------------------------------------------------------------------

// F-TP1 — direct attacker-controlled format string
function testFormatTP1(req) {
  const fmt = req.query.fmt;
  console.log(fmt, { role: "admin" });
}

// F-TP2 — user-controlled string concatenation
function testFormatTP2(req) {
  console.log(
    "User: " + req.query.name + " %s",
    { secret: "dummy-data" }
  );
}

// F-TP3 — util.format with untrusted format
function testFormatTP3(req) {
  return util.format(req.query.fmt, 100);
}

// F-TP4 — template literal containing user input
function testFormatTP4(req) {
  console.error(
    `Request failed: ${req.body.message}`,
    { code: 500 }
  );
}

// F-TP5 — destructured request value
function testFormatTP5(req) {
  const { fmt } = req.body;
  return util.format(fmt, "test");
}

// F-TP6 — input propagated through variables
function testFormatTP6(req) {
  const input = req.query.format;
  const message = "Message: " + input;
  console.log(message, 123);
}

// ---------------------------------------------------------------------------
// Part 1B — format string, safe code (expected: no finding)
// ---------------------------------------------------------------------------

// F-FP1 — internal loop counter
function testFormatFP1() {
  for (let i = 0; i < 5; i++) {
    console.log("Iteration: " + i, { done: true });
  }
}

// F-FP2 — trusted startup numeric parameter
function testFormatFP2(port) {
  if (typeof port !== "number") return;

  console.log(`Server starting on ${port}`, { ready: true });
}

// F-FP3 — numeric concatenation
function testFormatFP3() {
  const count = 25;
  console.log("Total users: " + count, { completed: true });
}

// F-FP4 — escaped format specifiers
function testFormatFP4(req) {
  const safeText = String(req.query.name).replace(/%/g, "%%");
  console.log("User: " + safeText, 123);
}

// F-FP5 — single logging argument (no CWE-134; log injection is a separate question)
function testFormatFP5(req) {
  console.log(`User: ${req.query.name}`);
}

// F-FP6 — constant format string
function testFormatFP6(req) {
  console.log("Username: %s", req.body.username);
}

// F-FP7 — trusted static template variable
function testFormatFP7() {
  const service = "AuthService";
  console.error(`Failed to start ${service}`, new Error("Startup"));
}

// ---------------------------------------------------------------------------
// Part 2A — object injection, real vulnerability candidates (expected: detect)
// ---------------------------------------------------------------------------

// O-TP1 — user-controlled key writes to a sensitive object
function testObjectTP1(req) {
  const user = {
    name: "guest",
    isAdmin: false
  };

  user[req.body.key] = req.body.value;

  return user;
}

// O-TP2 — sensitive property read
function testObjectTP2(req, res) {
  const account = {
    username: "test",
    passwordHash: "dummy-hash"
  };

  res.json({
    value: account[req.query.field]
  });
}

// O-TP3 — dynamic method selection
function testObjectTP3(req) {
  const operations = {
    read: () => "safe",
    deleteAll: () => "sensitive-operation"
  };

  return operations[req.body.action]();
}

// O-TP4 — key propagated through a variable
function testObjectTP4(req) {
  const key = req.body.key;
  const config = { isAdmin: false, theme: "light" };

  config[key] = req.body.value;

  return config;
}

// ---------------------------------------------------------------------------
// Part 2B — object injection, safe code (expected: no finding)
// ---------------------------------------------------------------------------

// O-FP1 — key checked against a constant allowlist; rejection returns
function testObjectFP1(req, res) {
  const ALLOWED_FIELDS = new Set(["username", "displayName"]);
  const profile = { username: "test", displayName: "Test", passwordHash: "dummy-hash" };
  const field = req.query.field;

  if (!ALLOWED_FIELDS.has(field)) {
    return res.status(400).json({ error: "unknown field" });
  }

  res.json({ value: profile[field] });
}

// O-FP2 — operation looked up through an own-property check on a server-side table
function testObjectFP2(req) {
  const handlers = {
    read: () => "safe",
    list: () => "safe-list"
  };
  const action = req.body.action;

  if (!Object.prototype.hasOwnProperty.call(handlers, action)) {
    throw new Error("unsupported action");
  }

  return handlers[action]();
}

// O-FP3 — user-controlled key stored in a Map (no prototype, no property lookup)
function testObjectFP3(req) {
  const settings = new Map();

  settings.set(req.body.key, req.body.value);

  return settings;
}

// O-FP4 — constant key, request supplies only the value
function testObjectFP4(req) {
  const user = { name: "guest", isAdmin: false };
  const field = "name";

  user[field] = String(req.body.value);

  return user;
}

// O-FP5 — numeric index from the request; cannot name a property or method
function testObjectFP5(req, res) {
  const pages = ["intro", "pricing", "faq"];
  const index = parseInt(req.query.page, 10);

  res.json({ page: pages[index] });
}
