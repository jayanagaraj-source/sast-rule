// Regex helpers for the case search box and automation rules.
import RE2 from 're2';

const MAX_SEARCH_LENGTH = 64;

export function escapeRegExp(input: string): string {
  return input.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** Case-insensitive "contains" matcher over subject lines. Input is escaped, so it is a literal match. */
export function literalMatcher(term: string): RegExp {
  const escaped = escapeRegExp(term.slice(0, MAX_SEARCH_LENGTH));
  // CASE: R11-FP-01
  // ok: SAST-011 | src: escaped user input | sink: new RegExp | every metacharacter escaped; linear time
  return new RegExp(escaped);
}

// Functions available inside automation-rule expressions, e.g. {{ subject.toUpperCase() }}.
export const EXPRESSION_EXTENSION_METHODS = ['toUpperCase', 'toLowerCase', 'trim', 'slice', 'includes', 'startsWith'];

// CASE: R11-FP-02
// ok: SAST-011 | src: constant list | sink: new RegExp | alternation of fixed identifiers, built once at load
export const EXTENSION_CALL_RE = new RegExp(EXPRESSION_EXTENSION_METHODS.join('|'));

export interface RoutingRule {
  field: 'subject' | 'body' | 'from';
  __regex: string;
}

/** Compiles a tenant-defined routing rule like { field: "subject", __regex: "^(urgent|p1).*" }. */
export function compileRoutingRule(rule: RoutingRule): (text: string) => boolean {
  // CASE: R11-TP-01
  // ruleid: SAST-011 | src: DB row written by a tenant admin | sink: new RegExp + test | attacker-chosen pattern run on every inbound email by the shared worker
  const re = new RegExp(rule.__regex);
  return (text) => re.test(text);
}

/** Same feature on the RE2 engine (linear time, no backtracking) — used for the enterprise plan. */
export function compileRoutingRuleRe2(rule: RoutingRule): (text: string) => boolean {
  // CASE: R11-FP-03
  // ok: SAST-011 | src: DB row written by a tenant admin | sink: RE2 | RE2 guarantees linear-time matching
  const re = new RE2(rule.__regex);
  return (text) => re.test(text);
}

/** Builds the search regex from words the agent typed in the advanced search box. */
export function wordsMatcher(words: string[]): RegExp {
  const parts = words.map((w) => w.trim()).filter(Boolean);
  // CASE: R11-TP-02
  // ruleid: SAST-011 | src: req.query.words (cross-file caller) | sink: new RegExp (multi-line, with flags) | raw words joined into an alternation without escaping
  return new RegExp(
    parts.join('|'),
    'i',
  );
}

/** Validates a regex typed into the admin UI without ever running it. */
export function isValidPatternSyntax(candidate: string): boolean {
  try {
    // CASE: R11-FP-04
    // ok: SAST-011 | src: req.body (admin form) | sink: new RegExp (never executed) | compiled only to check syntax and discarded, never matched against input
    void new RegExp(candidate);
    return true;
  } catch {
    return false;
  }
}

// Email reply-chain splitter. Linear: no nested quantifiers.
// CASE: R11-FP-05
// ok: SAST-011 | src: static | sink: regex literal | static linear regex
export const REPLY_SEPARATOR = /^On .{1,200} wrote:$/m;

// Matches ticket references like "#TK-12345".
// CASE: R11-FP-06
// ok: SAST-011 | src: static | sink: regex literal | static, bounded
export const TICKET_REF = /#TK-\d{1,9}\b/g;
