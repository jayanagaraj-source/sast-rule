#!/usr/bin/env python3
"""Standalone reproduction and regression harness for four false-positive bug families.

Bug 1  Terraform findings on resources that are never created
Bug 2  Java HARD_CODE_KEY-2 / -3 on public HTTP header names
Bug 3  Stripe test-mode key severity
Bug 4  Slack documentation-placeholder webhook

What this is: a REFERENCE implementation of the four narrow filters plus a scenario runner.
It does not change, and does not stand in for, any product scanner. Rows are labelled:

  reference            the stdlib filter below, fed a synthetic finding
  gitleaks+reference   real gitleaks output, then the reference filter
  semgrep+reference    real Semgrep match spans, then the reference filter

Worker, CLI and CI-ingest paths are only exercised if they exist in this repository; otherwise
they are reported NOT RUN. The Java check is a tokenizer, not a Java AST; the Terraform check is
a conservative HCL subset parser, not the real HCL parser. Both keep the finding when unsure.

All fixtures are synthetic and live in a temporary directory that is removed on exit. Secret-shaped
values are assembled at run time so this file holds none of them as literals, and no value is ever
printed: findings are reported by scenario id only.

Usage: python3 recreate_all_bug_scenarios.py [--offline] [--keep] [--stress N]
"""

import argparse
import base64
import bisect
import hashlib
import json
import os
import re
import resource
import shutil
import subprocess
import sys
import tempfile
import time
import tracemalloc
from fractions import Fraction

PASS, FAIL, NOT_RUN, RECORDED = "PASS", "FAIL", "NOT RUN", "RECORDED"
MAX_PARSE_BYTES = 2 << 20
GITLEAKS_VERSION = "8.21.2"


# ---------------------------------------------------------------------------
# Synthetic values, assembled so the source holds no secret-shaped literal
# ---------------------------------------------------------------------------

BODY = "51OzK9pL2mN5qR8tU1vW4xY7zA0bC3dE"
SK_TEST, RK_TEST = "sk" + "_test_", "rk" + "_test_"
SK_LIVE, RK_LIVE = "sk" + "_live_", "rk" + "_live_"
SLACK_HOST = "hooks.slack" + ".com"
WS, CH, TOK = "T00000000", "B00000000", "X" * 24
WS2, CH2, TOK2 = "T01ABCDEF12", "B02GHIJKL34", "aB3dE5fG7hI9jK1lM3nO5pQ7"


def slack_url(ws, ch, tok, scheme="https", host=SLACK_HOST, kind="services"):
    return f"{scheme}://{host}/{kind}/{ws}/{ch}/{tok}"


PLACEHOLDER_URL = slack_url(WS, CH, TOK)
AWS_FAKE = "AKIA" + "QWERTYUIOP234567"
AWS_DOC = "AKIA" + "IOSFODNN7" + "EXAMPLE"
GITHUB_FAKE = "ghp" + "_" + hashlib.sha256(b"synthetic-github").hexdigest()[:36]
GITHUB_PLACEHOLDER = "ghp" + "_" + "x" * 36
# Mixed case: gitleaks generic-api-key does not report a hex-only value of this length.
GENERIC_FAKE = re.sub(r"[^A-Za-z0-9]", "", base64.b64encode(hashlib.sha512(b"synthetic-generic").digest()).decode())[:32]
DB_FAKE = hashlib.sha256(b"synthetic-database").hexdigest()[:24]
BOT_FAKE = "xoxb" + "-1234567890-0987654321-" + TOK2
PEM_BEGIN = "-----BEGIN " + "RSA PRIVATE KEY-----"
PEM_END = "-----END " + "RSA PRIVATE KEY-----"
PEM_LINES = [hashlib.sha512(f"synthetic-pem-{i}".encode()).hexdigest()[:64] for i in range(4)]
JAVA_KEY = "s3cr3t" + "K3y!2024"

FORBIDDEN_IN_OUTPUT = [BODY, TOK2, TOK, PLACEHOLDER_URL, AWS_FAKE, AWS_DOC, GITHUB_FAKE, GITHUB_PLACEHOLDER,
                       GENERIC_FAKE, DB_FAKE, BOT_FAKE, JAVA_KEY, PEM_LINES[0], SLACK_HOST + "/services"]


# ---------------------------------------------------------------------------
# Bug 1: Terraform disabled resources (reference HCL subset parser)
# ---------------------------------------------------------------------------

class HclError(Exception):
    pass


class Unknown(Exception):
    pass


_TF_SECRET_WORDS = ("secret", "password", "credential", "hardcoded", "token", "api-key", "private-key")


def tf_rule_can_be_disabled(rule):
    rule = rule.lower()
    return rule.startswith("terraform.") and not any(word in rule for word in _TF_SECRET_WORDS)


def hcl_lex(src):
    """Tokens as (kind, text, line). Raises HclError on anything it cannot read with certainty."""
    toks, i, line, n = [], 0, 1, len(src)
    while i < n:
        c = src[i]
        if c == "\n":
            toks.append(("nl", "\n", line))
            line += 1
            i += 1
        elif c in " \t\r":
            i += 1
        elif c == "#" or src.startswith("//", i):
            while i < n and src[i] != "\n":
                i += 1
        elif src.startswith("/*", i):
            end = src.find("*/", i + 2)
            if end < 0:
                raise HclError("unterminated comment")
            line += src.count("\n", i, end)
            i = end + 2
        elif src.startswith("<<", i):
            m = re.compile(r"<<-?([A-Za-z_]\w*)[ \t]*\n").match(src, i)
            if not m:
                raise HclError("bad heredoc")
            close = re.compile(r"^[ \t]*" + re.escape(m.group(1)) + r"[ \t]*$", re.M).search(src, m.end())
            if not close:
                raise HclError("unterminated heredoc")
            toks.append(("str", "<heredoc>", line))
            line += src.count("\n", i, close.end())
            i = close.end()
        elif c == '"':
            j, depth = i + 1, 0
            while True:
                if j >= n or src[j] == "\n":
                    raise HclError("unterminated string")
                if src[j] == "\\" and depth == 0:
                    j += 2
                elif src.startswith("${", j) or src.startswith("%{", j):
                    depth += 1
                    j += 2
                elif src[j] == "}" and depth:
                    depth -= 1
                    j += 1
                elif src[j] == '"' and depth == 0:
                    break
                else:
                    j += 1
            toks.append(("str", src[i:j + 1], line))
            i = j + 1
        else:
            m = re.compile(r"\d+(?:\.\d+)?(?:[eE][+-]?\d+)?").match(src, i)
            if m:
                toks.append(("num", m.group(), line))
                i = m.end()
                continue
            m = re.compile(r"[A-Za-z_][\w-]*").match(src, i)
            if m:
                toks.append(("id", m.group(), line))
                i = m.end()
                continue
            two = src[i:i + 2]
            if two in ("==", "!=", "<=", ">=", "&&", "||", "=>"):
                toks.append(("op", two, line))
                i += 2
            elif c in "{}[]()=+-*/%?:,.<>!":
                toks.append(("op", c, line))
                i += 1
            else:
                raise HclError("unexpected character")
    return toks


_HCL_PAIRS = {"(": ")", "[": "]", "{": "}"}


def hcl_parse_body(toks, pos, top):
    """Parse one body. Returns (attributes, blocks, position of the closing brace or EOF)."""
    attrs, blocks = {}, []
    while True:
        while pos < len(toks) and toks[pos][0] == "nl":
            pos += 1
        if pos >= len(toks):
            if top:
                return attrs, blocks, pos
            raise HclError("unexpected end of file")
        kind, text, line = toks[pos]
        if text == "}" and kind == "op":
            if top:
                raise HclError("unbalanced closing brace")
            return attrs, blocks, pos
        if kind != "id":
            raise HclError("expected an identifier")
        if pos + 1 < len(toks) and toks[pos + 1][1] == "=" and toks[pos + 1][0] == "op":
            pos += 2
            expr, stack = [], []
            while pos < len(toks):
                k, t, _ = toks[pos]
                if k == "op" and t in _HCL_PAIRS:
                    stack.append(_HCL_PAIRS[t])
                elif k == "op" and t in ")]}":
                    if not stack:
                        break
                    if stack.pop() != t:
                        raise HclError("mismatched bracket")
                elif k == "nl" and not stack:
                    break
                if k != "nl":
                    expr.append((k, t))
                pos += 1
            if stack:
                raise HclError("unbalanced expression")
            if not expr or text in attrs:
                raise HclError("empty expression or duplicate attribute")
            attrs[text] = expr
            continue
        labels, pos = [], pos + 1
        while pos < len(toks) and toks[pos][0] in ("str", "id"):
            labels.append(toks[pos][1].strip('"'))
            pos += 1
        if pos >= len(toks) or toks[pos][1] != "{" or toks[pos][0] != "op":
            raise HclError("expected a block")
        _, inner_blocks, close = hcl_parse_body(toks, pos + 1, False)
        inner_attrs = _
        blocks.append({"type": text, "labels": labels, "start": line, "end": toks[close][2],
                       "attrs": inner_attrs, "blocks": inner_blocks})
        pos = close + 1


class _ConstExpr:
    """Evaluates literal arithmetic and constant conditionals only. Anything else raises Unknown."""

    def __init__(self, toks):
        self.toks, self.i = toks, 0

    def peek(self):
        return self.toks[self.i][1] if self.i < len(self.toks) else None

    def eat(self):
        self.i += 1
        return self.toks[self.i - 1]

    def expect_end(self):
        if self.i != len(self.toks):
            raise Unknown()

    def conditional(self):
        cond = self.additive()
        if self.peek() != "?":
            return cond
        self.eat()
        yes = self.conditional()
        if self.peek() != ":":
            raise Unknown()
        self.eat()
        no = self.conditional()
        if not isinstance(cond, bool):
            raise Unknown()
        return yes if cond else no

    def additive(self):
        val = self.term()
        while self.peek() in ("+", "-"):
            op = self.eat()[1]
            right = self.term()
            if isinstance(val, bool) or isinstance(right, bool):
                raise Unknown()
            val = val + right if op == "+" else val - right
        return val

    def term(self):
        val = self.unary()
        while self.peek() in ("*", "/", "%"):
            op = self.eat()[1]
            right = self.unary()
            if isinstance(val, bool) or isinstance(right, bool) or (op != "*" and right == 0):
                raise Unknown()
            val = val * right if op == "*" else val / right if op == "/" else val % right
        return val

    def unary(self):
        if self.peek() == "-":
            self.eat()
            val = self.unary()
            if isinstance(val, bool):
                raise Unknown()
            return -val
        if self.i >= len(self.toks):
            raise Unknown()
        kind, text = self.eat()
        if kind == "num":
            return Fraction(text)
        if kind == "id" and text in ("true", "false") and self.peek() != ".":
            return text == "true"
        if text == "(":
            val = self.conditional()
            if self.peek() != ")":
                raise Unknown()
            self.eat()
            return val
        raise Unknown()


def tf_count_is_zero(expr):
    try:
        parser = _ConstExpr(expr)
        val = parser.conditional()
        parser.expect_end()
    except Unknown:
        return False
    return not isinstance(val, bool) and val == 0


def tf_for_each_is_empty(expr):
    texts = [t for _, t in expr]
    while len(texts) > 2 and texts[0] == "(" and texts[-1] == ")":
        texts = texts[1:-1]
    return texts in (["{", "}"], ["toset", "(", "[", "]", ")"], ["tomap", "(", "{", "}", ")"])


def tf_zero_instance_spans(src):
    """Line spans of resource blocks provably creating no instances. A file it cannot parse yields none."""
    if not src or len(src) > MAX_PARSE_BYTES:
        return []
    try:
        _, blocks, _ = hcl_parse_body(hcl_lex(src), 0, True)
    except HclError:
        return []
    spans = []
    for block in blocks:
        if block["type"] != "resource":
            continue
        count, for_each = block["attrs"].get("count"), block["attrs"].get("for_each")
        if count is not None and for_each is None and tf_count_is_zero(count):
            spans.append((block["start"], block["end"]))
        elif for_each is not None and count is None and tf_for_each_is_empty(for_each):
            spans.append((block["start"], block["end"]))
    return spans


def tf_should_drop(rule, path, line, read):
    """Drop only a Terraform configuration rule, in a .tf file, inside a provably disabled resource."""
    if not tf_rule_can_be_disabled(rule) or line <= 0 or not path.lower().endswith(".tf"):
        return False
    return any(start <= line <= end for start, end in tf_zero_instance_spans(read(path)))


# ---------------------------------------------------------------------------
# Bug 2: Java header-name constants (reference tokenizer, not a Java AST)
# ---------------------------------------------------------------------------

JAVA_RULES = {"gitlab.find_sec_bugs.HARD_CODE_KEY-2", "gitlab.find_sec_bugs.HARD_CODE_KEY-3"}
_HEADER_NAME = re.compile(r"[A-Za-z0-9](?:Header|HeaderName)$|_HEADER(?:_NAME)?$")
_HEADER_VALUE = re.compile(r"X(?:-[A-Z][A-Za-z]*){1,6}")
_JAVA_TOKEN = re.compile(r"""
    (?P<ws>\s+)
  | (?P<line>//[^\n]*)
  | (?P<block>/\*.*?\*/)
  | (?P<str>"(?:[^"\\\n]|\\.)*")
  | (?P<chr>'(?:[^'\\\n]|\\.)+')
  | (?P<id>[^\W\d][\w$]*|\$[\w$]*)
  | (?P<num>\d[\w.]*)
  | (?P<punct>[{}()\[\];,.=+\-*/%<>!&|^~?:@])
""", re.X | re.S)
_CLOSERS = {"}": "{", ")": "(", "]": "["}
_TYPE_WORDS = {"class", "interface", "enum", "record"}
_RECEIVERS = re.compile(r"(?i)(?:http)?(?:servlet)?(?:request|response|req|res|resp)$")
_BENIGN_CALLS = {"equals": True, "equalsIgnoreCase": True, "length": False, "isEmpty": False}
_HEADER_CALLS = {"setHeader": ",", "addHeader": ",", "getHeader": ")"}


class JavaIndex:
    """Token stream with bracket structure, an identifier index and a block kind for each brace."""

    def __init__(self, texts, kinds, positions, parent, partner, brace_kind, by_name):
        self.texts, self.kinds, self.positions = texts, kinds, positions
        self.parent, self.partner, self.brace_kind, self.by_name = parent, partner, brace_kind, by_name

    def text(self, i):
        return self.texts[i] if 0 <= i < len(self.texts) else ""


def java_index(src):
    """Tokenize src, or return None for anything unreadable: an unterminated comment or literal, a
    unicode escape (Java expands those before lexing), a text block, unbalanced brackets, an oversize file."""
    if len(src) > MAX_PARSE_BYTES or "\\u" in src or '"""' in src:
        return None
    texts, kinds, positions = [], [], []
    parent, partner, brace_kind, by_name = [], [], {}, {}
    stack, stmt_start, pos, n, match = [], 0, 0, len(src), _JAVA_TOKEN.match
    while pos < n:
        m = match(src, pos)
        if not m:
            return None
        kind, pos = m.lastgroup, m.end()
        if kind in ("ws", "line", "block"):
            continue
        idx, text = len(texts), m.group()
        texts.append(text)
        kinds.append(kind)
        positions.append(m.start())
        partner.append(-1)
        if kind == "id":
            by_name.setdefault(text, []).append(idx)
        if kind == "punct" and text in "{([":
            parent.append(stack[-1] if stack else -1)
            if text == "{":
                head = texts[stmt_start:idx]
                if _TYPE_WORDS.intersection(head):
                    brace_kind[idx] = "class"
                elif "new" in head and idx and texts[idx - 1] == ")":
                    brace_kind[idx] = "anon"
                else:
                    brace_kind[idx] = "block"
            stack.append(idx)
        elif kind == "punct" and text in _CLOSERS:
            if not stack or texts[stack[-1]] != _CLOSERS[text]:
                return None
            opener = stack.pop()
            partner[opener], partner[idx] = idx, opener
            parent.append(stack[-1] if stack else -1)
        else:
            parent.append(stack[-1] if stack else -1)
        if kind == "punct" and text in "{};":
            stmt_start = idx + 1
    return None if stack else JavaIndex(texts, kinds, positions, parent, partner, brace_kind, by_name)


def _java_use_is_benign(ix, i, is_field):
    """Default deny: a use is benign only in one of the explicitly listed shapes."""
    start = i
    if ix.text(i - 1) == ".":
        if not (is_field and ix.text(i - 2) == "this"):
            return False  # another object's member, e.g. cfg.KEY_HEADER
        start = i - 2
    before, after = ix.text(start - 1), ix.text(i + 1)
    if before == "return" and after == ";":
        return True
    if after == ".":
        method = ix.text(i + 2)
        if method in _BENIGN_CALLS and ix.text(i + 3) == "(":
            close = ix.partner[i + 3]
            if close < 0 or ix.text(close + 1) == ".":
                return False
            return _BENIGN_CALLS[method] or close == i + 4
        return False
    if before == "(" and start >= 3 and after == _HEADER_CALLS.get(ix.text(start - 2)):
        receiver_dot, receiver = start - 3, start - 4
        return (ix.text(receiver_dot) == "." and ix.kinds[receiver] == "id" and bool(_RECEIVERS.fullmatch(ix.texts[receiver]))
                and ix.text(receiver - 1) not in (".", "new"))
    return False


def java_should_drop(rule, ix, span):
    """Drop only when the span is exactly one header-name declaration whose every use is benign."""
    if rule not in JAVA_RULES or ix is None:
        return False
    lo = bisect.bisect_left(ix.positions, span[0])
    hi = bisect.bisect_left(ix.positions, span[1])
    toks = ix.texts[lo:hi]
    if toks and toks[-1] == ";":
        toks = toks[:-1]
    if len(toks) < 4 or toks[-4:-2] == [] or toks[-2] != "=" or ix.kinds[lo + len(toks) - 1] != "str" or toks[-4] != "String":
        return False
    modifiers, name, literal = toks[:-4], toks[-3], toks[-1]
    if not set(modifiers) <= {"private", "public", "protected", "static", "final"} or ix.kinds[lo + len(toks) - 3] != "id":
        return False
    value = literal[1:-1]
    if len(value) > 64 or not _HEADER_NAME.search(name) or not _HEADER_VALUE.fullmatch(value):
        return False
    decl = lo + len(toks) - 3
    enclosing = ix.parent[decl]
    kind = ix.brace_kind.get(enclosing)
    uses = ix.by_name.get(name, [])
    if kind == "class":
        if "private" not in modifiers:
            return False  # other files may use it
        scope, is_field = uses, True  # whole file: a sibling nested class can reach a private field
    elif kind == "block" and set(modifiers) <= {"final"}:
        close = ix.partner[enclosing]
        scope, is_field = uses[bisect.bisect_left(uses, decl):bisect.bisect_right(uses, close)], False
    else:
        return False  # top level, parentheses, anonymous class: not classified
    return all(u == decl or _java_use_is_benign(ix, u, is_field) for u in scope)


# ---------------------------------------------------------------------------
# Bugs 3 and 4: secret classification (reference)
# ---------------------------------------------------------------------------

BASE_SEVERITY = {"aws-access-token": "CRITICAL", "private-key": "CRITICAL", "github-pat": "MEDIUM", "generic-api-key": "HIGH",
                 "stripe-access-token": "HIGH", "slack-webhook-url": "HIGH", "slack-bot-token": "HIGH"}
STRIPE_RULES = {"stripe-access-token", "stripe-secret-token", "stripe-api-key"}
STRIPE_LIVE_TEXT = "Found a Stripe Access Token, posing a risk to payment processing services and sensitive financial data."
STRIPE_REMEDIATION = "Roll the API key in the Stripe dashboard (Developers -> API keys) and review recent API logs for misuse."
STRIPE_SK_TEST_TEXT = "Found a Stripe test-mode secret key. It cannot move real money, but it can still access or modify Stripe test-mode resources."
STRIPE_RK_TEST_TEXT = "Found a Stripe test-mode restricted key. It cannot move real money, but it can still access or modify the Stripe test-mode resources its permissions allow."
_STRIPE_TEST = re.compile(r"(sk|rk)_test_[0-9A-Za-z]{10,99}")
_SLACK_PLACEHOLDER = re.compile(r"https://" + re.escape(SLACK_HOST) + r"/services/T0{8}/B0{8}/(?:X{24}|x{24}|0{24})", re.ASCII)
_URL_CONTINUES = set("?#:/%@&=+~.-_") | set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")


def stripe_test_kind(rule, secret, line=None):
    """'sk' or 'rk' when secret is exactly a test key under a Stripe rule. With the source line, a value that
    is the tail of a longer token (key-sk_test_...) is not a standalone key and stays unclassified."""
    if rule not in STRIPE_RULES or not secret:
        return None
    m = _STRIPE_TEST.fullmatch(secret)
    if not m:
        return None
    if line is not None:
        at = line.find(secret)
        if at < 0 or (at > 0 and (line[at - 1].isalnum() or line[at - 1] in "_-./")):
            return None
    return m.group(1)


def slack_is_placeholder(rule, value, line=None):
    """Exact rule, exact URL, all three parts placeholders. With the source line, a URL that continues past the
    reported match (query, fragment, more path) or starts before it (user info, other host) is kept."""
    if rule != "slack-webhook-url" or not value or not _SLACK_PLACEHOLDER.fullmatch(value):
        return False
    if line is None:
        return True
    at = line.find(value)
    if at < 0 or line.count(value) != 1:
        return False
    before, after = line[at - 1] if at else "", line[at + len(value):at + len(value) + 1]
    return before not in _URL_CONTINUES and after not in _URL_CONTINUES


def is_doc_placeholder(value):
    if not value:
        return False
    if value == AWS_DOC:
        return True
    return value.startswith("ghp" + "_") and len(value) == 40 and len(set(value[4:])) == 1


def classify_secret(rule, secret, match=None, line=None, description=None):
    """One finding through the reference pipeline. severity is None when suppressed."""
    value = secret or match
    if is_doc_placeholder(value):
        return {"visible": False, "severity": None, "reason": "vendor documentation placeholder", "message": None}
    if slack_is_placeholder(rule, match or secret, line):
        return {"visible": False, "severity": None, "reason": "documentation placeholder webhook", "message": None}
    severity, message = BASE_SEVERITY.get(rule, "UNCLASSIFIED"), description or (STRIPE_LIVE_TEXT if rule in STRIPE_RULES else f"Potential {rule}")
    kind = stripe_test_kind(rule, secret, line)
    if kind:
        severity, message = "MEDIUM", STRIPE_RK_TEST_TEXT if kind == "rk" else STRIPE_SK_TEST_TEXT
    remediation = STRIPE_REMEDIATION if rule in STRIPE_RULES else None
    return {"visible": True, "severity": severity, "reason": None, "message": message, "remediation": remediation}


# ---------------------------------------------------------------------------
# Fixtures. Every scenario is annotated "# GT: id=<ID> type=FP|TP reason=<text>"
# ---------------------------------------------------------------------------

TF_RULE = "terraform.aws.security.aws-s3-bucket-public-read.aws-s3-bucket-public-read"
TF_SECRET_RULE = "terraform.lang.security.hardcoded-password.hardcoded-password"
HCK2, HCK3 = sorted(JAVA_RULES)


class Tree:
    def __init__(self, root):
        self.root, self.files, self.expected, self.annotated = root, {}, {}, {}

    def lines(self, path):
        return self.files.setdefault(path, [])

    def gt(self, path, sid, kind, reason, expected, prefix="#"):
        self.lines(path).append(f"{prefix} GT: id={sid} type={kind} reason={reason}".rstrip())
        self.expected[sid] = {"type": kind, "expected": expected, "file": path, "reason": reason}
        self.annotated[sid] = kind

    def write(self):
        for path, lines in self.files.items():
            full = os.path.join(self.root, path)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "w", encoding="utf-8") as fh:
                fh.write("\n".join(lines) + "\n")


def build_terraform(tree):
    path, cases = "tf/main.tf", {}

    def resource(sid, kind, reason, expect, attrs, name=None, extra=()):
        tree.gt(path, sid, kind, reason, expect)
        lines = tree.lines(path)
        start = len(lines) + 1
        lines.append(f'resource "aws_s3_bucket_acl" "{(name or sid).lower().replace("-", "_")}" {{')
        lines.extend(f"  {a}" for a in attrs)
        lines.append("  bucket = aws_s3_bucket.b.id")
        lines.append('  acl    = "public-read"')
        cases[sid] = {"path": path, "rule": TF_RULE, "line": len(lines), "start": start}
        lines.extend(f"  {e}" for e in extra)
        lines.append("}")
        lines.append("")

    for sid, attr, why in [("T1", "count = 0", "count is literal zero"), ("T2", "count = 1 - 1", "literal arithmetic"),
                           ("T3", "count = false ? 1 : 0", "constant conditional"), ("T4", "for_each = {}", "empty object"),
                           ("T5", "for_each = toset([])", "empty set"), ("T6", "for_each = tomap({})", "empty map")]:
        resource(sid, "FP", why, "dropped", [attr])
    for sid, attr, why in [("T7", "count = 1", "one instance"), ("T8", "count = var.enabled", "unknown at scan time"),
                           ("T9", "count = length(var.xs)", "function of a variable"), ("T10", "for_each = { a = 1 }", "non-empty"),
                           ("T11", "for_each = var.items", "unknown at scan time")]:
        resource(sid, "TP", why, "kept", [attr])
    resource("T12", "TP", "no count or for_each", "kept", [])
    resource("T13", "TP", "count and for_each together is invalid so fail open", "kept", ["count = 0", "for_each = {}"])
    resource("T14", "TP", "secret rule stays on a disabled resource", "kept", ["count = 0"], extra=['master_password = "synthetic-not-real"'])
    cases["T14"]["rule"] = TF_SECRET_RULE
    resource("T-X1", "TP", "non Terraform rule in a disabled resource", "kept", ["count = 0"])
    cases["T-X1"]["rule"] = "generic.misc.some-other-rule"
    resource("T-X2", "TP", "count zero only in a comment", "kept", ["# count = 0"])
    resource("T-X3", "TP", "count zero only in a nested block", "kept", ['lifecycle {', '  count = 0', '}'])
    resource("T-X4", "TP", "string count is not a number", "kept", ['count = "0"'])
    resource("T-X5", "TP", "unknown operand in arithmetic", "kept", ["count = 0 * var.x"])
    resource("T-X6", "TP", "unknown branch in a conditional", "kept", ["count = false ? var.x : 0"])
    # An unrelated finding outside any disabled block, in the same file.
    tree.gt(path, "T-X7", "TP", "enabled resource directly after a disabled one", "kept")
    lines = tree.lines(path)
    lines.extend(['resource "aws_s3_bucket_acl" "x7_off" {', "  count = 0", '  acl = "private"', "}",
                  'resource "aws_s3_bucket_acl" "x7_on" {', '  acl = "public-read"'])
    cases["T-X7"] = {"path": path, "rule": TF_RULE, "line": len(lines)}
    lines.extend(["}", ""])

    broken = "tf/broken.tf"
    tree.gt(broken, "T15", "TP", "invalid HCL fails open", "kept")
    tree.lines(broken).extend(['resource "aws_s3_bucket_acl" "broken" {', "  count = 0", '  acl = "public-read"'])
    cases["T15"] = {"path": broken, "rule": TF_RULE, "line": len(tree.lines(broken))}

    other = "tf/main.hcl"
    tree.gt(other, "T16", "TP", "same line number in a non tf file", "kept")
    tree.lines(other).extend(tree.lines(path)[:cases["T1"]["line"] + 2])
    cases["T16"] = {"path": other, "rule": TF_RULE, "line": cases["T1"]["line"] + 1}

    blocks = "tf/blocks.tf"
    for sid, head, body in [("T17a", 'data "aws_s3_bucket" "d" {', 'bucket = "b"'),
                            ("T17b", 'module "m" {', 'source = "./m"'),
                            ("T17c", "locals {", 'x = "public-read"')]:
        tree.gt(blocks, sid, "TP", "only resource blocks are dropped", "kept")
        lines = tree.lines(blocks)
        lines.extend([head, "  count = 0", f"  {body}"])
        cases[sid] = {"path": blocks, "rule": TF_RULE, "line": len(lines)}
        lines.extend(["}", ""])
    return cases


def build_java(tree):
    cases = {}
    pw = '"X-Password-Policy-Version"'

    def java(sid, kind, reason, expect, decl, body, wrap=True, field=True):
        path = f"java/{sid.replace('-', '_')}.java"
        tree.gt(path, sid, kind, reason, expect, prefix="// #")
        lines = tree.lines(path)
        lines.append(f"class {sid.replace('-', '_')} {{")
        if field:
            lines.append(f"  {decl}")
        lines.extend(f"  {b}" for b in body)
        lines.append("}")
        cases[sid] = {"path": path, "decl": decl}

    name = "PASSWORD_POLICY_HEADER"
    field = f"private static final String {name} = {pw};"
    java("J1", "FP", "header name never used", "dropped", field, [])
    java("J2", "FP", "only returned", "dropped", field, [f"String header() {{ return {name}; }}"])
    java("J3", "FP", "only passed as a header name", "dropped", field, [
        f"void a(Object response, String v) {{ response.setHeader({name}, v); response.addHeader({name}, v); }}",
        f"String b(Object request) {{ return request.getHeader({name}); }}"])
    java("J4", "FP", "only compared or measured", "dropped", field, [
        f"boolean a(String x) {{ return {name}.equals(x); }}", f"int b() {{ return {name}.length(); }}",
        f"boolean c() {{ return {name}.isEmpty(); }}"])
    java("J5", "FP", "private field with benign use in another method", "dropped", field, [
        "void unrelated() { int n = 1; }", f"String use() {{ return {name}; }}"])

    local = f'String passwordHeader = {pw};'
    path = "java/J6.java"
    tree.gt(path, "J6-safe", "FP", "local in the safe method", "dropped", prefix="// #")
    tree.gt(path, "J6-unsafe", "TP", "same name local used as a key in another method", "kept", prefix="// #")
    tree.lines(path).extend(["class J6 {", f"  String a() {{ {local} return passwordHeader; }}",
                             f'  Object b() {{ {local} return new SecretKeySpec(passwordHeader.getBytes(), "AES"); }}', "}"])
    cases["J6-safe"] = {"path": path, "decl": local, "occurrence": 0}
    cases["J6-unsafe"] = {"path": path, "decl": local, "occurrence": 1}

    java("J7", "TP", "used as key material", "kept", field, [f'Object k() {{ return new SecretKeySpec({name}.getBytes(), "AES"); }}'])
    for suffix, use in [("a", f"Object k() {{ return new PBEKeySpec({name}.toCharArray()); }}"),
                        ("b", f"void k(Object cipher) {{ cipher.init(1, {name}); }}"),
                        ("c", f"Object k() {{ return Jwts.builder().signWith({name}); }}"),
                        ("d", f"void k(Object c) {{ c.setPassword({name}); }}"),
                        ("e", f"void k(Object c) {{ c.setSecret({name}); }}")]:
        java(f"J8{suffix}", "TP", "credential sink", "kept", field, [use])
    java("J9", "TP", "copied into another variable", "kept", field, [f"void k() {{ String copy = {name}; send(copy); }}"])
    java("J10", "TP", "passed to an unknown method", "kept", field, [f"void k() {{ unknown({name}); }}"])
    java("J11", "TP", "member of another object", "kept", "private static final String KEY_HEADER = " + pw + ";",
         ["void k(Object cfg) { use(cfg.KEY_HEADER); }"])
    java("J12", "TP", "non private field other files may use", "kept", f"public static final String {name} = {pw};", [])
    java("J12b", "TP", "package private field", "kept", f"static final String {name} = {pw};", [])
    java("J13", "TP", "name is not header like", "kept", f"static final String KEY = {pw};", [])
    java("J14a", "TP", "lower case value fails the pattern", "kept", f'private static final String {name} = "x-password";', [])
    java("J14b", "TP", "value is not a header name", "kept", f'private static final String KEY_HEADER = "Bearer abc123";', [])
    java("J15", "TP", "real hardcoded key shape", "kept", f'private static final String SECRET_KEY = "{JAVA_KEY}";', [])
    java("J16a", "TP", "unbalanced brackets fail open", "kept", field, ["void k() { if (true) { }"])
    java("J16b", "TP", "unterminated string fails open", "kept", field, ['String s = "unterminated;'])
    java("J16c", "TP", "unicode escape fails open", "kept", field, ["String \\u0061 = null;"])
    java("J16d", "TP", "file over 2 MB fails open", "kept", field, ["// " + "p" * (MAX_PARSE_BYTES + 16)])
    java("J-X1", "TP", "another rule id is never touched", "kept", field, [])
    cases["J-X1"]["rules"] = ["gitlab.find_sec_bugs.HARD_CODE_KEY-1"]
    java("J-X2", "TP", "anonymous class field is not classified", "kept", "Object a = new Object() { private String keyHeader = \"X-Api-Key\"; };", [])
    cases["J-X2"]["decl"] = 'private String keyHeader = "X-Api-Key";'
    java("J-X3", "TP", "concatenated into a returned value", "kept", field, [f'String k() {{ return {name} + "x"; }}'])
    java("J-X4", "TP", "name appears only in a string and comment but also as a key", "kept", field, [
        f'// {name} is documented here', f'String d() {{ return "{name}"; }}', f'Object k() {{ return mac({name}); }}'])
    java("J-X5", "FP", "name only in comment and string literal is not a use", "dropped", field, [
        f'// see {name}', f'String d() {{ return "{name}"; }}'])

    path = "java/J17.java"
    comment = f'// private static final String {name} = {pw};'
    tree.gt(path, "J17", "TP", "comment only match recorded as current behaviour", "recorded", prefix="// #")
    tree.lines(path).extend(["class J17 {", f"  {comment}", "}"])
    cases["J17"] = {"path": path, "decl": comment, "comment": True}
    return cases


def build_stripe(tree):
    path, cases = "py/cloud_keys.py", {}

    def key(sid, kind, why, expect, name, value, quote='"', rule="stripe-access-token", coverage_only=False):
        tree.gt(path, sid, kind, why, expect)
        lines = tree.lines(path)
        lines.append(f"{name} = {quote}{value}{quote}")
        cases[sid] = {"path": path, "line": len(lines), "value": value, "rule": rule, "coverage_only": coverage_only}

    key("S1", "FP", "test secret key is not live", "MEDIUM", "S1", SK_TEST + BODY, "'")
    key("S2", "FP", "test restricted key is not live", "MEDIUM", "S2", RK_TEST + BODY, "'")
    key("S3", "TP", "live secret key", "HIGH", "S3", SK_LIVE + BODY, "'")
    key("S4", "TP", "live restricted key", "HIGH", "S4", RK_LIVE + BODY, "'")
    key("S5", "TP", "variable name must not matter", "HIGH", "STRIPE_TEST_KEY", SK_LIVE + BODY)
    key("S6", "FP", "variable name must not matter", "MEDIUM", "STRIPE_LIVE_KEY", SK_TEST + BODY)
    key("S7", "TP", "test inside the body must not matter", "HIGH", "S7", SK_LIVE + "test" + BODY)
    key("S8", "FP", "live inside the body must not matter", "MEDIUM", "S8", SK_TEST + "live" + BODY)
    key("S9a", "TP", "letter before the prefix is not a test key", "not downgraded", "S9a", "x" + SK_TEST + BODY)
    key("S9b", "TP", "prefix inside a longer token is not a test key", "not downgraded", "S9b", "key-" + SK_TEST + BODY)
    key("S9c", "TP", "misspelled prefix is not a test key", "not downgraded", "S9c", "sk" + "_tes_" + BODY)
    tree.gt(path, "S10", "TP", "test keys stay visible and keep rotation text", "visible+remediation")
    cases["S10"] = {"ids": ["S1", "S2"]}

    other = "py/unrelated.py"

    def unrelated(sid, why, expect, name, value, rule):
        tree.gt(other, sid, "TP", why, expect)
        lines = tree.lines(other)
        lines.append(f'{name} = "{value}"')
        cases[sid] = {"path": other, "line": len(lines), "value": value, "rule": rule}

    unrelated("U-AWS", "unrelated secret unchanged", "CRITICAL", "aws_access_key_id", AWS_FAKE, "aws-access-token")
    unrelated("U-GITHUB", "unrelated secret unchanged", "MEDIUM", "gh_credential", GITHUB_FAKE, "github-pat")
    unrelated("U-GENERIC", "unrelated secret unchanged", "HIGH", "api_key", GENERIC_FAKE, "generic-api-key")
    unrelated("U-DB", "database password keeps the scanner class", "rule base", "DB_PASSWORD", DB_FAKE, None)
    tree.gt(other, "U-PEM", "TP", "unrelated secret unchanged", "CRITICAL")
    lines = tree.lines(other)
    lines.append("PEM = '''" + PEM_BEGIN)
    cases["U-PEM"] = {"path": other, "line": len(lines), "value": None, "rule": "private-key"}
    lines.extend(PEM_LINES + [PEM_END + "'''"])
    for sid, name, value in [("U-AWSDOC", "doc_key", AWS_DOC), ("U-GHPLACE", "gh_placeholder", GITHUB_PLACEHOLDER)]:
        tree.gt(other, sid, "FP", "vendor placeholder suppression unchanged", "suppressed")
        lines = tree.lines(other)
        lines.append(f'{name} = "{value}"')
        cases[sid] = {"path": other, "line": len(lines), "value": value, "rule": None}
    return cases


def build_slack(tree):
    path, cases = "py/slack.py", {}
    x_lower, zero = "x" * 24, "0" * 24

    def url(sid, kind, why, expect, value, in_file=True, rule="slack-webhook-url", must_report=False):
        tree.gt(path, sid, kind, why, expect)
        lines = tree.lines(path)
        if in_file:
            lines.append(f'{sid.replace("-", "_")} = "{value}"')
        cases[sid] = {"path": path, "line": len(lines) if in_file else None, "value": value, "rule": rule, "must_report": must_report}

    url("W1", "FP", "exact documentation placeholder", "suppressed", PLACEHOLDER_URL, must_report=True)
    url("W2a", "FP", "lower case placeholder token", "suppressed", slack_url(WS, CH, x_lower), must_report=True)
    url("W2b", "FP", "zero placeholder token", "suppressed", slack_url(WS, CH, zero), must_report=True)
    url("W3", "TP", "realistic webhook", "kept", slack_url(WS2, CH2, TOK2), must_report=True)
    url("W4", "TP", "placeholder ids and real token", "kept", slack_url(WS, CH, TOK2), must_report=True)
    url("W5", "TP", "real ids and placeholder token", "kept", slack_url(WS2, CH2, TOK), must_report=True)
    for sid, ws, ch, tok, why in [("W6a", WS, CH2, TOK2, "placeholder workspace only"), ("W6b", WS2, CH, TOK2, "placeholder channel only"),
                                  ("W6c", WS, CH2, TOK, "workspace and token only"), ("W6d", WS2, CH, TOK, "channel and token only")]:
        url(sid, "TP", why, "kept", slack_url(ws, ch, tok), must_report=True)
    url("W7", "TP", "http scheme", "kept", slack_url(WS, CH, TOK, scheme="http"))
    url("W8", "TP", "workflows path", "kept", slack_url(WS, CH, TOK, kind="workflows"))
    url("W9a", "TP", "bot token rule is untouched", "kept", BOT_FAKE, rule="slack-bot-token")
    url("W9b", "TP", "placeholder under another rule id", "kept", PLACEHOLDER_URL, in_file=False, rule="slack-legacy-webhook")
    base = f"{SLACK_HOST}/services/{WS}/{CH}"
    for sid, why, value, in_file in [
            ("W10a", "wrong host", slack_url(WS, CH, TOK, host="hooks.example" + ".com"), True),
            ("W10b", "host as suffix", slack_url(WS, CH, TOK, host=SLACK_HOST + ".evil.io"), True),
            ("W10c", "host as prefix", slack_url(WS, CH, TOK, host="evil" + SLACK_HOST), True),
            ("W10d", "port", slack_url(WS, CH, TOK, host=SLACK_HOST + ":8443"), True),
            ("W10e", "user info", slack_url(WS, CH, TOK, host="user:pw@" + SLACK_HOST), True),
            ("W10f", "query", PLACEHOLDER_URL + "?a=1", True),
            ("W10g", "fragment", PLACEHOLDER_URL + "#a", True),
            ("W10h", "extra path part", PLACEHOLDER_URL + "/extra", True),
            ("W10i", "missing path part", f"https://{SLACK_HOST}/services/{WS}/{TOK}", True),
            ("W10j", "short token", slack_url(WS, CH, "X" * 23), True),
            ("W10k", "long token", slack_url(WS, CH, "X" * 25), True),
            ("W10l", "empty workspace", f"https://{SLACK_HOST}/services//{CH}/{TOK}", True),
            ("W10m", "empty token", slack_url(WS, CH, ""), True),
            ("W10n", "trailing slash", PLACEHOLDER_URL + "/", True),
            ("W10o", "quotes in the value", f'"{PLACEHOLDER_URL}"', False),
            ("W10p", "source line as the value", f'url = "{PLACEHOLDER_URL}"', False),
            ("W10q", "leading whitespace", " " + PLACEHOLDER_URL, False),
            ("W10r", "trailing whitespace", PLACEHOLDER_URL + " ", False),
            ("W10s", "trailing newline", PLACEHOLDER_URL + "\n", False),
            ("W10t", "percent encoded token", f"https://{base}/%58" + "X" * 23, True),
            ("W10u", "unicode lookalike token", f"https://{base}/" + "X" * 23 + "Х", True),
            ("W10v", "upper case host", slack_url(WS, CH, TOK, host=SLACK_HOST.upper()), True),
            ("W10w", "empty value", "", False)]:
        url(sid, "TP", why, "kept", value, in_file=in_file)
    return cases


# ---------------------------------------------------------------------------
# Real scanners, only those actually present
# ---------------------------------------------------------------------------

def tool_env(work):
    home = os.path.join(work, "home")
    tmp = os.path.join(work, "tmp")
    os.makedirs(home, exist_ok=True)
    os.makedirs(tmp, exist_ok=True)
    return {"PATH": os.environ.get("PATH", ""), "HOME": home, "TMPDIR": tmp, "LANG": os.environ.get("LANG", "C.UTF-8"),
            "XDG_CONFIG_HOME": os.path.join(home, ".config"), "XDG_CACHE_HOME": os.path.join(home, ".cache"),
            "SEMGREP_ENABLE_VERSION_CHECK": "0", "SEMGREP_SEND_METRICS": "off"}


def run_gitleaks(tree, work):
    """Real gitleaks over py/. Returns (findings by (file, line, rule), version or None, why not run)."""
    exe = shutil.which("gitleaks")
    if not exe:
        return {}, None, "gitleaks is not on PATH"
    env = tool_env(work)
    try:
        version = subprocess.run([exe, "version"], capture_output=True, text=True, timeout=30, env=env).stdout.strip()
        report = os.path.join(work, "gitleaks-report.json")
        done = subprocess.run([exe, "dir", os.path.join(tree.root, "py"), "--report-format", "json", "--report-path", report,
                               "--no-banner", "--exit-code", "0"], capture_output=True, text=True, timeout=180, env=env, cwd=work)
    except (OSError, subprocess.SubprocessError) as err:
        return {}, None, f"gitleaks could not run ({type(err).__name__})"
    if done.returncode != 0 or not os.path.exists(report):
        return {}, version, f"gitleaks exited with {done.returncode}"
    with open(report, encoding="utf-8") as fh:
        raw = json.load(fh)
    found = {}
    for f in raw:
        rel = os.path.relpath(os.path.join(work, f["File"]) if not os.path.isabs(f["File"]) else f["File"], tree.root).replace(os.sep, "/")
        found.setdefault((rel, f["StartLine"]), []).append(f)
    return found, version, None


def run_semgrep_java(tree, work, offline):
    """Real Semgrep with the two registry rules over java/. Returns ({(path, rule): [(start, end, line)]}, why not run)."""
    exe = shutil.which("semgrep")
    if not exe:
        return {}, "semgrep is not on PATH"
    if offline:
        return {}, "--offline: the rules come from the Semgrep registry"
    cmd = [exe, "scan", "--metrics", "off", "--json", "--quiet", "--disable-version-check"]
    for rule in sorted(JAVA_RULES):
        cmd += ["--config", f"r/{rule}"]
    cmd.append(os.path.join(tree.root, "java"))
    try:
        done = subprocess.run(cmd, capture_output=True, text=True, timeout=240, env=tool_env(work), cwd=work)
        data = json.loads(done.stdout or "{}")
    except (OSError, subprocess.SubprocessError, ValueError) as err:
        return {}, f"semgrep could not run ({type(err).__name__})"
    if "results" not in data or done.returncode not in (0, 1, 2):
        return {}, f"semgrep gave no results (exit {done.returncode}); the registry may be unreachable"
    matches = {}
    for r in data["results"]:
        rel = os.path.relpath(r["path"] if os.path.isabs(r["path"]) else os.path.join(work, r["path"]), tree.root).replace(os.sep, "/")
        matches.setdefault((rel, r["check_id"]), []).append((r["start"]["offset"], r["end"]["offset"], r["start"]["line"]))
    return matches, None


def discover_integrations(repo):
    paths = {"worker": "workers/code-reviewer", "CLI": "tools/tigergate-cli", "CI-ingest": "workers/ci-ingest", "shared filter": "workers/pkg/scanscope"}
    present = {name: os.path.isdir(os.path.join(repo, rel)) for name, rel in paths.items()}
    markers = re.compile(r"inZeroInstanceResource|StripeTestKeyOverride|isSlackDocPlaceholderWebhook|headerUsageIsBenign")
    implementations, this = [], os.path.abspath(__file__)
    for base, dirs, files in os.walk(repo):
        dirs[:] = [d for d in dirs if d not in (".git", "node_modules")]
        for name in files:
            full = os.path.join(base, name)
            if os.path.abspath(full) == this or os.path.getsize(full) > MAX_PARSE_BYTES:
                continue
            try:
                with open(full, encoding="utf-8") as fh:
                    if markers.search(fh.read()):
                        implementations.append(os.path.relpath(full, repo))
            except (OSError, UnicodeDecodeError):
                continue
    return present, implementations


def git_state(repo):
    try:
        done = subprocess.run(["git", "--no-optional-locks", "-C", repo, "status", "--porcelain"], capture_output=True, text=True, timeout=30)
        return done.stdout if done.returncode == 0 else None
    except (OSError, subprocess.SubprocessError):
        return None


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

class Report:
    def __init__(self):
        self.rows = []

    def add(self, sid, kind, expected, actual, engine, status=None, note=""):
        if status is None:
            status = PASS if actual == expected else FAIL
        self.rows.append({"id": sid, "type": kind, "expected": expected, "actual": actual, "engine": engine, "status": status, "note": note})


def run_terraform(tree, cases, report):
    contents = {path: "\n".join(lines) + "\n" for path, lines in tree.files.items()}
    read = contents.__getitem__
    for sid, case in cases.items():
        meta = tree.expected[sid]
        drop = tf_should_drop(case["rule"], case["path"], case["line"], read)
        report.add(sid, meta["type"], meta["expected"], "dropped" if drop else "kept", "reference HCL subset parser")
    # T14 also proves the non-secret rule on the same disabled block is dropped.
    if tf_should_drop(TF_RULE, "tf/main.tf", cases["T14"]["line"], read):
        report.add("T14-acl", "FP", "dropped", "dropped", "reference HCL subset parser")
    else:
        report.add("T14-acl", "FP", "dropped", "kept", "reference HCL subset parser")


def java_span(src, case):
    at, needed = -1, case.get("occurrence", 0)
    for _ in range(needed + 1):
        at = src.find(case["decl"], at + 1)
    if at < 0:
        raise ValueError("fixture declaration missing")
    end = at + len(case["decl"])
    # A field match ends before its semicolon; a local match includes it.
    return at, end - 1 if case["decl"].lstrip().startswith(("private", "public", "protected", "static")) and case["decl"].endswith(";") else end


def run_java(tree, cases, report, semgrep_matches, semgrep_error):
    contents = {path: "\n".join(lines) + "\n" for path, lines in tree.files.items()}
    indexes = {}
    no_match = []
    for sid, case in cases.items():
        meta, path = tree.expected[sid], case["path"]
        src = contents[path]
        ix = indexes.setdefault(path, java_index(src))
        span = java_span(src, case)
        decl_line = src.count("\n", 0, span[0]) + 1
        rules = case.get("rules", sorted(JAVA_RULES))
        real = []
        for rule in rules:
            for start, end, line in semgrep_matches.get((path, rule), []):
                if line == decl_line and start >= span[0] - 1 and end <= span[1] + 2:
                    real.append((rule, (start, end)))
        if case.get("comment"):
            detail = f"semgrep {'NOT RUN' if semgrep_error else ('reported it' if real else 'no match')}"
            drop = any(java_should_drop(r, ix, span) for r in rules)
            report.add(sid, meta["type"], "recorded", "kept (no tokens in span)" if not drop else "dropped",
                       "reference, " + detail, RECORDED, "Comment-only match: current behaviour recorded, no finding invented.")
            continue
        inputs = real or [(r, span) for r in rules]
        engine = "semgrep+reference" if real else "reference (synthetic match)"
        if not real and not semgrep_error and sid != "J-X1":
            no_match.append(sid)
        decisions = {java_should_drop(rule, ix, sp) for rule, sp in inputs}
        actual = "dropped" if decisions == {True} else "kept" if decisions == {False} else "mixed"
        report.add(sid, meta["type"], meta["expected"], actual, engine)
    return no_match


def run_java_stress(n, work):
    """n matches in one file: every 1000th is used as key material and must stay."""
    lines, unsafe = ["class Stress {"], []
    spans = []
    offset = len(lines[0]) + 1
    for i in range(n):
        name = f"h{i:06d}Header"
        decl = f'  private static final String {name} = "X-Password-Policy-Version"'
        spans.append((offset + 2, offset + len(decl)))
        line = decl + ";"
        lines.append(line)
        offset += len(line) + 1
        if i % 1000 == 999:
            unsafe.append(name)
    lines.append("  Object k() {")
    lines.extend(f'    mac({name});' for name in unsafe)
    lines.extend(["  }", "}"])
    src = "\n".join(lines) + "\n"

    def run():
        ix = java_index(src)
        return [java_should_drop(HCK2, ix, sp) for sp in spans]

    began = time.perf_counter()
    decisions = run()
    elapsed = time.perf_counter() - began
    tracemalloc.start()
    run()
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    expected_kept = len(unsafe)
    kept = decisions.count(False)
    # The same classification as small files: sample declarations re-run alone.
    consistent = True
    for i in (0, 1, 998, 999):
        if i >= n:
            continue
        name = f"h{i:06d}Header"
        use = f"mac({name});" if name in unsafe else f"String u = null;"
        small = f'class S {{\n  private static final String {name} = "X-Password-Policy-Version";\n  void m() {{ {use} }}\n}}\n'
        start = small.index("private")
        consistent &= java_should_drop(HCK2, java_index(small), (start, small.index(";"))) == decisions[i]
    return {"matches": n, "bytes": len(src), "seconds": elapsed, "dropped": decisions.count(True), "kept": kept, "expected_kept": expected_kept,
            "peak_mib": peak / (1 << 20), "maxrss_mib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024, "consistent": consistent}


def run_stripe(tree, cases, report, leaks, gl_engine, gl_error):
    reference = "reference classifier"
    contents = {path: lines for path, lines in tree.files.items()}
    for sid, case in cases.items():
        meta = tree.expected[sid]
        if sid == "S10":
            results = [classify_secret("stripe-access-token", cases[i]["value"]) for i in case["ids"]]
            good = all(r["visible"] and r["severity"] == "MEDIUM" and r["remediation"] == STRIPE_REMEDIATION for r in results)
            texts = all("test-mode" in r["message"] and "cannot move real money" in r["message"] for r in results)
            rk_text = "restricted" in results[1]["message"]
            report.add(sid, "TP", meta["expected"], "visible+remediation" if good and texts and rk_text else "changed", reference)
            continue
        if sid == "U-PEM" or case.get("rule") is None and sid not in ("U-AWSDOC", "U-GHPLACE"):
            pass
        else:
            if sid in ("U-AWSDOC", "U-GHPLACE"):
                r = classify_secret("any-rule", case["value"])
                report.add(sid, "FP", "suppressed", "suppressed" if not r["visible"] else "visible", reference)
            elif sid.startswith("S9"):
                line = contents[case["path"]][case["line"] - 1]
                r = classify_secret(case["rule"], case["value"], line=line)
                report.add(sid, "TP", "not downgraded", "not downgraded" if r["severity"] != "MEDIUM" else "downgraded", reference)
            else:
                r = classify_secret(case["rule"], case["value"])
                report.add(sid, meta["type"], meta["expected"], r["severity"], reference)
        # The same scenario through real gitleaks output.
        if sid == "U-PEM" or case.get("line"):
            if gl_error:
                report.add(sid, meta["type"], meta["expected"], "-", "gitleaks+reference", NOT_RUN, gl_error)
                continue
            line = contents[case["path"]][case["line"] - 1]
            found = leaks.get((case["path"], case["line"]), [])
            hits = [f for f in found if case.get("rule") in (None, f["RuleID"])]
            if sid == "U-DB":
                hits = found
            if sid.startswith("S9"):
                if not hits:
                    report.add(sid, "TP", "not downgraded", "NOT REPORTED", gl_engine, PASS, "Detector coverage: gitleaks does not report this value.")
                else:
                    r = classify_secret(hits[0]["RuleID"], hits[0]["Secret"], hits[0]["Match"], line, hits[0].get("Description"))
                    report.add(sid, "TP", "not downgraded", "not downgraded" if r["severity"] != "MEDIUM" else "downgraded", gl_engine,
                               note=f"Detector coverage: gitleaks reports this value under {hits[0]['RuleID']}.")
            elif sid in ("U-AWSDOC", "U-GHPLACE"):
                if not found:
                    report.add(sid, "FP", "suppressed", "suppressed", gl_engine, PASS, "Gitleaks itself does not report the placeholder.")
                else:
                    r = classify_secret(found[0]["RuleID"], found[0]["Secret"], found[0]["Match"], line)
                    report.add(sid, "FP", "suppressed", "suppressed" if not r["visible"] else "visible", gl_engine)
            elif not hits:
                expected = BASE_SEVERITY.get(case.get("rule"), "a finding") if sid == "U-DB" else meta["expected"]
                report.add(sid, meta["type"], expected, "NOT REPORTED", gl_engine, note="Gitleaks did not report the expected rule on this line.")
            else:
                f = hits[0]
                r = classify_secret(f["RuleID"], f["Secret"], f["Match"], line, f.get("Description"))
                expected = BASE_SEVERITY.get(f["RuleID"], "UNCLASSIFIED") if sid == "U-DB" else meta["expected"]
                note = f"Classified under {f['RuleID']}." if sid == "U-DB" else ""
                if sid in ("S3", "S4", "S5", "S7") and r["message"] != f.get("Description"):
                    note = "Live message changed."
                    expected = "unchanged message"
                report.add(sid, meta["type"], expected, r["severity"] if expected != "unchanged message" else "changed", gl_engine, note=note)


def run_slack(tree, cases, report, leaks, gl_engine, gl_error):
    contents = {path: lines for path, lines in tree.files.items()}
    for sid, case in cases.items():
        meta = tree.expected[sid]
        r = classify_secret(case["rule"], case["value"], case["value"])
        actual = "suppressed" if not r["visible"] else "kept"
        report.add(sid, meta["type"], meta["expected"], actual, "reference filter")
        if case["line"] is None:
            continue
        if gl_error:
            report.add(sid, meta["type"], meta["expected"], "-", "gitleaks+reference", NOT_RUN, gl_error)
            continue
        line = contents[case["path"]][case["line"] - 1]
        hits = [f for f in leaks.get((case["path"], case["line"]), []) if f["RuleID"] == case["rule"]]
        if not hits:
            if case["must_report"]:
                report.add(sid, meta["type"], meta["expected"], "NOT REPORTED", gl_engine, note="Gitleaks did not report this line.")
            else:
                report.add(sid, meta["type"], meta["expected"], "NOT REPORTED", gl_engine, PASS, "Detector coverage: gitleaks does not report this value, so it cannot be suppressed.")
            continue
        r = classify_secret(hits[0]["RuleID"], hits[0]["Secret"], hits[0]["Match"], line)
        report.add(sid, meta["type"], meta["expected"], "suppressed" if not r["visible"] else "kept", gl_engine)


def validate_annotations(tree):
    """Every expected scenario has its GT line in a written fixture, with the same type."""
    problems = []
    pattern = re.compile(r"# GT: id=(\S+) type=(FP|TP) reason=\S")
    seen = {}
    for path in tree.files:
        with open(os.path.join(tree.root, path), encoding="utf-8") as fh:
            for line in fh:
                if len(line) > 4096:
                    continue
                m = pattern.search(line)
                if m:
                    seen[m.group(1)] = m.group(2)
    for sid, meta in tree.expected.items():
        if seen.get(sid) != meta["type"]:
            problems.append(sid)
    return problems


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--offline", action="store_true", help="skip the Semgrep registry rules")
    parser.add_argument("--keep", action="store_true", help="keep the temporary directory and print its path")
    parser.add_argument("--stress", type=int, default=20000, help="matches in the Java stress case")
    args = parser.parse_args()

    out = []
    emit = out.append
    repo = os.path.dirname(os.path.abspath(__file__))
    before = git_state(repo)
    work = tempfile.mkdtemp(prefix="fp-scenarios-")
    try:
        tree = Tree(os.path.join(work, "fixtures"))
        tf_cases = build_terraform(tree)
        java_cases = build_java(tree)
        stripe_cases = build_stripe(tree)
        slack_cases = build_slack(tree)
        tree.write()
        with open(os.path.join(work, "EXPECTED.json"), "w", encoding="utf-8") as fh:
            json.dump(tree.expected, fh, indent=2, sort_keys=True)
        annotation_problems = validate_annotations(tree)

        present, implementations = discover_integrations(repo)
        leaks, gl_version, gl_error = run_gitleaks(tree, work)
        if gl_version and gl_version != GITLEAKS_VERSION and not gl_error:
            gl_engine = f"gitleaks {gl_version} (not {GITLEAKS_VERSION})+reference"
        else:
            gl_engine = f"gitleaks {gl_version}+reference"
        semgrep_matches, semgrep_error = run_semgrep_java(tree, work, args.offline)

        report = Report()
        run_terraform(tree, tf_cases, report)
        no_match = run_java(tree, java_cases, report, semgrep_matches, semgrep_error)
        stress = run_java_stress(args.stress, work)
        run_stripe(tree, stripe_cases, report, leaks, gl_engine, gl_error)
        run_slack(tree, slack_cases, report, leaks, gl_engine, gl_error)

        stress_ok = stress["kept"] == stress["expected_kept"] and stress["consistent"]
        report.add("J-STRESS", "FP/TP", f"{stress['expected_kept']} kept", f"{stress['kept']} kept", "reference tokenizer", PASS if stress_ok else FAIL,
                   f"{stress['matches']} matches in {stress['seconds'] * 1000:.0f} ms" + ("" if stress["seconds"] < 1 else " (over the 1 s target)"))
        for name in ("worker", "CLI", "CI-ingest", "shared filter"):
            if not present[name]:
                report.add(f"X-{name}", "-", "real path", "-", "absent from this repository", NOT_RUN,
                           f"No {name} code here, so parity, count and fingerprint checks cannot run.")
        report.add("X-terraform-parser", "-", "real HCL parser", "-", "no terraform/hcl tooling; stdlib only", NOT_RUN,
                   "Terraform rows use the reference subset parser.")
        if semgrep_error:
            report.add("X-semgrep", "-", "real Java rules", "-", "semgrep", NOT_RUN, semgrep_error)
        if gl_error:
            report.add("X-gitleaks", "-", "real gitleaks", "-", "gitleaks", NOT_RUN, gl_error)
        report.add("X-db", "-", "no database", "no database", "by construction", PASS, "This script opens no database connection.")
        if annotation_problems:
            report.add("X-annotations", "-", "all annotated", f"{len(annotation_problems)} missing", "self check", FAIL)
        else:
            report.add("X-annotations", "-", "all annotated", "all annotated", "self check", PASS)

        emit("Integrations in this repository")
        for name, there in present.items():
            emit(f"  {name:14} {'present' if there else 'absent'}")
        emit(f"  {'implementations':14} {len(implementations)} found")
        emit(f"  {'gitleaks':14} {gl_version or 'unavailable'}{' (' + gl_error + ')' if gl_error else ''}")
        emit(f"  {'semgrep rules':14} {'NOT RUN: ' + semgrep_error if semgrep_error else 'ran'}")
        emit("")

        widths = [13, 6, 22, 22, 30, 8]
        head = ["Scenario ID", "FP/TP", "Expected", "Actual", "Scanner/Reference", "Status"]
        emit(" | ".join(h.ljust(w) for h, w in zip(head, widths)))
        emit("-+-".join("-" * w for w in widths))
        for row in report.rows:
            cells = [row["id"], row["type"], str(row["expected"]), str(row["actual"]), row["engine"], row["status"]]
            emit(" | ".join(str(c)[:w].ljust(w) for c, w in zip(cells, widths)))

        emit("")
        emit("Summary")
        groups = [("Terraform", "T"), ("Java", "J"), ("Stripe+unrelated", ("S", "U-")), ("Slack", "W"), ("Cross-cutting", "X-")]
        for label, prefix in groups:
            rows = [r for r in report.rows if r["id"].startswith(prefix)]
            counts = {s: sum(1 for r in rows if r["status"] == s) for s in (PASS, FAIL, NOT_RUN, RECORDED)}
            emit(f"  {label:17} rows={len(rows):3}  PASS={counts[PASS]:3}  FAIL={counts[FAIL]:3}  NOT RUN={counts[NOT_RUN]:2}  RECORDED={counts[RECORDED]}")
        emit("")
        emit(f"Java stress: {stress['matches']} matches, {stress['bytes'] / (1 << 20):.2f} MiB, {stress['seconds'] * 1000:.0f} ms, dropped {stress['dropped']}, kept {stress['kept']}, "
             f"traced peak {stress['peak_mib']:.1f} MiB, process max RSS {stress['maxrss_mib']:.0f} MiB")
        if no_match:
            emit("Semgrep produced no match, so these used a synthetic match: " + ", ".join(no_match))
        emit("Boundary: a CI-ingest receiver cannot reclassify a redacted snippet, so an older CLI that sends HIGH for a test key stays HIGH until that CLI is upgraded.")

        differences = [r for r in report.rows if r["status"] == FAIL]
        emit("")
        emit(f"Differences from expected: {len(differences)}")
        for r in differences:
            emit(f"  {r['id']} [{r['engine']}]: expected {r['expected']}, got {r['actual']}. {r['note']}")
        not_run = [r for r in report.rows if r["status"] == NOT_RUN]
        emit(f"Not run: {len(not_run)}")
        for r in not_run:
            emit(f"  {r['id']}: {r['note']}")
        notes = [r for r in report.rows if r["note"] and r["status"] in (PASS, RECORDED) and r["id"][0] in "SWJ"]
        if notes:
            emit("Notes")
            for r in notes:
                emit(f"  {r['id']} [{r['engine']}]: {r['note']}")

        after = git_state(repo)
        clean = before == after if before is not None else None
        emit("")
        emit("Repository state unchanged by this run: " + ("yes" if clean else "NOT CHECKED (not a git repository)" if clean is None else "NO"))

        text = "\n".join(out)
        leaked = [i for i, value in enumerate(FORBIDDEN_IN_OUTPUT) if value and value in text]
        if leaked:
            print("Self check failed: output would contain a synthetic secret value; report withheld.")
            return 2
        print(text)
        if args.keep:
            print(f"\nFixtures kept in {work}")
        return 1 if differences or clean is False else 0
    finally:
        if not args.keep:
            shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
