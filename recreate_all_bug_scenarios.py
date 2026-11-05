#!/usr/bin/env python3
"""Single-file vulnerability and false-positive harness for four bug families.

Every sample is hardcoded in this file, and running it writes nothing to disk: no fixtures, no temp files.
All values are synthetic. The file deliberately contains secret-shaped literals, so secret scanners that
read this file will report them.

Three things are reported separately for each scenario:
  detection   did a real scanner report it? Only gitleaks can run here, through `gitleaks stdin`.
              Semgrep and Trivy need files on disk, so their detection is NOT RUN, never assumed.
  filter      what the Python reference filter in this file decides. This is not product code, so a
              pass here does not prove any product scanner is fixed.
  final       the outcome combining the two.

Result column:
  PASS            real gitleaks ran and its detection, the filter and the final outcome all match
  REFERENCE ONLY  no real scanner ran for this row; the Python filter matches its expected action
  FAIL            something differs from expected
  NOT RUN         a whole integration that could not be executed (listed under "Scanner availability")

Usage: python3 recreate_all_bug_scenarios.py [--no-scanner] [--stress N]
"""

import argparse
import bisect
import json
import os
import re
import resource
import shutil
import subprocess
import sys
import time
import tracemalloc
from fractions import Fraction

PASS, FAIL, NOT_RUN, REFERENCE_ONLY = "PASS", "FAIL", "NOT RUN", "REFERENCE ONLY"
DETECTED, NOT_DETECTED, ASSUMED, NOT_APPLICABLE = "DETECTED", "NOT DETECTED", "ASSUMED", "N/A"
KEEP, SUPPRESS, DOWNGRADE = "KEEP", "SUPPRESS", "DOWNGRADE"
CONFIRMED, UNCERTAIN, CONTROL, FALSE_POSITIVE = "confirmed", "uncertain", "control", "false-positive"
MAX_PARSE_BYTES = 2 << 20

EXPECTED_TOTALS = {  # family: (total, must remain, suppress or downgrade)
    "Terraform": (26, 20, 6), "Java": (32, 25, 7), "Stripe": (12, 8, 4), "Slack": (37, 34, 3), "Other": (7, 5, 2)}


# ===========================================================================
# 1 and 2. Hardcoded test data and expected results
# ===========================================================================

TF_ACL = "terraform.aws.security.aws-s3-bucket-public-read.aws-s3-bucket-public-read"
TF_SG = "terraform.aws.security.aws-ec2-security-group-open-ingress.aws-ec2-security-group-open-ingress"
TF_RDS = "terraform.aws.security.aws-rds-publicly-accessible.aws-rds-publicly-accessible"
TF_IAM = "terraform.aws.security.aws-iam-admin-policy.aws-iam-admin-policy"
TF_SECRET = "terraform.lang.security.hardcoded-password.hardcoded-password"


def tf(sid, why, kind, action, rule, path, marker, source):
    return {"id": sid, "family": "Terraform", "why": why, "kind": kind, "detection": ASSUMED, "action": action,
            "final": "SUPPRESSED" if action == SUPPRESS else "REPORTED", "rule": rule, "path": path, "marker": marker, "source": source}


TERRAFORM_CASES = [
    tf("T1", "count is literal zero", FALSE_POSITIVE, SUPPRESS, TF_ACL, "tf/main.tf", "public-read", '''resource "aws_s3_bucket_acl" "t1" {
  count  = 0
  bucket = aws_s3_bucket.b.id
  acl    = "public-read"
}
'''),
    tf("T2", "literal arithmetic is zero", FALSE_POSITIVE, SUPPRESS, TF_ACL, "tf/main.tf", "public-read", '''resource "aws_s3_bucket_acl" "t2" {
  count  = 1 - 1
  bucket = aws_s3_bucket.b.id
  acl    = "public-read"
}
'''),
    tf("T3", "constant conditional is zero", FALSE_POSITIVE, SUPPRESS, TF_SG, "tf/main.tf", "0.0.0.0/0", '''resource "aws_security_group_rule" "t3" {
  count       = false ? 1 : 0
  type        = "ingress"
  cidr_blocks = ["0.0.0.0/0"]
}
'''),
    tf("T4", "for_each is an empty object", FALSE_POSITIVE, SUPPRESS, TF_RDS, "tf/main.tf", "publicly_accessible", '''resource "aws_db_instance" "t4" {
  for_each            = {}
  engine              = "postgres"
  publicly_accessible = true
}
'''),
    tf("T5", "for_each is an empty set", FALSE_POSITIVE, SUPPRESS, TF_IAM, "tf/main.tf", "policy   =", '''resource "aws_iam_policy" "t5" {
  for_each = toset([])
  name     = "admin"
  policy   = data.aws_iam_policy_document.admin.json
}
'''),
    tf("T6", "for_each is an empty map", FALSE_POSITIVE, SUPPRESS, TF_ACL, "tf/main.tf", "public-read", '''resource "aws_s3_bucket_acl" "t6" {
  for_each = tomap({})
  bucket   = aws_s3_bucket.b.id
  acl      = "public-read"
}
'''),
    tf("T7", "one instance is created", CONFIRMED, KEEP, TF_ACL, "tf/main.tf", "public-read", '''resource "aws_s3_bucket_acl" "t7" {
  count  = 1
  bucket = aws_s3_bucket.b.id
  acl    = "public-read"
}
'''),
    tf("T8", "variable is unknown at scan time", UNCERTAIN, KEEP, TF_SG, "tf/main.tf", "0.0.0.0/0", '''resource "aws_security_group_rule" "t8" {
  count       = var.enabled
  type        = "ingress"
  cidr_blocks = ["0.0.0.0/0"]
}
'''),
    tf("T9", "function of a variable is unknown", UNCERTAIN, KEEP, TF_RDS, "tf/main.tf", "publicly_accessible", '''resource "aws_db_instance" "t9" {
  count               = length(var.xs)
  publicly_accessible = true
}
'''),
    tf("T10", "for_each is not empty", CONFIRMED, KEEP, TF_ACL, "tf/main.tf", "public-read", '''resource "aws_s3_bucket_acl" "t10" {
  for_each = { a = 1 }
  acl      = "public-read"
}
'''),
    tf("T11", "for_each variable is unknown", UNCERTAIN, KEEP, TF_IAM, "tf/main.tf", "policy   =", '''resource "aws_iam_policy" "t11" {
  for_each = var.items
  policy   = data.aws_iam_policy_document.admin.json
}
'''),
    tf("T12", "no count or for_each means one instance", CONFIRMED, KEEP, TF_ACL, "tf/main.tf", "public-read", '''resource "aws_s3_bucket_acl" "t12" {
  bucket = aws_s3_bucket.b.id
  acl    = "public-read"
}
'''),
    tf("T13", "count with for_each is invalid Terraform, so fail open", UNCERTAIN, KEEP, TF_ACL, "tf/main.tf", "public-read", '''resource "aws_s3_bucket_acl" "t13" {
  count    = 0
  for_each = {}
  acl      = "public-read"
}
'''),
    tf("T14", "a secret stays exposed even in a disabled resource", CONFIRMED, KEEP, TF_SECRET, "tf/main.tf", "master_password", '''resource "aws_db_instance" "t14" {
  count           = 0
  master_password = "synthetic-not-real-value"
}
'''),
    tf("T15", "invalid HCL fails open", UNCERTAIN, KEEP, TF_ACL, "tf/broken.tf", "public-read", '''resource "aws_s3_bucket_acl" "t15" {
  count = 0
  acl   = "public-read"
'''),
    tf("T16", "same text in a non .tf file is not Terraform", CONTROL, KEEP, TF_ACL, "tf/main.hcl", "public-read", '''resource "aws_s3_bucket_acl" "t16" {
  count = 0
  acl   = "public-read"
}
'''),
    tf("T17a", "only resource blocks are dropped: data", CONTROL, KEEP, TF_ACL, "tf/blocks.tf", "bucket =", '''data "aws_s3_bucket" "t17a" {
  count  = 0
  bucket = "b"
}
'''),
    tf("T17b", "only resource blocks are dropped: module", CONTROL, KEEP, TF_ACL, "tf/blocks.tf", "source =", '''module "t17b" {
  count  = 0
  source = "./m"
}
'''),
    tf("T17c", "only resource blocks are dropped: locals", CONTROL, KEEP, TF_ACL, "tf/blocks.tf", "public-read", '''locals {
  count = 0
  x     = "public-read"
}
'''),
    tf("T-X1", "a non Terraform rule in a disabled resource is untouched", CONTROL, KEEP, "generic.misc.some-other-rule", "tf/main.tf", "public-read", '''resource "aws_s3_bucket_acl" "tx1" {
  count = 0
  acl   = "public-read"
}
'''),
    tf("T-X2", "count zero only in a comment", CONFIRMED, KEEP, TF_ACL, "tf/main.tf", "public-read", '''resource "aws_s3_bucket_acl" "tx2" {
  # count = 0
  acl = "public-read"
}
'''),
    tf("T-X3", "count zero only in a nested block", CONFIRMED, KEEP, TF_ACL, "tf/main.tf", "public-read", '''resource "aws_s3_bucket_acl" "tx3" {
  lifecycle {
    count = 0
  }
  acl = "public-read"
}
'''),
    tf("T-X4", "a string is not a numeric count", UNCERTAIN, KEEP, TF_ACL, "tf/main.tf", "public-read", '''resource "aws_s3_bucket_acl" "tx4" {
  count = "0"
  acl   = "public-read"
}
'''),
    tf("T-X5", "unknown operand in arithmetic", UNCERTAIN, KEEP, TF_ACL, "tf/main.tf", "public-read", '''resource "aws_s3_bucket_acl" "tx5" {
  count = 0 * var.x
  acl   = "public-read"
}
'''),
    tf("T-X6", "unknown branch in a conditional", UNCERTAIN, KEEP, TF_ACL, "tf/main.tf", "public-read", '''resource "aws_s3_bucket_acl" "tx6" {
  count = false ? var.x : 0
  acl   = "public-read"
}
'''),
    tf("T-X7", "enabled resource right after a disabled one", CONFIRMED, KEEP, TF_ACL, "tf/main.tf", "public-read", '''resource "aws_s3_bucket_acl" "tx7_off" {
  count = 0
  acl   = "private"
}
resource "aws_s3_bucket_acl" "tx7_on" {
  acl = "public-read"
}
'''),
]

HCK1, HCK2, HCK3 = ("gitlab.find_sec_bugs.HARD_CODE_KEY-1", "gitlab.find_sec_bugs.HARD_CODE_KEY-2", "gitlab.find_sec_bugs.HARD_CODE_KEY-3")
JAVA_RULES = {HCK2, HCK3}
J_FIELD = 'private static final String PASSWORD_POLICY_HEADER = "X-Password-Policy-Version"'
J_LOCAL = 'String passwordHeader = "X-Password-Policy-Version";'


def java(sid, why, kind, action, decl, source, detection=DETECTED, rules=(HCK2, HCK3), occurrence=0, final=None):
    return {"id": sid, "family": "Java", "why": why, "kind": kind, "detection": detection, "action": action,
            "final": final or ("SUPPRESSED" if action == SUPPRESS else "REPORTED"), "rules": rules, "decl": decl, "occurrence": occurrence, "source": source}


# Detection states record an earlier real Semgrep run: rules HARD_CODE_KEY-2 and -3 matched everything except
# J16b, J16d and J17. Semgrep cannot run here without files, so these rows always show actual detection NOT RUN.
JAVA_CASES = [
    java("J1", "header name constant, never used", FALSE_POSITIVE, SUPPRESS, J_FIELD, '''class J1 {
  private static final String PASSWORD_POLICY_HEADER = "X-Password-Policy-Version";
}
'''),
    java("J2", "only returned", FALSE_POSITIVE, SUPPRESS, J_FIELD, '''class J2 {
  private static final String PASSWORD_POLICY_HEADER = "X-Password-Policy-Version";
  String header() { return PASSWORD_POLICY_HEADER; }
}
'''),
    java("J3", "used only as a name in HTTP header APIs", FALSE_POSITIVE, SUPPRESS, J_FIELD, '''class J3 {
  private static final String PASSWORD_POLICY_HEADER = "X-Password-Policy-Version";
  void a(Object response, String v) { response.setHeader(PASSWORD_POLICY_HEADER, v); response.addHeader(PASSWORD_POLICY_HEADER, v); }
  String b(Object request) { return request.getHeader(PASSWORD_POLICY_HEADER); }
}
'''),
    java("J4", "only compared or measured", FALSE_POSITIVE, SUPPRESS, J_FIELD, '''class J4 {
  private static final String PASSWORD_POLICY_HEADER = "X-Password-Policy-Version";
  boolean a(String x) { return PASSWORD_POLICY_HEADER.equals(x); }
  int b() { return PASSWORD_POLICY_HEADER.length(); }
  boolean c() { return PASSWORD_POLICY_HEADER.isEmpty(); }
}
'''),
    java("J5", "private field, benign use in another method", FALSE_POSITIVE, SUPPRESS, J_FIELD, '''class J5 {
  private static final String PASSWORD_POLICY_HEADER = "X-Password-Policy-Version";
  void unrelated() { int n = 1; }
  String use() { return PASSWORD_POLICY_HEADER; }
}
'''),
    java("J6-safe", "method-local variable used safely", FALSE_POSITIVE, SUPPRESS, J_LOCAL, '''class J6 {
  String a() { String passwordHeader = "X-Password-Policy-Version"; return passwordHeader; }
  Object b() { String passwordHeader = "X-Password-Policy-Version"; return new SecretKeySpec(passwordHeader.getBytes(), "AES"); }
}
'''),
    java("J-X5", "name only in a comment and a string is not a use", FALSE_POSITIVE, SUPPRESS, J_FIELD, '''class JX5 {
  private static final String PASSWORD_POLICY_HEADER = "X-Password-Policy-Version";
  // see PASSWORD_POLICY_HEADER
  String d() { return "PASSWORD_POLICY_HEADER"; }
}
'''),
    java("J6-unsafe", "same local name used as key material in another method", CONFIRMED, KEEP, J_LOCAL, '''class J6 {
  String a() { String passwordHeader = "X-Password-Policy-Version"; return passwordHeader; }
  Object b() { String passwordHeader = "X-Password-Policy-Version"; return new SecretKeySpec(passwordHeader.getBytes(), "AES"); }
}
''', occurrence=1),
    java("J7", "used as SecretKeySpec key material", CONFIRMED, KEEP, J_FIELD, '''class J7 {
  private static final String PASSWORD_POLICY_HEADER = "X-Password-Policy-Version";
  Object k() { return new SecretKeySpec(PASSWORD_POLICY_HEADER.getBytes(), "AES"); }
}
'''),
    java("J8a", "used for key generation with PBEKeySpec", CONFIRMED, KEEP, J_FIELD, '''class J8a {
  private static final String PASSWORD_POLICY_HEADER = "X-Password-Policy-Version";
  Object k() { return new PBEKeySpec(PASSWORD_POLICY_HEADER.toCharArray()); }
}
'''),
    java("J8b", "used for encryption with cipher.init", CONFIRMED, KEEP, J_FIELD, '''class J8b {
  private static final String PASSWORD_POLICY_HEADER = "X-Password-Policy-Version";
  void k(Object cipher) { cipher.init(1, PASSWORD_POLICY_HEADER); }
}
'''),
    java("J8c", "used to sign a JWT", CONFIRMED, KEEP, J_FIELD, '''class J8c {
  private static final String PASSWORD_POLICY_HEADER = "X-Password-Policy-Version";
  Object k() { return Jwts.builder().signWith(PASSWORD_POLICY_HEADER); }
}
'''),
    java("J8d", "passed to setPassword", CONFIRMED, KEEP, J_FIELD, '''class J8d {
  private static final String PASSWORD_POLICY_HEADER = "X-Password-Policy-Version";
  void k(Object c) { c.setPassword(PASSWORD_POLICY_HEADER); }
}
'''),
    java("J8e", "passed to setSecret", CONFIRMED, KEEP, J_FIELD, '''class J8e {
  private static final String PASSWORD_POLICY_HEADER = "X-Password-Policy-Version";
  void k(Object c) { c.setSecret(PASSWORD_POLICY_HEADER); }
}
'''),
    java("J9", "copied into another variable", UNCERTAIN, KEEP, J_FIELD, '''class J9 {
  private static final String PASSWORD_POLICY_HEADER = "X-Password-Policy-Version";
  void k() { String copy = PASSWORD_POLICY_HEADER; send(copy); }
}
'''),
    java("J10", "passed to an unknown method", UNCERTAIN, KEEP, J_FIELD, '''class J10 {
  private static final String PASSWORD_POLICY_HEADER = "X-Password-Policy-Version";
  void k() { unknown(PASSWORD_POLICY_HEADER); }
}
'''),
    java("J11", "member of another object", UNCERTAIN, KEEP, 'private static final String KEY_HEADER = "X-Password-Policy-Version"', '''class J11 {
  private static final String KEY_HEADER = "X-Password-Policy-Version";
  void k(Object cfg) { use(cfg.KEY_HEADER); }
}
'''),
    java("J12", "public field other files may use", UNCERTAIN, KEEP, 'public static final String PASSWORD_POLICY_HEADER = "X-Password-Policy-Version"', '''class J12 {
  public static final String PASSWORD_POLICY_HEADER = "X-Password-Policy-Version";
}
'''),
    java("J12b", "package-private field other files may use", UNCERTAIN, KEEP, 'static final String PASSWORD_POLICY_HEADER = "X-Password-Policy-Version"', '''class J12b {
  static final String PASSWORD_POLICY_HEADER = "X-Password-Policy-Version";
}
'''),
    java("J13", "value alone cannot clear a name that is not header-like", UNCERTAIN, KEEP, 'static final String KEY = "X-Password-Policy-Version"', '''class J13 {
  static final String KEY = "X-Password-Policy-Version";
}
'''),
    java("J14a", "header-like name alone cannot clear a lower case value", UNCERTAIN, KEEP, 'private static final String PASSWORD_POLICY_HEADER = "x-password"', '''class J14a {
  private static final String PASSWORD_POLICY_HEADER = "x-password";
}
'''),
    java("J14b", "header-like name alone cannot clear a token-shaped value", CONFIRMED, KEEP, 'private static final String KEY_HEADER = "Bearer abc123"', '''class J14b {
  private static final String KEY_HEADER = "Bearer abc123";
}
'''),
    java("J15", "actual hardcoded key shape", CONFIRMED, KEEP, 'private static final String SECRET_KEY = "s3cr3tK3y!2024"', '''class J15 {
  private static final String SECRET_KEY = "s3cr3tK3y!2024";
}
'''),
    java("J16a", "unbalanced brackets fail open", UNCERTAIN, KEEP, J_FIELD, '''class J16a {
  private static final String PASSWORD_POLICY_HEADER = "X-Password-Policy-Version";
  void k() { if (true) { }
}
'''),
    java("J16b", "unterminated string fails open", UNCERTAIN, KEEP, J_FIELD, '''class J16b {
  private static final String PASSWORD_POLICY_HEADER = "X-Password-Policy-Version";
  String s = "unterminated;
}
''', detection=NOT_DETECTED),
    java("J16c", "unicode escape fails open", UNCERTAIN, KEEP, J_FIELD, '''class J16c {
  private static final String PASSWORD_POLICY_HEADER = "X-Password-Policy-Version";
  String ''' + chr(92) + '''u0061 = null;
}
'''),
    java("J16d", "source over 2 MB fails open", UNCERTAIN, KEEP, J_FIELD, '''class J16d {
  private static final String PASSWORD_POLICY_HEADER = "X-Password-Policy-Version";
  // ''' + "p" * (MAX_PARSE_BYTES + 16) + '''
}
''', detection=NOT_DETECTED),
    java("J-X1", "another rule id is never touched", CONTROL, KEEP, J_FIELD, '''class JX1 {
  private static final String PASSWORD_POLICY_HEADER = "X-Password-Policy-Version";
}
''', detection=NOT_APPLICABLE, rules=(HCK1,)),
    java("J-X2", "anonymous class field is not classified", UNCERTAIN, KEEP, 'private String keyHeader = "X-Api-Key"', '''class JX2 {
  Object a = new Object() { private String keyHeader = "X-Api-Key"; };
}
'''),
    java("J-X3", "concatenated into a returned value", UNCERTAIN, KEEP, J_FIELD, '''class JX3 {
  private static final String PASSWORD_POLICY_HEADER = "X-Password-Policy-Version";
  String k() { return PASSWORD_POLICY_HEADER + "x"; }
}
'''),
    java("J-X4", "documented in a comment but also used for a MAC", CONFIRMED, KEEP, J_FIELD, '''class JX4 {
  private static final String PASSWORD_POLICY_HEADER = "X-Password-Policy-Version";
  // PASSWORD_POLICY_HEADER is documented here
  Object k() { return mac(PASSWORD_POLICY_HEADER); }
}
'''),
    java("J17", "comment-only control, not a vulnerability", CONTROL, KEEP, '// private static final String PASSWORD_POLICY_HEADER = "X-Password-Policy-Version";', '''class J17 {
  // private static final String PASSWORD_POLICY_HEADER = "X-Password-Policy-Version";
}
''', detection=NOT_DETECTED, final="CONTROL, NO FINDING"),
]


def secret(sid, family, why, kind, detection, action, final, rule, value, source=None):
    return {"id": sid, "family": family, "why": why, "kind": kind, "detection": detection, "action": action, "final": final,
            "rule": rule, "value": value, "source": source}


STRIPE = "stripe-access-token"
HIGH, MEDIUM = "REPORTED HIGH", "REPORTED MEDIUM"

STRIPE_CASES = [
    secret("S1", "Stripe", "test secret key cannot move real money", FALSE_POSITIVE, DETECTED, DOWNGRADE, MEDIUM, STRIPE,
           "sk_test_51OzK9pL2mN5qR8tU1vW4xY7zA0bC3dE", "S1 = 'sk_test_51OzK9pL2mN5qR8tU1vW4xY7zA0bC3dE'"),
    secret("S2", "Stripe", "test restricted key cannot move real money", FALSE_POSITIVE, DETECTED, DOWNGRADE, MEDIUM, STRIPE,
           "rk_test_51OzK9pL2mN5qR8tU1vW4xY7zA0bC3dE", "S2 = 'rk_test_51OzK9pL2mN5qR8tU1vW4xY7zA0bC3dE'"),
    secret("S3", "Stripe", "live secret key", CONFIRMED, DETECTED, KEEP, HIGH, STRIPE,
           "sk_live_51OzK9pL2mN5qR8tU1vW4xY7zA0bC3dE", "S3 = 'sk_live_51OzK9pL2mN5qR8tU1vW4xY7zA0bC3dE'"),
    secret("S4", "Stripe", "live restricted key", CONFIRMED, DETECTED, KEEP, HIGH, STRIPE,
           "rk_live_51OzK9pL2mN5qR8tU1vW4xY7zA0bC3dE", "S4 = 'rk_live_51OzK9pL2mN5qR8tU1vW4xY7zA0bC3dE'"),
    secret("S5", "Stripe", "test in the variable name must not matter", CONFIRMED, DETECTED, KEEP, HIGH, STRIPE,
           "sk_live_51OzK9pL2mN5qR8tU1vW4xY7zA0bC3dE", 'STRIPE_TEST_KEY = "sk_live_51OzK9pL2mN5qR8tU1vW4xY7zA0bC3dE"'),
    secret("S6", "Stripe", "live in the variable name must not matter", FALSE_POSITIVE, DETECTED, DOWNGRADE, MEDIUM, STRIPE,
           "sk_test_51OzK9pL2mN5qR8tU1vW4xY7zA0bC3dE", 'STRIPE_LIVE_KEY = "sk_test_51OzK9pL2mN5qR8tU1vW4xY7zA0bC3dE"'),
    secret("S7", "Stripe", "test inside a live key body must not matter", CONFIRMED, DETECTED, KEEP, HIGH, STRIPE,
           "sk_live_test51OzK9pL2mN5qR8tU1vW4xY7zA0bC3dE", "S7 = 'sk_live_test51OzK9pL2mN5qR8tU1vW4xY7zA0bC3dE'"),
    secret("S8", "Stripe", "live inside a test key body must not matter", FALSE_POSITIVE, DETECTED, DOWNGRADE, MEDIUM, STRIPE,
           "sk_test_live51OzK9pL2mN5qR8tU1vW4xY7zA0bC3dE", "S8 = 'sk_test_live51OzK9pL2mN5qR8tU1vW4xY7zA0bC3dE'"),
    secret("S9a", "Stripe", "a letter before the prefix is not a test key", UNCERTAIN, NOT_DETECTED, KEEP, HIGH, STRIPE,
           "xsk_test_51OzK9pL2mN5qR8tU1vW4xY7zA0bC3dE", "S9a = 'xsk_test_51OzK9pL2mN5qR8tU1vW4xY7zA0bC3dE'"),
    secret("S9b", "Stripe", "the prefix inside a longer token is not a test key", UNCERTAIN, DETECTED, KEEP, HIGH, STRIPE,
           "key-sk_test_51OzK9pL2mN5qR8tU1vW4xY7zA0bC3dE", "S9b = 'key-sk_test_51OzK9pL2mN5qR8tU1vW4xY7zA0bC3dE'"),
    secret("S9c", "Stripe", "a misspelled prefix is not a test key", UNCERTAIN, NOT_DETECTED, KEEP, HIGH, STRIPE,
           "sk_tes_51OzK9pL2mN5qR8tU1vW4xY7zA0bC3dE", "S9c = 'sk_tes_51OzK9pL2mN5qR8tU1vW4xY7zA0bC3dE'"),
    # S10 validates S1 and S2. It is not an additional key.
    secret("S10", "Stripe", "validates that S1 and S2 stay visible and keep rotation guidance", CONTROL, NOT_APPLICABLE, KEEP, "VISIBLE+REMEDIATION", STRIPE, None),
]

SLACK = "slack-webhook-url"
W_PLACEHOLDER = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"


def slack(sid, why, kind, detection, action, value, rule=SLACK, in_scan=True):
    final = "SUPPRESSED" if action == SUPPRESS else HIGH
    return secret(sid, "Slack", why, kind, detection, action, final, rule, value, f'{sid.replace("-", "_")} = "{value}"' if in_scan else None)


# W10o-s, W10w and W9b test the filter's own input handling. A scanner cannot produce them, so detection is N/A.
SLACK_CASES = [
    slack("W1", "exact documentation placeholder", FALSE_POSITIVE, DETECTED, SUPPRESS, "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"),
    slack("W2a", "exact placeholder with a lower case token", FALSE_POSITIVE, DETECTED, SUPPRESS, "https://hooks.slack.com/services/T00000000/B00000000/xxxxxxxxxxxxxxxxxxxxxxxx"),
    slack("W2b", "exact placeholder with a zero token", FALSE_POSITIVE, DETECTED, SUPPRESS, "https://hooks.slack.com/services/T00000000/B00000000/000000000000000000000000"),
    slack("W3", "realistic webhook", CONFIRMED, DETECTED, KEEP, "https://hooks.slack.com/services/T01ABCDEF12/B02GHIJKL34/aB3dE5fG7hI9jK1lM3nO5pQ7"),
    slack("W4", "placeholder ids with a real token", CONFIRMED, DETECTED, KEEP, "https://hooks.slack.com/services/T00000000/B00000000/aB3dE5fG7hI9jK1lM3nO5pQ7"),
    slack("W5", "real ids with a placeholder token", UNCERTAIN, DETECTED, KEEP, "https://hooks.slack.com/services/T01ABCDEF12/B02GHIJKL34/XXXXXXXXXXXXXXXXXXXXXXXX"),
    slack("W6a", "placeholder workspace only", CONFIRMED, DETECTED, KEEP, "https://hooks.slack.com/services/T00000000/B02GHIJKL34/aB3dE5fG7hI9jK1lM3nO5pQ7"),
    slack("W6b", "placeholder channel only", CONFIRMED, DETECTED, KEEP, "https://hooks.slack.com/services/T01ABCDEF12/B00000000/aB3dE5fG7hI9jK1lM3nO5pQ7"),
    slack("W6c", "placeholder workspace and token", UNCERTAIN, DETECTED, KEEP, "https://hooks.slack.com/services/T00000000/B02GHIJKL34/XXXXXXXXXXXXXXXXXXXXXXXX"),
    slack("W6d", "placeholder channel and token", UNCERTAIN, DETECTED, KEEP, "https://hooks.slack.com/services/T01ABCDEF12/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"),
    slack("W7", "http instead of https", UNCERTAIN, DETECTED, KEEP, "http://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"),
    slack("W8", "workflows path", UNCERTAIN, DETECTED, KEEP, "https://hooks.slack.com/workflows/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"),
    slack("W9a", "bot token rule is untouched", CONFIRMED, DETECTED, KEEP, "xoxb-1234567890-0987654321-aB3dE5fG7hI9jK1lM3nO5pQ7", rule="slack-bot-token"),
    slack("W9b", "placeholder under another rule id", CONTROL, NOT_APPLICABLE, KEEP, W_PLACEHOLDER, rule="slack-legacy-webhook", in_scan=False),
    slack("W10a", "wrong host", UNCERTAIN, NOT_DETECTED, KEEP, "https://hooks.example.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"),
    slack("W10b", "host as a suffix", UNCERTAIN, NOT_DETECTED, KEEP, "https://hooks.slack.com.evil.io/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"),
    slack("W10c", "host as a prefix", UNCERTAIN, DETECTED, KEEP, "https://evilhooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"),
    slack("W10d", "port", UNCERTAIN, NOT_DETECTED, KEEP, "https://hooks.slack.com:8443/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"),
    slack("W10e", "user information", UNCERTAIN, DETECTED, KEEP, "https://user:pw@hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"),
    slack("W10f", "query parameters", UNCERTAIN, DETECTED, KEEP, "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX?a=1"),
    slack("W10g", "fragment", UNCERTAIN, DETECTED, KEEP, "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX#a"),
    slack("W10h", "extra path part", UNCERTAIN, DETECTED, KEEP, "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX/extra"),
    slack("W10i", "missing path part", UNCERTAIN, NOT_DETECTED, KEEP, "https://hooks.slack.com/services/T00000000/XXXXXXXXXXXXXXXXXXXXXXXX"),
    slack("W10j", "token too short", UNCERTAIN, DETECTED, KEEP, "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXX"),
    slack("W10k", "token too long", UNCERTAIN, DETECTED, KEEP, "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXXX"),
    slack("W10l", "empty workspace", UNCERTAIN, NOT_DETECTED, KEEP, "https://hooks.slack.com/services//B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"),
    slack("W10m", "empty token", UNCERTAIN, NOT_DETECTED, KEEP, "https://hooks.slack.com/services/T00000000/B00000000/"),
    slack("W10n", "trailing slash", UNCERTAIN, DETECTED, KEEP, "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX/"),
    slack("W10o", "quotes inside the value", UNCERTAIN, NOT_APPLICABLE, KEEP, '"https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"', in_scan=False),
    slack("W10p", "a whole source line as the value", UNCERTAIN, NOT_APPLICABLE, KEEP, 'url = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"', in_scan=False),
    slack("W10q", "leading whitespace", UNCERTAIN, NOT_APPLICABLE, KEEP, " https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX", in_scan=False),
    slack("W10r", "trailing whitespace", UNCERTAIN, NOT_APPLICABLE, KEEP, "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX ", in_scan=False),
    slack("W10s", "trailing newline", UNCERTAIN, NOT_APPLICABLE, KEEP, "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX\n", in_scan=False),
    slack("W10t", "percent-encoded token", UNCERTAIN, NOT_DETECTED, KEEP, "https://hooks.slack.com/services/T00000000/B00000000/%58XXXXXXXXXXXXXXXXXXXXXXX"),
    slack("W10u", "unicode lookalike in the token", UNCERTAIN, DETECTED, KEEP, "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXХ"),
    slack("W10v", "upper case host", UNCERTAIN, NOT_DETECTED, KEEP, "https://HOOKS.SLACK.COM/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"),
    slack("W10w", "empty value", CONTROL, NOT_APPLICABLE, KEEP, "", in_scan=False),
]

SYNTHETIC_PEM = """PEM = '''-----BEGIN RSA PRIVATE KEY-----
3f7a9c1e5b2d8046a1c7e93f5d0b8a26c4e1f7093d5ba2860c9e4f1d7a3b6058
b2e8d4016f3a9c75e0d1b84a2f6c9037d5e1a8b4c0f27396ae5d8c14b07f3e62
7c1f5a93e8b2064dd3a7f0c9e15b82467fa0c3d9b81e5f2460d7c3a9e1b5f086
e4a09d7c3f1b6825c0e7f4a1d9b3528764fc1ae0d3b97f5286c4e0a1f7d9b335
-----END RSA PRIVATE KEY-----'''"""

OTHER_CASES = [
    secret("U-AWS", "Other", "unrelated AWS key unchanged", CONFIRMED, DETECTED, KEEP, "REPORTED CRITICAL", "aws-access-token",
           "AKIAQWERTYUIOP234567", 'aws_access_key_id = "AKIAQWERTYUIOP234567"'),
    secret("U-GITHUB", "Other", "unrelated GitHub token unchanged", CONFIRMED, DETECTED, KEEP, "REPORTED MEDIUM", "github-pat",
           "ghp_7Hq2Lm9Xv4Tn6Rb3Zs8Kd1Fw5Gy0Jc7Pa2Qe", 'gh_credential = "ghp_7Hq2Lm9Xv4Tn6Rb3Zs8Kd1Fw5Gy0Jc7Pa2Qe"'),
    secret("U-GENERIC", "Other", "unrelated generic API key unchanged", CONFIRMED, DETECTED, KEEP, HIGH, "generic-api-key",
           "q7ZpL4mX2vT9nR6bH3sK8dF1wG5yJ0cA", 'api_key = "q7ZpL4mX2vT9nR6bH3sK8dF1wG5yJ0cA"'),
    secret("U-DB", "Other", "database password keeps the scanner's class", CONFIRMED, DETECTED, KEEP, HIGH, "generic-api-key",
           "Zk3Vt8Qm1Xp6Rb2Nw9Hs4Ly7", 'DB_PASSWORD = "Zk3Vt8Qm1Xp6Rb2Nw9Hs4Ly7"'),
    secret("U-PEM", "Other", "unrelated private key unchanged", CONFIRMED, DETECTED, KEEP, "REPORTED CRITICAL", "private-key",
           "3f7a9c1e5b2d8046a1c7e93f5d0b8a26c4e1f7093d5ba2860c9e4f1d7a3b6058", SYNTHETIC_PEM),
    secret("U-AWSDOC", "Other", "AWS documentation placeholder", FALSE_POSITIVE, NOT_DETECTED, SUPPRESS, "SUPPRESSED", None,
           "AKIAIOSFODNN7EXAMPLE", 'doc_key = "AKIAIOSFODNN7EXAMPLE"'),
    secret("U-GHPLACE", "Other", "GitHub placeholder of one repeated character", FALSE_POSITIVE, NOT_DETECTED, SUPPRESS, "SUPPRESSED", None,
           "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", 'gh_placeholder = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"'),
]

ALL_CASES = TERRAFORM_CASES + JAVA_CASES + STRIPE_CASES + SLACK_CASES + OTHER_CASES


# ===========================================================================
# 3. Terraform reference filter: a conservative HCL subset parser, not the real one
# ===========================================================================

class HclError(Exception):
    pass


class Unknown(Exception):
    pass


_TF_SECRET_WORDS = ("secret", "password", "credential", "hardcoded", "token", "api-key", "private-key")
_HCL_PAIRS = {"(": ")", "[": "]", "{": "}"}


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
            if src[i:i + 2] in ("==", "!=", "<=", ">=", "&&", "||", "=>"):
                toks.append(("op", src[i:i + 2], line))
                i += 2
            elif c in "{}[]()=+-*/%?:,.<>!":
                toks.append(("op", c, line))
                i += 1
            else:
                raise HclError("unexpected character")
    return toks


def hcl_parse_body(toks, pos, top):
    """Parse one body. Returns (attributes, blocks, position of the closing brace or end of input)."""
    attrs, blocks = {}, []
    while True:
        while pos < len(toks) and toks[pos][0] == "nl":
            pos += 1
        if pos >= len(toks):
            if top:
                return attrs, blocks, pos
            raise HclError("unexpected end of input")
        kind, text, line = toks[pos]
        if kind == "op" and text == "}":
            if top:
                raise HclError("unbalanced closing brace")
            return attrs, blocks, pos
        if kind != "id":
            raise HclError("expected an identifier")
        if pos + 1 < len(toks) and toks[pos + 1][:2] == ("op", "="):
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
            if stack or not expr or text in attrs:
                raise HclError("bad attribute")
            attrs[text] = expr
            continue
        labels, pos = [], pos + 1
        while pos < len(toks) and toks[pos][0] in ("str", "id"):
            labels.append(toks[pos][1].strip('"'))
            pos += 1
        if pos >= len(toks) or toks[pos][:2] != ("op", "{"):
            raise HclError("expected a block")
        inner_attrs, inner_blocks, close = hcl_parse_body(toks, pos + 1, False)
        blocks.append({"type": text, "labels": labels, "start": line, "end": toks[close][2], "attrs": inner_attrs, "blocks": inner_blocks})
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
        if parser.i != len(expr):
            return False
    except Unknown:
        return False
    return not isinstance(val, bool) and val == 0


def tf_for_each_is_empty(expr):
    texts = [t for _, t in expr]
    while len(texts) > 2 and texts[0] == "(" and texts[-1] == ")":
        texts = texts[1:-1]
    return texts in (["{", "}"], ["toset", "(", "[", "]", ")"], ["tomap", "(", "{", "}", ")"])


def tf_zero_instance_spans(src):
    """Line spans of resource blocks provably creating no instances. Input it cannot parse yields none."""
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


def tf_should_drop(rule, path, line, source):
    """Drop only a Terraform configuration rule, in a .tf path, inside a provably disabled resource."""
    if not tf_rule_can_be_disabled(rule) or line <= 0 or not path.lower().endswith(".tf"):
        return False
    return any(start <= line <= end for start, end in tf_zero_instance_spans(source))


# ===========================================================================
# 4. Java reference filter: a tokenizer with bracket structure, not a Java AST or Semgrep
# ===========================================================================

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
_RECEIVERS = re.compile(r"(?i)(?:http)?(?:servlet)?(?:request|response|req|res|resp)")
_BENIGN_CALLS = {"equals": True, "equalsIgnoreCase": True, "length": False, "isEmpty": False}
_HEADER_CALLS = {"setHeader": ",", "addHeader": ",", "getHeader": ")"}


class JavaIndex:
    """Token stream with bracket structure, an identifier index and a kind for each brace."""

    def __init__(self, texts, kinds, positions, parent, partner, brace_kind, by_name):
        self.texts, self.kinds, self.positions = texts, kinds, positions
        self.parent, self.partner, self.brace_kind, self.by_name = parent, partner, brace_kind, by_name

    def text(self, i):
        return self.texts[i] if 0 <= i < len(self.texts) else ""


def java_index(src):
    """Tokenize src, or return None for anything unreadable: an unterminated comment or literal, a unicode
    escape (Java expands those before lexing), a text block, unbalanced brackets, oversized input."""
    if len(src) > MAX_PARSE_BYTES or "\\u" in src or '"""' in src:
        return None
    texts, kinds, positions, parent, partner, brace_kind, by_name = [], [], [], [], [], {}, {}
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


def java_use_is_benign(ix, i, is_field):
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
        receiver = start - 4
        return (ix.text(start - 3) == "." and receiver >= 0 and ix.kinds[receiver] == "id"
                and bool(_RECEIVERS.fullmatch(ix.texts[receiver])) and ix.text(receiver - 1) not in (".", "new"))
    return False


def java_should_drop(rule, ix, span):
    """Drop only when the span is exactly one header-name declaration whose every use is benign."""
    if rule not in JAVA_RULES or ix is None:
        return False
    lo, hi = bisect.bisect_left(ix.positions, span[0]), bisect.bisect_left(ix.positions, span[1])
    toks = ix.texts[lo:hi]
    if toks and toks[-1] == ";":
        toks = toks[:-1]
    if len(toks) < 4 or toks[-4] != "String" or toks[-2] != "=" or ix.kinds[lo + len(toks) - 1] != "str" or ix.kinds[lo + len(toks) - 3] != "id":
        return False
    modifiers, name, value = toks[:-4], toks[-3], toks[-1][1:-1]
    if not set(modifiers) <= {"private", "public", "protected", "static", "final"}:
        return False
    if len(value) > 64 or not _HEADER_NAME.search(name) or not _HEADER_VALUE.fullmatch(value):
        return False
    decl = lo + len(toks) - 3
    enclosing = ix.parent[decl]
    kind = ix.brace_kind.get(enclosing)
    uses = ix.by_name.get(name, [])
    if kind == "class":
        if "private" not in modifiers:
            return False  # other files may use it
        scope, is_field = uses, True  # the whole source: a sibling nested class can reach a private field
    elif kind == "block" and set(modifiers) <= {"final"}:
        close = ix.partner[enclosing]
        scope, is_field = uses[bisect.bisect_left(uses, decl):bisect.bisect_right(uses, close)], False
    else:
        return False  # top level, parentheses, anonymous class: not classified
    return all(u == decl or java_use_is_benign(ix, u, is_field) for u in scope)


def java_case_span(case):
    at = -1
    for _ in range(case["occurrence"] + 1):
        at = case["source"].find(case["decl"], at + 1)
    if at < 0:
        raise ValueError(f"{case['id']}: declaration missing from its source")
    return at, at + len(case["decl"])


# ===========================================================================
# 5 and 6. Stripe severity classifier and Slack placeholder filter
# ===========================================================================

BASE_SEVERITY = {"aws-access-token": "CRITICAL", "private-key": "CRITICAL", "github-pat": "MEDIUM", "generic-api-key": "HIGH",
                 STRIPE: "HIGH", SLACK: "HIGH", "slack-bot-token": "HIGH", "slack-legacy-webhook": "HIGH"}
STRIPE_RULES = {STRIPE, "stripe-secret-token", "stripe-api-key"}
STRIPE_REMEDIATION = "Roll the API key in the Stripe dashboard (Developers -> API keys) and review recent API logs for misuse."
_STRIPE_TEST = re.compile(r"(sk|rk)_test_[0-9A-Za-z]{10,99}")
_SLACK_PLACEHOLDER = re.compile(r"https://hooks\.slack\.com/services/T0{8}/B0{8}/(?:X{24}|x{24}|0{24})", re.ASCII)
_URL_CONTINUES = set("?#:/%@&=+~.-_") | set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")


def stripe_test_kind(rule, value, line=None):
    """'sk' or 'rk' when value is exactly a test key under a Stripe rule. With the source line, a value that
    is the tail of a longer token (key-sk_test_...) is not a standalone key and stays unclassified."""
    if rule not in STRIPE_RULES or not value:
        return None
    m = _STRIPE_TEST.fullmatch(value)
    if not m:
        return None
    if line is not None:
        at = line.find(value)
        if at < 0 or (at > 0 and (line[at - 1].isalnum() or line[at - 1] in "_-./")):
            return None
    return m.group(1)


def slack_is_placeholder(rule, value, line=None):
    """Exact rule, exact URL, all three parts placeholders. With the source line, a URL continuing past the
    reported value (query, fragment, more path) or starting before it (user info, other host) is kept."""
    if rule != SLACK or not value or not _SLACK_PLACEHOLDER.fullmatch(value):
        return False
    if line is None:
        return True
    at = line.find(value)
    if at < 0 or line.count(value) != 1:
        return False
    before, after = line[at - 1] if at else "", line[at + len(value):at + len(value) + 1]
    return before not in _URL_CONTINUES and after not in _URL_CONTINUES


# ===========================================================================
# 7. Unrelated secret regression: known placeholders and the shared classifier
# ===========================================================================

def is_doc_placeholder(value):
    if not value:
        return False
    if value == "AKIAIOSFODNN7EXAMPLE":
        return True
    return value.startswith("ghp_") and len(value) == 40 and len(set(value[4:])) == 1


def classify_secret(rule, secret_value, match=None, line=None):
    """One finding through the reference pipeline: (filter action, final result, remediation)."""
    if is_doc_placeholder(secret_value or match) or slack_is_placeholder(rule, match or secret_value, line):
        return SUPPRESS, "SUPPRESSED", None
    remediation = STRIPE_REMEDIATION if rule in STRIPE_RULES else None
    if stripe_test_kind(rule, secret_value, line):
        return DOWNGRADE, "REPORTED MEDIUM", remediation
    return KEEP, f"REPORTED {BASE_SEVERITY.get(rule, 'UNCLASSIFIED')}", remediation


# ===========================================================================
# Real scanner: gitleaks through stdin only. Nothing is written to disk.
# ===========================================================================

def scan_blob(cases):
    """All scannable secret samples as one in-memory text, with each case's first line (1-based)."""
    lines, where = [], {}
    for case in cases:
        if case.get("source") is None:
            continue
        where[case["id"]] = len(lines) + 1
        lines.extend(case["source"].split("\n"))
    return lines, where


def run_gitleaks_stdin(lines):
    """Real gitleaks on stdin. Returns (findings by 1-based line, version, reason it did not run)."""
    exe = shutil.which("gitleaks")
    if not exe:
        return {}, None, "gitleaks is not on PATH"
    try:
        version = subprocess.run([exe, "version"], capture_output=True, text=True, timeout=30, cwd="/").stdout.strip()
        # /dev/stdout is this process's pipe, not a file on disk. cwd=/ so no project config or ignore file is read.
        done = subprocess.run([exe, "stdin", "--report-format", "json", "--report-path", "/dev/stdout", "--no-banner", "--exit-code", "0"],
                              input="\n".join(lines) + "\n", capture_output=True, text=True, timeout=120, cwd="/")
        report = json.loads(done.stdout or "[]")
    except (OSError, subprocess.SubprocessError, ValueError) as err:
        return {}, None, f"gitleaks could not run ({type(err).__name__})"
    if done.returncode != 0:
        return {}, version, f"gitleaks exited with {done.returncode}"
    found = {}
    for finding in report:
        # gitleaks stdin numbers lines from 0.
        found.setdefault(finding["StartLine"] + 1, []).append(finding)
    return found, version, None


# ===========================================================================
# 8. Java stress test: 20,000 matches built in memory from one hardcoded template
# ===========================================================================

def run_java_stress(n):
    """n matches in one in-memory source: every 1000th is used as key material and must stay."""
    lines, unsafe, spans = ["class Stress {"], [], []
    offset = len(lines[0]) + 1
    for i in range(n):
        name = f"h{i:06d}Header"
        decl = f'  private static final String {name} = "X-Password-Policy-Version"'
        spans.append((offset + 2, offset + len(decl)))
        lines.append(decl + ";")
        offset += len(decl) + 2
        if i % 1000 == 999:
            unsafe.append(name)
    lines.append("  Object k() {")
    lines.extend(f"    mac({name});" for name in unsafe)
    lines.extend(["  }", "}"])
    src = "\n".join(lines) + "\n"

    def run():
        ix = java_index(src)
        return [java_should_drop(HCK2, ix, span) for span in spans]

    began = time.perf_counter()
    decisions = run()
    elapsed = time.perf_counter() - began
    tracemalloc.start()
    run()
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return {"matches": n, "bytes": len(src), "seconds": elapsed, "suppressed": decisions.count(True), "kept": decisions.count(False),
            "expected_kept": len(unsafe), "expected_suppressed": n - len(unsafe), "peak_mib": peak / (1 << 20),
            "maxrss_mib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024}


# ===========================================================================
# 9. Test runner
# ===========================================================================

def evaluate_terraform(case):
    lines = case["source"].splitlines()
    candidates = [i for i, text in enumerate(lines, 1) if case["marker"] in text and not text.lstrip().startswith("#")]
    drop = tf_should_drop(case["rule"], case["path"], candidates[-1], case["source"])
    return SUPPRESS if drop else KEEP, "SUPPRESSED" if drop else "REPORTED"


def evaluate_java(case):
    ix = java_index(case["source"])
    span = java_case_span(case)
    decisions = {java_should_drop(rule, ix, span) for rule in case["rules"]}
    drop = decisions == {True}
    return SUPPRESS if drop else KEEP, "SUPPRESSED" if drop else (case["final"] if case["final"].startswith("CONTROL") else "REPORTED")


def row(case, actual_detection, actual_filter, actual_final, real_ran):
    expected_final = "NO FINDING" if case["detection"] == NOT_DETECTED and real_ran else case["final"]
    wrong = []
    if actual_filter != case["action"]:
        wrong.append("filter")
    if actual_final != expected_final:
        wrong.append("final")
    if real_ran and actual_detection != case["detection"]:
        wrong.append("detection")
    result = FAIL if wrong else PASS if real_ran else REFERENCE_ONLY
    return {"id": case["id"], "family": case["family"], "kind": case["kind"], "EXPECTED_DETECTION": case["detection"], "ACTUAL_DETECTION": actual_detection,
            "EXPECTED_FILTER_ACTION": case["action"], "ACTUAL_FILTER_ACTION": actual_filter, "EXPECTED_FINAL_RESULT": expected_final,
            "ACTUAL_FINAL_RESULT": actual_final, "result": result, "wrong": wrong, "why": case["why"]}


def evaluate_secret(case, blob_lines, where, found, scanner_error):
    first_line = case["source"].split("\n")[0] if case["source"] else None
    reference_action, reference_final, _ = classify_secret(case["rule"], case["value"], case["value"], first_line if case["id"] != "U-PEM" else None)
    if case["source"] is None or scanner_error:
        return row(case, NOT_APPLICABLE if case["source"] is None else NOT_RUN, reference_action, reference_final, False)
    first = where[case["id"]]
    hits = [f for f in found.get(first, []) if case["rule"] in (None, f["RuleID"])]
    if not hits:
        return row(case, NOT_DETECTED, reference_action, "NO FINDING", True)
    # The real finding, not the hardcoded value, goes through the reference filter.
    hit = hits[0]
    action, final, _ = classify_secret(hit["RuleID"], hit["Secret"], hit["Match"], blob_lines[first - 1] if case["id"] != "U-PEM" else None)
    return row(case, DETECTED, action, final, True)


def evaluate_s10(case, rows_by_id):
    s1, s2 = rows_by_id["S1"], rows_by_id["S2"]
    good = all(r["ACTUAL_FILTER_ACTION"] == DOWNGRADE and r["ACTUAL_FINAL_RESULT"] == MEDIUM for r in (s1, s2))
    good = good and all(classify_secret(STRIPE, c["value"])[2] == STRIPE_REMEDIATION for c in STRIPE_CASES[:2])
    result = row(case, NOT_APPLICABLE, KEEP if good else "CHANGED", "VISIBLE+REMEDIATION" if good else "CHANGED", False)
    if good and s1["result"] == PASS and s2["result"] == PASS:
        result["result"] = PASS  # it validates two rows that did run through the real scanner
    return result


def integrity_checks():
    """Cross-family checks that do not count as scenarios. Returns the names of any that failed."""
    failed = []
    ids = [c["id"] for c in ALL_CASES]
    if len(ids) != len(set(ids)):
        failed.append("scenario ids are not unique")
    for family, (total, remain, act) in EXPECTED_TOTALS.items():
        cases = [c for c in ALL_CASES if c["family"] == family]
        actions = sum(1 for c in cases if c["action"] != KEEP)
        if len(cases) != total or actions != act or len(cases) - actions != remain:
            failed.append(f"{family} totals differ from the agreed {total}/{remain}/{act}")
    samples = [c["value"] for c in STRIPE_CASES if c["value"]]
    if len(samples) != 11 or len(set(samples)) != 9:  # S5 repeats S3's value and S6 repeats S1's, under another variable name
        failed.append("unexpected number of Stripe samples")
    t14 = next(c for c in TERRAFORM_CASES if c["id"] == "T14")
    if not tf_should_drop(TF_ACL, "tf/main.tf", 2, t14["source"]):
        failed.append("T14: a configuration rule on the same disabled block should still be dropped")
    if classify_secret("generic-api-key", "sk_test_51OzK9pL2mN5qR8tU1vW4xY7zA0bC3dE")[1] != HIGH:
        failed.append("the Stripe downgrade leaked into another rule")
    if classify_secret("generic-api-key", W_PLACEHOLDER, W_PLACEHOLDER)[0] != KEEP:
        failed.append("the Slack suppression leaked into another rule")
    return failed


def git_state():
    try:
        done = subprocess.run(["git", "--no-optional-locks", "status", "--porcelain"], capture_output=True, text=True, timeout=30,
                              cwd=os.path.dirname(os.path.abspath(__file__)))
        return done.stdout if done.returncode == 0 else None
    except (OSError, subprocess.SubprocessError):
        return None


# ===========================================================================
# 10. Summary report
# ===========================================================================

def build_report(rows, stress, integrity, gl_version, gl_error, clean):
    out = []
    emit = out.append
    emit("Filter results below come from the Python reference filter in this file, not from product code.")
    emit("")
    emit("Scanner availability")
    emit(f"  {'gitleaks':10} {'NOT RUN: ' + gl_error if gl_error else 'RAN through stdin, version ' + str(gl_version)}")
    for name, reason in [("Semgrep", "needs files on disk and writes its own logs, and this script may not write anything"),
                         ("Trivy", "`trivy config` only accepts a directory"), ("Terraform", "no terraform binary or real HCL parser is available"),
                         ("Worker", "not in this repository"), ("CLI", "not in this repository"), ("CI-ingest", "not in this repository")]:
        emit(f"  {name:10} NOT RUN: {reason}")
    emit("")
    widths = [10, 9, 12, 12, 10, 10, 20, 20, 14]
    head = ["ID", "Family", "Expected det", "Actual det", "Exp filter", "Act filter", "Expected final", "Actual final", "Result"]
    emit(" | ".join(h.ljust(w) for h, w in zip(head, widths)))
    emit("-+-".join("-" * w for w in widths))
    for r in rows:
        cells = [r["id"], r["family"], r["EXPECTED_DETECTION"], r["ACTUAL_DETECTION"], r["EXPECTED_FILTER_ACTION"], r["ACTUAL_FILTER_ACTION"],
                 r["EXPECTED_FINAL_RESULT"], r["ACTUAL_FINAL_RESULT"], r["result"]]
        emit(" | ".join(str(c)[:w].ljust(w) for c, w in zip(cells, widths)))

    emit("")
    emit("Summary")
    emit(f"  Total scenarios: {len(rows)}")
    expected_states = {s: sum(1 for r in rows if r["EXPECTED_DETECTION"] == s) for s in (DETECTED, NOT_DETECTED, ASSUMED, NOT_APPLICABLE)}
    emit(f"  Expected detection coverage: detected {expected_states[DETECTED]}, not detected {expected_states[NOT_DETECTED]}, "
         f"assumed with no scanner {expected_states[ASSUMED]}, not applicable {expected_states[NOT_APPLICABLE]}")
    actual_states = {s: sum(1 for r in rows if r["ACTUAL_DETECTION"] == s) for s in (DETECTED, NOT_DETECTED, NOT_RUN, NOT_APPLICABLE)}
    emit(f"  Actual scanner detection coverage: detected {actual_states[DETECTED]}, not detected {actual_states[NOT_DETECTED]}, "
         f"NOT RUN {actual_states[NOT_RUN]}, not applicable {actual_states[NOT_APPLICABLE]}")
    misses = [r["id"] for r in rows if r["ACTUAL_DETECTION"] == NOT_DETECTED]
    emit("  Gitleaks does not report: " + (", ".join(misses) if misses else "none, or it did not run"))
    gaps = [r["id"] for r in rows if r["EXPECTED_DETECTION"] == DETECTED and r["ACTUAL_DETECTION"] == NOT_DETECTED]
    emit("  Expected but not detected: " + (", ".join(gaps) if gaps else "none"))
    expected_suppress = [r for r in rows if r["EXPECTED_FILTER_ACTION"] == SUPPRESS]
    emit(f"  False positives correctly suppressed: {sum(r['ACTUAL_FILTER_ACTION'] == SUPPRESS for r in expected_suppress)} of {len(expected_suppress)} (reference)")
    keep_rows = [r for r in rows if r["EXPECTED_FILTER_ACTION"] == KEEP]
    emit(f"  Genuine, uncertain and control findings correctly retained: {sum(r['ACTUAL_FILTER_ACTION'] == KEEP for r in keep_rows)} of {len(keep_rows)} (reference)")
    emit("    " + ", ".join(f"{kind} {sum(r['kind'] == kind for r in keep_rows)}" for kind in (CONFIRMED, UNCERTAIN, CONTROL)))
    downgrades = [r["id"] for r in rows if r["ACTUAL_FILTER_ACTION"] == DOWNGRADE]
    emit("  Stripe severity changes, HIGH to MEDIUM and still visible: " + (", ".join(downgrades) if downgrades else "none"))
    unexpected_suppress = [r["id"] for r in rows if r["ACTUAL_FILTER_ACTION"] == SUPPRESS and r["EXPECTED_FILTER_ACTION"] != SUPPRESS]
    unexpected_keep = [r["id"] for r in rows if r["EXPECTED_FILTER_ACTION"] != KEEP and r["ACTUAL_FILTER_ACTION"] == KEEP]
    emit("  Unexpected suppressions: " + (", ".join(unexpected_suppress) if unexpected_suppress else "none"))
    emit("  Unexpected retained findings: " + (", ".join(unexpected_keep) if unexpected_keep else "none"))
    stress_ok = stress["kept"] == stress["expected_kept"] and stress["suppressed"] == stress["expected_suppressed"]
    emit(f"  Java stress test: {stress['matches']} matches, {stress['bytes'] / (1 << 20):.2f} MiB in memory, {stress['seconds'] * 1000:.0f} ms, "
         f"kept {stress['kept']} (expected {stress['expected_kept']}), suppressed {stress['suppressed']} (expected {stress['expected_suppressed']}), "
         f"traced peak {stress['peak_mib']:.1f} MiB, process max RSS {stress['maxrss_mib']:.0f} MiB: {REFERENCE_ONLY if stress_ok else FAIL}")

    emit("")
    emit("Per-family summary")
    emit(f"  {'Family':10} {'Total':>5} {'Remain':>6} {'Action':>6} {'PASS':>5} {'REF ONLY':>8} {'FAIL':>5} {'Detection NOT RUN':>18}")
    for family in EXPECTED_TOTALS:
        fam = [r for r in rows if r["family"] == family]
        action = sum(1 for r in fam if r["EXPECTED_FILTER_ACTION"] != KEEP)
        emit(f"  {family:10} {len(fam):5} {len(fam) - action:6} {action:6} {sum(r['result'] == PASS for r in fam):5} "
             f"{sum(r['result'] == REFERENCE_ONLY for r in fam):8} {sum(r['result'] == FAIL for r in fam):5} {sum(r['ACTUAL_DETECTION'] == NOT_RUN for r in fam):18}")

    failed = [r for r in rows if r["result"] == FAIL]
    if failed:
        emit("")
        emit("Failures")
        for r in failed:
            emit(f"  {r['id']}: {', '.join(r['wrong'])} differ. Expected {r['EXPECTED_DETECTION']}/{r['EXPECTED_FILTER_ACTION']}/{r['EXPECTED_FINAL_RESULT']}, "
                 f"got {r['ACTUAL_DETECTION']}/{r['ACTUAL_FILTER_ACTION']}/{r['ACTUAL_FINAL_RESULT']}.")
    if integrity:
        emit("")
        emit("Integrity check failures")
        for item in integrity:
            emit(f"  {item}")

    emit("")
    emit("Files created by this script: none. Repository status unchanged: " + ("yes" if clean else "NOT CHECKED" if clean is None else "NO"))
    emit("")
    bad = bool(failed or integrity or not stress_ok or clean is False)
    if bad:
        verdict = "FAIL: at least one check differs from expected."
    elif gl_error:
        verdict = "REFERENCE ONLY: the Python filters match every expected action, and no real scanner ran."
    else:
        verdict = ("REFERENCE CHECKS PASS: the Python filters and real gitleaks detection match expectations. "
                   "Terraform and Java detection did not run, and this does not prove any product scanner is fixed.")
    emit("Overall verdict: " + verdict)
    return "\n".join(out), bad


# ===========================================================================
# 11. Real Python SAST scenarios: scanned as source code, never executed
# ===========================================================================
# These are real functions, not strings, so a SAST engine analyses them as code. Nothing in this file calls
# them and the server is never started; sast_case_problems() fails the run if that ever changes. A pass here
# only proves the functions exist and stay uncalled: whether they are detected is a scanner result.
# sast_vuln_* is intentionally vulnerable, sast_safe_* is the secure version of the same operation.
# Third-party imports are optional so this harness keeps working on a machine without them.

import ast  # noqa: E402
import hashlib  # noqa: E402
import hmac  # noqa: E402
import logging  # noqa: E402
import pickle  # noqa: E402
import random  # noqa: E402
import secrets  # noqa: E402
import sqlite3  # noqa: E402
import ssl  # noqa: E402
import string  # noqa: E402
import tarfile  # noqa: E402
import tempfile  # noqa: E402
import urllib.parse  # noqa: E402
import urllib.request  # noqa: E402
import xml.etree.ElementTree as StdlibET  # noqa: E402
import zipfile  # noqa: E402

try:
    from flask import Flask, jsonify, redirect, render_template_string, request, send_file
except ImportError:
    class Flask:
        """Stand-in so the route decorators still load when Flask is not installed."""

        def __init__(self, name):
            self.name = name

        def route(self, _path, **_options):
            return lambda function: function

    jsonify = redirect = render_template_string = request = send_file = None

try:
    import requests
except ImportError:
    requests = None

try:
    import yaml
except ImportError:
    yaml = None

try:
    from lxml import etree
except ImportError:
    etree = None

try:
    import defusedxml.ElementTree as DefusedET
except ImportError:
    DefusedET = None

try:
    import jwt
except ImportError:
    jwt = None

app = Flask(__name__)
sast_logger = logging.getLogger("sast-scenarios")

SAST_UPLOAD_ROOT = "/srv/caseflow/uploads"
SAST_ALLOWED_HOSTS = {"api.caseflow.example"}
SAST_REDIRECTS = {"home": "/", "profile": "/profile"}
SAST_HOST_FORMAT = re.compile(r"[a-z0-9][a-z0-9.-]{0,252}")


def sast_contained_path(name):
    """Canonical path under SAST_UPLOAD_ROOT, or None when the name escapes it."""
    root = os.path.realpath(SAST_UPLOAD_ROOT)
    path = os.path.realpath(os.path.join(root, name))
    return path if os.path.commonpath([root, path]) == root else None


# --- OS command injection ---

# CWE-78: request value concatenated into a shell command.
@app.route("/sast/vuln/ping")
def sast_vuln_command_os_system():
    host = request.args["host"]
    return str(os.system("ping -c 1 " + host))


# CWE-78: request value run through a shell.
@app.route("/sast/vuln/lookup")
def sast_vuln_command_subprocess_shell():
    host = request.args["host"]
    command = f"nslookup {host}"
    return subprocess.run(command, shell=True, capture_output=True, text=True, check=False).stdout


def sast_shell_helper(command):
    return subprocess.Popen(command, shell=True)


# CWE-78: the request value reaches the shell through another function.
@app.route("/sast/vuln/trace")
def sast_vuln_command_through_helper():
    return str(sast_shell_helper("traceroute " + request.args["host"]).pid)


# Safe: format checked, argument array, no shell.
@app.route("/sast/safe/ping")
def sast_safe_command_argument_array():
    host = request.args["host"]
    if not SAST_HOST_FORMAT.fullmatch(host):
        return "invalid host", 400
    done = subprocess.run(["ping", "-c", "1", "--", host], shell=False, capture_output=True, text=True, timeout=10, check=False)
    return done.stdout


# --- Python code injection ---

# CWE-95: request value evaluated as Python.
@app.route("/sast/vuln/calculate")
def sast_vuln_code_eval():
    expression = request.args["expression"]
    return str(eval(expression))


# CWE-94: request body executed as Python.
@app.route("/sast/vuln/script", methods=["POST"])
def sast_vuln_code_exec():
    source = request.get_data(as_text=True)
    exec(source)
    return "done"


# Safe: only Python literals are parsed.
@app.route("/sast/safe/calculate")
def sast_safe_code_literal_eval():
    return str(ast.literal_eval(request.args["expression"]))


# --- SQL injection ---

# CWE-89: query built by concatenation.
@app.route("/sast/vuln/case")
def sast_vuln_sql_concatenation():
    case_id = request.args["id"]
    connection = sqlite3.connect(":memory:")
    return jsonify(connection.execute("SELECT * FROM cases WHERE id = '" + case_id + "'").fetchall())


# CWE-89: query built with an f-string in a variable.
@app.route("/sast/vuln/search")
def sast_vuln_sql_fstring():
    owner = request.args["owner"]
    query = f"SELECT * FROM cases WHERE owner = '{owner}'"
    cursor = sqlite3.connect(":memory:").cursor()
    cursor.execute(query)
    return jsonify(cursor.fetchall())


# Safe: bound parameter.
@app.route("/sast/safe/case")
def sast_safe_sql_parameterized():
    connection = sqlite3.connect(":memory:")
    return jsonify(connection.execute("SELECT * FROM cases WHERE id = ?", (request.args["id"],)).fetchall())


# --- Path traversal ---

# CWE-22: user path joined to the base directory with no containment check.
@app.route("/sast/vuln/attachment")
def sast_vuln_path_traversal_read():
    path = os.path.join(SAST_UPLOAD_ROOT, request.args["name"])
    with open(path, encoding="utf-8") as handle:
        return handle.read()


# Safe: canonical path must stay under the base directory.
@app.route("/sast/safe/attachment")
def sast_safe_path_contained_read():
    path = sast_contained_path(request.args["name"])
    if path is None:
        return "not found", 404
    with open(path, encoding="utf-8") as handle:
        return handle.read()


# --- Arbitrary file read and write ---

# CWE-73: the caller chooses which file is served.
@app.route("/sast/vuln/download")
def sast_vuln_file_read_any():
    return send_file(request.args["path"])


# CWE-73: the caller chooses which file is overwritten and its content.
@app.route("/sast/vuln/save", methods=["POST"])
def sast_vuln_file_write_any():
    with open(request.args["path"], "wb") as handle:
        handle.write(request.get_data())
    return "saved"


# Safe: the caller's text goes to a new temporary file whose name the server chose.
@app.route("/sast/safe/save", methods=["POST"])
def sast_safe_file_write_generated_name():
    with tempfile.NamedTemporaryFile(dir=tempfile.gettempdir(), delete=False) as handle:
        handle.write(request.get_data())
        return os.path.basename(handle.name)


# --- Server-side request forgery ---

# CWE-918: user URL given to requests.
@app.route("/sast/vuln/preview")
def sast_vuln_ssrf_requests():
    return requests.get(request.args["url"], timeout=5).text


# CWE-918: user URL given to urllib, which also accepts file:// URLs.
@app.route("/sast/vuln/fetch")
def sast_vuln_ssrf_urllib():
    with urllib.request.urlopen(request.args["url"], timeout=5) as response:
        return response.read()


# Safe: fixed host, the caller picks only a validated numeric id.
@app.route("/sast/safe/preview")
def sast_safe_ssrf_fixed_host():
    case_id = int(request.args["id"])
    return requests.get(f"https://api.caseflow.example/cases/{case_id}", timeout=5).text


# Safe: scheme and host checked against an allowlist, redirects off.
def sast_safe_ssrf_allowlist(url):
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https" or parts.hostname not in SAST_ALLOWED_HOSTS:
        raise ValueError("host not allowed")
    return requests.get(url, timeout=5, allow_redirects=False).text


# --- Unsafe deserialization ---

# CWE-502: pickle runs code from the request body.
@app.route("/sast/vuln/restore", methods=["POST"])
def sast_vuln_deserialize_pickle():
    return str(pickle.loads(request.get_data()))


# CWE-502: the full YAML loader can build arbitrary objects.
@app.route("/sast/vuln/import", methods=["POST"])
def sast_vuln_deserialize_yaml():
    return str(yaml.load(request.get_data(), Loader=yaml.Loader))


# Safe: JSON builds only plain data.
@app.route("/sast/safe/restore", methods=["POST"])
def sast_safe_deserialize_json():
    return str(json.loads(request.get_data()))


# Safe: yaml.safe_load builds only plain data.
@app.route("/sast/safe/import", methods=["POST"])
def sast_safe_deserialize_yaml():
    return str(yaml.safe_load(request.get_data()))


# --- Insecure temporary files ---

# CWE-377: the name can be taken over before the file is created.
def sast_vuln_tempfile_mktemp(content):
    path = tempfile.mktemp(suffix=".csv")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)
    return path


# CWE-377: fixed, predictable name in a shared directory.
def sast_vuln_tempfile_predictable(content):
    path = "/tmp/caseflow-export.csv"
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)
    return path


# Safe: created atomically with an unpredictable name and private permissions.
def sast_safe_tempfile_mkstemp(content):
    descriptor, path = tempfile.mkstemp(suffix=".csv")
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(content)
    return path


# --- Weak cryptographic algorithms ---

# CWE-328: MD5 used to protect a value against tampering.
def sast_vuln_weak_hash_md5_signature(payload):
    return hashlib.md5(b"caseflow" + payload).hexdigest()


# CWE-328: SHA-1 used to protect a value against tampering.
def sast_vuln_weak_hash_sha1_signature(payload):
    return hashlib.sha1(b"caseflow" + payload).hexdigest()


# Safe: HMAC-SHA-256 with a key read from the environment.
def sast_safe_hmac_sha256_signature(payload):
    return hmac.new(os.environ["CASEFLOW_SIGNING_KEY"].encode(), payload, hashlib.sha256).hexdigest()


# --- Hardcoded cryptographic keys ---

# CWE-321: synthetic signing key committed in source.
SAST_WEBHOOK_SIGNING_KEY = "f4Q9zLw2Xv7TnR1cKp8HsY3mBd6GjE0a"


def sast_vuln_hardcoded_signing_key(payload):
    return hmac.new(SAST_WEBHOOK_SIGNING_KEY.encode(), payload, hashlib.sha256).hexdigest()


# CWE-321: synthetic JWT key written directly into the call.
def sast_vuln_hardcoded_jwt_key(user_id):
    return jwt.encode({"sub": user_id}, "N7vK2pXq9Lm4Zt8RwB3cYh6Fd1Gs5Ja0", algorithm="HS256")


# --- Insecure TLS verification ---

# CWE-295: certificate checks disabled for requests.
def sast_vuln_tls_verify_disabled(url):
    return requests.get(url, verify=False, timeout=5).text


# CWE-295: context that accepts any certificate.
def sast_vuln_tls_unverified_context(url):
    with urllib.request.urlopen(url, context=ssl._create_unverified_context(), timeout=5) as response:
        return response.read()


# CWE-295: verification turned off on a client context.
def sast_vuln_tls_cert_none():
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


# Safe: certificates verified.
def sast_safe_tls_verified(url):
    return requests.get(url, verify=True, timeout=5).text


# Safe: default context verifies certificates and host names.
def sast_safe_tls_default_context():
    with urllib.request.urlopen("https://api.caseflow.example/health", context=ssl.create_default_context(), timeout=5) as response:
        return response.read()


# --- Weak random numbers for security tokens ---

# CWE-338: predictable generator for a login code.
def sast_vuln_random_login_code():
    login_code = random.randint(100000, 999999)
    return login_code


# CWE-338: predictable generator inside a join.
def sast_vuln_random_reset_token():
    return "".join(random.choice(string.ascii_letters) for _ in range(32))


# CWE-338: random.choices for an API key.
def sast_vuln_random_api_key():
    api_key = "".join(random.choices(string.ascii_letters + string.digits, k=40))
    return api_key


# Safe: cryptographically secure generator.
def sast_safe_secrets_token():
    return secrets.token_urlsafe(32)


# --- Insecure password hashing ---

# CWE-916: fast unsalted MD5.
def sast_vuln_password_md5(password):
    return hashlib.md5(password.encode()).hexdigest()


# CWE-759: fast unsalted SHA-256.
def sast_vuln_password_sha256_unsalted(password):
    return hashlib.sha256(password.encode()).hexdigest()


# Safe: memory-hard KDF with a random salt.
def sast_safe_password_scrypt(password):
    salt = os.urandom(16)
    return salt.hex() + ":" + hashlib.scrypt(password.encode(), salt=salt, n=2 ** 14, r=8, p=1).hex()


# --- Sensitive information exposure ---

# CWE-532: the password is written to the log.
def sast_vuln_exposure_password_logged(username, password):
    sast_logger.info("login user=%s password=%s", username, password)


# CWE-200: every environment variable is returned to the caller.
@app.route("/sast/vuln/debug-env")
def sast_vuln_exposure_environment():
    return jsonify(dict(os.environ))


# CWE-209: the raw exception goes back to the caller.
@app.route("/sast/vuln/report")
def sast_vuln_exposure_exception():
    try:
        return str(1 / int(request.args["divisor"]))
    except (ValueError, ZeroDivisionError) as err:
        return repr(err), 500


# CWE-489: the debugger allows code execution from the browser. Nothing calls this.
def sast_vuln_exposure_debug_server():
    app.run(host="0.0.0.0", debug=True)


# Safe: the password is left out of the log.
def sast_safe_exposure_log_username_only(username):
    sast_logger.info("login user=%s", username)


# Safe: only the generic message goes back.
@app.route("/sast/safe/report")
def sast_safe_exposure_generic_error():
    try:
        return str(1 / int(request.args["divisor"]))
    except (ValueError, ZeroDivisionError):
        sast_logger.exception("report failed")
        return "report failed", 500


# --- Open redirect ---

# CWE-601: the target comes straight from the request.
@app.route("/sast/vuln/continue")
def sast_vuln_open_redirect():
    return redirect(request.args["next"])


# Safe: the request picks a key from a server-side table.
@app.route("/sast/safe/continue")
def sast_safe_redirect_allowlist():
    return redirect(SAST_REDIRECTS.get(request.args.get("next"), "/"))


# --- ReDoS ---

# CWE-1333: nested quantifier backtracks exponentially on input like "aaaa!".
@app.route("/sast/vuln/validate")
def sast_vuln_redos_nested_quantifier():
    return str(bool(re.match(r"^(a+)+$", request.args["value"])))


# CWE-1333: overlapping alternatives backtrack exponentially.
def sast_vuln_redos_overlapping_alternatives(value):
    return re.fullmatch(r"(\w|\d)+@caseflow\.example", value) is not None


# Safe: no nested quantifier, input length limited.
@app.route("/sast/safe/validate")
def sast_safe_regex_linear():
    value = request.args["value"][:256]
    return str(re.fullmatch(r"a+", value) is not None)


# --- XML external entities ---

# CWE-611: entity resolution switched on explicitly.
@app.route("/sast/vuln/xml-lxml", methods=["POST"])
def sast_vuln_xxe_lxml_resolve_entities():
    parser = etree.XMLParser(resolve_entities=True)
    return etree.tostring(etree.fromstring(request.get_data(), parser))


# CWE-611: lxml parse with its default parser.
@app.route("/sast/vuln/xml-upload", methods=["POST"])
def sast_vuln_xxe_lxml_parse():
    return etree.tostring(etree.parse(request.files["document"]))


# CWE-776: stdlib parser has no protection against entity expansion.
@app.route("/sast/vuln/xml-stdlib", methods=["POST"])
def sast_vuln_xml_stdlib_expansion():
    return StdlibET.fromstring(request.get_data()).tag


# Safe: entities and network access turned off.
@app.route("/sast/safe/xml-lxml", methods=["POST"])
def sast_safe_xml_lxml_hardened():
    parser = etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False)
    return etree.tostring(etree.fromstring(request.get_data(), parser))


# Safe: defusedxml rejects entity tricks.
@app.route("/sast/safe/xml-defused", methods=["POST"])
def sast_safe_xml_defusedxml():
    return DefusedET.fromstring(request.get_data()).tag


# --- Unsafe archive extraction ---

# CWE-22: tar member names are trusted on extraction.
def sast_vuln_archive_tar_extractall(archive_path, destination):
    with tarfile.open(archive_path) as archive:
        archive.extractall(destination)


# CWE-22: zip member name joined by hand and written with no containment check.
def sast_vuln_archive_zip_slip(archive_path, destination):
    with zipfile.ZipFile(archive_path) as archive:
        for member in archive.namelist():
            target = os.path.join(destination, member)
            with open(target, "wb") as handle:
                handle.write(archive.read(member))


# Safe: the "data" filter rejects path escapes, links and device files.
def sast_safe_archive_tar_filter(archive_path, destination):
    with tarfile.open(archive_path) as archive:
        archive.extractall(destination, filter="data")


# Safe: each member's canonical path must stay under the destination.
def sast_safe_archive_zip_contained(archive_path, destination):
    root = os.path.realpath(destination)
    with zipfile.ZipFile(archive_path) as archive:
        for member in archive.infolist():
            target = os.path.realpath(os.path.join(root, member.filename))
            if os.path.commonpath([root, target]) != root:
                raise ValueError("archive member escapes the destination")
            archive.extract(member, root)


# --- Insecure JWT verification ---

# CWE-347: the signature is never checked.
@app.route("/sast/vuln/whoami")
def sast_vuln_jwt_signature_disabled():
    claims = jwt.decode(request.headers["X-Token"], options={"verify_signature": False})
    return claims["sub"]


# CWE-347: the unsigned "none" algorithm is accepted.
@app.route("/sast/vuln/whoami-none")
def sast_vuln_jwt_none_algorithm():
    claims = jwt.decode(request.headers["X-Token"], "", algorithms=["none", "HS256"])
    return claims["sub"]


# Safe: signature verified with a fixed algorithm and a key from the environment.
@app.route("/sast/safe/whoami")
def sast_safe_jwt_verified():
    claims = jwt.decode(request.headers["X-Token"], os.environ["CASEFLOW_JWT_KEY"], algorithms=["HS256"])
    return claims["sub"]


# --- Other Python weaknesses in TigerGate's rule scope ---

# CWE-1336: the template text comes from the request.
@app.route("/sast/vuln/greeting")
def sast_vuln_template_injection():
    return render_template_string("<p>" + request.args["name"] + "</p>")


# Safe: fixed template, the value is autoescaped.
@app.route("/sast/safe/greeting")
def sast_safe_template_variable():
    return render_template_string("<p>{{ name }}</p>", name=request.args["name"])


# CWE-79: request value returned as HTML without escaping.
@app.route("/sast/vuln/banner")
def sast_vuln_reflected_xss():
    return "<h1>" + request.args["title"] + "</h1>"


# Safe: Flask's template engine escapes the value.
@app.route("/sast/safe/banner")
def sast_safe_escaped_output():
    return render_template_string("<h1>{{ title }}</h1>", title=request.args["title"])


# CWE-134: format string from the request can read object attributes.
@app.route("/sast/vuln/label")
def sast_vuln_format_string():
    return request.args["template"].format(app=app)


# Safe: fixed format string.
@app.route("/sast/safe/label")
def sast_safe_fixed_format():
    return "Case {}".format(int(request.args["id"]))


# CWE-915: the request chooses which attribute is written.
@app.route("/sast/vuln/settings", methods=["POST"])
def sast_vuln_attribute_injection():
    setattr(sast_logger, request.args["field"], request.args["value"])
    return "updated"


# Safe: the field must be on a fixed allowlist.
@app.route("/sast/safe/settings", methods=["POST"])
def sast_safe_attribute_allowlist():
    field = request.args["field"]
    if field not in {"name"}:
        return "unknown field", 400
    setattr(sast_logger, field, request.args["value"])
    return "updated"


# CWE-732: world-writable permissions on an uploaded file.
def sast_vuln_world_writable_file(path):
    os.chmod(path, 0o777)


# Safe: only the owner can read and write.
def sast_safe_owner_only_file(path):
    os.chmod(path, 0o600)


# ID, category, CWE, OWASP 2021 (* nearest category, the CWE is not on the official list; n/a none fits), vulnerable
# function, its safe comparison (None when no direct equivalent exists).
SAST_CASES = [
    ("PY-V01", "OS command injection", "CWE-78", "A03", "sast_vuln_command_os_system", "sast_safe_command_argument_array"),
    ("PY-V02", "OS command injection", "CWE-78", "A03", "sast_vuln_command_subprocess_shell", "sast_safe_command_argument_array"),
    ("PY-V03", "OS command injection across functions", "CWE-78", "A03", "sast_vuln_command_through_helper", "sast_safe_command_argument_array"),
    ("PY-V04", "Code injection, eval", "CWE-95", "A03", "sast_vuln_code_eval", "sast_safe_code_literal_eval"),
    ("PY-V05", "Code injection, exec", "CWE-94", "A03", "sast_vuln_code_exec", "sast_safe_code_literal_eval"),
    ("PY-V06", "SQL injection, concatenation", "CWE-89", "A03", "sast_vuln_sql_concatenation", "sast_safe_sql_parameterized"),
    ("PY-V07", "SQL injection, f-string", "CWE-89", "A03", "sast_vuln_sql_fstring", "sast_safe_sql_parameterized"),
    ("PY-V08", "Path traversal", "CWE-22", "A01", "sast_vuln_path_traversal_read", "sast_safe_path_contained_read"),
    ("PY-V09", "Arbitrary file read", "CWE-73", "A04", "sast_vuln_file_read_any", "sast_safe_path_contained_read"),
    ("PY-V10", "Arbitrary file write", "CWE-73", "A04", "sast_vuln_file_write_any", "sast_safe_file_write_generated_name"),
    ("PY-V11", "SSRF, requests", "CWE-918", "A10", "sast_vuln_ssrf_requests", "sast_safe_ssrf_fixed_host"),
    ("PY-V12", "SSRF, urllib", "CWE-918", "A10", "sast_vuln_ssrf_urllib", "sast_safe_ssrf_allowlist"),
    ("PY-V13", "Deserialization, pickle", "CWE-502", "A08", "sast_vuln_deserialize_pickle", "sast_safe_deserialize_json"),
    ("PY-V14", "Deserialization, YAML", "CWE-502", "A08", "sast_vuln_deserialize_yaml", "sast_safe_deserialize_yaml"),
    ("PY-V15", "Temporary file, mktemp", "CWE-377", "A01", "sast_vuln_tempfile_mktemp", "sast_safe_tempfile_mkstemp"),
    ("PY-V16", "Temporary file, predictable name", "CWE-377", "A01", "sast_vuln_tempfile_predictable", "sast_safe_tempfile_mkstemp"),
    ("PY-V17", "Weak hash, MD5", "CWE-328", "A02", "sast_vuln_weak_hash_md5_signature", "sast_safe_hmac_sha256_signature"),
    ("PY-V18", "Weak hash, SHA-1", "CWE-328", "A02", "sast_vuln_weak_hash_sha1_signature", "sast_safe_hmac_sha256_signature"),
    ("PY-V19", "Hardcoded signing key", "CWE-321", "A02", "sast_vuln_hardcoded_signing_key", "sast_safe_hmac_sha256_signature"),
    ("PY-V20", "Hardcoded JWT key", "CWE-321", "A02", "sast_vuln_hardcoded_jwt_key", "sast_safe_jwt_verified"),
    ("PY-V21", "TLS, verify=False", "CWE-295", "A07", "sast_vuln_tls_verify_disabled", "sast_safe_tls_verified"),
    ("PY-V22", "TLS, unverified context", "CWE-295", "A07", "sast_vuln_tls_unverified_context", "sast_safe_tls_default_context"),
    ("PY-V23", "TLS, CERT_NONE", "CWE-295", "A07", "sast_vuln_tls_cert_none", "sast_safe_tls_default_context"),
    ("PY-V24", "Weak random, randint", "CWE-338", "A02", "sast_vuln_random_login_code", "sast_safe_secrets_token"),
    ("PY-V25", "Weak random, choice in join", "CWE-338", "A02", "sast_vuln_random_reset_token", "sast_safe_secrets_token"),
    ("PY-V26", "Weak random, choices", "CWE-338", "A02", "sast_vuln_random_api_key", "sast_safe_secrets_token"),
    ("PY-V27", "Password hash, MD5", "CWE-916", "A02", "sast_vuln_password_md5", "sast_safe_password_scrypt"),
    ("PY-V28", "Password hash, unsalted SHA-256", "CWE-759", "A02", "sast_vuln_password_sha256_unsalted", "sast_safe_password_scrypt"),
    ("PY-V29", "Password in logs", "CWE-532", "A09", "sast_vuln_exposure_password_logged", "sast_safe_exposure_log_username_only"),
    ("PY-V30", "Environment returned to caller", "CWE-200", "A01", "sast_vuln_exposure_environment", None),
    ("PY-V31", "Exception returned to caller", "CWE-209", "A04", "sast_vuln_exposure_exception", "sast_safe_exposure_generic_error"),
    ("PY-V32", "Flask debug server", "CWE-489", "A05*", "sast_vuln_exposure_debug_server", None),
    ("PY-V33", "Open redirect", "CWE-601", "A01", "sast_vuln_open_redirect", "sast_safe_redirect_allowlist"),
    ("PY-V34", "ReDoS, nested quantifier", "CWE-1333", "n/a", "sast_vuln_redos_nested_quantifier", "sast_safe_regex_linear"),
    ("PY-V35", "ReDoS, overlapping alternatives", "CWE-1333", "n/a", "sast_vuln_redos_overlapping_alternatives", "sast_safe_regex_linear"),
    ("PY-V36", "XXE, lxml resolve_entities", "CWE-611", "A05", "sast_vuln_xxe_lxml_resolve_entities", "sast_safe_xml_lxml_hardened"),
    ("PY-V37", "XXE, lxml parse", "CWE-611", "A05", "sast_vuln_xxe_lxml_parse", "sast_safe_xml_lxml_hardened"),
    ("PY-V38", "XML expansion, stdlib", "CWE-776", "A05", "sast_vuln_xml_stdlib_expansion", "sast_safe_xml_defusedxml"),
    ("PY-V39", "Archive extraction, tar", "CWE-22", "A01", "sast_vuln_archive_tar_extractall", "sast_safe_archive_tar_filter"),
    ("PY-V40", "Archive extraction, zip", "CWE-22", "A01", "sast_vuln_archive_zip_slip", "sast_safe_archive_zip_contained"),
    ("PY-V41", "JWT signature disabled", "CWE-347", "A02", "sast_vuln_jwt_signature_disabled", "sast_safe_jwt_verified"),
    ("PY-V42", "JWT none algorithm", "CWE-347", "A02", "sast_vuln_jwt_none_algorithm", "sast_safe_jwt_verified"),
    ("PY-V43", "Template injection", "CWE-1336", "A03*", "sast_vuln_template_injection", "sast_safe_template_variable"),
    ("PY-V44", "Reflected XSS", "CWE-79", "A03", "sast_vuln_reflected_xss", "sast_safe_escaped_output"),
    ("PY-V45", "Format string", "CWE-134", "A03*", "sast_vuln_format_string", "sast_safe_fixed_format"),
    ("PY-V46", "Attribute injection", "CWE-915", "A08", "sast_vuln_attribute_injection", "sast_safe_attribute_allowlist"),
    ("PY-V47", "World-writable file", "CWE-732", "A01*", "sast_vuln_world_writable_file", "sast_safe_owner_only_file"),
]


def sast_case_problems():
    """Every listed function exists, every sast_vuln_ and sast_safe_ function is listed, and none is ever called."""
    with open(os.path.abspath(__file__), encoding="utf-8") as handle:
        tree = ast.parse(handle.read())
    defined = {node.name for node in tree.body if isinstance(node, ast.FunctionDef)}
    scenario = {name for name in defined if name.startswith(("sast_vuln_", "sast_safe_"))}
    listed = {name for case in SAST_CASES for name in case[4:6] if name}
    problems = [f"{name} is listed but not defined" for name in sorted(listed - defined)]
    problems += [f"{name} is defined but not listed" for name in sorted(scenario - listed)]
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = node.func.id if isinstance(node.func, ast.Name) else node.func.attr if isinstance(node.func, ast.Attribute) else ""
        if name in scenario or (name == "sast_shell_helper" and not_inside_helper_caller(tree, node)):
            problems.append(f"line {node.lineno} calls {name}")
    return problems


def not_inside_helper_caller(tree, call):
    """The shell helper may be called only from the scenario that demonstrates it, which is itself never called."""
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == "sast_vuln_command_through_helper":
            return call not in ast.walk(node)
    return True


def sast_summary(problems):
    vulnerable = {case[4] for case in SAST_CASES}
    safe = {case[5] for case in SAST_CASES if case[5]}
    lines = ["", "Python SAST source scenarios", f"  {len(vulnerable)} vulnerable and {len(safe)} safe functions, none executed. Detection NOT RUN here: scan this file with a SAST engine."]
    lines += [f"  PROBLEM: {problem}" for problem in problems]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--no-scanner", action="store_true", help="do not run gitleaks; every row becomes reference only")
    parser.add_argument("--stress", type=int, default=20000, help="matches in the Java stress test")
    args = parser.parse_args()

    before = git_state()
    secret_cases = STRIPE_CASES + SLACK_CASES + OTHER_CASES
    blob_lines, where = scan_blob(secret_cases)
    if args.no_scanner:
        found, gl_version, gl_error = {}, None, "--no-scanner was given"
    else:
        found, gl_version, gl_error = run_gitleaks_stdin(blob_lines)

    rows = []
    for case in TERRAFORM_CASES:
        action, final = evaluate_terraform(case)
        rows.append(row(case, NOT_RUN, action, final, False))
    for case in JAVA_CASES:
        action, final = evaluate_java(case)
        rows.append(row(case, NOT_APPLICABLE if case["detection"] == NOT_APPLICABLE else NOT_RUN, action, final, False))
    by_id = {c["id"]: evaluate_secret(c, blob_lines, where, found, gl_error) for c in secret_cases if c["id"] != "S10"}
    for case in secret_cases:
        rows.append(evaluate_s10(case, by_id) if case["id"] == "S10" else by_id[case["id"]])

    stress = run_java_stress(args.stress)
    integrity = integrity_checks()
    after = git_state()
    clean = (before == after) if before is not None else None
    text, bad = build_report(rows, stress, integrity, gl_version, gl_error, clean)
    problems = sast_case_problems()
    text += "\n" + sast_summary(problems)
    bad = bad or bool(problems)

    # The report carries scenario ids and labels only. Refuse to print if a sample value got into it.
    if any(c.get("value") and c["value"] in text for c in secret_cases):
        print("Self check failed: the report would contain a sample secret value, so it was withheld.")
        return 2
    print(text)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
