"""Outbound HTTP to customer systems for the e-mail/ticket ingestion service."""
from __future__ import annotations

import logging
import os
import ssl
import urllib.request

import httpx
import requests
import urllib3

log = logging.getLogger(__name__)

CA_BUNDLE = os.environ.get("CASEFLOW_CA_BUNDLE", "/etc/ssl/certs/ca-certificates.crt")
PARTNER_STATUS_URL = "https://status.partner-crm.example/api/v2/status.json"


def fetch_mailbox_export(url: str, token: str) -> bytes:
    """Pulls an mbox export from a customer's on-prem mail archive (often self-signed)."""
    # CASE: R03-TP-13
    # ruleid: SAST-042 | src: constant | sink: requests.get verify | certificate validation off for every customer archive
    resp = requests.get(url, headers={"Authorization": f"Bearer {token}"}, verify=False, timeout=30)
    resp.raise_for_status()
    return resp.content


def fetch_partner_status() -> dict:
    # CASE: R03-FP-15
    # ok: SAST-042 | src: constant | sink: requests.get verify | explicit verification with the system CA bundle
    return requests.get(PARTNER_STATUS_URL, verify=CA_BUNDLE, timeout=5).json()


def fetch_partner_status_default() -> dict:
    # CASE: R03-FP-16
    # ok: SAST-042 | src: default | sink: requests.get | requests verifies by default
    return requests.get(PARTNER_STATUS_URL, timeout=5).json()


def helpdesk_client(base_url: str) -> httpx.Client:
    # CASE: R03-TP-14
    # ruleid: SAST-042 | src: constant | sink: httpx.Client verify | httpx client accepting any certificate
    return httpx.Client(base_url=base_url, verify=False, timeout=10.0)


def strict_helpdesk_client(base_url: str) -> httpx.Client:
    # CASE: R03-FP-17
    # ok: SAST-042 | src: constant | sink: httpx.Client verify | verification on
    return httpx.Client(base_url=base_url, verify=True, timeout=10.0)


def legacy_soap_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    # CASE: R03-GAP-05
    # todoruleid: SAST-042 | src: constant | sink: ssl verify_mode | CERT_NONE disables validation; not one of the rule's three patterns
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def download_legacy_attachment(url: str) -> bytes:
    # CASE: R03-GAP-06
    # todoruleid: SAST-042 | src: constant | sink: urllib with unverified context | _create_unverified_context() skips validation; not a rule pattern
    with urllib.request.urlopen(url, context=ssl._create_unverified_context(), timeout=30) as r:
        return r.read()


def quiet_proxy_warnings() -> None:
    # CASE: R03-FP-18
    # ok: SAST-042 | src: constant | sink: urllib3.disable_warnings | only silences warnings; verification is unchanged
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def reconcile_totals(rows: list[dict], verify: bool = True) -> int:
    """Sums ticket counts; `verify` re-checks each row against the source system (slow)."""
    return sum(int(r["count"]) for r in rows)


def nightly_rollup(rows: list[dict]) -> int:
    # CASE: R03-FP-19
    # ok: SAST-042 | src: constant | sink: unrelated keyword argument | "verify" here means skip re-counting, nothing to do with TLS
    return reconcile_totals(rows, verify=False)
