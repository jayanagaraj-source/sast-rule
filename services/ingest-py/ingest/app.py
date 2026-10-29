"""Ingestion API (FastAPI): receives inbound e-mail webhooks and search requests from the support console."""
from __future__ import annotations

import os
import re
from pathlib import Path

import requests
from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel

from .upstream import fetch_partner_status

app = FastAPI(title="caseflow-ingest")

TEMPLATE_DIR = Path(os.environ.get("INGEST_TEMPLATE_DIR", "/srv/ingest/templates"))
DEFAULT_ROUTING = {"queue": "general", "priority": "normal"}
ALLOWED_OVERRIDES = {"queue", "priority"}
STATUS_URL = "https://status.partner-crm.example/api/v2/status.json"


class InboundEmail(BaseModel):
    tenant_id: str
    sender: str
    subject: str
    body: str
    routing: dict[str, str] = {}


@app.get("/search")
def search(q: str = Query(..., max_length=200), subjects: list[str] = Query(default=[])) -> list[str]:
    # CASE: R11-GAP-06
    # todoruleid: SAST-011 | src: query param q | sink: re.compile + search | attacker regex (Python is not a language SAST-011 is served for)
    pattern = re.compile(q)
    return [s for s in subjects if pattern.search(s)]


@app.get("/search/literal")
def search_literal(q: str = Query(..., max_length=200), subjects: list[str] = Query(default=[])) -> list[str]:
    # CASE: R11-FP-16
    # ok: SAST-011 | src: query param q (escaped) | sink: re.compile | re.escape makes the search literal
    pattern = re.compile(re.escape(q), re.IGNORECASE)
    return [s for s in subjects if pattern.search(s)]


@app.post("/inbound")
def inbound(mail: InboundEmail) -> dict:
    routing = dict(DEFAULT_ROUTING)
    # CASE: R08-FP-25
    # ok: JS-002 | src: allowlisted keys of the inbound payload | sink: dict.update | Python dict update, not JS Object.assign; JS-only rule must stay silent
    routing.update({k: v for k, v in mail.routing.items() if k in ALLOWED_OVERRIDES})
    # CASE: R13-FP-16, R10-FP-27
    # ok: javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal, gitlab.eslint.detect-non-literal-fs-filename | src: constant filename | sink: os.path.join + open | Python path join of a fixed name; JS-only rules must stay silent
    with open(os.path.join(TEMPLATE_DIR, "ack.txt"), encoding="utf-8") as fh:
        ack = fh.read()
    return {"routing": routing, "ack": ack.format(subject=mail.subject[:120])}


@app.get("/partner-status")
def partner_status() -> dict:
    # CASE: R04-FP-13
    # ok: TG-TAINT-JS-SSRF | src: constant URL | sink: requests.get | fixed partner endpoint in Python; JS-only taint rule must stay silent
    resp = requests.get(STATUS_URL, timeout=5)
    if resp.status_code >= 500:
        raise HTTPException(status_code=502, detail="partner status unavailable")
    return {"partner": resp.json(), "cached": fetch_partner_status()}
