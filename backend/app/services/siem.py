"""SIEM export: SwarmGuard alerts as OCSF Detection Findings (Open Cybersecurity Schema Framework, class 2004).

OCSF is the open schema Splunk, Microsoft Sentinel, AWS Security Lake, IBM QRadar and others ingest, so alerts land in
a security team's existing tools instead of only in our UI.

    GET /api/runs/{run_id}/alerts?format=ocsf      the run's alerts as OCSF findings
    SWARMGUARD_SIEM_URL=https://siem/collector     opt-in: push each finished run's findings (JSON array, one POST)
    SWARMGUARD_SIEM_AUTH="Splunk <token>"          optional Authorization header for that POST

Each finding carries the rule, severity, the agents (as resources), the evidence event ids, the recommended action and
the OWASP Agentic Top 10 risks the rule maps to.
"""
from __future__ import annotations

import json
import logging
import os
import queue
import threading
import urllib.request
from typing import Callable

from app.schemas import Alert
from app.timeutil import parse_iso

log = logging.getLogger(__name__)

SEVERITY_ID = {"low": 2, "medium": 3, "high": 4, "critical": 5}  # OCSF: 1 informational .. 5 critical
CLASS_UID, CATEGORY_UID, ACTIVITY_CREATE = 2004, 2, 1  # Detection Finding, Findings, Create


def _owasp_by_rule() -> dict[str, list[str]]:
    from app.modules.detection.owasp import OWASP_AGENTIC

    out: dict[str, list[str]] = {}
    for risk in OWASP_AGENTIC:
        for rule in risk["rules"]:
            out.setdefault(rule, []).append(f"{risk['id']} {risk['name']}")
    return out


def to_ocsf(alert: Alert, owasp: dict[str, list[str]] | None = None) -> dict:
    owasp = owasp if owasp is not None else _owasp_by_rule()
    ms = int(parse_iso(alert.created_at).timestamp() * 1000)
    return {
        "class_uid": CLASS_UID, "class_name": "Detection Finding", "category_uid": CATEGORY_UID,
        "category_name": "Findings", "activity_id": ACTIVITY_CREATE, "activity_name": "Create",
        "type_uid": CLASS_UID * 100 + ACTIVITY_CREATE, "time": ms,
        "severity_id": SEVERITY_ID.get(alert.severity, 0), "severity": alert.severity.title(),
        "status_id": 1 if alert.status == "open" else 99, "status": alert.status.title(),
        "message": alert.reason,
        "finding_info": {"uid": alert.alert_id, "title": f"{alert.rule_id} {alert.rule_name}", "desc": alert.reason,
                         "created_time": ms, "types": owasp.get(alert.rule_id, []),
                         "analytic": {"uid": alert.rule_id, "name": alert.rule_name, "type_id": 1, "type": "Rule"}},
        "resources": [{"uid": a, "type": "AI Agent", "group": {"uid": alert.run_id, "name": "SwarmGuard run"}}
                      for a in alert.agent_ids] + ([{"uid": alert.resource, "type": "Data"}] if alert.resource else []),
        "metadata": {"version": "1.3.0", "product": {"name": "SwarmGuard", "vendor_name": "SwarmGuard team"},
                     "log_name": "swarmguard.alerts", "correlation_uid": alert.run_id},
        "unmapped": {"rule_id": alert.rule_id, "recommended_action": alert.recommended_action,
                     "event_ids": alert.event_ids, "run_id": alert.run_id},
    }


def findings(alerts: list[Alert]) -> list[dict]:
    owasp = _owasp_by_rule()
    return [to_ocsf(a, owasp) for a in alerts]


def _post(url: str, body: list[dict], auth: str | None) -> None:
    headers = {"Content-Type": "application/json", **({"Authorization": auth} if auth else {})}
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers=headers, method="POST")
    urllib.request.urlopen(req, timeout=10).read()


class Forwarder:
    """Hub tap: on run_finished, send that run's findings to the SIEM (in a background thread)."""

    def __init__(self, url: str, alerts_of: Callable[[str], list[Alert]], auth: str | None = None,
                 send: Callable = _post):
        self.url, self.alerts_of, self.auth, self.send = url, alerts_of, auth, send
        self.queue: queue.Queue = queue.Queue(maxsize=200)
        self.sent = 0
        threading.Thread(target=self._work, name="swarmguard-siem", daemon=True).start()

    def __call__(self, msg: dict) -> None:
        if msg.get("type") == "run_finished" and msg.get("run_id"):
            try:
                self.queue.put_nowait(msg["run_id"])
            except queue.Full:
                log.warning("SIEM queue full; dropping run %s", msg["run_id"])

    def _work(self) -> None:
        while True:
            run_id = self.queue.get()
            try:
                body = findings(self.alerts_of(run_id))
                if body:
                    self.send(self.url, body, self.auth)
                    self.sent += len(body)
            except Exception as exc:  # never let the SIEM break a run
                log.warning("SIEM export failed for %s: %s", run_id, exc)
            finally:
                self.queue.task_done()


def install(hub, alerts_of: Callable[[str], list[Alert]], url: str | None = None) -> Forwarder | None:
    url = url or os.getenv("SWARMGUARD_SIEM_URL")
    if not url:
        return None
    f = Forwarder(url, alerts_of, os.getenv("SWARMGUARD_SIEM_AUTH"))
    hub.taps.append(f)
    log.info("SwarmGuard SIEM export enabled")
    return f
