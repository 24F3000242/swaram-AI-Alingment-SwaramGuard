"""Notifications: tell a human the moment an agent is contained (Security Response).

Opt-in: set SWARMGUARD_WEBHOOK_URL to an incoming-webhook URL (Slack, Discord and Teams all accept a JSON `text`
field). Containments, quarantines, critical detections and new review items are posted from a background thread, so
a slow or failing webhook never delays a run. The URL is a secret: keep it in backend/.env.
"""
from __future__ import annotations

import json
import logging
import os
import queue
import threading
import urllib.request
from typing import Callable

log = logging.getLogger(__name__)

NOTIFY_TYPES = {"containment", "quarantine", "detection", "review"}


def summary(msg: dict) -> str | None:
    """One line for a human, or None if this message isn't worth a notification."""
    d, run = msg.get("data") or {}, msg.get("run_id")
    t = msg.get("type")
    if t == "containment":
        what = "outbound transfers held" if d.get("scope") == "egress" else "paused"
        return f"SwarmGuard: {d.get('agent_id')} ({d.get('role')}) {what} in {run}: {d.get('explanation') or ''}".strip()
    if t == "quarantine":
        return (f"SwarmGuard: quarantined {d.get('resource')} for {d.get('agent_id')} in {run} "
                f"(claims to be from {d.get('claimed_sender')}, not verified)")
    if t == "detection" and d.get("severity") == "critical":
        return f"SwarmGuard: CRITICAL {d.get('rule_id')} {d.get('rule_name')} in {run}: {d.get('reason')}"
    if t == "review" and d.get("action") == "created":
        item = d.get("item") or {}
        return f"SwarmGuard: review needed for {item.get('agent_id')} ({item.get('kind')}) in {run}"
    if t == "review" and d.get("action") == "escalated":
        item = d.get("item") or {}
        return (f"SwarmGuard: OVERDUE review for {item.get('agent_id')} ({item.get('kind')}) in {run}: "
                f"waiting {d.get('waiting_minutes')} min")
    return None


def _post(url: str, text: str, msg: dict) -> None:
    body = json.dumps({"text": text, "swarmguard": msg}).encode()
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    urllib.request.urlopen(req, timeout=5).read()


class Notifier:
    def __init__(self, url: str, send: Callable[[str, str, dict], None] = _post):
        self.url, self.send = url, send
        self.queue: queue.Queue = queue.Queue(maxsize=500)
        self.sent = 0
        threading.Thread(target=self._work, name="swarmguard-notify", daemon=True).start()

    def __call__(self, msg: dict) -> None:  # hub tap: runs in the publisher's thread, so only enqueue
        if msg.get("type") in NOTIFY_TYPES and (text := summary(msg)):
            try:
                self.queue.put_nowait((text, msg))
            except queue.Full:
                log.warning("notification queue full; dropping: %s", text)

    def _work(self) -> None:
        while True:
            text, msg = self.queue.get()
            try:
                self.send(self.url, text, msg)
                self.sent += 1
            except Exception as exc:  # never let a webhook break anything
                log.warning("notification failed: %s", exc)
            finally:
                self.queue.task_done()


def install(hub, url: str | None = None) -> Notifier | None:
    url = url or os.getenv("SWARMGUARD_WEBHOOK_URL")
    if not url:
        return None
    n = Notifier(url)
    hub.taps.append(n)
    log.info("SwarmGuard notifications enabled")
    return n
