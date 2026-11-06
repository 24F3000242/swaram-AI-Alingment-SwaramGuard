"""SG-028: prompt injection found in the content itself, by the trained classifier (injection_classifier.py).

Every untrusted input an agent reads (payload.untrusted with payload.content: an email, a web page, a tool result, a
ticket filed from outside) is scored. A high score raises a run-level alert naming the source and who read it: the
reader is the target, not the culprit, so nobody is blamed for reading it. If the reader then acts out of policy,
SG-012 blames it as before; SG-028 is the earlier, content-based warning. In `contain` mode the live guard can also
withhold such content before the agent reads it (params.quarantine_live).
"""
from __future__ import annotations

from app.modules.detection import injection_classifier as clf
from app.schemas import Agent, Alert, DetectionRule, NormalizedEvent


def content_of(e) -> str | None:
    """The untrusted text an event carries, if any."""
    p = e.payload or {}
    if p.get("untrusted") is not True:
        return None
    text = p.get("content")
    return text if isinstance(text, str) and text.strip() else None


def rule_injected_content(rule: DetectionRule, run_id: str, events: list[NormalizedEvent], registry: dict[str, Agent]) -> list[Alert]:
    from app.modules.detection.rules import _make_alert

    if not clf.available():
        return []
    thr = float(rule.params.get("threshold") or clf.threshold())
    alerts = []
    for e in events:
        text = content_of(e)
        if text is None:
            continue
        s = clf.cached_score(text)
        if s < thr:
            continue
        reason = (f"{e.resource or e.event_type} read by {e.agent_id} looks like a prompt injection (classifier score "
                  f"{s:.2f}, threshold {thr:.2f}). The reader is not blamed; any out-of-policy action it takes next is.")
        alerts.append(_make_alert(rule, run_id, [], [e], e.resource, reason, severity="high" if s >= 0.9 else "medium"))
    return alerts


CONTENT_RULES = [DetectionRule(
    rule_id="SG-028", name="Prompt injection in content", severity="medium", recommended_action="alert",
    description="A trained classifier scores every untrusted input an agent reads (email, web page, tool result, outside "
    "ticket). A likely injection is flagged before anyone acts on it; the reader is not blamed. In contain mode the "
    "live guard can withhold it (quarantine_live).",
    params={"threshold": None, "quarantine_live": False, "quarantine_threshold": 0.9})]
CONTENT_IMPLS = {"SG-028": rule_injected_content}
