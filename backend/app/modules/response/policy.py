"""Security Response: map alerts to allow/alert/block/pause decisions.

Honesty rule: an outcome of `blocked` is only recorded when the controlled gateway
denied the request *before* it executed (event status `denied`, gateway `blocked`).
Everything else is `would_block` / `would_pause` - post-hoc logging cannot undo an
action that already completed.
"""
from __future__ import annotations

import hashlib

from app.schemas import Alert, NormalizedEvent, ResponseAction, ResponsePolicy
from app.timeutil import now_iso

DEFAULT_POLICY = ResponsePolicy()


def decide(alert: Alert, policy: ResponsePolicy) -> str:
    return policy.rule_overrides.get(alert.rule_id) or policy.severity_actions.get(alert.severity, alert.recommended_action)


def respond(alerts: list[Alert], events: list[NormalizedEvent], policy: ResponsePolicy | None = None) -> list[ResponseAction]:
    policy = policy or DEFAULT_POLICY
    by_id = {e.event_id: e for e in events}
    actions = []
    for alert in alerts:
        decision = decide(alert, policy)
        gateway_ids = [eid for eid in alert.event_ids
                       if eid in by_id and by_id[eid].gateway_decision == "blocked" and by_id[eid].status == "denied"]
        completed = [eid for eid in alert.event_ids if eid in by_id and by_id[eid].status == "success"]
        enforced = False

        if decision == "allow":
            outcome, note = "allowed", "Policy allows this alert type; no action taken."
        elif decision == "alert":
            outcome, note = "alerted", "Alert raised for human review; no request was stopped."
        elif policy.mode == "enforce" and gateway_ids:
            outcome, enforced = "blocked", True
            note = f"Gateway denied {len(gateway_ids)} request(s) before execution."
            if completed:
                note += f" {len(completed)} related event(s) had already completed and were not prevented."
        else:
            outcome = "would_pause" if decision == "pause" else "would_block"
            if policy.mode == "enforce":
                note = ("Enforce mode requested, but no gateway denial is recorded for these events; completed actions "
                        "cannot be retroactively prevented. Re-run the simulation with gateway_mode=enforce.")
            else:
                note = "Simulation mode: the decision was recorded but no request was denied."
            if gateway_ids:
                note += f" (The gateway independently denied {len(gateway_ids)} request(s).)"

        rid = hashlib.sha1(f"{alert.alert_id}|{policy.policy_id}|{policy.mode}".encode()).hexdigest()[:10]
        actions.append(ResponseAction(
            response_id=f"rsp-{rid}",
            run_id=alert.run_id,
            alert_id=alert.alert_id,
            policy_id=policy.policy_id,
            decision=decision,
            outcome=outcome,
            mode="enforced" if enforced else "simulated",
            enforced=enforced,
            agent_ids=alert.agent_ids,
            event_ids=alert.event_ids,
            gateway_event_ids=gateway_ids,
            note=note,
            created_at=now_iso(),
        ))
    return actions


def respond_live(containments: list, alerts: list[Alert], policy: ResponsePolicy | None = None) -> list[ResponseAction]:
    """Response records for what the live guard did mid-run: every pause / egress hold becomes an auditable action.

    `blocked` only when later actions were actually denied before executing; otherwise `contained` (the agent was
    stopped, but tried nothing more). Each record links to the alert that best explains it (the policy's rule if it
    triggered the containment, else the agent's most severe alert).
    """
    policy = policy or DEFAULT_POLICY
    rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    out = []
    for c in containments:
        mine = [a for a in alerts if c.agent_id in a.agent_ids]
        linked = next((a for a in mine if c.rule_id and a.rule_id == c.rule_id), None) or max(
            mine, key=lambda a: rank.get(a.severity, 0), default=None)
        decision = "block" if c.scope == "egress" else "pause"
        what = "outbound transfers held" if c.scope == "egress" else "agent paused"
        note = (f"Live guard ({c.trigger or 'risk'}): {what} at event #{c.paused_at_sequence}. {c.explanation or ''} "
                f"{c.blocked_actions} later action(s) denied before execution.").strip()
        rid = hashlib.sha1(f"live|{c.agent_id}|{c.scope}|{c.paused_at_sequence}".encode()).hexdigest()[:10]
        out.append(ResponseAction(
            response_id=f"rsp-live-{rid}", run_id=(linked.run_id if linked else ""), alert_id=linked.alert_id if linked else "",
            policy_id=policy.policy_id, decision=decision, outcome="blocked" if c.blocked_actions else "contained",
            mode="enforced", enforced=True, agent_ids=[c.agent_id], event_ids=linked.event_ids if linked else [],
            gateway_event_ids=[], note=note, created_at=now_iso()))
    return out


def alert_status_after(action: ResponseAction) -> str:
    return "contained" if action.outcome in ("blocked", "contained") else "responded"
