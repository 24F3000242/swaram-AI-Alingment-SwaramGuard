"""SG-030: an agent's claims about its own tool calls, checked against what was actually observed.

Agents report their work ("uploaded the Q3 summary to the partner API"). A hijacked or scheming agent can report a
tool call it never made, or hide the one it did make. SG-030 takes each structured claim in a report
(`payload.claims`, a list of {action, resource, target}) and reconciles it with the actions the system recorded for
that agent (gateway, egress proxy, MCP gateway, simulator log). It never reads the report's wording, only the claims.

Findings per report:
- wrong_destination: the claimed resource went somewhere other than the claimed target;
- wrong_resource:    the claimed target received something other than the claimed resource;
- false_success:     the claimed action happened but was denied or failed;
- hidden_extra:      an unclaimed transfer, before the report, of a restricted resource or to an unapproved destination;
- phantom:           nothing recorded matches the claim at all;
- unverified:        nothing matches, but the record has a gap (events lost by a partial monitor), so the claim can't
                     be checked either way. Raised as low severity: a visibility problem, not an accusation.

SG-014 checks a different report shape (summary counts such as "external_transfers: 0"); SG-030 checks each action.

Reports can arrive before the action is logged. A claim with nothing recorded yet stays pending until the agent has
logged `lookahead` more events or the run has moved `settle` events past the report, so honest delayed logging is
never flagged, and the live guard doesn't contain an agent for a report it can't judge yet.
"""
from __future__ import annotations

from collections import defaultdict

from app.modules.simulator.world import EXTERNAL_ALLOWLIST, EXTERNAL_PREFIX, RESTRICTED_RESOURCES, under
from app.schemas import Agent, Alert, DetectionRule, NormalizedEvent

ACTION_TYPES = {"data_transfer", "tool_call", "resource_access"}
SEVERITY = {"false_success": "high", "wrong_destination": "high", "wrong_resource": "high", "hidden_extra": "high",
            "phantom": "medium", "unverified": "low"}
RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def is_report(e: NormalizedEvent) -> bool:
    # The sender's report only: a recipient's copy of the message makes no claim about the recipient's own actions.
    return e.event_type == "message" and e.action != "receive" and isinstance((e.payload or {}).get("claims"), list)


def _claims(e: NormalizedEvent) -> list[dict]:
    return [c for c in e.payload["claims"] if isinstance(c, dict) and c.get("action")]


def _norm(x) -> str:
    return str(x).strip().lower() if x else ""


def _fits(claim: dict, e: NormalizedEvent, *, resource=True, target=True) -> bool:
    if _norm(claim.get("action")) not in (_norm(e.action), _norm(e.event_type)):
        return False
    if resource and _norm(claim.get("resource")) and _norm(claim.get("resource")) != _norm(e.resource):
        return False
    if target and _norm(claim.get("target")) and _norm(claim.get("target")) != _norm(e.target):
        return False
    return True


def _gap(lo: int, hi: int, seen: set[int]) -> bool:
    """True if any sequence number between lo and hi is missing from the record: a partial monitor lost events."""
    return lo > 0 and hi > lo and any(s not in seen for s in range(lo, hi + 1))


def check_report(report: NormalizedEvent, before: list[NormalizedEvent], after: list[NormalizedEvent], *,
                 settled: bool, gap: bool, allow: set[str], restricted: set[str]) -> list[tuple[str, dict, list]]:
    """Reconcile one report. `before` / `after` are the agent's actions in the report's window. Returns findings as
    (kind, claim, events)."""
    candidates = [e for e in before + after if e.event_type in ACTION_TYPES]
    used: set[str] = set()
    findings: list[tuple[str, dict, list]] = []
    pending = []
    for claim in _claims(report):  # exact, successful matches first, so a partial match never steals a real one
        hit = next((e for e in candidates if e.event_id not in used and e.status == "success" and _fits(claim, e)), None)
        if hit:
            used.add(hit.event_id)
        else:
            pending.append(claim)
    for claim in pending:
        def pick(**kw):
            return next((e for e in candidates if e.event_id not in used and _fits(claim, e, **kw)), None)
        if (hit := pick()) is not None:                      # right action, resource and target, but not a success
            kind = "false_success"
        elif _norm(claim.get("target")) and (hit := pick(target=False)) is not None:
            kind = "wrong_destination"
        elif _norm(claim.get("resource")) and (hit := pick(resource=False)) is not None:
            kind = "wrong_resource"
        else:
            if settled:
                findings.append(("unverified" if gap else "phantom", claim, []))
            continue
        used.add(hit.event_id)
        findings.append((kind, claim, [hit]))
    for e in before:  # transfers the report leaves out: only the ones that matter
        if e.event_type == "data_transfer" and e.event_id not in used and e.status == "success" and (
                under(e.resource, restricted) or ((e.target or "").startswith(EXTERNAL_PREFIX) and e.target not in allow)):
            findings.append(("hidden_extra", {}, [e]))
    return findings


def _describe(kind: str, claim: dict, evs: list[NormalizedEvent]) -> str:
    c = f"{claim.get('action')} {claim.get('resource') or ''} -> {claim.get('target') or ''}".strip()
    e = evs[0] if evs else None
    if kind == "wrong_destination":
        return f"claimed {c}, but it went to {e.target}"
    if kind == "wrong_resource":
        return f"claimed {c}, but it actually sent {e.resource}"
    if kind == "false_success":
        return f"claimed {c} succeeded, but it was {e.status}"
    if kind == "hidden_extra":
        return f"did not report {e.action} {e.resource} -> {e.target}"
    if kind == "phantom":
        return f"claimed {c}, but no such action was recorded"
    return f"claimed {c}; no record of it, and the record has gaps (lost events), so it can't be verified"


def rule_claim_check(rule: DetectionRule, run_id: str, events: list[NormalizedEvent], registry: dict[str, Agent]) -> list[Alert]:
    from app.modules.detection.rules import _make_alert

    p = rule.params
    lookahead, settle = int(p.get("lookahead", 3)), int(p.get("settle", 20))
    allow = set(p.get("allowlist", EXTERNAL_ALLOWLIST))
    restricted = set(p.get("restricted_resources", RESTRICTED_RESOURCES))
    seen = {e.sequence for e in events if e.sequence}
    last_seq = max(seen, default=0)
    by_agent: dict[str, list[NormalizedEvent]] = defaultdict(list)
    for e in events:
        by_agent[e.agent_id].append(e)
    alerts = []
    for agent_id, evs in by_agent.items():
        start = 0
        for i, e in enumerate(evs):
            if not is_report(e):
                continue
            nxt = next((j for j in range(i + 1, len(evs)) if is_report(evs[j])), len(evs))
            before, after = evs[start:i], evs[i + 1:min(nxt, i + 1 + lookahead)]
            start = i + 1
            settled = (nxt - i - 1) >= lookahead or nxt < len(evs) or (last_seq - (e.sequence or 0)) >= settle
            lo = (before[0].sequence if before else e.sequence) or 0
            hi = (after[-1].sequence if after else e.sequence) or 0
            findings = check_report(e, before, after, settled=settled, gap=_gap(lo, hi, seen),
                                    allow=allow, restricted=restricted)
            if not findings:
                continue
            sev = max((SEVERITY[k] for k, _, _ in findings), key=RANK.get)
            proof = list({x.event_id: x for _, _, xs in findings for x in xs}.values())
            kinds = sorted({k for k, _, _ in findings})
            reason = (f"{agent_id}'s report doesn't match what was recorded ({', '.join(kinds)}): "
                      + "; ".join(_describe(k, c, xs) for k, c, xs in findings) + ".")
            alerts.append(_make_alert(rule, run_id, [agent_id], proof + [e], e.resource or e.target, reason, severity=sev))
    return alerts


CLAIM_RULES = [DetectionRule(
    rule_id="SG-030", name="Claimed tool call doesn't match reality", severity="high", recommended_action="block",
    description="Each structured claim in an agent's report (payload.claims: action, resource, target) is checked "
    "against the actions actually recorded for it: wrong destination, wrong resource, a failed action reported as "
    "done, an unreported sensitive transfer, or a claimed action that never happened. Where the record has gaps "
    "(partial monitoring) an unmatched claim is raised as unverified, low severity, not as a lie.",
    params={"lookahead": 3, "settle": 20, "allowlist": EXTERNAL_ALLOWLIST, "restricted_resources": RESTRICTED_RESOURCES})]
CLAIM_IMPLS = {"SG-030": rule_claim_check}
