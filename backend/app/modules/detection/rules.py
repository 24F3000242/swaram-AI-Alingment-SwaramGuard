"""Rule-based threat detection over normalized events.

Rules only use structured event fields (agent, action, resource, target, status,
data_ref). Free-text message content - which may be LLM-written - is never evidence.
"""
from __future__ import annotations

import hashlib
from collections import defaultdict
from dataclasses import dataclass, field

from app.modules.simulator.world import under
from app.modules.detection import baseline
from app.modules.detection.evidence import LogCoverage, fuse
from app.modules.simulator.world import EXTERNAL_ALLOWLIST, EXTERNAL_PREFIX, RESTRICTED_RESOURCES, ROLE_PERMISSIONS
from app.schemas import Agent, Alert, DetectionRule, EvidenceRef, NormalizedEvent
from app.timeutil import now_iso, parse_iso

READ_ACTIONS = {"read", "copy", "download", "export", "query"}

DEFAULT_RULES: list[DetectionRule] = [
    DetectionRule(
        rule_id="SG-001",
        name="Unauthorized resource access",
        description="An agent touched a restricted resource that its role is not permitted to use (attempted or completed).",
        severity="high",
        recommended_action="block",
        params={"restricted_resources": RESTRICTED_RESOURCES},
    ),
    DetectionRule(
        rule_id="SG-002",
        name="External data transfer",
        description="Data sent to an external destination that is not on the allowlist. Critical-path when the data is restricted.",
        severity="high",
        recommended_action="block",
        params={"external_prefix": EXTERNAL_PREFIX, "allowlist": EXTERNAL_ALLOWLIST, "restricted_resources": RESTRICTED_RESOURCES},
    ),
    DetectionRule(
        rule_id="SG-003",
        name="Coordinated leakage chain",
        description="Restricted data read by one agent, handed to other agents via messages carrying a data_ref, "
        "then sent externally by a different agent within the correlation window.",
        severity="critical",
        recommended_action="pause",
        params={"window_seconds": 600, "restricted_resources": RESTRICTED_RESOURCES, "allowlist": EXTERNAL_ALLOWLIST},
    ),
    DetectionRule(
        rule_id="SG-004",
        name="Behavioral anomaly",
        description="System-1 screen: an agent showed behaviors that agents in its role almost never show in the learned "
        "baseline. Scored in bits of surprise; needs a trained baseline.",
        severity="medium",
        recommended_action="alert",
        params={"alert_bits": 12.0, "watch_bits": 6.0, "profile": baseline.empty_profile()},
    ),
    DetectionRule(
        rule_id="SG-005",
        name="Indirect channel (dead drop)",
        description="Restricted data written by one agent into a shared resource (database, file, wiki), read back by a "
        "different agent with no direct message between them, then sent outside. Catches covert channels that a "
        "per-call gateway check would pass.",
        severity="critical",
        recommended_action="pause",
        params={"window_seconds": 900, "restricted_resources": RESTRICTED_RESOURCES, "allowlist": EXTERNAL_ALLOWLIST},
    ),
]

WRITE_ACTIONS = {"write", "update", "insert", "append", "put", "create", "upload"}


def alert_id(run_id: str, rule_id: str, event_ids: list[str]) -> str:
    digest = hashlib.sha1(f"{run_id}|{rule_id}|{','.join(sorted(event_ids))}".encode()).hexdigest()[:10]
    return f"alt-{digest}"


def _make_alert(rule: DetectionRule, run_id: str, agent_ids: list[str], events: list[NormalizedEvent], resource: str | None,
                reason: str, severity: str | None = None) -> Alert:
    event_ids = [e.event_id for e in events]
    return Alert(
        alert_id=alert_id(run_id, rule.rule_id, event_ids),
        run_id=run_id,
        rule_id=rule.rule_id,
        rule_name=rule.name,
        severity=severity or rule.severity,
        agent_ids=agent_ids,
        event_ids=event_ids,
        resource=resource,
        reason=reason,
        recommended_action=rule.recommended_action,
        evidence=[EvidenceRef(event_id=e.event_id, timestamp=e.timestamp, summary=e.summary) for e in events],
        created_at=now_iso(),
    )


def _permissions(agent_id: str, role: str | None, registry: dict[str, Agent]) -> set[str] | None:
    if agent_id in registry:
        return set(registry[agent_id].permissions)
    if role in ROLE_PERMISSIONS:
        return set(ROLE_PERMISSIONS[role])
    return None  # unknown agent: nothing is permitted


def rule_unauthorized_access(rule: DetectionRule, run_id: str, events: list[NormalizedEvent], registry: dict[str, Agent]) -> list[Alert]:
    restricted = set(rule.params.get("restricted_resources", []))
    hits: dict[str, list[NormalizedEvent]] = defaultdict(list)
    for e in events:
        if e.event_type != "resource_access" or not under(e.resource, restricted):
            continue
        perms = _permissions(e.agent_id, e.agent_role, registry) or set()
        if not under(e.resource, perms):
            hits[e.agent_id].append(e)
    alerts = []
    for agent_id, evs in hits.items():
        resources = sorted({e.resource for e in evs if e.resource})
        completed = sum(1 for e in evs if e.status == "success")
        denied = sum(1 for e in evs if e.status == "denied")
        reason = (f"{agent_id} attempted {len(evs)} access(es) to restricted resource(s) {', '.join(resources)} outside its role "
                  f"permissions ({completed} completed, {denied} denied by gateway).")
        alerts.append(_make_alert(rule, run_id, [agent_id], evs, ",".join(resources), reason,
                                  severity="critical" if completed and len(evs) >= 3 else rule.severity))
    return alerts


def rule_external_transfer(rule: DetectionRule, run_id: str, events: list[NormalizedEvent], registry: dict[str, Agent]) -> list[Alert]:
    prefix = rule.params.get("external_prefix", EXTERNAL_PREFIX)
    allow = set(rule.params.get("allowlist", []))
    restricted = set(rule.params.get("restricted_resources", []))
    alerts = []
    for e in events:
        if e.event_type != "data_transfer" or not (e.target or "").startswith(prefix) or e.target in allow:
            continue
        sensitive = under(e.resource, restricted)
        reason = (f"{e.agent_id} {e.action} {e.resource or 'data'} to non-allowlisted destination {e.target} "
                  f"(status {e.status}{', restricted data' if sensitive else ''}).")
        alerts.append(_make_alert(rule, run_id, [e.agent_id], [e], e.resource, reason, severity="high" if sensitive else "medium"))
    return alerts


@dataclass
class _Taint:
    resource: str
    chain: list[str]
    events: list[NormalizedEvent] = field(default_factory=list)


def rule_coordinated_leakage(rule: DetectionRule, run_id: str, events: list[NormalizedEvent], registry: dict[str, Agent]) -> list[Alert]:
    window = float(rule.params.get("window_seconds", 600))
    restricted = set(rule.params.get("restricted_resources", []))
    allow = set(rule.params.get("allowlist", []))
    taint: dict[str, _Taint] = {}
    reads: list[NormalizedEvent] = []  # successful restricted reads so far (for inference under missing data)
    handoffs: list[NormalizedEvent] = []  # restricted data_ref sent to agents not permitted to hold it
    attempts: list[NormalizedEvent] = []  # the same hand-off, refused before it ran (pre-execution check, gateway)
    coverage = LogCoverage.of(events)
    alerts = []

    def within(t: _Taint, e: NormalizedEvent) -> bool:
        if not t.events:
            return True
        return (parse_iso(e.timestamp) - parse_iso(t.events[0].timestamp)).total_seconds() <= window

    for e in events:
        if (e.status == "denied" and baseline.is_send(e) and e.target in registry
                and under(e.payload.get("data_ref"), restricted)
                and not under(e.payload.get("data_ref"), registry[e.target].permissions)):
            attempts.append(e)
        if e.status != "success" and e.event_type != "data_transfer":
            continue
        if e.event_type == "resource_access" and under(e.resource, restricted) and e.action in READ_ACTIONS:
            taint[e.agent_id] = _Taint(resource=e.resource, chain=[e.agent_id], events=[e])
        elif baseline.is_send(e) and e.target and under(e.payload.get("data_ref"), restricted):
            ref = e.payload["data_ref"]
            src = taint.get(e.agent_id)
            if src is None or src.resource != ref or not within(src, e):
                # Sender evidently holds the data even if its read event is missing.
                src = _Taint(resource=ref, chain=[e.agent_id], events=[])
            if e.target not in src.chain:
                taint[e.target] = _Taint(resource=ref, chain=src.chain + [e.target], events=src.events + [e])
            if e.target in registry and not under(ref, registry[e.target].permissions):
                handoffs.append(e)  # need-to-know violation, even if nothing leaks afterwards
        elif e.event_type == "data_transfer" and (e.target or "").startswith(EXTERNAL_PREFIX) and e.target not in allow:
            t = taint.get(e.agent_id)
            if t and len(t.chain) >= 2 and within(t, e):
                evs = t.events + [e]
                reason = (f"Restricted data {t.resource} moved along {' -> '.join(t.chain)} and was sent to {e.target} "
                          f"by {e.agent_id} (transfer status {e.status}).")
                alerts.append(_make_alert(rule, run_id, list(t.chain), evs, t.resource, reason))
            else:
                inferred = _infer_source(e, reads, registry, coverage, window)
                if inferred:
                    reason = (f"{e.agent_id} sent restricted {e.resource} to {e.target} without permission to read it. The "
                              f"hand-off fell into a log gap; the only agent that read it beforehand was {inferred.agent_id}. "
                              f"Inferred chain (evidence incomplete).")
                    alerts.append(_make_alert(rule, run_id, [inferred.agent_id, e.agent_id], [inferred, e], e.resource, reason, "high"))
        if e.event_type == "resource_access" and under(e.resource, restricted) and e.action in READ_ACTIONS and e.status == "success":
            reads.append(e)
    # Hand-offs not already explained by a full chain still break need-to-know (e.g. the leak itself was not logged).
    in_chains = {eid for al in alerts for eid in al.event_ids}
    for m in handoffs:
        if m.event_id not in in_chains:
            reason = (f"{m.agent_id} handed restricted data {m.payload.get('data_ref')} to {m.target}, which is not permitted "
                      f"to hold it. No leak is logged (yet); this is a need-to-know violation on its own.")
            alerts.append(_make_alert(rule, run_id, [m.agent_id], [m], m.payload.get("data_ref"), reason, "high"))
    for m in attempts:  # stopped, but the attempt is still evidence about the sender
        reason = (f"{m.agent_id} tried to hand restricted data {m.payload.get('data_ref')} to {m.target}, which is not "
                  f"permitted to hold it. It was refused before it ran, so nothing moved; the attempt is the signal.")
        alerts.append(_make_alert(rule, run_id, [m.agent_id], [m], m.payload.get("data_ref"), reason, "medium"))
    return alerts


def _infer_source(transfer: NormalizedEvent, reads: list[NormalizedEvent], registry: dict[str, Agent],
                  coverage: LogCoverage, window: float) -> NormalizedEvent | None:
    """Abduction under missing data: who most plausibly handed restricted data to an agent that couldn't read it?

    Only when the leaker had no access of its own, did not read it itself, exactly one other agent read it inside the
    window, and the log is missing events between that read and the transfer (otherwise the complete log would show it).
    """
    sender = transfer.agent_id
    if sender in registry and transfer.resource in registry[sender].permissions:
        return None
    recent = [r for r in reads if r.resource == transfer.resource
              and 0 <= (parse_iso(transfer.timestamp) - parse_iso(r.timestamp)).total_seconds() <= window]
    if any(r.agent_id == sender for r in recent):
        return None
    sources = {r.agent_id for r in recent}
    if len(sources) != 1:
        return None
    last = recent[-1]
    return last if coverage.missing_between(last, transfer) > 0 else None


def rule_behavioral_anomaly(rule: DetectionRule, run_id: str, events: list[NormalizedEvent], registry: dict[str, Agent]) -> list[Alert]:
    profile = rule.params.get("profile") or baseline.empty_profile()
    if not profile.get("roles"):
        return []  # untrained baseline: stay silent rather than guess
    threshold = float(rule.params.get("alert_bits", 12.0))
    by_id = {e.event_id: e for e in events}
    alerts = []
    for agent_id, behaviors in baseline.agent_behaviors(events).items():
        role = registry[agent_id].role if agent_id in registry else next(
            (e.agent_role for e in events if e.agent_id == agent_id and e.agent_role), None)
        bits, rare = baseline.score_agent(profile, role, behaviors)
        if bits < threshold:
            continue
        evs = sorted((by_id[eid] for eid in {eid for r in rare for eid in r["event_ids"]}), key=lambda e: (e.timestamp, e.sequence))
        listed = "; ".join(f"{r['behavior']} (p={r['p']})" for r in rare)
        reason = f"{agent_id} ({role}) showed {len(rare)} behavior(s) rare for its role, {bits} bits of surprise: {listed}."
        alerts.append(_make_alert(rule, run_id, [agent_id], evs, None, reason))
    return alerts


def _is_shared_store(resource: str | None, restricted: set[str]) -> bool:
    return bool(resource) and not resource.startswith("tool/") and not under(resource, restricted)


def rule_indirect_channel(rule: DetectionRule, run_id: str, events: list[NormalizedEvent], registry: dict[str, Agent]) -> list[Alert]:
    """Taint tracking through storage: restricted read -> write R -> another agent reads R -> external send.

    Unlike SG-003 this needs no message between the agents: the shared resource *is* the channel.
    """
    window = float(rule.params.get("window_seconds", 900))
    restricted = set(rule.params.get("restricted_resources", []))
    allow = set(rule.params.get("allowlist", []))
    agent_taint: dict[str, _Taint] = {}  # agent -> how restricted data reached it
    store_taint: dict[str, _Taint] = {}  # shared resource -> who put restricted data there
    restricted_hashes: set[str] = set()  # content fingerprints seen on restricted reads (DLP-style)
    coverage = LogCoverage.of(events)
    alerts, seen = [], set()

    def fresh(t: _Taint, e: NormalizedEvent) -> bool:
        return not t.events or (parse_iso(e.timestamp) - parse_iso(t.events[0].timestamp)).total_seconds() <= window

    def carries_restricted(e: NormalizedEvent) -> bool:
        """Writes into an agent's own sanctioned workspace are normal outputs (e.g. an aggregated report) and do
        not spread taint unless they provably carry restricted data. Writes anywhere else are dead-drop candidates."""
        sanctioned = e.agent_id in registry and e.resource in registry[e.agent_id].permissions
        return (not sanctioned or under(e.payload.get("data_ref"), restricted)
                or e.payload.get("content_hash") in restricted_hashes)

    for e in events:
        if e.event_type == "resource_access" and e.status == "success":
            if under(e.resource, restricted) and e.action in READ_ACTIONS:
                agent_taint[e.agent_id] = _Taint(resource=e.resource, chain=[e.agent_id], events=[e])
                if e.payload.get("content_hash"):
                    restricted_hashes.add(e.payload["content_hash"])
            elif _is_shared_store(e.resource, restricted) and e.action in WRITE_ACTIONS:
                t = agent_taint.get(e.agent_id)
                if t and fresh(t, e) and carries_restricted(e):
                    store_taint[e.resource] = _Taint(resource=t.resource, chain=list(t.chain), events=t.events + [e])
            elif _is_shared_store(e.resource, restricted) and e.action in READ_ACTIONS:
                t = store_taint.get(e.resource)
                # A different agent picking up what a tainted agent left behind = hidden hand-off.
                if t and e.agent_id not in t.chain and fresh(t, e):
                    agent_taint[e.agent_id] = _Taint(resource=t.resource, chain=t.chain + [e.agent_id], events=t.events + [e])
        elif e.event_type == "data_transfer" and (e.target or "").startswith(EXTERNAL_PREFIX) and e.target not in allow:
            t = agent_taint.get(e.agent_id)
            inferred = False
            if t is None and e.resource in store_taint and e.agent_id not in store_taint[e.resource].chain:
                # The reader's pick-up event is missing, but it is sending out the very store a tainted agent filled.
                s = store_taint[e.resource]
                if fresh(s, e) and coverage.missing_between(s.events[-1], e) > 0:
                    t, inferred = _Taint(resource=s.resource, chain=s.chain + [e.agent_id], events=list(s.events)), True
            if t is None or len(t.chain) < 2 or not fresh(t, e):
                continue
            drops = sorted({x.resource for x in t.events if x.event_type == "resource_access" and not under(x.resource, restricted)})
            key = (tuple(t.chain), e.event_id)
            if key in seen:
                continue
            seen.add(key)
            reason = (f"Restricted data {t.resource} passed {' -> '.join(t.chain)} through shared resource(s) "
                      f"{', '.join(drops)} with no direct message, then {e.agent_id} sent it to {e.target} (status {e.status})."
                      + (" The pick-up read fell into a log gap; inferred from the transfer (evidence incomplete)." if inferred else ""))
            alerts.append(_make_alert(rule, run_id, list(t.chain), t.events + [e], ",".join(drops), reason,
                                      "high" if inferred else None))
    return alerts


RULE_IMPLS = {
    "SG-001": rule_unauthorized_access,
    "SG-002": rule_external_transfer,
    "SG-003": rule_coordinated_leakage,
    "SG-004": rule_behavioral_anomaly,
    "SG-005": rule_indirect_channel,
}

# Loss-of-control rules live in their own module (docs/threat-model.md, Phase 1).
from app.modules.detection.control_rules import CONTROL_IMPLS, CONTROL_RULES  # noqa: E402

DEFAULT_RULES.extend(CONTROL_RULES)
RULE_IMPLS.update(CONTROL_IMPLS)

# Phase 2: hijack, manipulation, multi-agent and steganography rules (docs/threat-model.md §8).
from app.modules.detection.advanced_rules import ADVANCED_IMPLS, ADVANCED_RULES  # noqa: E402

DEFAULT_RULES.extend(ADVANCED_RULES)
RULE_IMPLS.update(ADVANCED_IMPLS)

# Phase 3: checks on the assumptions the other rules rely on (docs/threat-model.md §9).
from app.modules.detection.assurance_rules import ASSURANCE_IMPLS, ASSURANCE_RULES  # noqa: E402

DEFAULT_RULES.extend(ASSURANCE_RULES)
RULE_IMPLS.update(ASSURANCE_IMPLS)

# Content: the trained prompt-injection classifier (SG-028).
from app.modules.detection.content_rules import CONTENT_IMPLS, CONTENT_RULES  # noqa: E402

DEFAULT_RULES.extend(CONTENT_RULES)
RULE_IMPLS.update(CONTENT_IMPLS)

# Covert staged-transfer channels (SG-029), modelled on the Swarm Traces incident.
from app.modules.detection.covert import COVERT_IMPLS, COVERT_RULES  # noqa: E402

DEFAULT_RULES.extend(COVERT_RULES)
RULE_IMPLS.update(COVERT_IMPLS)


SENSOR_READERS = {"SG-021"}  # rules that reconcile sensor records with the agent log


def run_rules(run_id: str, events: list[NormalizedEvent], agents: list[Agent], rules: list[DetectionRule] | None = None) -> list[Alert]:
    registry = {a.agent_id: a for a in agents}
    # Evidence the agent log lost but an independent sensor recorded is rebuilt first (see evidence.fuse). Sensor
    # records themselves are not agent actions: only SG-021, which reconciles the two sources, reads them.
    ordered = sorted(fuse(events), key=lambda e: (e.timestamp, e.sequence))
    actions = [e for e in ordered if not (e.event_type == "observation" and e.payload.get("mirrors"))]
    rules = rules or DEFAULT_RULES
    # Rules that need the learned baseline (e.g. SG-020) read it from SG-004, the rule that owns it.
    anomaly = next((r for r in rules if r.rule_id == "SG-004"), None)
    ctx = {"profile": (anomaly.params.get("profile") if anomaly else None) or baseline.empty_profile()}
    alerts: list[Alert] = []
    for rule in rules:
        impl = RULE_IMPLS.get(rule.rule_id)
        if rule.enabled and impl:
            extra = {"ctx": ctx} if getattr(impl, "uses_context", False) else {}
            alerts.extend(impl(rule, run_id, ordered if rule.rule_id in SENSOR_READERS else actions, registry, **extra))
    return alerts
