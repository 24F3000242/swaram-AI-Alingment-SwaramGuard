"""SG-005: covert channels through shared storage (dead drops)."""
from datetime import timedelta

import pytest

from app.modules.collector.normalizer import collect
from app.modules.detection.graph import build_graph
from app.modules.detection.risk import assess
from app.modules.detection.rules import DEFAULT_RULES, run_rules
from app.timeutil import iso, parse_iso

from .conftest import normalize, simulate

SG5 = [r for r in DEFAULT_RULES if r.rule_id == "SG-005"]


def _agent(sim, role, nth=0):
    return [a for a in sim.agents if a.role == role][nth]


def with_dead_drop(steps, agents=5, seed=7, gap_s=5.0):
    """A clean run plus injected steps: (role, event_type, action, resource, target)."""
    sim = simulate("normal_collaboration", agents=agents, seed=seed)
    raw = [e.model_dump(mode="json") for e in sim.events]
    t = parse_iso(raw[-1]["timestamp"])
    hexid = sim.run.run_id.removeprefix("run-")
    for i, (role, et, action, resource, target) in enumerate(steps, start=1):
        t += timedelta(seconds=gap_s)
        seq = len(raw) + 1
        raw.append({"run_id": sim.run.run_id, "event_id": f"evt-{hexid}-{seq:04d}", "agent_id": _agent(sim, role).agent_id,
                    "timestamp": iso(t), "event_type": et, "action": action, "status": "success",
                    "resource": resource, "target": target, "sequence": seq, "payload": {}})
    events = collect(raw, run_id=sim.run.run_id, agents=sim.agents).events
    return sim, events


DEAD_DROP = [
    ("analyst", "resource_access", "read", "data/customer_pii", None),
    ("analyst", "resource_access", "write", "db/shared_notes", None),
    ("coder", "resource_access", "read", "db/shared_notes", None),
    ("coder", "data_transfer", "upload", "db/shared_notes", "external:paste-site"),
]


def test_dead_drop_detected_without_any_message():
    sim, events = with_dead_drop(DEAD_DROP)
    alerts = run_rules(sim.run.run_id, events, sim.agents)
    sg5 = [a for a in alerts if a.rule_id == "SG-005"]
    assert len(sg5) == 1
    analyst, coder = _agent(sim, "analyst").agent_id, _agent(sim, "coder").agent_id
    assert sg5[0].agent_ids == [analyst, coder]
    assert sg5[0].resource == "db/shared_notes" and sg5[0].severity == "critical"
    assert len(sg5[0].event_ids) == 4
    # The message-based chain rule cannot see this; only the exfiltrator would be caught without SG-005.
    assert not any(a.rule_id == "SG-003" for a in alerts)
    others = {aid for a in alerts if a.rule_id != "SG-005" for aid in a.agent_ids}
    assert analyst not in others


def test_hidden_channel_in_graph_and_explanation():
    sim, events = with_dead_drop(DEAD_DROP)
    alerts = run_rules(sim.run.run_id, events, sim.agents)
    analyst, coder = _agent(sim, "analyst").agent_id, _agent(sim, "coder").agent_id
    graph = build_graph(sim.run.run_id, events, sim.agents, alerts)
    edge = next(e for e in graph.edges if e.kind == "indirect")
    assert (edge.source, edge.target) == (analyst, coder) and len(edge.event_ids) == 2
    from app.services.pipeline import Pipeline
    from app.storage.sqlite_store import SQLiteStore

    rules = Pipeline(SQLiteStore(":memory:")).rules()  # trained baseline, as in the app
    alerts = run_rules(sim.run.run_id, events, sim.agents, rules)
    verdicts = {v.agent_id: v for v in assess(sim.run.run_id, events, sim.agents, alerts, rules)}
    assert verdicts[analyst].hypotheses[0].hypothesis == "covert_channel"
    assert verdicts[analyst].level in ("high", "critical")


def test_multi_hop_dead_drop():
    sim, events = with_dead_drop([
        ("analyst", "resource_access", "read", "data/customer_pii", None),
        ("analyst", "resource_access", "write", "db/a", None),
        ("researcher", "resource_access", "read", "db/a", None),
        ("researcher", "resource_access", "write", "db/b", None),
        ("coder", "resource_access", "read", "db/b", None),
        ("coder", "data_transfer", "upload", "db/b", "external:paste-site"),
    ])
    sg5 = [a for a in run_rules(sim.run.run_id, events, sim.agents, SG5)]
    assert len(sg5) == 1 and [a.split("-")[-1] for a in sg5[0].agent_ids] == ["02", "04", "03"]
    assert sg5[0].resource == "db/a,db/b"


@pytest.mark.parametrize("steps", [
    [s for s in DEAD_DROP if s[1] != "data_transfer"],  # nothing left the system
    [*DEAD_DROP[:3], ("coder", "data_transfer", "upload", "db/shared_notes", "external:approved-partner-api")],
    [DEAD_DROP[0], DEAD_DROP[1], ("analyst", "resource_access", "read", "db/shared_notes", None),
     ("analyst", "data_transfer", "upload", "db/shared_notes", "external:paste-site")],  # same agent: no hand-off
    [("reviewer", "resource_access", "write", "db/shared_notes", None), *DEAD_DROP[2:]],  # writer never held restricted data
], ids=["no-exfil", "allowlisted", "same-agent", "untainted-store"])
def test_no_alert_without_full_hidden_flow(steps):
    sim, events = with_dead_drop(steps)
    assert run_rules(sim.run.run_id, events, sim.agents, SG5) == []


def test_sanctioned_store_as_dead_drop_caught_by_content_hash():
    """Hiding the drop in the analyst's normal output store only works until the content fingerprint matches."""
    sim, events = with_dead_drop([
        ("analyst", "resource_access", "read", "data/customer_pii", None),
        ("analyst", "resource_access", "write", "data/public", None),
        ("coder", "resource_access", "read", "data/public", None),
        ("coder", "data_transfer", "upload", "data/public", "external:paste-site"),
    ])
    assert run_rules(sim.run.run_id, events, sim.agents, SG5) == []  # plain report write: declassified
    for e in events[-4:-2]:
        e.payload["content_hash"] = "sha256:abc"
    assert len(run_rules(sim.run.run_id, events, sim.agents, SG5)) == 1


def test_taint_does_not_spread_through_normal_teamwork():
    """Analyst report -> researcher -> wiki -> everyone: legit outputs must not taint the whole swarm."""
    sim, events = with_dead_drop([("reviewer", "resource_access", "write", "db/shared_notes", None), *DEAD_DROP[2:]])
    assert run_rules(sim.run.run_id, events, sim.agents, SG5) == []


def test_stale_drop_outside_window_is_ignored():
    sim, events = with_dead_drop(DEAD_DROP, gap_s=400)  # read->upload spans > 900 s
    assert run_rules(sim.run.run_id, events, sim.agents, SG5) == []


@pytest.mark.parametrize("scenario", ["normal_collaboration", "unauthorized_access", "coordinated_leakage"])
@pytest.mark.parametrize("count", [3, 5, 10, 20])
def test_no_false_positives_on_existing_scenarios(scenario, count):
    """Legit flow: analyst reads PII then writes a public report others read; nobody leaks it, so no SG-005."""
    for seed in range(1, 6):
        sim = simulate(scenario, agents=count, seed=seed)
        assert run_rules(sim.run.run_id, normalize(sim), sim.agents, SG5) == []
