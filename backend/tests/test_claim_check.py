"""SG-030: an agent's claimed tool calls reconciled with what was recorded, batch and live, incl. partial monitors."""
import pytest

from app.modules.collector.normalizer import collect
from app.modules.detection.claims import CLAIM_RULES, rule_claim_check
from app.modules.detection.live import LiveGuard
from app.modules.detection.rules import run_rules
from app.modules.simulator.engine import run_simulation
from app.modules.simulator.scenarios import SCENARIOS
from app.schemas import Agent, NormalizedEvent, ResponsePolicy, ScenarioConfig
from app.services.pipeline import Pipeline
from app.storage.sqlite_store import SQLiteStore

RULE = CLAIM_RULES[0]
CLAIM = {"action": "upload", "resource": "reports/q3", "target": "external:approved-partner-api"}
REG = {"a": Agent(agent_id="a", run_id="r", name="A", role="analyst", permissions=["reports"])}


def ev(seq, event_type="data_transfer", action="upload", status="success", resource="reports/q3",
       target="external:approved-partner-api", payload=None, agent="a"):
    return NormalizedEvent(event_id=f"e{seq}", run_id="r", agent_id=agent, agent_role="analyst",
                           timestamp=f"2026-11-07T10:00:{seq:02d}Z", event_type=event_type, action=action, status=status,
                           sequence=seq, payload=payload or {}, resource=resource, target=target, summary="",
                           raw_hash="h", raw={}, normalized_at="2026-11-07T10:00:00Z")


def report(seq, *claims, agent="a"):
    return ev(seq, "message", "report", resource=None, target="planner", agent=agent,
              payload={"content": "done", "claims": list(claims) or [CLAIM]})


def filler(start, n, agent="a"):
    return [ev(start + i, "tool_call", "run", resource="tool/sql_query", target=None, agent=agent) for i in range(n)]


def kinds(events):
    return [(al.severity, al.reason) for al in rule_claim_check(RULE, "r", events, REG)]


# ------------------------------------------------------------ batch
def test_matching_claim_is_verified():
    assert kinds([ev(1), report(2)] + filler(3, 3)) == []


@pytest.mark.parametrize("actual,kind", [
    (dict(target="external:elsewhere"), "wrong_destination"),
    (dict(resource="reports/other"), "wrong_resource"),
    (dict(status="denied"), "false_success"),
])
def test_mismatches(actual, kind):
    (sev, reason), = kinds([ev(1, **actual), report(2)] + filler(3, 3))
    assert kind in reason and sev == "high"


def test_unreported_sensitive_transfer_is_hidden_extra_but_routine_one_is_not():
    hidden = ev(2, resource="data/customer_pii", target="external:exfil")
    assert "hidden_extra" in kinds([ev(1), hidden, report(3)] + filler(4, 3))[0][1]
    routine = ev(2, resource="reports/other")  # approved destination, not restricted: an omission, not a cover-up
    assert kinds([ev(1), routine, report(3)] + filler(4, 3)) == []


def test_phantom_waits_for_the_window_then_fires():
    assert kinds([report(1)]) == []                      # nothing recorded yet: pending, not accused
    (sev, reason), = kinds([report(1)] + filler(2, 3))   # agent moved on without doing it
    assert "phantom" in reason and sev == "medium"


def test_delayed_log_is_not_a_lie():
    assert kinds([report(1)] + filler(2, 1) + [ev(3)] + filler(4, 3)) == []


def test_gap_in_the_record_makes_it_unverified_not_phantom():
    events = [ev(1, "tool_call", "run", resource="tool/x", target=None), report(3)] + filler(4, 3)  # seq 2 was lost
    (sev, reason), = kinds(events)
    assert "unverified" in reason and sev == "low"


def test_one_action_cannot_satisfy_two_claims():
    (sev, reason), = kinds([ev(1), report(2, CLAIM, CLAIM)] + filler(3, 3))
    assert "phantom" in reason


def test_each_report_only_covers_actions_since_the_last_one():
    events = [ev(1), report(2), report(3)] + filler(4, 3)  # the second report reuses the first one's upload
    (sev, reason), = kinds(events)
    assert "phantom" in reason


def test_recipient_copy_and_summary_claims_are_ignored():
    recv = ev(1, "message", "receive", resource=None, target=None, payload={"claims": [CLAIM]})
    summary = ev(2, "message", "send", resource=None, target="planner", payload={"claims": {"restricted_access": False}})
    assert kinds([recv, summary] + filler(3, 3)) == []


# ------------------------------------------------------------ through the simulator
def _rules():
    return Pipeline(SQLiteStore(":memory:")).rules()


@pytest.mark.parametrize("scenario", [s.scenario_id for s in SCENARIOS if "SG-030" not in s.tags])
def test_never_fires_on_any_other_scenario(scenario):
    sim = run_simulation(ScenarioConfig(scenario_id=scenario, agent_count=5, persist=False))
    events = collect([e.model_dump(mode="json") for e in sim.events], run_id=sim.run.run_id, agents=sim.agents).events
    assert not [a for a in run_rules(sim.run.run_id, events, sim.agents, CLAIM_RULES) if a.rule_id == "SG-030"]


@pytest.mark.parametrize("scenario", ["claim_wrong_destination", "claim_hidden_extra", "claim_wrong_resource",
                                      "claim_false_success", "claim_phantom_action"])
def test_live_guard_contains_the_liar(scenario):
    live = LiveGuard(_rules(), "contain", policy=ResponsePolicy())
    sim = run_simulation(ScenarioConfig(scenario_id=scenario, agent_count=5, persist=False), live=live)
    liar = sim.run.labels.malicious_agent_ids[0]
    hits = [d for d in live.detections if d.rule_id == "SG-030"]
    assert all(d.agent_ids == [liar] for d in hits)
    if scenario == "claim_hidden_extra":
        # The pre-execution check refuses the hidden exfil upload, so there is nothing left to hide: contained anyway.
        assert liar in live.held or liar in live.paused
    else:
        assert hits
        if any(d.severity == "high" for d in hits):  # high -> the default policy holds its egress
            assert liar in live.held or liar in live.paused


@pytest.mark.parametrize("scenario", ["claim_honest_reworded", "claim_honest_batch", "claim_honest_delayed",
                                      "claim_missing_telemetry"])
def test_live_guard_leaves_honest_agents_alone(scenario):
    live = LiveGuard(_rules(), "contain", policy=ResponsePolicy())
    run_simulation(ScenarioConfig(scenario_id=scenario, agent_count=5, persist=False), live=live)
    assert not [d for d in live.detections if d.rule_id == "SG-030" and d.severity != "low"]
    assert not any(c.rule_id == "SG-030" for c in list(live.paused.values()) + list(live.held.values()))
