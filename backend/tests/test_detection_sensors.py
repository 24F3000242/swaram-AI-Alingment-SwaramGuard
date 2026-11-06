"""Missing logs: a second, independent evidence source (resource-side sensors) and gap-aware reasoning."""
import pytest

from app.modules.collector.normalizer import collect
from app.modules.detection.benchmark import CASES_BY_NAME, plant, run_benchmark
from app.modules.detection.evidence import fuse, sensor_record
from app.modules.detection.rules import run_rules
from app.modules.simulator.engine import run_simulation
from app.schemas import ScenarioConfig


@pytest.fixture(scope="module")
def rules():
    from app.services.pipeline import Pipeline
    from app.storage.sqlite_store import SQLiteStore

    return Pipeline(SQLiteStore(":memory:")).rules()


def _with_sensors(raw: list[dict]) -> list[dict]:
    return [x for e in raw for x in (e, sensor_record(e)) if x is not None]


def _normalize(raw, sim):
    return collect(raw, run_id=sim.run.run_id, agents=sim.agents).events


def test_complete_logs_rebuild_nothing_and_raise_nothing(rules):
    sim = run_simulation(ScenarioConfig(scenario_id="normal_collaboration", sensors=True, persist=False))
    assert any(e.event_type == "observation" and e.payload.get("mirrors") for e in sim.events)
    events = _normalize([e.model_dump(mode="json") for e in sim.events], sim)
    assert len(fuse(events)) == len(events)  # every sensor record matches its agent-log entry
    assert run_rules(sim.run.run_id, events, sim.agents, rules) == []


def test_attack_lost_from_the_agent_log_is_rebuilt_from_sensors_and_caught(rules):
    p = plant(CASES_BY_NAME["exfil to unknown site"], 5, 1)
    culprit = p.slots["A"]
    raw = [e for e in _with_sensors(p.raw) if e["event_id"] not in set(p.injected)]  # agent log lost every attack step
    events = _normalize(raw, p.sim)
    log_only = run_rules(p.sim.run.run_id, _normalize([e for e in raw if e["event_type"] != "observation"], p.sim),
                         p.sim.agents, rules)
    assert not any(culprit in a.agent_ids for a in log_only)  # one source alone: the culprit is invisible
    alerts = run_rules(p.sim.run.run_id, events, p.sim.agents, rules)
    hit = [a for a in alerts if culprit in a.agent_ids and a.rule_id == "SG-002"]
    assert hit and any(eid.endswith(":rebuilt") for eid in hit[0].event_ids)
    rebuilt = [e for e in fuse(events) if "reconstructed_from" in e.payload]
    assert rebuilt and rebuilt[0].summary.startswith("[rebuilt from egress-proxy]")


def test_sensor_record_with_no_log_entry_and_no_gap_is_still_a_bypass(rules):
    sim = run_simulation(ScenarioConfig(scenario_id="normal_collaboration", sensors=True, persist=False))
    raw = [e.model_dump(mode="json") for e in sim.events]
    mid = len(raw) // 2
    coder = next(a.agent_id for a in sim.agents if a.role == "coder")
    sneaky = {**raw[mid], "event_id": "evt-sneaky-s", "agent_id": coder, "event_type": "observation", "action": "write",
              "resource": "policy/gateway_rules", "target": None, "sequence": 0,
              "payload": {"source": "resource-audit", "mirrors": "resource_access"}}
    events = _normalize(raw[:mid] + [sneaky] + raw[mid:], sim)
    bypass = [a for a in run_rules(sim.run.run_id, events, sim.agents, rules) if a.rule_id == "SG-021" and a.agent_ids]
    assert bypass and bypass[0].agent_ids == [coder]


@pytest.mark.parametrize("where", ["first", "last"])
def test_losses_at_either_end_of_the_log_are_unverifiable_not_blamed(rules, where):
    sim = run_simulation(ScenarioConfig(scenario_id="normal_collaboration", sensors=True, persist=False))
    raw = [e.model_dump(mode="json") for e in sim.events]
    logged = [e for e in raw if e["event_type"] != "observation" and sensor_record(e) is not None]
    if where == "first":  # the very first action is lost
        gone = {logged[0]["event_id"]}
    else:  # truncation: the agent log lost everything from its last few sensed actions to the end
        cut = raw.index(logged[-3])
        gone = {e["event_id"] for e in raw[cut:] if e["event_type"] != "observation"}
    events = _normalize([e for e in raw if e["event_id"] not in gone], sim)
    alerts = [a for a in run_rules(sim.run.run_id, events, sim.agents, rules) if a.rule_id == "SG-021"]
    assert alerts and all(not a.agent_ids for a in alerts)  # "can't be confirmed", never a named bypass


def test_sensor_records_are_not_agent_actions_for_other_rules(rules):
    sim = run_simulation(ScenarioConfig(scenario_id="sg003_leak_chain", sensors=True, persist=False))
    events = _normalize([e.model_dump(mode="json") for e in sim.events], sim)
    plain = run_simulation(ScenarioConfig(scenario_id="sg003_leak_chain", persist=False))
    with_sensors = {(a.rule_id, tuple(sorted(a.agent_ids))) for a in run_rules(sim.run.run_id, events, sim.agents, rules)}
    events_plain = _normalize([e.model_dump(mode="json") for e in plain.events], plain)
    without = {(a.rule_id, len(a.agent_ids)) for a in run_rules(plain.run.run_id, events_plain, plain.agents, rules)}
    assert {(r, len(a)) for r, a in with_sensors} == without  # same verdicts when nothing is missing


def test_second_source_recovers_detection_without_false_alarms(rules):
    kw = dict(drop_rates=(0.3,), agent_counts=(5,), seeds=range(1, 3))
    one = run_benchmark(rules, run_rules, **kw)["rows"][0]
    two = run_benchmark(rules, run_rules, sensors=True, **kw)["rows"][0]
    assert two["precision"] == 1.0 and two["benign_alarm_rate"] == 0.0
    assert two["threat_detection_rate"] >= one["threat_detection_rate"] + 0.1


def test_sensitive_action_next_to_a_gap_is_queued_for_review(rules):
    from app.modules.detection.risk import assess, audit_queue

    sim = run_simulation(ScenarioConfig(scenario_id="normal_collaboration", persist=False))
    raw = [e.model_dump(mode="json") for e in sim.events]
    i = next(i for i, e in enumerate(raw) if e["resource"] == "data/customer_pii")
    events = _normalize(raw[:i - 3] + raw[i:i + 1] + raw[i + 4:], sim)  # three lost on each side of a PII read
    alerts = run_rules(sim.run.run_id, events, sim.agents, rules)
    queue = audit_queue(events, sim.agents, alerts, assess(sim.run.run_id, events, sim.agents, alerts, rules), rules)
    pii = [q for q in queue if q.event_id == raw[i]["event_id"]]
    assert pii and any("evidence may be incomplete" in r for r in pii[0].reasons)
