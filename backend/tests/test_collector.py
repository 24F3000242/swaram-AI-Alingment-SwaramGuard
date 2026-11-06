from app.modules.collector.normalizer import collect, normalize_event_type, normalize_timestamp
from app.schemas import Agent

from .conftest import load_jsonl, normalize, simulate

MESSY_AGENTS = [
    Agent(agent_id=f"agt-messy01-0{i}", run_id="run-messy01", name=f"A{i}", role=role, permissions=[])
    for i, role in [(1, "planner"), (2, "analyst"), (3, "coder")]
]


def test_timestamp_formats():
    assert normalize_timestamp("2026-01-15T09:00:01Z") == "2026-01-15T09:00:01.000Z"
    assert normalize_timestamp("2026-01-15 10:00:05+01:00") == "2026-01-15T09:00:05.000Z"
    assert normalize_timestamp(1768467603) == "2026-01-15T09:00:03.000Z"
    assert normalize_timestamp("1768467608000") == "2026-01-15T09:00:08.000Z"


def test_event_type_aliases():
    assert normalize_event_type("ResourceAccess") == ("resource_access", True)
    assert normalize_event_type("msg") == ("message", True)
    assert normalize_event_type("tool_use") == ("tool_call", True)
    assert normalize_event_type("weird") == ("weird", False)


def test_messy_fixture_report():
    result = collect(load_jsonl("raw_events_messy.jsonl"), run_id="run-messy01", agents=MESSY_AGENTS)
    r = result.report
    codes = [e.code for e in r.errors]
    assert r.total_input == 9
    assert r.duplicates == 1
    assert "invalid_timestamp" in codes and "missing_field" in codes and "run_mismatch" in codes
    assert r.valid == 5
    assert any(w.code == "unknown_agent" for w in r.warnings)
    by_id = {e.event_id: e for e in result.events}
    assert by_id["evt-messy01-0004"].status == "denied"
    assert by_id["evt-messy01-0004"].event_type == "data_transfer"
    assert by_id["evt-messy01-0001"].status == "success"


def test_preserves_original_evidence():
    raw = load_jsonl("raw_events_messy.jsonl")
    ev = collect(raw, run_id="run-messy01").events[0]
    assert ev.raw == raw[0]
    assert len(ev.raw_hash) == 64


def test_conflicting_duplicate_is_error():
    raw = load_jsonl("raw_events_messy.jsonl")[:1]
    dup = dict(raw[0], action="changed")
    report = collect(raw + [dup]).report
    assert report.duplicates == 1 and report.errors[0].code == "conflicting_duplicate"


def test_simulated_events_are_clean_and_sorted():
    sim = simulate("coordinated_leakage")
    result = collect([e.model_dump(mode="json") for e in sim.events], run_id=sim.run.run_id, agents=sim.agents)
    assert result.report.valid == len(sim.events) and not result.report.errors and not result.report.warnings
    stamps = [e.timestamp for e in result.events]
    assert stamps == sorted(stamps)
    assert all(e.summary and e.agent_role for e in normalize(sim))


def test_not_an_object():
    assert collect(["oops"]).report.errors[0].code == "not_an_object"
