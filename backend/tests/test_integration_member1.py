"""Integration of member 1's simulator: security fixes and contracts with Threat Detection."""
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.modules.collector.normalizer import collect
from app.modules.detection.rules import run_rules
from app.modules.simulator.engine import _execute_code_safely, run_simulation
from app.modules.simulator.environment import VirtualFilesystem
from app.schemas import ScenarioConfig


# ------------------------------------------------------------ security: path traversal
@pytest.mark.parametrize("path", ["../../escape.txt", "docs/../../../escape.txt", "C:/Windows/escape.txt",
                                  "/etc/escape.txt", "..\\..\\escape.txt", "./././../escape.txt"])
def test_virtual_paths_cannot_leave_the_workspace(tmp_path, path):
    root = tmp_path / "workspace"
    fs = VirtualFilesystem(disk_root=root)
    norm = fs.normalize_path(path)
    assert ".." not in norm.split("/") and not norm.startswith("/") and ":" not in norm.split("/")[0]
    fs._sync_to_disk(norm, "x")
    written = [p for p in tmp_path.rglob("*") if p.is_file()]
    assert written and all(p.resolve().is_relative_to(root.resolve()) for p in written)


def test_sync_refuses_a_path_that_resolves_outside(tmp_path):
    root = tmp_path / "workspace"
    fs = VirtualFilesystem(disk_root=root)
    fs._sync_to_disk("../outside.txt", "x")  # bypassing normalize_path on purpose
    assert not (tmp_path / "outside.txt").exists()


# ------------------------------------------------------------ security: agent-written code execution
def test_code_runs_sandboxed_by_default(monkeypatch):
    monkeypatch.delenv("SWARMGUARD_CODE_EXEC", raising=False)
    ok, msg = _execute_code_safely("print(sum(range(10)))")
    assert ok, msg
    ok, msg = _execute_code_safely("open('pwned.txt', 'w').write('x')")
    assert ok is False and "Sandbox refused" in msg and not Path("pwned.txt").exists()


def test_code_execution_can_be_turned_off(monkeypatch):
    monkeypatch.setenv("SWARMGUARD_CODE_EXEC", "off")
    ok, msg = _execute_code_safely("print('hi')")
    assert ok is False and "turned off" in msg


def test_generated_code_does_not_inherit_secrets(monkeypatch, tmp_path):
    from app.modules.simulator.sandbox import _run

    monkeypatch.setenv("GEMINI_API_KEY", "secret-should-not-leak")
    # Static policy would refuse `import os`; this checks the process environment itself.
    (tmp_path / "solution.py").write_text("import os, sys\nsys.exit(1 if os.getenv('GEMINI_API_KEY') else 0)")
    assert _run(tmp_path, "solution", 10).returncode == 0


def test_api_rejects_client_chosen_workspace():
    r = TestClient(app).post("/api/simulate", json={"scenario_id": "normal_collaboration", "workspace_dir": "C:/Users"})
    assert r.status_code == 400


def test_default_workspace_is_outside_the_repo(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    run_simulation(ScenarioConfig(scenario_id="user_directed", user_task="Add two numbers", persist=False))
    assert not (tmp_path / "runs").exists()


# ------------------------------------------------------------ contract: inbox reads are not hand-offs
def test_receive_events_are_not_read_as_sends():
    sim = run_simulation(ScenarioConfig(scenario_id="sg003_leak_chain", persist=False))
    receives = [e for e in sim.events if e.event_type == "message" and e.action == "receive"]
    assert receives, "member 1's simulator records inbox reads"
    events = collect([e.model_dump(mode="json") for e in sim.events], run_id=sim.run.run_id, agents=sim.agents).events
    alerts = run_rules(sim.run.run_id, events, sim.agents)
    culprits = set(sim.run.labels.malicious_agent_ids)
    flagged = {a for al in alerts for a in al.agent_ids}
    assert culprits <= flagged and not (flagged - culprits)  # nobody blamed for merely receiving


def test_live_guard_contains_attack_in_new_simulator():
    from app.services.pipeline import Pipeline
    from app.storage.sqlite_store import SQLiteStore

    p = Pipeline(SQLiteStore(":memory:"))
    res = p.simulate(ScenarioConfig(scenario_id="sg003_leak_chain", live_guard="contain", persist=False))
    assert res.live_report.metrics["data_left_the_system"] is False
    assert res.live_report.metrics["paused_innocent"] == 0


# ------------------------------------------------------------ contract: canonical export keeps what detection needs
def test_canonical_export_round_trips_into_detection():
    import json

    from app.modules.simulator.export import export_canonical_jsonl, parse_canonical_jsonl

    sim = run_simulation(ScenarioConfig(scenario_id="sg003_leak_chain", gateway_mode="enforce", persist=False))
    records = parse_canonical_jsonl(export_canonical_jsonl(sim))  # still exactly 12 top-level fields
    assert all("sequence" not in r and "telemetry" in r["details"] for r in records)
    events = collect(records, run_id=sim.run.run_id, agents=sim.agents).events
    by_id = {e.event_id: e for e in events}
    original = {e.event_id: e for e in sim.events}
    assert all(by_id[i].sequence == original[i].sequence for i in by_id)
    assert any(e.gateway_decision == "blocked" for e in events)  # proof of a real block survives
    assert any(e.payload.get("data_ref") for e in events)  # hand-off evidence survives
    assert all("telemetry" not in e.payload for e in events)
    rules = {a.rule_id for a in run_rules(sim.run.run_id, events, sim.agents)}
    assert "SG-003" in rules
    assert json.loads(json.dumps(records[0]))["details"]["telemetry"]["sequence"] == 1


# ------------------------------------------------------------ every simulator scenario vs Threat Detection
from app.modules.simulator.scenarios import SCENARIOS  # noqa: E402

ATTACK_SCENARIOS = [s for s in SCENARIOS if s.scenario_id != "user_directed"]


@pytest.fixture(scope="module")
def trained_rules():
    from app.services.pipeline import Pipeline
    from app.storage.sqlite_store import SQLiteStore

    return Pipeline(SQLiteStore(":memory:")).rules()


@pytest.mark.parametrize("scenario", ATTACK_SCENARIOS, ids=[s.scenario_id for s in ATTACK_SCENARIOS])
def test_every_scenario_is_detected_without_blaming_innocents(scenario, trained_rules):
    import re

    sim = run_simulation(ScenarioConfig(scenario_id=scenario.scenario_id, agent_count=5, persist=False))
    events = collect([e.model_dump(mode="json") for e in sim.events], run_id=sim.run.run_id, agents=sim.agents).events
    alerts = run_rules(sim.run.run_id, events, sim.agents, trained_rules)
    fired = {a.rule_id for a in alerts}
    flagged = {x for a in alerts for x in a.agent_ids}
    culprits = set(sim.run.labels.malicious_agent_ids)
    expected = set(re.findall(r"SG-\d{3}", " ".join(scenario.tags)))
    assert expected <= fired or not expected, f"expected {expected}, fired {fired}"
    assert culprits <= flagged and not (flagged - culprits)


def test_baseline_saved_before_the_merge_is_retrained(pipeline):
    """A workspace baseline from the old simulator (no inbox reads) would make every receiver look anomalous."""
    from app.modules.detection import baseline

    rules = pipeline.rules()
    anomaly = next(r for r in rules if r.rule_id == "SG-004")
    old = anomaly.params["profile"]
    old["version"] = 4
    for role in old["roles"].values():
        role["behaviors"].pop("message:receive", None)
    pipeline.save_rule(anomaly)
    fresh = next(r for r in pipeline.rules() if r.rule_id == "SG-004").params["profile"]
    assert fresh["version"] == baseline.PROFILE_VERSION
    assert any("message:receive" in r["behaviors"] for r in fresh["roles"].values())
