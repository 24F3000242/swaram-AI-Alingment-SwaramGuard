"""Security Response, live: the policy acts as alerts fire, operators can pause agents, and records show it all."""
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import app, get_pipeline
from app.modules.detection.live import LiveGuard
from app.modules.simulator.engine import run_simulation
from app.schemas import ResponsePolicy, ScenarioConfig
from app.services.pipeline import Pipeline
from app.storage.sqlite_store import SQLiteStore

sys.path.insert(0, str(Path(__file__).parent))
from test_ingest import AGENTS  # noqa: E402


@pytest.fixture()
def pipeline(tmp_path):
    return Pipeline(SQLiteStore(str(tmp_path / "t.db")))


@pytest.fixture()
def client(pipeline):
    app.dependency_overrides[get_pipeline] = lambda: pipeline
    yield TestClient(app)
    app.dependency_overrides.clear()


def _guarded_run(pipeline, policy, scenario="sg002_external_leak"):
    guard = LiveGuard(pipeline.rules(), "contain", policy=policy)
    run_simulation(ScenarioConfig(scenario_id=scenario, persist=False), live=guard)
    return guard


def test_the_response_policy_acts_live_as_alerts_fire(pipeline):
    default = _guarded_run(pipeline, ResponsePolicy())
    # The upload is refused before it runs and the agent's egress held at once (pre-execution check); the policy's
    # "block" for the SG-002 alert then finds it already held and records the decision.
    assert any(r["rule_id"] == "SG-002" and r["decision"] == "block" and r["applied"] in (["egress held"], ["recorded"])
               for r in default.responses)
    assert any(c.trigger in ("policy", "policy_check") for c in default.held.values())
    no_gate = LiveGuard(pipeline.rules(), "contain", policy=ResponsePolicy(), policy_gate=False)
    run_simulation(ScenarioConfig(scenario_id="sg002_external_leak", persist=False), live=no_gate)
    assert any(r["rule_id"] == "SG-002" and r["applied"] == ["egress held"] for r in no_gate.responses)
    assert any(c.trigger == "policy" and c.rule_id == "SG-002" for c in no_gate.held.values())
    relaxed = _guarded_run(pipeline, ResponsePolicy(rule_overrides={"SG-002": "alert"}))
    sg002 = [r for r in relaxed.responses if r["rule_id"] == "SG-002"]
    assert sg002 and sg002[0]["applied"] == ["recorded"]  # the policy decides; "alert" contains nothing
    assert not any(c.trigger == "policy" and c.rule_id == "SG-002" for c in [*relaxed.held.values(), *relaxed.paused.values()])


def test_detect_mode_only_records_what_the_policy_would_do(pipeline):
    guard = LiveGuard(pipeline.rules(), "detect", policy=ResponsePolicy())
    run_simulation(ScenarioConfig(scenario_id="sg002_external_leak", persist=False), live=guard)
    assert not guard.paused and not guard.held
    assert any("would_block" in r["applied"] for r in guard.responses)


def test_operator_can_pause_an_agent_and_stop_a_live_run(client):
    run_id = client.post("/api/ingest/sessions", json={"name": "op-demo", "agents": AGENTS}).json()["run_id"]
    ask = {"agent_id": "ext-planner", "event_type": "resource_access", "action": "read", "resource": "docs/wiki"}
    assert client.post(f"/api/ingest/{run_id}/gate", json=ask).json()["allow"] is True
    with client.websocket_connect(f"/api/live?run_id={run_id}") as ws:
        r = client.post(f"/api/live/{run_id}/agents/ext-planner", json={"action": "pause", "note": "looked odd"}).json()
        assert r["result"] == "paused"
        seen = []
        while not any(m["type"] == "operator" for m in seen):
            seen.append(ws.receive_json())
    assert any(m["type"] == "containment" and m["data"]["trigger"] == "operator" for m in seen)
    gate = client.post(f"/api/ingest/{run_id}/gate", json=ask).json()
    assert gate["allow"] is False and "paused" in gate["reason"]
    item = next(i for i in client.get("/api/reviews", params={"run_id": run_id}).json() if i["agent_id"] == "ext-planner")
    assert item["trigger"] == "operator" and "looked odd" in item["explanation"]
    stop = client.post(f"/api/live/{run_id}/stop").json()["paused"]
    assert stop == {"ext-planner": "already paused", "ext-analyst": "paused", "ext-coder": "paused"}
    assert client.post(f"/api/live/{run_id}/agents/nobody", json={"action": "pause"}).status_code == 400
    assert client.post(f"/api/live/{run_id}/agents/ext-coder", json={"action": "explode"}).status_code == 400
    client.post(f"/api/ingest/{run_id}/finish")
    assert client.post(f"/api/live/{run_id}/stop").status_code == 409  # nothing live to stop any more


def test_operator_needs_a_contained_run(client):
    run_id = client.post("/api/ingest/sessions", json={"agents": AGENTS, "live_guard": "detect"}).json()["run_id"]
    assert client.post(f"/api/live/{run_id}/agents/ext-coder", json={"action": "pause"}).status_code == 400


def test_response_records_include_what_happened_live(pipeline):
    pipeline.simulate(ScenarioConfig(scenario_id="sg003_leak_chain", live_guard="contain", persist=True, auto_pipeline=True),
                      run_id="run-resp0001")
    actions = pipeline.responses("run-resp0001")
    live = [a for a in actions if a.response_id.startswith("rsp-live-")]
    assert live and all(a.enforced and a.mode == "enforced" for a in live)
    assert {a.outcome for a in live} <= {"blocked", "contained"}
    assert any(a.outcome == "blocked" for a in live)  # the paused coder's later actions were denied
    alerts = {a.alert_id: a for a in pipeline.alerts("run-resp0001")}
    assert all(a.alert_id in alerts for a in live)  # each links to the alert that explains it
    assert any(alerts[a.alert_id].status == "contained" for a in live)
    assert pipeline.evaluate("run-resp0001").containment_rate == 1.0  # both culprits contained
