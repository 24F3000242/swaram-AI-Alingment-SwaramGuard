"""Live guard: detection while the run happens, containment before harm."""
import pytest
from fastapi.testclient import TestClient

from app.main import app, get_pipeline
from app.modules.detection.rules import run_rules
from app.modules.simulator.engine import run_simulation
from app.schemas import ScenarioConfig
from app.services.pipeline import Pipeline
from app.storage.sqlite_store import SQLiteStore

from .conftest import BASE_TIME


@pytest.fixture(scope="module")
def pipe():
    p = Pipeline(SQLiteStore(":memory:"))
    p.seed_defaults()
    p.rules()  # train baseline once
    return p


def live(pipe, scenario, agents=5, mode="contain", gateway="monitor", seed=7):
    cfg = ScenarioConfig(scenario_id=scenario, agent_count=agents, seed=seed, gateway_mode=gateway, live_guard=mode, persist=False)
    return pipe.simulate(cfg)


def test_unauthorized_agent_is_paused_mid_attack(pipe):
    res = live(pipe, "unauthorized_access")
    m, attacker = res.live_report.metrics, res.run.labels.malicious_agent_ids[0]
    assert {x.agent_id for x in res.live_report.containment} == {attacker}  # only the attacker is ever contained
    c = next(x for x in res.live_report.containment if x.scope == "agent")
    assert c.risk >= 0.6
    assert m["attack_actions_blocked_by_pause"] >= 1 and m["paused_innocent"] == 0
    blocked = [e for e in res.events if e.payload.get("quarantined")]
    assert blocked and all(e.agent_id == attacker and e.status == "denied" and e.gateway_decision == "blocked" for e in blocked)
    # The first out-of-policy read is refused before it runs (pre-execution check); after that the agent is paused.
    first = min(blocked, key=lambda e: e.sequence)
    assert "pre-execution check" in first.payload["gateway_reason"] and first.sequence <= c.paused_at_sequence
    assert all(e.sequence > c.paused_at_sequence or "pre-execution check" in e.payload["gateway_reason"] for e in blocked)


@pytest.mark.parametrize("agents", [5, 10])
def test_leak_is_stopped_before_data_leaves(pipe, agents):
    res = live(pipe, "coordinated_leakage", agents=agents)
    m = res.live_report.metrics
    assert m["data_left_the_system"] is False  # even with the static gateway only monitoring
    contained = {c.agent_id for c in res.live_report.containment}
    assert set(res.run.labels.malicious_agent_ids) <= contained and m["paused_innocent"] == 0
    assert contained <= set(res.run.labels.malicious_agent_ids)  # nobody innocent is held either
    # The hand-off itself is refused before it runs, and so is the upload: nothing moves at all.
    handoff = next(e for e in res.events if e.event_type == "message" and e.payload.get("data_ref") == "data/customer_pii")
    upload = next(e for e in res.events if e.event_type == "data_transfer" and e.target == "external:paste-site")
    for e in (handoff, upload):
        assert e.status == "denied" and e.payload["quarantined"] and "pre-execution check" in e.payload["gateway_reason"]
    assert m["blocked_by_policy_check"] >= 2


def test_detect_mode_observes_without_blocking(pipe):
    res = live(pipe, "coordinated_leakage", mode="detect")
    m = res.live_report.metrics
    assert res.live_report.detections and not res.live_report.containment
    assert m["data_left_the_system"] is True and not any(e.payload.get("quarantined") for e in res.events)
    assert m["detected_live"] == m["malicious_agents"] and m["mean_latency_events"] is not None


@pytest.mark.parametrize("agents", [5, 10, 20])
def test_normal_runs_stay_untouched(pipe, agents):
    for seed in (1, 2):
        res = live(pipe, "normal_collaboration", agents=agents, seed=seed)
        assert res.live_report.detections == [] and res.live_report.containment == []
        assert not any(e.payload.get("quarantined") for e in res.events)


def test_hook_is_inert_when_off():
    cfg = ScenarioConfig(scenario_id="coordinated_leakage", persist=False)
    a = run_simulation(cfg, run_id="run-same0001", base_time=BASE_TIME)
    b = run_simulation(cfg, run_id="run-same0001", base_time=BASE_TIME, live=None)
    assert [e.model_dump() for e in a.events] == [e.model_dump() for e in b.events] and a.live_report is None


def test_own_containment_is_not_evidence_of_power_seeking(pipe):
    res = live(pipe, "unauthorized_access")
    from app.modules.collector.normalizer import collect

    events = collect([e.model_dump(mode="json") for e in res.events], run_id=res.run.run_id, agents=res.agents).events
    rules = {a.rule_id for a in run_rules(res.run.run_id, events, res.agents, pipe.rules())}
    assert "SG-011" not in rules and "SG-013" not in rules and "SG-001" in rules


def test_live_report_api(tmp_path):
    db = str(tmp_path / "live.sqlite")
    app.dependency_overrides[get_pipeline] = lambda: Pipeline(SQLiteStore(db))
    try:
        c = TestClient(app)
        sim = c.post("/api/simulate", json={"scenario_id": "coordinated_leakage", "live_guard": "contain", "auto_pipeline": True}).json()
        run_id = sim["run"]["run_id"]
        assert sim["live_report"]["metrics"]["data_left_the_system"] is False
        rep = c.get(f"/api/runs/{run_id}/live-report")
        assert rep.status_code == 200 and rep.json()["containment"]
        plain = c.post("/api/simulate", json={"scenario_id": "normal_collaboration"}).json()["run"]["run_id"]
        plain_rep = c.get(f"/api/runs/{plain}/live-report")
        assert plain_rep.status_code == 200 and plain_rep.json() is None  # not live: empty, not an error
        assert c.get("/api/runs/run-missing/live-report").status_code == 404
    finally:
        app.dependency_overrides.clear()
