import pytest
from fastapi.testclient import TestClient

from app.main import app, get_pipeline
from app.schemas import ScenarioConfig
from app.services.pipeline import Pipeline
from app.storage.sqlite_store import SQLiteStore


def test_sqlite_store_roundtrip(store):
    store.put_many("raw_events", [("e1", {"run_id": "r1", "x": 1}), ("e2", {"run_id": "r2", "x": 2})])
    store.put("raw_events", "e1", {"run_id": "r1", "x": 3})
    assert store.get("raw_events", "e1")["x"] == 3
    assert [d["x"] for d in store.list("raw_events", run_id="r1")] == [3]
    assert store.delete_run_docs("raw_events", "r1") == 1
    assert store.get("raw_events", "e1") is None
    with pytest.raises(ValueError):
        store.put("nope", "x", {})


def test_workspaces_are_isolated(tmp_path):
    path = str(tmp_path / "db.sqlite")
    a, b = SQLiteStore(path, "team-a"), SQLiteStore(path, "team-b")
    a.put("runs", "r", {"run_id": "r"})
    assert b.get("runs", "r") is None


def test_rerun_upstream_invalidates_downstream(pipeline):
    run_id = pipeline.simulate(ScenarioConfig(scenario_id="unauthorized_access")).run.run_id
    pipeline.run_all(run_id)
    assert pipeline.responses(run_id)
    pipeline.collect(run_id)
    assert pipeline.alerts(run_id) == [] and pipeline.responses(run_id) == []
    assert "detected" not in pipeline.get_run(run_id).stages


def test_respond_requires_detection(pipeline):
    run_id = pipeline.simulate(ScenarioConfig()).run.run_id
    with pytest.raises(ValueError):
        pipeline.respond(run_id)


@pytest.fixture
def client(tmp_path):
    db = str(tmp_path / "api.sqlite")
    app.dependency_overrides[get_pipeline] = lambda: Pipeline(SQLiteStore(db))
    Pipeline(SQLiteStore(db)).seed_defaults()
    yield TestClient(app), db
    app.dependency_overrides.clear()


def test_definition_of_done_flow(client):
    """Simulate -> inspect -> normalize -> detect -> respond -> dashboard -> recover after 'reload'."""
    c, db = client
    sim = c.post("/api/simulate", json={"scenario_id": "coordinated_leakage", "agent_count": 5, "gateway_mode": "enforce"}).json()
    run_id = sim["run"]["run_id"]
    raw = c.get(f"/api/runs/{run_id}/raw-events").json()
    assert len(raw) == len(sim["events"]) > 0

    col = c.post("/api/collect", json={"run_id": run_id}).json()
    assert col["report"]["valid"] == len(raw)

    det = c.post("/api/detect", json={"run_id": run_id}).json()
    assert {a["rule_id"] for a in det["alerts"]} == {"SG-002", "SG-003", "SG-004"}
    assert det["assessments"][0]["level"] == "critical"

    policy = c.get("/api/response-policies/default").json()
    policy["mode"] = "enforce"
    resp = c.post("/api/respond", json={"run_id": run_id, "policy": policy}).json()
    outcomes = {a["alert_id"]: a["outcome"] for a in resp["actions"]}
    sg4 = next(a["alert_id"] for a in det["alerts"] if a["rule_id"] == "SG-004")
    assert outcomes.pop(sg4) == "alerted"  # medium anomaly -> human review
    assert set(outcomes.values()) == {"blocked"}

    # Simulate a browser reload: a brand-new store connection on the same database.
    app.dependency_overrides[get_pipeline] = lambda: Pipeline(SQLiteStore(db))
    assert run_id in [r["run_id"] for r in c.get("/api/runs").json()]
    dash = c.get(f"/api/runs/{run_id}/dashboard").json()
    assert dash["totals"]["threats"] == 3
    assert dash["response_outcomes"] == {"blocked": 2, "alerted": 1}
    assert dash["evaluation"]["recall"] == 1.0 and dash["evaluation"]["false_positive_rate"] == 0.0
    assert {a["status"] for a in c.get(f"/api/runs/{run_id}/alerts").json()} == {"contained", "responded"}
    assert c.get(f"/api/runs/{run_id}/assessments").json()[0]["best_explanation"]
    assert c.get("/api/detection/baseline").json()["trained"] is True


def test_api_errors_and_meta(client):
    c, _ = client
    assert c.get("/api/runs/run-missing").status_code == 404
    assert c.post("/api/simulate", json={"agent_count": 7}).status_code == 422
    assert c.post("/api/collect", json={}).status_code == 400
    assert c.get("/api/health").json()["storage"] == "sqlite"
    for module in ("simulator", "collector", "detection", "response", "evaluation"):
        info = c.get(f"/api/modules/{module}").json()
        assert info["input"]["schema"] and info["output"]["schema"]


def test_inline_collect_and_auto_pipeline(client):
    c, _ = client
    report = c.post("/api/collect", json={"events": [{"run_id": "x"}], "persist": False}).json()["report"]
    assert report["invalid"] == 1
    sim = c.post("/api/simulate", json={"scenario_id": "unauthorized_access", "auto_pipeline": True}).json()
    assert set(sim["run"]["stages"]) == {"simulated", "collected", "detected", "responded", "evaluated"}


def test_suite_endpoint(client):
    c, _ = client
    body = {"drop_rates": [0.0, 0.3], "seeds": [1, 2]}
    suite = c.post("/api/evaluate/suite", json=body).json()
    assert [r["drop_rate"] for r in suite["rows"]] == [0.0, 0.3]
    assert suite["rows"][0]["recall"] == 1.0 and suite["rows"][0]["false_positive_rate"] == 0.0
    assert c.get("/api/evaluations").json()[0]["evaluation_id"] == suite["evaluation_id"]
