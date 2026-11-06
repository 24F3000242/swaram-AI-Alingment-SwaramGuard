"""Attack replay: plant a benchmark case into a fresh run and stream it through the live guard."""
import pytest
from fastapi.testclient import TestClient

from app.main import app, get_pipeline
from app.modules.detection.benchmark import ALL_CASES, ATTACKS, BENIGN
from app.schemas import ReplayRequest
from app.services.pipeline import Pipeline
from app.storage.sqlite_store import SQLiteStore


@pytest.fixture(scope="module")
def pipe():
    p = Pipeline(SQLiteStore(":memory:"))
    p.seed_defaults()
    p.rules()
    return p


@pytest.mark.parametrize("case", ALL_CASES, ids=[c.name for c in ALL_CASES])
def test_every_case_replays_as_expected(pipe, case):
    res = pipe.replay(ReplayRequest(case=case.name, seed=11))
    rep, m = res.live_report, res.live_report.metrics
    fired = {d.rule_id for d in rep.detections}
    flagged = {a for d in rep.detections for a in d.agent_ids}
    culprits = set(res.run.labels.malicious_agent_ids)
    assert m["paused_innocent"] == 0
    if culprits:
        assert fired & set(case.expect_rules) and culprits & flagged
    else:
        assert not flagged


def test_replay_is_saved_and_runs_the_pipeline(pipe):
    res = pipe.replay(ReplayRequest(case="leak chain via message", agent_count=10))
    run = pipe.get_run(res.run.run_id)
    assert run.scenario_id == "replay:leak chain via message" and len(run.labels.malicious_agent_ids) == 2
    assert set(run.stages) == {"simulated", "collected", "detected", "responded", "evaluated"}
    assert pipe.live_report(run.run_id).metrics["data_left_the_system"] is False
    assert any(e.payload.get("quarantined") for e in pipe.raw_events(run.run_id))  # the upload was held live
    assert {a.rule_id for a in pipe.alerts(run.run_id)} >= {"SG-003"}


def test_replay_without_guard_lets_the_leak_through(pipe):
    res = pipe.replay(ReplayRequest(case="leak chain via message", live_guard="off"))
    assert res.live_report is None
    assert not any(e.payload.get("quarantined") for e in res.events)


def test_replays_get_unique_runs(pipe):
    a = pipe.replay(ReplayRequest(case="honeytoken"))
    b = pipe.replay(ReplayRequest(case="honeytoken"))
    assert a.run.run_id != b.run.run_id


def test_replay_api(tmp_path):
    db = str(tmp_path / "replay.sqlite")
    app.dependency_overrides[get_pipeline] = lambda: Pipeline(SQLiteStore(db))
    try:
        c = TestClient(app)
        cases = c.get("/api/detection/replay-cases").json()
        assert len(cases) == len(ALL_CASES)
        assert sum(not x["benign"] for x in cases) == len(ATTACKS) + sum(1 for b in BENIGN if b.flagged)
        res = c.post("/api/detection/replay", json={"case": "oversight tampering"}).json()
        assert res["run"]["scenario_id"] == "replay:oversight tampering" and res["live_report"]["detections"]
        assert c.post("/api/detection/replay", json={"case": "nope"}).status_code == 400
    finally:
        app.dependency_overrides.clear()
