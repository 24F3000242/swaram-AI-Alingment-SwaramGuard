"""Live streaming: what happens in a run reaches connected UIs as it happens."""
import asyncio
import threading

import pytest
from fastapi.testclient import TestClient

from app.main import app, get_pipeline
from app.modules.simulator.engine import run_simulation
from app.schemas import ScenarioConfig
from app.services.live_hub import LiveHub, get_hub
from app.services.pipeline import Pipeline
from app.storage.sqlite_store import SQLiteStore


@pytest.fixture()
def client(tmp_path):
    app.dependency_overrides[get_pipeline] = lambda: Pipeline(SQLiteStore(str(tmp_path / "t.db")))
    yield TestClient(app)
    app.dependency_overrides.clear()


def _collect(ws, until="run_finished", limit=2000):
    msgs = []
    for _ in range(limit):
        m = ws.receive_json()
        msgs.append(m)
        if m["type"] in (until, "run_failed"):
            break
    return msgs


def test_hub_delivers_messages_published_from_worker_threads():
    hub = LiveHub()

    async def listen():
        sub = hub.subscribe(asyncio.get_running_loop(), run_id="run-a")
        t = threading.Thread(target=lambda: [hub.publish("event", {"i": i}, "run-a" if i % 2 else "run-b") for i in range(6)])
        t.start()
        got = [await asyncio.wait_for(sub.queue.get(), 2) for _ in range(3)]
        t.join()
        return got

    got = asyncio.run(listen())
    assert [m["data"]["i"] for m in got] == [1, 3, 5]  # only the run it follows, in order
    assert [m["seq"] for m in hub.replay("run-b")] == [1, 3, 5]  # late joiners can catch up


def test_background_run_streams_start_to_finish_with_containment(client):
    cfg = {"scenario_id": "sg003_leak_chain", "live_guard": "contain", "auto_pipeline": True, "persist": True}
    r = client.post("/api/runs/start", json=cfg)
    assert r.status_code == 200
    run_id = r.json()["run_id"]
    with client.websocket_connect(f"/api/live?run_id={run_id}") as ws:
        assert ws.receive_json()["type"] == "hello"
        msgs = _collect(ws)
    types = [m["type"] for m in msgs]
    assert types[0] == "run_started" and types[-1] == "run_finished" and "run_agents" in types
    assert types.count("event") > 20 and "detection" in types and "containment" in types
    assert all(m["run_id"] == run_id for m in msgs)
    seqs = [m["seq"] for m in msgs]
    assert seqs == sorted(seqs)  # strictly in order
    first_containment = types.index("containment")
    assert first_containment < types.index("run_finished")  # pushed mid-run, not after
    blocked = [m for m in msgs if m["type"] == "event" and m["data"]["status"] == "denied"]
    assert blocked and blocked[0]["data"]["payload"].get("quarantined")
    done = msgs[-1]["data"]
    assert done["persisted"] and done["live_metrics"]["data_left_the_system"] is False and done["alerts"] > 0
    assert client.get(f"/api/runs/{run_id}").status_code == 200  # saved like any other run


def test_streaming_never_changes_a_run():
    cfg = ScenarioConfig(scenario_id="sg002_external_leak", persist=False)
    plain = run_simulation(cfg, run_id="run-plain001")
    streamed = Pipeline(SQLiteStore(":memory:")).simulate(cfg, run_id="run-plain002")
    short = lambda x: x.split("-")[-1] if x and x.startswith("agt-") else x  # agent ids embed the run id
    strip = lambda sim: [(short(e.agent_id), e.event_type, e.action, e.resource, short(e.target), e.status) for e in sim.events]
    assert strip(plain) == strip(streamed)


def test_bad_start_requests_fail_fast(client):
    assert client.post("/api/runs/start", json={"scenario_id": "nope"}).status_code == 400
    assert client.post("/api/runs/start", json={"scenario_id": "sg001_unauthorized_access", "workspace_dir": "C:/"}).status_code == 400


def test_active_runs_listing(client):
    assert isinstance(client.get("/api/live/active").json(), list)
    assert get_hub().subscribers == 0  # every test socket was cleaned up


def test_a_fresh_pipeline_keeps_every_rule_after_the_first_call():
    """Regression: rules() used to save only SG-004 on first use, so every later call ran SG-004 alone."""
    from app.modules.detection.rules import DEFAULT_RULES

    p = Pipeline(SQLiteStore(":memory:"))  # never seeded, like scripts and ingest sessions
    first, second = p.rules(), p.rules()
    assert {r.rule_id for r in second} == {r.rule_id for r in first} == {r.rule_id for r in DEFAULT_RULES}
    assert next(r for r in second if r.rule_id == "SG-004").params.get("profile")  # the trained baseline is kept
