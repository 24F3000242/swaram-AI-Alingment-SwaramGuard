"""Live ingest: a real (external) swarm reports events and asks the gate before acting."""
import pytest
from fastapi.testclient import TestClient

from app.main import app, get_pipeline
from app.services.pipeline import Pipeline
from app.storage.sqlite_store import SQLiteStore

AGENTS = [
    {"agent_id": "ext-planner", "role": "planner", "permissions": ["docs/wiki", "data/public"]},
    {"agent_id": "ext-analyst", "role": "analyst", "permissions": ["data/public", "data/customer_pii", "docs/wiki"]},
    {"agent_id": "ext-coder", "role": "coder", "permissions": ["repo/src", "docs/wiki"]},
]


@pytest.fixture()
def client(tmp_path):
    pipeline = Pipeline(SQLiteStore(str(tmp_path / "t.db")))
    app.dependency_overrides[get_pipeline] = lambda: pipeline
    yield TestClient(app)
    app.dependency_overrides.clear()


def test_external_swarm_is_watched_gated_and_scored(client):
    s = client.post("/api/ingest/sessions", json={"name": "crew-demo", "agents": AGENTS}).json()
    run_id = s["run_id"]
    with client.websocket_connect(s["stream"]) as ws:
        assert ws.receive_json()["type"] == "hello"
        client.post(f"/api/ingest/{run_id}/events", json=[
            {"agent_id": "ext-planner", "event_type": "message", "action": "send", "target": "ext-analyst",
             "payload": {"content": "Please summarise SG-101."}},
            {"agent_id": "ext-analyst", "event_type": "resource_access", "action": "read", "resource": "data/customer_pii"},
        ])
        # The insider hands PII to a coder who may not hold it: the coder's egress is held at once.
        r = client.post(f"/api/ingest/{run_id}/events", json={
            "agent_id": "ext-analyst", "event_type": "message", "action": "send", "target": "ext-coder",
            "payload": {"data_ref": "data/customer_pii", "content": "extract attached"}}).json()
        # The coder may not hold PII (need-to-know hold); the policy also blocks the insider's outbound (SG-003 -> block).
        assert r["accepted"] == 1 and r["held_egress"] == ["ext-analyst", "ext-coder"]
        # Before uploading, the coder's platform asks the gate: denied, so the leak never happens.
        g = client.post(f"/api/ingest/{run_id}/gate", json={"agent_id": "ext-coder", "event_type": "data_transfer",
                                                               "action": "upload", "resource": "data/customer_pii",
                                                               "target": "external:paste-site"}).json()
        assert g["allow"] is False and "egress held" in g["reason"]
        # Ordinary work is still allowed.
        ok = client.post(f"/api/ingest/{run_id}/gate", json={"agent_id": "ext-planner", "event_type": "resource_access",
                                                                "action": "read", "resource": "docs/wiki"}).json()
        assert ok == {"allow": True, "reason": None}
        done = client.post(f"/api/ingest/{run_id}/finish").json()
        msgs = []
        while not msgs or msgs[-1]["type"] != "run_finished":
            msgs.append(ws.receive_json())
    types = [m["type"] for m in msgs]
    assert "run_started" in types and "run_agents" in types and types.count("event") == 3 and "containment" in types
    assert done["alerts"] >= 1 and done["live_metrics"]["held_egress"] == 2
    alerts = client.get(f"/api/runs/{run_id}/alerts").json()
    assert any(a["rule_id"] == "SG-003" and "ext-analyst" in a["agent_ids"] for a in alerts)


def test_ingest_errors_are_clear(client):
    assert client.post("/api/ingest/sessions", json={"agents": []}).status_code == 400
    assert client.post("/api/ingest/run-nope/events", json=[{"agent_id": "a"}]).status_code == 400
    s = client.post("/api/ingest/sessions", json={"agents": AGENTS}).json()
    assert client.post(f"/api/ingest/{s['run_id']}/gate", json={}).status_code == 400
