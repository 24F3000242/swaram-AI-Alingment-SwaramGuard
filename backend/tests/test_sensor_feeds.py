"""Collector (member 2): real sensor feeds (egress proxy, file audit, broker) as a second evidence source."""
import pytest
from fastapi.testclient import TestClient

from app.main import app, get_pipeline
from app.modules.collector.formats import from_broker, from_egress, from_file_audit
from app.modules.collector.normalizer import collect
from app.services.pipeline import Pipeline
from app.storage.sqlite_store import SQLiteStore

AGENTS = [{"agent_id": "analyst-1", "role": "analyst", "permissions": ["data/public", "data/customer_pii"]},
          {"agent_id": "coder-1", "role": "coder", "permissions": ["repo/src"]}]


def T(s):
    return f"2026-11-05T10:00:{s:02d}.000Z"


@pytest.fixture()
def client(tmp_path):
    p = Pipeline(SQLiteStore(str(tmp_path / "t.db")))
    app.dependency_overrides[get_pipeline] = lambda: p
    yield TestClient(app)
    app.dependency_overrides.clear()


def test_sensor_records_become_mirrored_observations():
    egress, _ = from_egress([{"timestamp": T(1), "client": "coder-1", "host": "paste-site", "method": "POST", "bytes": 9000}], "run-s")
    audit, _ = from_file_audit([{"ts": T(2), "actor": "analyst-1", "path": "data/customer_pii", "operation": "READ"}], "run-s")
    broker, _ = from_broker([{"time": T(3), "sender": "analyst-1", "recipient": "coder-1", "message_id": "m1",
                              "data_ref": "data/customer_pii"}], "run-s")
    e, a, b = egress[0], audit[0], broker[0]
    assert (e["event_type"], e["action"], e["target"], e["payload"]["mirrors"]) == ("observation", "upload", "external:paste-site", "data_transfer")
    assert (a["action"], a["resource"], a["payload"]["mirrors"]) == ("read", "data/customer_pii", "resource_access")
    assert (b["target"], b["payload"]["data_ref"], b["payload"]["mirrors"]) == ("coder-1", "data/customer_pii", "message")
    assert collect(egress + audit + broker, run_id="run-s").report.valid == 3


def _session(client):
    run_id = client.post("/api/ingest/sessions", json={"name": "sensors", "agents": AGENTS, "live_guard": "detect"}).json()["run_id"]
    log = [{"agent_id": "analyst-1", "event_type": "resource_access", "action": "read", "resource": "data/public", "timestamp": T(0)},
           {"agent_id": "analyst-1", "event_type": "data_transfer", "action": "upload", "resource": "data/public",
            "target": "external:approved-partner-api", "timestamp": T(20)},
           {"agent_id": "coder-1", "event_type": "resource_access", "action": "read", "resource": "repo/src", "timestamp": T(40)}]
    client.post(f"/api/ingest/{run_id}/events", json=log)
    return run_id


def test_an_upload_only_the_proxy_saw_is_a_gateway_bypass(client):
    run_id = _session(client)
    feed = [{"timestamp": T(20), "client": "analyst-1", "host": "approved-partner-api", "method": "POST"},  # also in the log
            {"timestamp": T(30), "client": "coder-1", "host": "paste-site", "method": "POST", "bytes": 52000}]  # never logged
    assert client.post(f"/api/ingest/{run_id}/events", params={"format": "egress"}, json=feed).json()["accepted"] == 2
    client.post(f"/api/ingest/{run_id}/finish")
    alerts = client.get(f"/api/runs/{run_id}/alerts").json()
    bypass = [a for a in alerts if a["rule_id"] == "SG-021" and a["agent_ids"]]
    assert bypass and bypass[0]["agent_ids"] == ["coder-1"]  # only the unlogged upload; the logged one matched
    assert not any("analyst-1" in a["agent_ids"] for a in alerts if a["rule_id"] == "SG-021")


def test_matching_feeds_raise_nothing(client):
    run_id = _session(client)
    client.post(f"/api/ingest/{run_id}/events", params={"format": "egress"},
                json=[{"timestamp": T(20), "client": "analyst-1", "host": "approved-partner-api"}])
    client.post(f"/api/ingest/{run_id}/events", params={"format": "file_audit"},
                json=[{"timestamp": T(0), "actor": "analyst-1", "path": "data/public", "operation": "read"},
                      {"timestamp": T(40), "actor": "coder-1", "path": "repo/src", "operation": "read"}])
    client.post(f"/api/ingest/{run_id}/finish")
    assert client.get(f"/api/runs/{run_id}/alerts").json() == []
