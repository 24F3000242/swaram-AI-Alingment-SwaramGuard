"""API keys with roles: who may watch, act, change the rules, or only report in."""
import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from app.auth import load_keys
from app.main import app, get_pipeline
from app.services.pipeline import Pipeline
from app.storage.sqlite_store import SQLiteStore

KEYS = {"admin": "adm-0123456789abcdef", "operator": "opr-0123456789abcdef", "viewer": "vwr-0123456789abcdef",
        "agent": "agt-0123456789abcdef"}


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("SWARMGUARD_API_KEYS", ",".join(f"{r}-user:{k}:{r}" for r, k in KEYS.items()))
    p = Pipeline(SQLiteStore(str(tmp_path / "t.db")))
    app.dependency_overrides[get_pipeline] = lambda: p
    yield TestClient(app)
    app.dependency_overrides.clear()


def H(role):
    return {"Authorization": f"Bearer {KEYS[role]}"}


def test_no_key_no_access_except_health(client):
    assert client.get("/api/health").json()["auth"] == "on"
    r = client.get("/api/runs")
    assert r.status_code == 401 and "API key" in r.json()["detail"]
    assert client.get("/api/runs", headers={"Authorization": "Bearer wrong-key-0123456789"}).status_code == 401
    assert client.options("/api/runs", headers={"Origin": "http://localhost:5173",
                                                "Access-Control-Request-Method": "GET"}).status_code != 401  # CORS pre-flight


@pytest.mark.parametrize("role,read,act,configure,ingest", [
    ("viewer", 200, 403, 403, 403),
    ("operator", 200, 200, 403, 200),
    ("admin", 200, 200, 200, 200),
    ("agent", 403, 403, 403, 200),
])
def test_each_role_can_do_exactly_its_part(client, role, read, act, configure, ingest):
    assert client.get("/api/runs", headers=H(role)).status_code == read
    sim = client.post("/api/simulate", headers=H(role), json={"scenario_id": "normal_collaboration", "persist": False})
    assert sim.status_code == act
    pol = client.get("/api/response-policies/default", headers=H("admin")).json()
    assert client.put("/api/response-policies/default", headers=H(role), json=pol).status_code == configure
    s = client.post("/api/ingest/sessions", headers=H(role),
                    json={"agents": [{"agent_id": "a1", "role": "analyst", "permissions": []}]})
    assert s.status_code == ingest


def test_x_api_key_header_and_whoami(client):
    me = client.get("/api/whoami", headers={"X-API-Key": KEYS["operator"]}).json()
    assert me == {"auth": True, "name": "operator-user", "role": "operator"}


def test_live_stream_needs_a_viewer_key(client):
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/api/live") as ws:
            ws.receive_json()
    with client.websocket_connect(f"/api/live?key={KEYS['viewer']}") as ws:
        assert ws.receive_json()["type"] == "hello"


def test_review_decisions_record_the_key_owner(client):
    client.post("/api/simulate", headers=H("operator"),
                json={"scenario_id": "sg003_leak_chain", "live_guard": "contain", "persist": True})
    item = client.get("/api/reviews", headers=H("viewer")).json()[0]
    done = client.post(f"/api/reviews/{item['review_id']}", headers=H("operator"),
                       json={"decision": "confirm", "by": "someone-else"}).json()
    assert done["decided_by"] == "operator-user"  # can't be spoofed through the body


def test_auth_is_off_without_keys_and_bad_config_is_refused(monkeypatch, tmp_path):
    monkeypatch.delenv("SWARMGUARD_API_KEYS", raising=False)
    app.dependency_overrides[get_pipeline] = lambda: Pipeline(SQLiteStore(str(tmp_path / "u.db")))
    try:
        c = TestClient(app)
        assert c.get("/api/health").json()["auth"] == "off" and c.get("/api/runs").status_code == 200
    finally:
        app.dependency_overrides.clear()
    with pytest.raises(ValueError, match="too short"):
        load_keys("bob:short:admin")
    with pytest.raises(ValueError, match="unknown role"):
        load_keys("bob:0123456789abcdefgh:superuser")
