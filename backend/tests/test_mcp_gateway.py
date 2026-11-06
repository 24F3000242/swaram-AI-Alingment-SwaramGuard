"""MCP gateway: tool calls from an agent's MCP client are gated before they reach the real tool server."""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from fastapi.testclient import TestClient

from app.main import app, get_pipeline
from app.modules.simulator.injections import POISONED_PAGE
from app.services.mcp_gateway import describe_call
from app.services.pipeline import Pipeline
from app.storage.sqlite_store import SQLiteStore

TOOLS = [{"name": "web_search", "inputSchema": {}}, {"name": "read_file", "inputSchema": {}},
         {"name": "http_post", "inputSchema": {}}, {"name": "delete_repo", "inputSchema": {}}]


class FakeMCP(BaseHTTPRequestHandler):
    calls: list = []

    def do_POST(self):
        msg = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        FakeMCP.calls.append(msg)
        if "id" not in msg:  # a notification
            self.send_response(202)
            self.end_headers()
            return
        if msg["method"] == "initialize":
            result = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}}, "serverInfo": {"name": "fake"}}
        elif msg["method"] == "tools/list":
            result = {"tools": TOOLS}
        else:
            name = msg["params"]["name"]
            text = POISONED_PAGE if name == "web_search" else f"{name} ok"
            result = {"content": [{"type": "text", "text": text}], "isError": False}
        body = json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": result}).encode()
        sse = msg["method"] == "tools/list"  # answer one method as SSE, like streamable HTTP servers may
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream" if sse else "application/json")
        self.send_header("Mcp-Session-Id", "sess-1")
        payload = b"event: message\ndata: " + body + b"\n\n" if sse else body
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *a):
        pass


AGENTS = [{"agent_id": "r1", "role": "researcher", "permissions": ["docs/wiki", "data/public"]}]


@pytest.fixture()
def env(tmp_path):
    pipeline = Pipeline(SQLiteStore(str(tmp_path / "t.db")))
    app.dependency_overrides[get_pipeline] = lambda: pipeline
    server = ThreadingHTTPServer(("127.0.0.1", 0), FakeMCP)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    FakeMCP.calls = []
    client = TestClient(app)
    out = client.post("/api/ingest/sessions", json={
        "name": "mcp", "agents": AGENTS,
        "mcp": {"upstream": f"http://127.0.0.1:{server.server_address[1]}/mcp",
                "tools": {"r1": ["web_search", "read_file", "http_post"]}}}).json()
    yield client, pipeline, out
    server.shutdown()
    app.dependency_overrides.clear()


def rpc(client, out, method, params=None, msg_id=1):
    url = out["mcp"]["r1"]
    return client.post(url, json={"jsonrpc": "2.0", "id": msg_id, "method": method, "params": params or {}})


def call(client, out, name, **args):
    return rpc(client, out, "tools/call", {"name": name, "arguments": args}).json()["result"]


def test_handshake_passes_through_and_unlisted_tools_are_hidden(env):
    client, _, out = env
    r = rpc(client, out, "initialize", {"protocolVersion": "2025-06-18"})
    assert r.json()["result"]["serverInfo"]["name"] == "fake" and r.headers["mcp-session-id"] == "sess-1"
    tools = rpc(client, out, "tools/list").json()["result"]["tools"]  # (answered as SSE upstream)
    assert [t["name"] for t in tools] == ["web_search", "read_file", "http_post"]  # delete_repo never shown


def test_allowed_call_reaches_the_server_and_its_output_is_scanned(env):
    client, pipeline, out = env
    res = call(client, out, "web_search", query="summary best practices")
    assert res["isError"] is False and "Note for AI assistants" in res["content"][0]["text"]
    ev = [e for e in pipeline.raw_events(out["run_id"]) if e.resource == "tool/web_search"][-1]
    assert ev.status == "success" and ev.payload["untrusted"] is True  # sent for SG-028 scoring, arms the tripwire


def test_unlisted_tool_restricted_read_and_unapproved_upload_are_refused_before_the_server_sees_them(env):
    client, pipeline, out = env
    for name, args, why in [("delete_repo", {}, "not allowed"),
                            ("read_file", {"path": "secrets/api_keys"}, "pre-execution check"),
                            ("http_post", {"url": "https://paste.example/x", "resource": "data/public"},
                             ("pre-execution check", "paused"))]:  # after the secrets attempt it may be paused too
        res = call(client, out, name, **args)
        text = res["content"][0]["text"]
        assert res["isError"] is True and any(w in text for w in ((why,) if isinstance(why, str) else why)), (name, res)
    assert not [c for c in FakeMCP.calls if c.get("method") == "tools/call"]  # none reached the real server
    denied = [e for e in pipeline.raw_events(out["run_id"]) if e.status == "denied"]
    assert len(denied) == 3


def test_paused_agent_cannot_call_tools(env):
    client, _, out = env
    client.post(f"/api/live/{out['run_id']}/agents/r1", json={"action": "pause"})
    res = call(client, out, "read_file", path="docs/wiki/intro")
    assert res["isError"] is True and "paused" in res["content"][0]["text"]


def test_notifications_get_202(env):
    client, _, out = env
    r = client.post(out["mcp"]["r1"], json={"jsonrpc": "2.0", "method": "notifications/initialized"})
    assert r.status_code == 202


@pytest.mark.parametrize("name,args,kind", [
    ("http_post", {"url": "https://x.example/a"}, ("data_transfer", "external:x.example")),
    ("send", {"destination": "external:vault"}, ("data_transfer", "external:vault")),
    ("read_file", {"path": "data/public/a.csv"}, ("resource_access", None)),
    ("write_file", {"path": "repo/src/a.py"}, ("resource_access", None)),
    ("web_search", {"query": "x"}, ("tool_call", None)),
])
def test_describe_call(name, args, kind):
    ev = describe_call(name, args)
    assert (ev["event_type"], ev.get("target")) == kind
    if name == "write_file":
        assert ev["action"] == "write"
