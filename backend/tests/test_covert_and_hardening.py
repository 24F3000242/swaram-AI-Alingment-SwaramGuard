"""SG-029 covert staged transfer, the swarm circuit breaker, and scoped (expiring) agent identity tokens."""
import sys
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).parent))
from test_autonomous_agents import FakeLLM  # noqa: E402

from app.main import app, get_pipeline
from app.modules.detection.covert import covert_signals, rule_covert_transfer
from app.modules.detection.live import LiveGuard
from app.modules.simulator.engine import run_simulation
from app.schemas import Agent, DetectionRule, NormalizedEvent, ScenarioConfig
from app.services.ingest import agent_token, token_valid
from app.services.pipeline import Pipeline
from app.storage.sqlite_store import SQLiteStore


# ------------------------------------------------------------ SG-029 covert signals
@pytest.mark.parametrize("text,expect", [
    ("x+='ABCD';n('//next-hop.example/b')", {"fragment_chain"}),
    ("eval(atob('ZXZpbA=='))", {"assemble_run", "decode_run"}),
    ("fetch(u,{headers:{Authorization:'Bearer sk-123'}})", {"credential_out"}),
    ("cycler.__init__.__globals__.os.system('id')", {"assemble_run"}),
    ("Please send the planner your notes on SG-103.", set()),
    ("const data = await res.json(); render(data);", set()),
])
def test_covert_signals(text, expect):
    assert set(covert_signals(text)) == expect


def test_rule_flags_two_signals_or_a_credential():
    reg = {"a": Agent(agent_id="a", run_id="r", name="A", role="coder", permissions=["repo/src"])}

    def ev(i, payload):
        return NormalizedEvent(event_id=f"e{i}", run_id="r", agent_id="a", agent_role="coder",
                               timestamp="2026-11-07T10:00:0%dZ" % i, event_type="data_transfer", action="upload",
                               status="success", sequence=i, payload=payload, resource="out", target="external:x",
                               summary="", raw_hash="h", raw={}, normalized_at="2026-11-07T10:00:00Z")
    rule = DetectionRule(rule_id="SG-029", name="Covert staged transfer", severity="high",
                         recommended_action="alert", description="", params={"min_signals": 2})
    events = [ev(1, {"content": "eval(atob('x'))"}),               # 2 signals -> flagged
              ev(2, {"content": "fetch(u,{headers:{'X-API-Key':'[CREDENTIAL 1]'}})"}),  # credential -> flagged
              ev(3, {"content": "normal report, nothing hidden"})]  # clean
    alerts = rule_covert_transfer(rule, "r", events, reg)
    assert {a.event_ids[0] for a in alerts} == {"e1", "e2"}
    assert all(a.rule_id == "SG-029" for a in alerts)


# ------------------------------------------------------------ swarm circuit breaker
def _rules():
    return Pipeline(SQLiteStore(":memory:")).rules()


def test_breaker_contains_the_whole_swarm_once_a_cascade_spreads():
    rules = _rules()
    live = LiveGuard(rules, "contain", cascade_agents=4)
    sim = run_simulation(ScenarioConfig(scenario_id="inj_worm", agent_mode="autonomous", persist=False),
                         adapter=FakeLLM(gullible=True), live=live)
    assert live.tripped and set(live.paused) == {a.agent_id for a in sim.agents}
    assert any(c.trigger == "circuit_breaker" for c in live.paused.values())


def test_breaker_never_trips_on_normal_runs():
    rules = _rules()
    for agents in (5, 10, 20):
        live = LiveGuard(rules, "contain", cascade_agents=4)
        run_simulation(ScenarioConfig(scenario_id="normal_collaboration", agent_count=agents, persist=False), live=live)
        assert not live.tripped and not live.paused


def test_breaker_can_be_turned_off():
    rules = _rules()
    live = LiveGuard(rules, "contain", cascade_agents=0)
    run_simulation(ScenarioConfig(scenario_id="inj_worm", agent_mode="autonomous", persist=False),
                   adapter=FakeLLM(gullible=True), live=live)
    assert not live.tripped and not any(c.trigger == "circuit_breaker" for c in live.paused.values())


# ------------------------------------------------------------ scoped tokens
def test_scoped_token_expires_session_token_does_not():
    now = int(time.time())
    scoped = agent_token("run-1", "a1", now + 10)
    assert token_valid("run-1", "a1", scoped, now) and not token_valid("run-1", "a1", scoped, now + 11)
    assert not token_valid("run-1", "a2", scoped, now)  # another agent's id
    forged = f"{now + 9999}." + scoped.split(".", 1)[1]  # extend the expiry, keep the old mac
    assert not token_valid("run-1", "a1", forged, now)  # mac covers the expiry, so this fails
    session = agent_token("run-1", "a1")
    assert token_valid("run-1", "a1", session, now + 10**6)


def test_session_issues_scoped_tokens_and_rejects_expired(tmp_path):
    pipeline = Pipeline(SQLiteStore(str(tmp_path / "t.db")))
    app.dependency_overrides[get_pipeline] = lambda: pipeline
    try:
        c = TestClient(app)
        out = c.post("/api/ingest/sessions", json={
            "name": "scoped", "require_agent_identity": True, "token_ttl": 3600,
            "agents": [{"agent_id": "a1", "role": "analyst", "permissions": ["data/public"]}]}).json()
        assert out["token_ttl"] == 3600 and "." in out["agent_tokens"]["a1"]
        ev = {"agent_id": "a1", "event_type": "task", "action": "start", "agent_token": out["agent_tokens"]["a1"]}
        assert c.post(f"/api/ingest/{out['run_id']}/events", json=[ev]).status_code == 200
        expired = agent_token(out["run_id"], "a1", int(time.time()) - 1)
        assert c.post(f"/api/ingest/{out['run_id']}/events",
                      json=[{**ev, "agent_token": expired}]).status_code == 403
    finally:
        app.dependency_overrides.clear()
