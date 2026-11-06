"""Security Response: human review of live containment, policy defaults for newer rules, and notifications."""
import sys
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import app, get_pipeline
from app.schemas import ScenarioConfig
from app.services.live_hub import LiveHub
from app.services.pipeline import Pipeline
from app.storage.sqlite_store import SQLiteStore

sys.path.insert(0, str(Path(__file__).parent))
from test_ingest import AGENTS  # noqa: E402


@pytest.fixture()
def pipeline(tmp_path):
    return Pipeline(SQLiteStore(str(tmp_path / "t.db")))


@pytest.fixture()
def client(pipeline):
    app.dependency_overrides[get_pipeline] = lambda: pipeline
    yield TestClient(app)
    app.dependency_overrides.clear()


def test_contained_agents_become_review_items(pipeline):
    pipeline.simulate(ScenarioConfig(scenario_id="sg003_leak_chain", live_guard="contain", persist=True), run_id="run-rev00001")
    from app.services import review

    items = review.items(pipeline.store, "pending", "run-rev00001")
    kinds = {(i["role"], i["kind"]) for i in items}
    # Both culprits' first harmful actions are refused before they run and their egress held; the coder is also
    # paused by live detection. Every containment is a review item.
    assert {("analyst", "held_egress"), ("coder", "held_egress"), ("coder", "paused_agent")} <= kinds
    assert all(i["explanation"] for i in items)


def test_release_un_pauses_a_live_agent_and_confirm_keeps_it(client):
    run_id = client.post("/api/ingest/sessions", json={"name": "review-demo", "agents": AGENTS}).json()["run_id"]
    client.post(f"/api/ingest/{run_id}/events", json=[
        {"agent_id": "ext-analyst", "event_type": "resource_access", "action": "read", "resource": "data/customer_pii"},
        {"agent_id": "ext-analyst", "event_type": "message", "action": "send", "target": "ext-coder",
         "payload": {"data_ref": "data/customer_pii"}}])
    ask = {"agent_id": "ext-coder", "event_type": "data_transfer", "action": "upload", "resource": "repo/src",
           "target": "external:approved-partner-api"}
    assert client.post(f"/api/ingest/{run_id}/gate", json=ask).json()["allow"] is False
    pending = client.get("/api/reviews", params={"status": "pending", "run_id": run_id}).json()
    hold = next(i for i in pending if i["kind"] == "held_egress" and i["agent_id"] == "ext-coder")
    with client.websocket_connect(f"/api/live?run_id={run_id}") as ws:
        done = client.post(f"/api/reviews/{hold['review_id']}", json={"decision": "release", "note": "partner verified"}).json()
        assert done["status"] == "released" and "egress hold lifted" in done["effect"]
        decided = []
        for _ in range(100):  # replayed history, then the decision
            m = ws.receive_json()
            if m["type"] == "review" and m["data"]["action"] == "decided":
                decided.append(m)
                break
    assert decided and decided[-1]["data"]["item"]["review_id"] == hold["review_id"]
    assert client.post(f"/api/ingest/{run_id}/gate", json=ask).json()["allow"] is True  # really released
    assert client.post(f"/api/reviews/{hold['review_id']}", json={"decision": "confirm"}).status_code == 400  # decided once


def test_decisions_after_a_run_are_recorded_honestly(pipeline):
    from app.services import review

    pipeline.simulate(ScenarioConfig(scenario_id="sg003_leak_chain", live_guard="contain", persist=True), run_id="run-rev00002")
    items = review.items(pipeline.store, "pending", "run-rev00002")
    a, b = items[0], items[1]
    assert "already finished" in review.decide(pipeline.store, a["review_id"], "release")["effect"]
    assert review.decide(pipeline.store, b["review_id"], "confirm")["status"] == "confirmed"
    with pytest.raises(ValueError, match="already decided"):
        review.decide(pipeline.store, a["review_id"], "confirm")
    with pytest.raises(ValueError, match="release' or 'confirm"):
        review.decide(pipeline.store, items[2]["review_id"], "ignore")


def test_quarantined_inputs_are_queued_for_review(pipeline):
    from test_autonomous_agents import FakeLLM

    from app.services import review

    import app.adapters as adapters

    orig = adapters.get_adapter
    adapters.get_adapter = lambda name: FakeLLM(gullible=True)
    try:
        import app.modules.simulator.engine as engine

        engine.get_adapter = adapters.get_adapter
        pipeline.simulate(ScenarioConfig(scenario_id="inj_spoofed_planner", agent_mode="autonomous", agent_backend="fake",
                                         live_guard="contain", persist=True), run_id="run-rev00003")
    finally:
        adapters.get_adapter = orig
        engine.get_adapter = orig
    q = [i for i in review.items(pipeline.store, run_id="run-rev00003") if i["kind"] == "quarantined_input"]
    assert len(q) == 1 and q[0]["claimed_sender"] == "planner" and q[0]["resource"] == "inbox/msg_9921"
    assert "sender marked as verified" in review.decide(pipeline.store, q[0]["review_id"], "release")["effect"]


def test_policy_defaults_cover_the_newer_rules():
    from app.modules.response.policy import DEFAULT_POLICY

    assert DEFAULT_POLICY.rule_overrides == {"SG-012": "pause", "SG-026": "block", "SG-027": "block"}


def test_notifications_go_out_for_containment_and_nothing_else():
    from app.services.notify import Notifier, summary

    sent = []
    hub = LiveHub()
    hub.taps.append(Notifier("https://hooks.example/x", send=lambda url, text, msg: sent.append(text)))
    hub.publish("event", {"agent_id": "a"}, "run-1")
    hub.publish("detection", {"severity": "high", "rule_id": "SG-001"}, "run-1")
    hub.publish("containment", {"agent_id": "a1", "role": "coder", "scope": "agent", "explanation": "leak chain"}, "run-1")
    hub.publish("detection", {"severity": "critical", "rule_id": "SG-012", "rule_name": "Goal hijack", "reason": "r"}, "run-1")
    for _ in range(50):
        if len(sent) >= 2:
            break
        time.sleep(0.05)
    assert sent == ["SwarmGuard: a1 (coder) paused in run-1: leak chain",
                    "SwarmGuard: CRITICAL SG-012 Goal hijack in run-1: r"]
    assert summary({"type": "event", "data": {}}) is None


def test_a_failing_webhook_never_breaks_a_run():
    from app.services.notify import Notifier

    def boom(*a):
        raise RuntimeError("webhook down")

    hub = LiveHub()
    n = Notifier("https://hooks.example/x", send=boom)
    hub.taps.append(n)
    hub.publish("containment", {"agent_id": "a1", "scope": "agent"}, "run-1")
    n.queue.join()
    assert n.sent == 0  # logged, swallowed


# ------------------------------------------------------------ escalation and who decided
def test_overdue_reviews_are_escalated_once_and_decisions_record_who(pipeline):
    from app.services import review
    from app.services.live_hub import get_hub
    from app.services.notify import summary

    pipeline.simulate(ScenarioConfig(scenario_id="sg003_leak_chain", live_guard="contain", persist=True), run_id="run-rev00009")
    items = review.items(pipeline.store, "pending", "run-rev00009")
    assert review.escalate(pipeline.store, after_minutes=15) == []  # just created: not overdue yet
    later = "2099-01-01T00:00:00.000Z"
    due = review.escalate(pipeline.store, after_minutes=15, now=later)
    assert {i["review_id"] for i in due} == {i["review_id"] for i in items}
    assert review.escalate(pipeline.store, after_minutes=15, now=later) == []  # announced once, not every minute
    msg = next(m for m in reversed(get_hub().history) if m["type"] == "review" and m["data"]["action"] == "escalated")
    assert summary(msg).startswith("SwarmGuard: OVERDUE review")
    done = review.decide(pipeline.store, items[0]["review_id"], "confirm", "checked the chain", by="Aarya")
    assert done["decided_by"] == "Aarya" and done["escalated_at"]
    assert review.decide(pipeline.store, items[1]["review_id"], "confirm")["decided_by"] == "unknown"


def test_escalate_endpoint(client):
    assert client.post("/api/reviews/escalate", params={"minutes": 0}).status_code == 200
