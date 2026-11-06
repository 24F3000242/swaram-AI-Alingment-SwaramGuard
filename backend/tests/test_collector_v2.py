"""Event Collector: personal-data redaction, tamper-evident log, AI-trace summary, real log formats, dataset import."""
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import app, get_pipeline
from app.modules.collector import integrity
from app.modules.collector.formats import from_langsmith, from_otel
from app.modules.collector.normalizer import collect
from app.modules.collector.privacy import redact_text
from app.schemas import ScenarioConfig
from app.services.pipeline import Pipeline
from app.storage.sqlite_store import SQLiteStore

sys.path.insert(0, str(Path(__file__).parent))
from test_autonomous_agents import FakeLLM  # noqa: E402


# ------------------------------------------------------------ personal data
@pytest.mark.parametrize("text,kinds", [
    ("mail jane.doe@example.com now", ["email"]),
    ("call +1 (415) 555-0134 today", ["phone"]),
    ("card 4111 1111 1111 1111", ["card"]),
    ("ssn 123-45-6789", ["ssn"]),
])
def test_personal_data_becomes_stable_pseudonyms(text, kinds):
    out, n = redact_text(text)
    assert n == 1 and f"<{kinds[0]}:" in out
    assert redact_text(text)[0] == out  # same value, same pseudonym (copy detection keeps working)


@pytest.mark.parametrize("text", ["ticket SG-103 due 2026-11-05", "order 4111 1111 1111 1112", "seq 12345", "data/customer_pii"])
def test_ids_dates_and_non_luhn_numbers_are_left_alone(text):
    assert redact_text(text) == (text, 0)


def test_collector_stores_redacted_text_but_hashes_the_original(monkeypatch):
    raw = {"run_id": "run-p", "event_id": "e1", "agent_id": "a", "timestamp": "2026-11-05T10:00:00Z", "event_type": "message",
           "action": "send", "status": "success", "target": "b", "payload": {"content": "write to bob@corp.example",
                                                                              "message_id": "m1"}}
    res = collect([raw], run_id="run-p")
    e = res.events[0]
    assert "bob@corp.example" not in str(e.payload) and "bob@corp.example" not in str(e.raw)
    assert e.payload["message_id"] == "m1" and res.report.redactions == 1
    from app.modules.collector.normalizer import raw_hash

    assert e.raw_hash == raw_hash(raw)  # integrity of what was received
    monkeypatch.setenv("SWARMGUARD_REDACT_PII", "0")
    assert "bob@corp.example" in collect([raw], run_id="run-p").events[0].payload["content"]


# ------------------------------------------------------------ tamper-evident log
@pytest.fixture()
def collected():
    p = Pipeline(SQLiteStore(":memory:"))
    p.simulate(ScenarioConfig(scenario_id="sg003_leak_chain", persist=True, auto_pipeline=True), run_id="run-chain001")
    return p


def test_untouched_log_verifies(collected):
    r = collected.integrity("run-chain001")
    assert r["intact"] and r["anchor"] == r["computed_anchor"] and r["telemetry_gaps"] == []


@pytest.mark.parametrize("tamper", ["edit", "delete", "truncate"])
def test_tampering_is_detected(collected, tamper):
    events = collected.normalized_events("run-chain001")
    victim = events[len(events) // 2]
    if tamper == "edit":
        victim.payload = {**victim.payload, "content": "nothing to see here"}
        collected.store.put("normalized_events", victim.event_id, victim.model_dump(mode="json"))
    else:
        gone = {victim.event_id} if tamper == "delete" else {e.event_id for e in integrity.log_order(events)[-3:]}
        collected._replace("normalized_events", "run-chain001",
                           [(e.event_id, e.model_dump(mode="json")) for e in events if e.event_id not in gone])
    r = collected.integrity("run-chain001")
    assert not r["intact"] and r["problems"]


def test_missing_telemetry_is_reported_as_gaps_not_tampering():
    p = Pipeline(SQLiteStore(":memory:"))
    p.simulate(ScenarioConfig(scenario_id="sg003_leak_chain", drop_rate=0.3, persist=True, auto_pipeline=True), run_id="run-chain002")
    r = p.integrity("run-chain002")
    assert r["intact"] and r["telemetry_gaps"]


# ------------------------------------------------------------ AI trace summary
def test_collection_report_summarises_ai_decisions():
    from app.modules.simulator.engine import run_simulation

    sim = run_simulation(ScenarioConfig(scenario_id="inj_phishing_email", agent_mode="autonomous", persist=False),
                         adapter=FakeLLM(gullible=False))
    rep = collect([e.model_dump(mode="json") for e in sim.events], run_id=sim.run.run_id, agents=sim.agents).report
    assert rep.ai == {"model_decisions": 10, "fallbacks": 0, "refusals": 1, "exposed_to_untrusted": 1}  # 8 worker + 2 planner


# ------------------------------------------------------------ real log formats
def _a(k, v):
    return {"key": k, "value": {"stringValue": v}}


OTEL = {"resourceSpans": [{"resource": {"attributes": [_a("service.name", "crew")]}, "scopeSpans": [{"spans": [
    {"spanId": "s1", "name": "invoke_agent analyst", "startTimeUnixNano": "1793900000000000000",
     "attributes": [_a("gen_ai.operation.name", "invoke_agent"), _a("gen_ai.agent.id", "analyst-1"), _a("swarmguard.role", "analyst")]},
    {"spanId": "s2", "parentSpanId": "s1", "name": "chat", "startTimeUnixNano": "1793900001000000000",
     "attributes": [_a("gen_ai.operation.name", "chat")]},
    {"spanId": "s3", "parentSpanId": "s1", "name": "execute_tool sql", "startTimeUnixNano": "1793900002000000000",
     "status": {"code": 2}, "attributes": [_a("gen_ai.operation.name", "execute_tool"), _a("gen_ai.tool.name", "sql")]},
    {"spanId": "s4", "parentSpanId": "s1", "name": "upload", "startTimeUnixNano": "1793900003000000000",
     "attributes": [_a("swarmguard.event_type", "data_transfer"), _a("swarmguard.action", "upload"),
                    _a("swarmguard.resource", "data/customer_pii"), _a("swarmguard.target", "external:paste-site")]},
]}]}]}


def test_otel_genai_spans_become_events():
    events, agents = from_otel(OTEL, "run-o")
    assert [(e["event_type"], e["action"], e["resource"], e["status"]) for e in events] == [
        ("task", "start", None, "success"), ("tool_call", "run", "tool/sql", "failed"),
        ("data_transfer", "upload", "data/customer_pii", "success")]  # the model call is skipped
    assert {e["agent_id"] for e in events} == {"analyst-1"} and agents[0]["role"] == "analyst"
    assert collect(events, run_id="run-o").report.valid == 3


def test_langsmith_runs_become_events():
    runs = [
        {"id": "r1", "name": "AgentExecutor", "run_type": "chain", "start_time": "2026-11-05T10:00:00",
         "extra": {"metadata": {"agent_id": "researcher-1", "role": "researcher"}}},
        {"id": "r2", "parent_run_id": "r1", "name": "ChatModel", "run_type": "llm", "start_time": "2026-11-05T10:00:01"},
        {"id": "r3", "parent_run_id": "r1", "name": "web_search", "run_type": "tool", "start_time": "2026-11-05T10:00:02"},
        {"id": "r4", "parent_run_id": "r1", "name": "docs", "run_type": "retriever", "start_time": "2026-11-05T10:00:03",
         "error": "timeout"},
    ]
    events, agents = from_langsmith(runs, "run-l")
    assert [(e["agent_id"], e["event_type"], e["resource"], e["status"]) for e in events] == [
        ("researcher-1", "tool_call", "tool/web_search", "success"),
        ("researcher-1", "resource_access", "retriever/docs", "failed")]
    assert collect(events, run_id="run-l").report.valid == 2


def test_live_ingest_accepts_otel_and_catches_the_leak(tmp_path):
    p = Pipeline(SQLiteStore(str(tmp_path / "t.db")))
    app.dependency_overrides[get_pipeline] = lambda: p
    try:
        c = TestClient(app)
        rid = c.post("/api/ingest/sessions", json={"name": "otel-demo", "agents": [
            {"agent_id": "analyst-1", "role": "analyst", "permissions": ["data/customer_pii"]}]}).json()["run_id"]
        r = c.post(f"/api/ingest/{rid}/events", params={"format": "otel"}, json=OTEL).json()
        assert r["accepted"] == 3
        c.post(f"/api/ingest/{rid}/finish")
        assert any(a["rule_id"] == "SG-002" for a in c.get(f"/api/runs/{rid}/alerts").json())
        assert c.post("/api/convert", params={"format": "nope"}, json={}).status_code == 400
    finally:
        app.dependency_overrides.clear()


# ------------------------------------------------------------ dataset import
def test_dataset_batch_imports_into_the_workspace(tmp_path):
    from app.services.dataset import BatchConfig, generate
    from app.services.dataset_import import import_dataset

    rules = Pipeline(SQLiteStore(":memory:")).rules()
    cfg = BatchConfig(out_dir=str(tmp_path / "batch"), scenarios=["sg003_leak_chain"], runs_per_scenario=1, learn_runs=1,
                      backend="fake")
    generate(cfg, rules, adapter_factory=lambda: FakeLLM(), log=lambda m: None)
    p = Pipeline(SQLiteStore(str(tmp_path / "w.db")))
    first = import_dataset(p, tmp_path / "batch")
    assert first["imported"] == 2
    test_run = next(r for r in first["run_ids"] if p.get_run(r).scenario_id == "sg003_leak_chain")
    run = p.get_run(test_run)
    assert run.labels.malicious_agent_ids and run.stages.get("evaluated") and p.alerts(test_run)
    assert import_dataset(p, tmp_path / "batch")["skipped_existing"] == 2  # safe to run twice
    with pytest.raises(ValueError, match="labels.jsonl"):
        import_dataset(p, tmp_path)
