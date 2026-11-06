"""SIEM export: alerts as OCSF Detection Findings, on demand and pushed when a run finishes."""

from fastapi.testclient import TestClient

from app.main import app, get_pipeline
from app.schemas import ScenarioConfig
from app.services import siem
from app.services.live_hub import get_hub
from app.services.pipeline import Pipeline
from app.storage.sqlite_store import SQLiteStore


def _pipeline(tmp_path):
    p = Pipeline(SQLiteStore(str(tmp_path / "t.db")))
    p.seed_defaults()
    return p


def test_alerts_export_as_ocsf_detection_findings(tmp_path):
    p = _pipeline(tmp_path)
    app.dependency_overrides[get_pipeline] = lambda: p
    try:
        c = TestClient(app)
        run_id = p.simulate(ScenarioConfig(scenario_id="sg003_leak_chain")).run.run_id
        p.run_all(run_id)
        plain = c.get(f"/api/runs/{run_id}/alerts").json()
        found = c.get(f"/api/runs/{run_id}/alerts?format=ocsf").json()
    finally:
        app.dependency_overrides.clear()
    assert plain and len(found) == len(plain)
    f = next(x for x in found if x["unmapped"]["rule_id"] == "SG-003")
    assert (f["class_uid"], f["category_uid"], f["type_uid"]) == (2004, 2, 200401)
    assert f["severity_id"] in (3, 4, 5) and f["finding_info"]["analytic"]["uid"] == "SG-003"
    assert any(t.startswith("ASI07") for t in f["finding_info"]["types"])  # OWASP agentic mapping travels along
    assert {r["type"] for r in f["resources"]} >= {"AI Agent"} and isinstance(f["time"], int)


def test_forwarder_pushes_findings_when_a_run_finishes(tmp_path):
    p = _pipeline(tmp_path)
    run_id = p.simulate(ScenarioConfig(scenario_id="sg002_external_leak")).run.run_id
    p.run_all(run_id)
    sent = []
    f = siem.Forwarder("http://siem.example/collect", p.alerts, auth="Splunk t",
                       send=lambda url, body, auth: sent.append((url, body, auth)))
    f({"type": "event", "run_id": run_id})  # ignored
    f({"type": "run_finished", "run_id": run_id})
    f.queue.join()
    assert len(sent) == 1 and sent[0][2] == "Splunk t" and sent[0][1][0]["class_uid"] == 2004


def test_forwarder_is_off_without_a_url(monkeypatch):
    monkeypatch.delenv("SWARMGUARD_SIEM_URL", raising=False)
    assert siem.install(get_hub(), lambda r: []) is None
