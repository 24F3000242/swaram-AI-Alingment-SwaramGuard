"""'Teach AI behaviour': learn clean AI-mode runs so model-written work stops looking anomalous."""
import sys
from pathlib import Path

import pytest

from app.schemas import BaselineTrainRequest
from app.services.pipeline import Pipeline
from app.storage.sqlite_store import SQLiteStore

sys.path.insert(0, str(Path(__file__).parent))
from test_autonomous_agents import FakeLLM  # noqa: E402


@pytest.fixture()
def pipeline():
    return Pipeline(SQLiteStore(":memory:"))


def test_teaching_learns_clean_ai_runs(pipeline, monkeypatch):
    monkeypatch.setattr("app.adapters.get_adapter", lambda name: FakeLLM())
    before = pipeline.baseline_summary()["runs_learned"]
    out = pipeline.train_baseline(BaselineTrainRequest(source="ai", runs=2))
    assert [t["learned"] for t in out["taught"]] == [True, True]
    assert out["runs_learned"] == before + 2
    assert all(t["ai_decisions"] == 8 for t in out["taught"])


def test_runs_the_model_did_not_drive_are_not_learned(pipeline, monkeypatch):
    class Silent(FakeLLM):
        def generate_response(self, prompt, **kw):
            return ""  # quota exhausted / model down: every turn falls back to scripted work

    monkeypatch.setattr("app.adapters.get_adapter", lambda name: Silent())
    before = pipeline.baseline_summary()["runs_learned"]
    out = pipeline.train_baseline(BaselineTrainRequest(source="ai", runs=3))
    assert len(out["taught"]) == 1 and not out["taught"][0]["learned"]  # stops after the first dead run
    assert "fell back" in out["taught"][0]["skipped_because"] and out["runs_learned"] == before


def test_api_accepts_the_ai_source(monkeypatch, tmp_path):
    from fastapi.testclient import TestClient

    from app.main import app, get_pipeline

    monkeypatch.setattr("app.adapters.get_adapter", lambda name: FakeLLM())
    app.dependency_overrides[get_pipeline] = lambda: Pipeline(SQLiteStore(str(tmp_path / "t.db")))  # never the real workspace
    try:
        r = TestClient(app).post("/api/detection/baseline", json={"source": "ai", "runs": 1})
    finally:
        app.dependency_overrides.clear()
    assert r.status_code == 200 and r.json()["taught"][0]["learned"]
