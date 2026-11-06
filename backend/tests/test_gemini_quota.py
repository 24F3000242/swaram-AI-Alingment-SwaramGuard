"""Gemini quota: Google's real limits and reset time, shared usage, and refusing runs that wouldn't fit."""
from datetime import datetime, timezone

import pytest

from app.adapters import gemini_adapter as ga
from app.schemas import BaselineTrainRequest, ScenarioConfig
from app.services import quota


def _ts(s: str) -> float:
    return datetime.fromisoformat(s).replace(tzinfo=timezone.utc).timestamp()


@pytest.mark.parametrize("utc,day,reset_utc", [
    ("2026-11-05T12:00:00", "2026-11-05", "2026-11-06T08:00:00"),  # PST (UTC-8): midnight Pacific = 08:00 UTC
    ("2026-07-01T06:59:00", "2026-06-30", "2026-07-01T07:00:00"),  # PDT (UTC-7), just before local midnight
    ("2026-07-01T07:00:00", "2026-07-01", "2026-07-02T07:00:00"),
])
def test_quota_day_follows_googles_pacific_midnight(utc, day, reset_utc):
    assert ga.quota_day(_ts(utc)) == day
    assert ga.next_reset(_ts(utc)) == _ts(reset_utc)


def test_usage_is_shared_between_processes_through_the_state_file(tmp_path):
    f = tmp_path / "q.json"
    app_tracker, script_tracker = ga.GeminiQuotaTracker(10, 5, state_file=f), ga.GeminiQuotaTracker(10, 5, state_file=f)
    for _ in range(3):
        script_tracker.record_call()
    assert app_tracker.status()["calls_today"] == 3 and app_tracker.remaining() == 7
    assert ga.GeminiQuotaTracker(10, 5, state_file=f).status()["calls_today"] == 3  # survives a restart


def test_a_daily_429_blocks_until_the_reset_instead_of_retrying_every_minute(tmp_path):
    t = ga.GeminiQuotaTracker(480, 14, state_file=tmp_path / "q.json")
    t.record_429(60.0, daily=True)  # Google: "requests per day limit exceeded"
    ok, reason = t.can_call()
    assert not ok and "daily Gemini quota is used up" in reason and t.remaining() == 0
    st = t.status()
    assert st["exhausted"] and st["resets_in_s"] > 600 and "resets in" in st["blocked_reason"]
    assert ga.GeminiQuotaTracker(480, 14, state_file=tmp_path / "q.json").remaining() == 0  # other processes see it


def test_a_long_retry_hint_counts_as_daily_and_a_short_one_as_per_minute(tmp_path):
    t = ga.GeminiQuotaTracker(480, 14, state_file=tmp_path / "q.json")
    t.record_429(14.0)  # "retry in 14s": per-minute limit
    assert t.remaining() == 480 and not t.status()["exhausted"]
    t.record_429(8 * 3600.0)  # "retry in 8h": the day is spent
    assert t.remaining() == 0 and t.status()["exhausted"]


def test_runs_that_dont_fit_are_refused_up_front(monkeypatch, tmp_path):
    tracker = ga.GeminiQuotaTracker(20, 14, state_file=tmp_path / "q.json")
    monkeypatch.setattr(ga, "GLOBAL_QUOTA_TRACKER", tracker)
    for _ in range(10):
        tracker.record_call()  # 10 left
    small = ScenarioConfig(scenario_id="normal_collaboration", agent_count=5, agent_backend="gemini", agent_mode="autonomous")
    quota.check_run(small)  # 10 calls: fits
    big = ScenarioConfig(scenario_id="normal_collaboration", agent_count=10, agent_backend="gemini", agent_mode="autonomous")
    with pytest.raises(ValueError, match=r"needs about 20 model calls and 10 are left"):
        quota.check_run(big)
    quota.check_run(big.model_copy(update={"agent_backend": "deterministic"}))  # never limited


def test_api_refuses_an_over_quota_run_and_reports_quota(monkeypatch, tmp_path):
    from fastapi.testclient import TestClient

    from app.main import app, get_pipeline
    from app.services.pipeline import Pipeline
    from app.storage.sqlite_store import SQLiteStore

    tracker = ga.GeminiQuotaTracker(480, 14, state_file=tmp_path / "q.json")
    tracker.record_429(60.0, daily=True)
    monkeypatch.setattr(ga, "GLOBAL_QUOTA_TRACKER", tracker)
    app.dependency_overrides[get_pipeline] = lambda: Pipeline(SQLiteStore(str(tmp_path / "t.db")))
    try:
        c = TestClient(app)
        q = c.get("/api/gemini/quota").json()
        assert q["exhausted"] and q["remaining_today"] == 0 and q["calls_per_run"]["5"] == {"scripted": 20, "autonomous": 10}
        r = c.post("/api/simulate", json={"scenario_id": "normal_collaboration", "agent_backend": "gemini", "persist": False})
        assert r.status_code == 400 and "Not enough Gemini quota" in r.json()["detail"]
        ok = c.post("/api/simulate", json={"scenario_id": "normal_collaboration", "persist": False})
        assert ok.status_code == 200  # the deterministic backend still works
    finally:
        app.dependency_overrides.clear()


def test_teaching_ai_checks_quota_first(monkeypatch, tmp_path):
    from app.services.pipeline import Pipeline
    from app.storage.sqlite_store import SQLiteStore

    tracker = ga.GeminiQuotaTracker(20, 14, state_file=tmp_path / "q.json")
    monkeypatch.setattr(ga, "GLOBAL_QUOTA_TRACKER", tracker)
    with pytest.raises(ValueError, match="teaching 3 AI run"):
        Pipeline(SQLiteStore(":memory:")).train_baseline(BaselineTrainRequest(source="ai", runs=3))  # needs ~48
